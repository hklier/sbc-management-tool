import base64, datetime, json, tempfile, threading, time, unittest
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import devices_tools as d
import server, snmp_tools
import test_server as existing

KEY=rsa.generate_private_key(public_exponent=65537,key_size=2048)
PUBLIC=KEY.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
NAME=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Device tests CA')])
CA=x509.CertificateBuilder().subject_name(NAME).issuer_name(NAME).public_key(KEY.public_key()).serial_number(1).not_valid_before(datetime.datetime(2026,1,1)).not_valid_after(datetime.datetime(2030,1,1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(KEY,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
def profile(ip='192.0.2.51'):
    return dict(name='Test SBC',management_ip=ip,rest_username='admin',rest_password='private-rest-password',ssh_port=22,ssh_public_key=PUBLIC,ca_certificate=CA,snmp=dict(version='3',port=161,username='monitor',security_level='authPriv',auth_protocol='SHA256',auth_password='private-auth-password',priv_protocol='AES128',priv_password='private-privacy-password',trap_communities=['private-trap-community']))

class DeviceStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.store=d.Store(Path(self.directory.name));self.store.initialize({})
    def test_encryption_public_redaction_and_restart(self):
        record=self.store.create(profile());raw=self.store.path.read_bytes();public=json.dumps(d.public(record,True))
        for secret in ['private-rest-password','private-auth-password','private-privacy-password','private-trap-community']:
            self.assertNotIn(secret.encode(),raw);self.assertNotIn(secret,public)
        reopened=d.Store(Path(self.directory.name));reopened.initialize({});self.assertEqual(reopened.get(record['id'])['rest_password'],'private-rest-password')
        self.store.key_path.unlink()
        with self.assertRaises(d.DeviceError):d.Store(Path(self.directory.name)).initialize({})
    def test_edit_preserves_secrets_conflict_and_duplicate(self):
        record=self.store.create(profile());changed=self.store.update(record['id'],dict(name='Renamed',rest_password='',snmp=dict(version='3',username='monitor',auth_password='',priv_password='')),1)
        self.assertEqual(changed['rest_password'],record['rest_password']);self.assertEqual(changed['snmp']['priv_password'],record['snmp']['priv_password'])
        with self.assertRaises(d.DeviceError):self.store.update(record['id'],dict(name='stale'),1)
        with self.assertRaises(d.DeviceError):self.store.create(profile())
        with self.assertRaises(d.DeviceError):self.store.delete(record['id'],1)
        self.store.delete(record['id'],2);self.assertEqual(self.store.listing(),[])
    def test_bootstrap_once_and_delete_stays_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            env={'SBC_HOST':'192.0.2.51','SBC_PASSWORD':'initial-password','SBC_SSH_FINGERPRINT':d.ssh_key(PUBLIC)[1],'SNMP_VERSION':'disabled'}
            store=d.Store(Path(directory));store.initialize(env);self.assertEqual(store.get('bootstrap')['rest_password'],'initial-password')
            store.delete('bootstrap',1);store=d.Store(Path(directory));store.initialize(env);self.assertEqual(store.records(),[])
    def test_public_key_formats_and_private_key_rejection(self):
        canonical,fp=d.ssh_key(PUBLIC);encoded=PUBLIC.split()[1]
        wrapped='OpenSSH rsa public-key:\nssh-rsa '+encoded[:70]+'\n'+encoded[70:]
        rfc='---- BEGIN SSH2 PUBLIC KEY ----\nComment: "SBC"\n'+encoded+'\n---- END SSH2 PUBLIC KEY ----'
        for value in (wrapped,rfc):self.assertEqual(d.ssh_key(value),(canonical,fp))
        with self.assertRaises(d.DeviceError):d.ssh_key('-----BEGIN '+'PRIVATE KEY-----')
        with self.assertRaises(d.DeviceError):d.ca_certificate(PUBLIC)
    def test_snmp_conditional_credentials(self):
        for version,extra in [('disabled',{}),('1',{'community':'read-only'}),('2c',{'community':'read-only'}),('3',{'username':'monitor','security_level':'noAuthNoPriv'}),('3',{'username':'monitor','security_level':'authNoPriv','auth_password':'auth-password'})]:
            data=profile();data['snmp']={'version':version,**extra};self.assertEqual(d.normalize(data)['snmp']['version'],version)
        for settings in ({'version':'2c'},{'version':'3','username':'monitor','security_level':'authPriv'}):
            data=profile();data['snmp']=settings
            with self.assertRaises(d.DeviceError):d.normalize(data)
    def test_request_scoped_clients_and_caches(self):
        first=self.store.create(profile());second=self.store.create(profile('192.0.2.52'))
        a,b=server.DeviceRuntime(first),server.DeviceRuntime(second)
        proxy=d.ScopedMap('snapshots',{})
        try:
            d.CONTEXT.set(a);proxy['same']='first';d.CONTEXT.set(b);self.assertNotIn('same',proxy);proxy['same']='second'
            d.CONTEXT.set(a);self.assertEqual(proxy['same'],'first');self.assertEqual(a.client.host,'192.0.2.51');self.assertEqual(b.monitor.settings['SBC_HOST'],'192.0.2.52')
        finally:d.CONTEXT.set(None)
    def test_stale_profile_cannot_replace_latest_runtime(self):
        first=self.store.create(profile())
        with patch.object(server,'DEVICES',self.store):
            latest=self.store.update(first['id'],dict(name='New settings'),1)
            current=server.runtime(latest)
            self.assertIs(server.runtime(first),current)
            server.RUNTIMES.pop(first['id'],None)
    def test_trap_views_are_filtered_by_management_ip(self):
        import trap_tools,test_traps
        store=trap_tools.Store(Path(self.directory.name)/'traps.sqlite3')
        a=test_traps.event();a['source']='192.0.2.51';first=store.append(a)
        b=test_traps.event();b['source']='192.0.2.52';second=store.append(b)
        record=self.store.create(profile());d.CONTEXT.set(server.DeviceRuntime(record))
        try:
            self.assertEqual(store.overview()['retained'],1);self.assertEqual(store.query()['filtered'],1)
            self.assertIsNotNone(store.event(first));self.assertIsNone(store.event(second))
        finally:d.CONTEXT.set(None)

class DeviceHttpTests(unittest.TestCase):
    def setUp(self):
        existing.UpdateRouteTests.setUp(self)
        # The existing fixture replaces the SBC proxy; restore it for device scoping.
        server.SBC_CLIENT=self.original
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.store=d.Store(Path(self.directory.name));self.store.initialize({})
        self.device_patch=patch.object(server,'DEVICES',self.store);self.device_patch.start();self.addCleanup(self.device_patch.stop)
        self.addCleanup(server.RUNTIMES.clear);self.addCleanup(lambda:d.CONTEXT.set(None))
    tearDown=existing.UpdateRouteTests.tearDown
    def api(self,path,body=None,headers=None,cookie='test-cookie'):
        req=Request('http://127.0.0.1:'+str(self.http.server_port)+path,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json','Cookie':'sbc_session='+cookie,'X-CSRF-Token':'test-csrf',**(headers or {})})
        try:response=urlopen(req)
        except HTTPError as exc:response=exc
        with response:return response.status,json.load(response)
    def test_crud_selection_and_stale_tab_rejection(self):
        status,data=self.api('/api/devices',profile());self.assertEqual(status,201,data);first=data['device']
        _,data=self.api('/api/devices',profile('192.0.2.52'));second=data['device']
        self.assertEqual(self.api('/api/devices/select',{'id':first['id']})[0],200)
        _,session=self.api('/api/session');self.assertEqual(session['device']['id'],first['id'])
        self.api('/api/devices/select',{'id':second['id']})
        status,_=self.api('/api/action',{'action':'save'},{'X-Device-ID':first['id'],'X-Device-Version':'1'});self.assertEqual(status,409)
        status,data=self.api('/api/devices/update',dict(id=second['id'],version=1,name='Updated'));self.assertEqual(status,200,data)
        self.assertEqual(self.api('/api/devices/update',dict(id=second['id'],version=1,name='Stale'))[0],409)
        self.assertEqual(self.api('/api/devices/delete',dict(id=first['id'],version=1))[0],200)
    def test_operator_cannot_edit_but_can_select_and_csrf_required(self):
        record=self.store.create(profile());server.USERS.create('operator','operator-password')
        server.SESSIONS['operator']=dict(csrf='test-csrf',expires=time.time()+60,username='operator',auth_version=1)
        self.assertEqual(self.api('/api/devices',profile('192.0.2.53'),cookie='operator')[0],403)
        self.assertEqual(self.api('/api/devices/detail?id='+record['id'],cookie='operator')[0],403)
        self.assertEqual(self.api('/api/devices/select',dict(id=record['id']),cookie='operator')[0],200)
        self.assertEqual(self.api('/api/devices/delete',dict(id=record['id'],version=1),{'X-CSRF-Token':'bad'})[0],403)

if __name__=='__main__':unittest.main()
