import datetime as dt,io,json,os,socket,sqlite3,stat,tempfile,threading,types,unittest
from pathlib import Path
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
import certificate_tools as certs,devices_tools,hdr_tools,users_tools,server
import test_devices,test_server,test_users

class FirstRunTests(unittest.TestCase):
    def test_default_admin_requires_change_and_is_not_recreated(self):
        with tempfile.TemporaryDirectory() as directory:
            store=users_tools.Store(Path(directory)/'users.sqlite3');store.initialize()
            user=store.authenticate('admin','oracle');self.assertTrue(user['must_change_password'])
            with self.assertRaises(users_tools.UserError):store.change_password('admin','oracle','short')
            changed=store.change_password('admin','oracle','replacement-password');self.assertFalse(changed['must_change_password'])
            store.initialize();self.assertIsNone(store.authenticate('admin','oracle'));self.assertTrue(store.authenticate('admin','replacement-password'))
    def test_existing_schema_migrates_without_resetting_account(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'users.sqlite3'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,role TEXT NOT NULL,version INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)')
                db.execute('INSERT INTO users VALUES(?,?,?,?,?,?)',('existing',test_server.TEST_LOGIN_HASH,'admin',1,'old','old'))
            db.close()
            store=users_tools.Store(path);store.initialize()
            self.assertFalse(store.authenticate('existing','test-admin-password')['must_change_password']);self.assertIsNone(store.authenticate('admin','oracle'))

class FirstLoginHttpTests(unittest.TestCase):
    tearDown=test_server.UpdateRouteTests.tearDown
    api=test_users.UserHttpTests.api
    def setUp(self):
        test_server.UpdateRouteTests.setUp(self);server.ATTEMPTS.clear()
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        store=users_tools.Store(Path(self.directory.name)/'users.sqlite3');store.initialize()
        item=patch.object(server,'USERS',store);item.start();self.addCleanup(item.stop)
    def test_initial_session_is_restricted_until_password_rotates(self):
        _,session,_=self.api('GET','/api/session');self.assertTrue(session['must_change_password'])
        for path in ('/api/users','/api/devices','/api/status','/api/certificates','/api/hdr'):
            status,data,_=self.api('GET',path);self.assertEqual(status,403);self.assertTrue(data['password_change_required'])
        self.assertEqual(self.api('POST','/api/devices',{})[0],403)
        status,data,headers=self.api('POST','/api/users/password',dict(current_password='oracle',new_password='replacement-password'))
        self.assertEqual(status,200);cookie=headers['Set-Cookie'].split(';')[0].split('=',1)[1]
        self.assertEqual(self.api('GET','/api/session')[0],401)
        _,session,_=self.api('GET','/api/session',cookie=cookie);self.assertFalse(session['must_change_password'])
        self.assertEqual(self.api('GET','/api/users',cookie=cookie)[0],200)

class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.manager=certs.Manager(Path(self.directory.name));self.manager.setup({})
    def request(self):return self.manager.generate(dict(common_name='console.example.test',organization='Test',country='DE',dns_names=['console.example.test'],ip_addresses=['127.0.0.1'],key_size=2048))
    def signed(self,request,wrong_names=False,expired=False):
        _,path=self.manager.paths(request['id']);key=serialization.load_pem_private_key(path.read_bytes(),None)
        csr=x509.load_pem_x509_csr(request['csr_pem'].encode());names=csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if wrong_names:names=x509.SubjectAlternativeName([x509.DNSName('wrong.example.test')])
        leaf=x509.CertificateBuilder().subject_name(csr.subject).issuer_name(test_devices.NAME).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(certs.now()-dt.timedelta(days=2)).not_valid_after(certs.now()+dt.timedelta(days=-1 if expired else 30)).add_extension(names,False).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(test_devices.KEY,hashes.SHA256())
        return leaf.public_bytes(serialization.Encoding.PEM).decode()+test_devices.CA
    def test_self_signed_is_generated_once_and_persists(self):
        original=self.manager.status();reopened=certs.Manager(Path(self.directory.name));reopened.setup({})
        self.assertEqual(reopened.status()['active']['sha256'],original['active']['sha256']);self.assertIn('127.0.0.1',original['active']['ip_addresses'])
    def test_csr_and_install_persist_and_switch_context(self):
        request=self.request();self.assertNotIn('PRIVATE KEY',json.dumps(request))
        self.manager.server=types.SimpleNamespace(tls_context=None)
        result=self.manager.install(request['id'],self.signed(request));self.assertEqual(result['source'],'imported');self.assertEqual(result['requests'],[]);self.assertIsNotNone(self.manager.server.tls_context)
        reopened=certs.Manager(Path(self.directory.name));reopened.setup({});self.assertEqual(reopened.status()['active']['sha256'],result['active']['sha256'])
    def test_invalid_imports_leave_original_certificate_active(self):
        original=self.manager.status()['active']['sha256'];request=self.request()
        for pem in (test_devices.CA,self.signed(request,wrong_names=True),self.signed(request,expired=True)):
            with self.assertRaises(certs.CertificateError):self.manager.install(request['id'],pem)
            self.assertEqual(self.manager.status()['active']['sha256'],original)
        self.manager.remove(request['id']);self.assertEqual(self.manager.status()['requests'],[])
    def test_invalid_subject_names_and_path_are_rejected(self):
        for body in (dict(common_name='x',dns_names=['https://bad']),dict(common_name='x',dns_names=['x'],country='Germany'),dict(common_name='x',dns_names=[])):
            with self.assertRaises(certs.CertificateError):self.manager.generate(body)
        with self.assertRaises(certs.CertificateError):self.manager.remove('../active')

class SettingsHttpTests(unittest.TestCase):
    tearDown=test_server.UpdateRouteTests.tearDown
    api=test_users.UserHttpTests.api
    def setUp(self):
        test_server.UpdateRouteTests.setUp(self)
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup);root=Path(self.directory.name)
        devices_tools.Store(root).initialize({});cert=certs.Manager(root);cert.setup({})
        for name,value in [('CERTIFICATES',cert),('HDR',hdr_tools.Manager(root))]:
            item=patch.object(server,name,value);item.start();self.addCleanup(item.stop)
        server.USERS.create('member','member-password')
        server.SESSIONS['member']=dict(csrf='test-csrf',expires=server.time.time()+60,username='member',auth_version=1)
    def test_admin_settings_routes_csrf_and_member_restrictions(self):
        self.assertEqual(self.api('GET','/api/certificates')[0],200)
        self.assertEqual(self.api('GET','/api/certificates',cookie='member')[0],403)
        for endpoint in ('/api/hdr','/api/certificates/csr','/api/certificates/install','/api/certificates/remove'):
            self.assertEqual(self.api('POST',endpoint,{},cookie='member')[0],403)
            self.assertEqual(self.api('POST',endpoint,{},csrf='wrong')[0],403)
        status,data,_=self.api('GET','/api/hdr',cookie='member');self.assertEqual(status,200);self.assertEqual(data['mode'],'local')
        self.assertEqual(self.api('GET','/api/hdr/files',cookie='member')[0],200)

class HdrTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name);devices_tools.Store(self.root).initialize({});self.hdr=hdr_tools.Manager(self.root)
    def test_local_csv_listing_and_path_confinement(self):
        (self.hdr.local_root/'sample.csv').write_text('timestamp,value\n1,2\n');(self.hdr.local_root/'ignore.txt').write_text('ignored');(self.hdr.local_root/'directory.csv').mkdir()
        self.assertEqual([r['name'] for r in self.hdr.listing()['files']],['sample.csv'])
        with self.assertRaises(hdr_tools.HdrError):self.hdr.save(dict(version=0,mode='local',path=str(self.root)))
        self.hdr.save(dict(version=0,mode='local',path=str(self.hdr.local_root)))
        with self.assertRaises(devices_tools.DeviceError):self.hdr.save(dict(version=0,mode='local',path=str(self.hdr.local_root)))
    def config(self):return dict(version=0,mode='sftp',host='192.0.2.20',port=22,username='hdr-reader',path='/incoming/hdr',password='private-hdr-password',host_key=test_devices.PUBLIC)
    def test_credentials_encrypted_redacted_preserved_and_not_reused_for_new_host(self):
        body=self.config();value=self.hdr.save(body);self.assertTrue(value['has_password']);self.assertNotIn('private-hdr-password',json.dumps(value));self.assertNotIn(b'private-hdr-password',self.hdr.store.path.read_bytes())
        body.update(version=1,password='');self.hdr.save(body);self.assertEqual(self.hdr.raw()['value']['password'],'private-hdr-password')
        body.update(version=2,host='192.0.2.21')
        with self.assertRaises(hdr_tools.HdrError):self.hdr.save(body)
    def test_private_key_auth_and_host_key_validation(self):
        key=test_devices.KEY.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()).decode()
        body=self.config();body.update(password='',private_key=key);value=self.hdr.save(body);self.assertTrue(value['has_private_key']);self.assertNotIn('PRIVATE KEY',json.dumps(value))
        body.update(version=1,host_key='not-a-key')
        with self.assertRaises(hdr_tools.HdrError):self.hdr.save(body)
    def test_missing_encryption_key_does_not_regenerate_over_saved_hdr(self):
        self.hdr.save(self.config());(self.root/'device-encryption.key').unlink()
        with self.assertRaises(devices_tools.DeviceError):devices_tools.Store(self.root).initialize({})

class QuickstartTests(unittest.TestCase):
    def test_rollback_journal_mode_for_network_storage(self):
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'SQLITE_JOURNAL_MODE':'DELETE'}):
            root=Path(directory);users=users_tools.Store(root/'users.sqlite3');users.initialize();devices_tools.Store(root).initialize({})
            import trap_tools
            traps=trap_tools.Store(root/'traps.sqlite3');traps.overview()
            for name in ('users.sqlite3','devices.sqlite3','traps.sqlite3'):
                db=sqlite3.connect(root/name)
                try:self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0],'delete')
                finally:db.close()
    def test_no_credentials_secrets_lab_storage_or_node_binding_required(self):
        path=Path(__file__).resolve().parents[1]/'deploy/kubernetes/quickstart/resources.json';resources=json.loads(path.read_text());payload=json.dumps(resources)
        for forbidden in ('secretKeyRef','secretRef','secretName','APP_PASSWORD_HASH','SBC_PASSWORD','hostPath','nodeSelector'):self.assertNotIn(forbidden,payload)
        pvc=next(r for r in resources['items'] if r['kind']=='PersistentVolumeClaim');self.assertNotIn('storageClassName',pvc['spec'])

class HdrSftpIntegrationTests(unittest.TestCase):
    def setUp(self):
        import paramiko
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup);root=Path(self.directory.name)
        devices_tools.Store(root).initialize({});self.hdr=hdr_tools.Manager(root)
        pem=test_devices.KEY.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()).decode()
        host_key=paramiko.RSAKey.from_private_key(io.StringIO(pem));self.pem=pem
        from cryptography.hazmat.primitives.asymmetric import ed25519
        alternate=ed25519.Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.OpenSSH,serialization.NoEncryption()).decode()
        self.host_keys=[host_key,paramiko.Ed25519Key.from_private_key(io.StringIO(alternate))]
        self.host_algorithms=None;self.auth_attempts=[]
        owner=self
        class Auth(paramiko.ServerInterface):
            def check_auth_password(self,username,password):
                owner.auth_attempts.append(username)
                return paramiko.AUTH_SUCCESSFUL if username=='hdr-reader' and password=='private-hdr-password' else paramiko.AUTH_FAILED
            def check_auth_publickey(self,username,key):return paramiko.AUTH_SUCCESSFUL if username=='hdr-reader' and key==host_key else paramiko.AUTH_FAILED
            def get_allowed_auths(self,username):return 'publickey,password'
            def check_channel_request(self,kind,channel):return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        class Files(paramiko.SFTPServerInterface):
            def list_folder(self,path):
                if path!='/incoming/hdr':return paramiko.SFTP_NO_SUCH_FILE
                rows=[]
                for name,mode in [('sample.csv',stat.S_IFREG),('ignore.txt',stat.S_IFREG),('link.csv',stat.S_IFLNK)]:
                    item=paramiko.SFTPAttributes();item.filename=name;item.st_mode=mode|0o600;item.st_size=10;item.st_mtime=1;rows.append(item)
                return rows
        self.socket=socket.socket();self.socket.bind(('127.0.0.1',0));self.socket.listen(4);self.socket.settimeout(.2);self.stop=threading.Event();self.transports=[]
        def serve():
            while not self.stop.is_set():
                try:client,_=self.socket.accept()
                except socket.timeout:continue
                except OSError:break
                transport=paramiko.Transport(client);self.transports.append(transport)
                for key in self.host_keys:transport.add_server_key(key)
                if self.host_algorithms:transport.get_security_options().key_types=self.host_algorithms
                transport.set_subsystem_handler('sftp',paramiko.SFTPServer,Files)
                try:transport.start_server(server=Auth())
                except Exception:transport.close()
        self.thread=threading.Thread(target=serve,daemon=True);self.thread.start();self.addCleanup(self.close)
    def close(self):
        self.stop.set();self.socket.close()
        for transport in self.transports:transport.close()
        self.thread.join(timeout=2)
    def config(self):return dict(version=0,mode='sftp',host='127.0.0.1',port=self.socket.getsockname()[1],username='hdr-reader',path='/incoming/hdr',password='private-hdr-password',host_key=test_devices.PUBLIC)
    def test_password_and_private_key_auth_list_only_csv_regular_files(self):
        body=self.config();self.hdr.save(body);self.assertEqual([f['name'] for f in self.hdr.listing()['files']],['sample.csv'])
        body.update(version=1,password='',clear_password=True,private_key=self.pem);self.hdr.save(body);self.assertEqual([f['name'] for f in self.hdr.listing()['files']],['sample.csv'])
    def test_changed_host_key_is_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
        body=self.config();body['host_key']=key;self.hdr.save(body)
        with self.assertRaisesRegex(hdr_tools.HdrError,'does not match'):self.hdr.listing()
        self.assertEqual(self.auth_attempts,[])
    def test_saved_rsa_key_with_ed25519_and_only_rsa_sha256(self):
        self.host_algorithms=('ssh-ed25519','rsa-sha2-256')
        self.hdr.save(self.config())
        self.assertEqual([f['name'] for f in self.hdr.listing()['files']],['sample.csv'])
    def test_authentication_and_missing_directory_errors_are_actionable(self):
        body=self.config();body['password']='wrong';self.hdr.save(body)
        with self.assertRaisesRegex(hdr_tools.HdrError,'authentication failed'):self.hdr.listing()
        body.update(version=1,password='private-hdr-password',path='/missing');self.hdr.save(body)
        with self.assertRaisesRegex(hdr_tools.HdrError,'directory does not exist'):self.hdr.listing()
    def test_empty_listing_with_subdirectories_explains_directory_scope(self):
        (self.hdr.local_root/'daily').mkdir()
        result=self.hdr.listing()
        self.assertEqual(result['files'],[]);self.assertEqual(result['subdirectories'],1)
        self.assertIn('Enter the path',result['message'])

if __name__=='__main__':unittest.main()
