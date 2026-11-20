"""Offline safety tests: never contact or modify an SBC."""
import os
import tempfile
os.environ['STATE_DIR'] = tempfile.mkdtemp(prefix='sbc-tests-')
import unittest
from unittest.mock import patch
import time
import threading
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import server as app

ELEMENT = '<configElement><elementType>session-agent</elementType><attribute><name>hostname</name><value>agent1</value></attribute><attribute><name>port</name><value>5060</value></attribute><attribute><name>description</name><value>Original</value></attribute></configElement>'
META = [dict(name='hostname', key=True, ranges=[], choices=[]), dict(name='port', key=False, ranges=[dict(min='1025', max='65535')], choices=[])]


class ConfigurationWorkflowTests(unittest.TestCase):
    def test_persistent_workflow_ignores_failed_actions_and_lrt_changes(self):
        with tempfile.TemporaryDirectory() as directory, patch('server.STATE', app.Path(directory)):
            versions=app.xml('<response><currentVersion>336</currentVersion><runningVersion>336</runningVersion></response>')
            def state():return app.configuration_workflow(versions)
            self.assertEqual(state(),dict(needsSave=False,needsActivate=False))
            app.audit('update','success')
            self.assertEqual(state(),dict(needsSave=True,needsActivate=False))
            app.audit('save','failed')
            self.assertTrue(state()['needsSave'])
            app.audit('verify','attention')
            self.assertTrue(state()['needsSave'])
            app.audit('save','attention')
            self.assertEqual(state(),dict(needsSave=False,needsActivate=True))
            app.audit('update','success')
            self.assertEqual(state(),dict(needsSave=True,needsActivate=False))
            app.audit('save','success')
            app.audit('activate','failed')
            self.assertTrue(state()['needsActivate'])
            app.audit('activate','attention')
            app.audit('lrt-add','success')
            self.assertEqual(state(),dict(needsSave=False,needsActivate=False))


class EditingTests(unittest.TestCase):
    def setUp(self):
        app.SNAPSHOTS.clear()
        app.SNAPSHOTS['snapshot'] = dict(session='session1', expires=time.time()+60, xml=ELEMENT, kind='session-agent', meta=META)

    def body(self, old='Original', new='Updated'):
        return dict(snapshot='snapshot', xml=ELEMENT.replace(old, new))

    def test_diff(self):
        *_, changes = app.prepare('session1', self.body())
        self.assertEqual(changes, [dict(field='description', before='Original', after='Updated', key=False)])

    def test_other_session_and_expired_snapshot(self):
        with self.assertRaises(app.Problem):
            app.prepare('session2', self.body())
        app.SNAPSHOTS['snapshot']['expires'] = 0
        with self.assertRaises(app.Problem):
            app.prepare('session1', self.body())

    def test_key_change_requires_replacement(self):
        snap,old,new,changes=app.prepare('session1', self.body('agent1', 'agent2'))
        self.assertTrue(app.replacement_required(snap,changes))
        self.assertEqual(changes[0]['field'],'hostname')

    def test_empty_key_is_rejected(self):
        with self.assertRaises(app.Problem):
            app.prepare('session1',self.body('agent1',''))

    def test_key_change_requires_reentry_of_masked_secret(self):
        original=ELEMENT.replace('</configElement>','<attribute><name>password</name><value>********</value></attribute></configElement>')
        app.SNAPSHOTS['snapshot']['xml']=original
        with self.assertRaises(app.Problem) as error:
            app.prepare('session1',dict(snapshot='snapshot',xml=original.replace('agent1','agent2')))
        self.assertIn('Re-enter',str(error.exception))

    def test_sbc_managed_fields_remain_read_only(self):
        original=ELEMENT.replace('</configElement>','<attribute><name>last-modified-by</name><value>admin</value></attribute></configElement>')
        app.SNAPSHOTS['snapshot']['xml']=original
        with self.assertRaises(app.Problem):
            app.prepare('session1',dict(snapshot='snapshot',xml=original.replace('>admin<','>other<')))

    def test_structured_value_edits_are_detected(self):
        original=ELEMENT.replace('Original','<part>old</part>')
        app.SNAPSHOTS['snapshot']['xml']=original
        *_,changes=app.prepare('session1',dict(snapshot='snapshot',xml=original.replace('>old<','>new<')))
        self.assertEqual(changes[0]['before'],'<part>old</part>')
        self.assertEqual(changes[0]['after'],'<part>new</part>')

    def test_nested_key_change_requires_replacement(self):
        original=ELEMENT.replace('</configElement>','<subElement><subElementType>sip-port</subElementType><attribute><name>address</name><value>192.0.2.1</value></attribute></subElement></configElement>')
        app.SNAPSHOTS['snapshot']['xml']=original
        app.SNAPSHOTS['snapshot']['meta']=META+[dict(name='address',scope=['sip-port'],key=True,choices=[],ranges=[])]
        snap,old,new,changes=app.prepare('session1',dict(snapshot='snapshot',xml=original.replace('192.0.2.1','192.0.2.2')))
        self.assertTrue(app.replacement_required(snap,changes))
        self.assertEqual(changes[0]['field'],'sip-port[1].address')

    def test_invalid_port_rejected(self):
        with self.assertRaises(app.Problem):
            app.prepare('session1', self.body('5060', '99999'))

    def test_no_changes_rejected(self):
        with self.assertRaises(app.Problem):
            app.prepare('session1', dict(snapshot='snapshot', xml=ELEMENT))

    def test_xml_entities_rejected(self):
        with self.assertRaises(app.Problem):
            app.xml('<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><x>&x;</x>')

    def test_masked_password_not_resubmitted(self):
        e=app.xml('<configElement><attribute><name>password</name><value>********</value></attribute><attribute><name>last-modified-by</name><value>admin</value></attribute></configElement>')
        self.assertEqual(len(app.clean_payload(e,e)),0)

    def test_whitespace_does_not_cause_false_conflict(self):
        self.assertEqual(app.canonical(app.xml(ELEMENT)),app.canonical(app.xml(ELEMENT.replace('><','>\n  <'))))


class LockTests(unittest.TestCase):
    def setUp(self):
        self.sbc=app.SBC()

    def test_unlock_on_failure(self):
        events=[]
        self.sbc.call=lambda m,p: events.append(p)
        self.sbc.raw=lambda m,p: events.append(p)
        def fail():
            raise app.Problem('Invalid change')
        with self.assertRaises(app.Problem):
            self.sbc.transaction(fail)
        self.assertEqual(events,['configuration/lock','configuration/unlock'])
        self.assertFalse(self.sbc.blocked)

    def test_async_timeout_keeps_lock_and_blocks_new_writes(self):
        events=[]
        self.sbc.call=lambda m,p: events.append(p)
        self.sbc.raw=lambda m,p: events.append(p)
        def pending():
            self.sbc.pending=True
            raise app.Problem('Timeout')
        with self.assertRaises(app.Problem):
            self.sbc.transaction(pending)
        self.assertEqual(events,['configuration/lock'])
        with self.assertRaises(app.Problem):
            self.sbc.transaction(lambda:None)

    def test_cannot_write_if_lock_acquisition_fails(self):
        def locked(*a):
            raise app.Problem('Locked')
        self.sbc.call=locked
        ran=[]
        with self.assertRaises(app.Problem):
            self.sbc.transaction(lambda:ran.append(True))
        self.assertEqual(ran,[])

    def test_async_poll_until_success(self):
        self.sbc.call=lambda *a:(202,app.xml('<response/>'))
        self.sbc.raw=lambda *a:(200,app.xml('<response><data><operationState><status>success</status></operationState></data></response>'))
        with patch('server.time.sleep'):
            self.sbc.operation('PUT','configuration/management?action=verify')
        self.assertFalse(self.sbc.pending)


class UpdateRouteTests(unittest.TestCase):
    def setUp(self):
        self.original = app.SBC_CLIENT
        self.sbc = app.SBC()
        app.SBC_CLIENT = self.sbc
        self.events = []
        self.current = ELEMENT
        def call(method, path, body=None):
            self.events.append((method, path, body))
            if method == 'PUT' and path == 'configuration/configElements':
                self.current = body
            return 200, app.xml('<response/>')
        self.sbc.call = call
        self.sbc.raw = self.sbc.call
        self.sbc.operation = lambda method, path: self.events.append((method, path, None)) or app.xml('<response/>')
        self.sbc.get = lambda path: app.xml('<response><data>' + app.serial(app.xml(self.current)) + '</data></response>')
        app.SESSIONS['test-cookie'] = dict(csrf='test-csrf', expires=time.time()+60)
        app.SNAPSHOTS['snapshot'] = dict(session='test-cookie', expires=time.time()+60, xml=ELEMENT, kind='session-agent', meta=META)
        self.http = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        app.SBC_CLIENT = self.original

    def request(self, csrf='test-csrf', action=None):
        body = dict(action=action) if action else dict(snapshot='snapshot', xml=ELEMENT.replace('Original','Updated'))
        req = Request('http://127.0.0.1:' + str(self.http.server_port) + ('/api/action' if action else '/api/update'), data=json.dumps(body).encode(), headers={'Content-Type':'application/json', 'Cookie':'sbc_session=test-cookie', 'X-CSRF-Token':csrf})
        try:
            with urlopen(req) as r:
                return r.status, json.load(r)
        except HTTPError as r:
            return r.code, json.load(r)

    def test_backup_before_put_then_unlock_without_save_or_activate(self):
        code, result = self.request()
        self.assertEqual(code, 200, result)
        self.assertEqual(self.events[0][1], 'configuration/lock')
        self.assertIn('action=backup', self.events[1][1])
        self.assertEqual(self.events[2][:2], ('PUT','configuration/configElements'))
        self.assertEqual(self.events[3][1], 'configuration/unlock')
        self.assertEqual(len(self.events), 4)
        self.assertTrue(self.events[2][2].startswith('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'))
        self.assertEqual(app.text(app.xml(self.events[2][2]),'elementType'),'session-agent')

    def test_success_response_without_retained_change_is_reported_as_failure(self):
        self.sbc.get=lambda path:app.xml('<response><data>'+ELEMENT+'</data></response>')
        code,result=self.request()
        self.assertEqual(code,502)
        self.assertIn('did not retain',result['error'])
        self.assertEqual(self.events[-1][1],'configuration/unlock')

    def test_conflicting_edit_aborts_before_backup_or_put(self):
        self.sbc.get = lambda path: app.xml('<response><data>'+ELEMENT.replace('Original','Changed externally')+'</data></response>')
        code, _ = self.request()
        self.assertEqual(code, 409)
        self.assertEqual([e[1] for e in self.events], ['configuration/lock','configuration/unlock'])

    def test_failed_backup_prevents_put(self):
        def fail(*args):
            raise app.Problem('Backup failed',502)
        self.sbc.operation=fail
        code, _ = self.request()
        self.assertEqual(code,502)
        self.assertFalse(any(e[0]=='PUT' for e in self.events))
        self.assertEqual(self.events[-1][1],'configuration/unlock')

    def test_csrf_rejected_before_any_sbc_request(self):
        code, _ = self.request(csrf='incorrect')
        self.assertEqual(code,403)
        self.assertEqual(self.events,[])

    def test_configuration_errors_allow_save_and_remain_in_response(self):
        report=app.xml('<response><data><operationState><status>success</status></operationState><additionalInfo><verifySummary numCriticals="0" numErrors="12" numWarnings="2"/></additionalInfo></data></response>')
        self.sbc.operation=lambda method,path:self.events.append((method,path,None)) or (report if 'action=verify' in path else app.xml('<response/>'))
        code, result=self.request(action='save')
        self.assertEqual(code,200)
        self.assertEqual(result['verification']['errors'],12)
        self.assertEqual([e[1] for e in self.events],['configuration/lock','configuration/management?action=verify','configuration/management?action=save','configuration/unlock'])

    def test_activation_without_ip_confirmation_keeps_backup_save_and_verification(self):
        report=app.xml('<response><data><additionalInfo><verifySummary numCriticals="1" numErrors="12" numWarnings="2"/></additionalInfo></data></response>')
        self.sbc.operation=lambda method,path:self.events.append((method,path,None)) or (report if 'action=verify' in path else app.xml('<response/>'))
        code, result=self.request(action='activate')
        self.assertEqual(code,200)
        self.assertEqual(result['verification']['criticals'],1)
        self.assertEqual([e[1].split('?')[0] for e in self.events],['configuration/lock']+['configuration/management']*4+['configuration/unlock'])
        self.assertIn('action=backup',self.events[2][1])
        self.assertIn('action=save',self.events[3][1])
        self.assertIn('action=activate',self.events[4][1])

    def test_missing_verification_summary_does_not_block_save(self):
        code, result=self.request(action='save')
        self.assertEqual(code,200)
        self.assertIsNone(result['verification'])
        self.assertTrue(any('action=save' in e[1] for e in self.events))

    def test_verification_transport_failure_does_not_continue_to_activation(self):
        def fail(method,path):
            self.events.append((method,path,None))
            raise app.Problem('SBC request failed',502)
        self.sbc.operation=fail
        code, _=self.request(action='activate')
        self.assertEqual(code,502)
        self.assertEqual([e[1] for e in self.events],['configuration/lock','configuration/management?action=verify','configuration/unlock'])


class DiagnosticsTests(unittest.TestCase):
    setUp = UpdateRouteTests.setUp
    tearDown = UpdateRouteTests.tearDown

    def get_request(self, path, cookie='test-cookie'):
        req=Request('http://127.0.0.1:'+str(self.http.server_port)+path, headers={'Cookie':'sbc_session='+cookie})
        try:
            with urlopen(req) as response:return response.status,json.load(response)
        except HTTPError as response:return response.code,json.load(response)

    def test_partial_failures_keep_measurements_and_only_issue_get_requests(self):
        paths=[]
        def get(path):
            paths.append(path)
            if path=='system/storage':raise app.Problem('Storage unavailable',502)
            if path=='statistics/kpiTypes':return app.xml('<response><data/><links><link>https://untrusted.invalid/rest/v1.2/statistics/kpiTypes?type=sysCPUUtil</link><link>https://untrusted.invalid/admin/reboot?type=bad</link></links></response>')
            if path=='statistics/kpis?type=sysCPUUtil':return app.xml('<response><data><sysCPUUtilPercent><percentUsed>0</percentUsed></sysCPUUtilPercent></data></response>')
            return app.xml('<response><data><healthScorePercent>100</healthScorePercent></data></response>')
        self.sbc.get=get
        with patch('server.lrt_configs',return_value=[{'name':'table1'}]):
            code,result=self.get_request('/api/diagnostics')
        self.assertEqual(code,200)
        self.assertFalse(result['sections']['storage']['ok'])
        self.assertEqual(result['sections']['sysCPUUtil']['fields'][0]['value'],'0')
        self.assertFalse(result['sections']['globalSessions']['ok'])
        self.assertEqual(result['lrtTables'],['table1'])
        self.assertTrue(all(p.startswith(('system/','statistics/')) for p in paths))
        self.assertNotIn('statistics/kpis?type=bad',paths)
        self.assertEqual(self.events,[])

    def test_route_lookup_encodes_user_without_modifying_configuration(self):
        paths=[]
        self.sbc.get=lambda path:paths.append(path) or app.xml('<response><data><nextHop>sip:user@example.invalid</nextHop></data></response>')
        with patch('server.lrt_configs',return_value=[{'name':'table one'}]):
            code,result=self.get_request('/api/diagnostics/route?'+app.urlencode(dict(name='table one',user='12&lrtName=other')))
        self.assertEqual(code,200)
        self.assertIn('lrtName=table+one&user=12%26lrtName%3Dother',paths[0])
        self.assertEqual(result['fields'][0]['value'],'sip:user@example.invalid')
        self.assertEqual(self.events,[])

    def test_route_rejects_unknown_tables_and_invalid_users(self):
        with patch('server.lrt_configs',return_value=[{'name':'one'}]):
            self.assertEqual(self.get_request('/api/diagnostics/route?name=other&user=123')[0],404)
            self.assertEqual(self.get_request('/api/diagnostics/route?name=one&user=')[0],400)
            self.assertEqual(self.get_request('/api/diagnostics/route?name=one&user=%00')[0],400)
        self.assertEqual(self.events,[])

    def test_diagnostics_requires_authentication(self):
        self.assertEqual(self.get_request('/api/diagnostics',cookie='invalid')[0],401)
        self.assertEqual(self.get_request('/api/diagnostics/route?name=one&user=123',cookie='invalid')[0],401)
        self.assertEqual(self.events,[])

    def test_repeated_fields_are_preserved_and_large_data_is_bounded(self):
        root=app.xml('<response><data><rows>'+''.join('<row><value>'+str(i)+'</value></row>' for i in range(510))+'</rows></data></response>')
        fields=app.diagnostic_fields(root)
        self.assertEqual(len(fields),500)
        self.assertEqual(fields[0]['name'],'rows.row[1].value')
        self.assertEqual(fields[-1]['value'],'499')


class TraceHttpTests(unittest.TestCase):
    setUp = UpdateRouteTests.setUp
    tearDown = UpdateRouteTests.tearDown

    def request(self, path, cookie='test-cookie'):
        req=Request('http://127.0.0.1:'+str(self.http.server_port)+path,headers={'Cookie':'sbc_session='+cookie})
        try:
            with urlopen(req) as response:return response.status,response.headers,response.read()
        except HTTPError as response:return response.code,response.headers,response.read()

    def test_download_is_authenticated_and_byte_exact(self):
        @app.contextmanager
        def copy(*args):yield app.io.BytesIO(b'PCAP exact bytes'),16
        with patch('server.trace_copy',copy):
            code,headers,data=self.request('/api/traces/download?name=call+one.pcap&version=v1')
        self.assertEqual(code,200)
        self.assertEqual(data,b'PCAP exact bytes')
        self.assertEqual(headers['Content-Type'],'application/octet-stream')
        self.assertIn("filename*=UTF-8''call%20one.pcap",headers['Content-Disposition'])
        self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertEqual(self.events,[])

    def test_all_trace_routes_require_a_session(self):
        for path in ['/api/traces','/api/traces/flow?name=x.pcap','/api/traces/download?name=x.pcap']:
            self.assertEqual(self.request(path,cookie='invalid')[0],401)
        self.assertEqual(self.events,[])

    def test_trace_list_and_flow_are_read_only(self):
        with patch('server.trace_list',return_value={'files':[]}),patch('server.trace_flow',return_value={'calls':[],'messages':[]}):
            self.assertEqual(self.request('/api/traces')[0],200)
            self.assertEqual(self.request('/api/traces/flow?name=x.pcap&version=1')[0],200)
        self.assertEqual(self.events,[])


class ReplaceRouteTests(unittest.TestCase):
    tearDown=UpdateRouteTests.tearDown

    def setUp(self):
        UpdateRouteTests.setUp(self)
        self.instances=[ELEMENT]
        self.backup=[]
        self.fail_create=False
        self.fail_restore=False
        def get(path):
            if path=='configuration/elementTypes':
                return app.xml('<response><data><elementType><name>session-agent</name></elementType></data></response>')
            from urllib.parse import parse_qs,urlsplit
            query=parse_qs(urlsplit(path).query)
            matches=[e for e in self.instances if not query.get('hostname') or app.keys_for(app.xml(e),META)['hostname']==query['hostname'][0]]
            return app.xml('<response><data>'+''.join(matches)+'</data></response>')
        def call(method,path,body=None):
            self.events.append((method,path,body))
            if method=='DELETE':
                from urllib.parse import parse_qs,urlsplit
                name=parse_qs(urlsplit(path).query)['hostname'][0]
                self.instances=[e for e in self.instances if app.keys_for(app.xml(e),META)['hostname']!=name]
            if method=='POST' and path=='configuration/configElements':
                if self.fail_create:
                    raise app.Problem('Creation rejected',502)
                self.instances.append(app.serial(app.xml(body)))
            return 200,app.xml('<response/>')
        def operation(method,path):
            self.events.append((method,path,None))
            if 'action=backup' in path:
                self.backup=self.instances[:]
            if 'action=restore' in path:
                if self.fail_restore:
                    raise app.Problem('Restore rejected',502)
                self.instances=self.backup[:]
            return app.xml('<response/>')
        self.sbc.get=get
        self.sbc.call=call
        self.sbc.raw=call
        self.sbc.operation=operation

    def request(self,path='/api/update'):
        req=Request('http://127.0.0.1:'+str(self.http.server_port)+path,data=json.dumps(dict(snapshot='snapshot',xml=ELEMENT.replace('agent1','agent2'))).encode(),headers={'Content-Type':'application/json','Cookie':'sbc_session=test-cookie','X-CSRF-Token':'test-csrf'})
        try:
            with urlopen(req) as r:
                return r.status,json.load(r)
        except HTTPError as r:
            return r.code,json.load(r)

    def test_preview_explains_instance_replacement(self):
        code,result=self.request('/api/preview')
        self.assertEqual(code,200)
        self.assertTrue(result['replacement'])
        self.assertEqual(self.events,[])

    def test_key_change_replaces_only_original_instance(self):
        untouched=ELEMENT.replace('agent1','agent3')
        self.instances.append(untouched)
        code,result=self.request()
        self.assertEqual(code,200,result)
        self.assertEqual(result['keys'],{'hostname':'agent2'})
        self.assertEqual(len(self.instances),2)
        self.assertIn(untouched,self.instances)
        self.assertEqual(self.events[0][1],'configuration/lock')
        self.assertIn('action=backup',self.events[1][1])
        self.assertEqual(self.events[2][0],'DELETE')
        self.assertIn('hostname=agent1',self.events[2][1])
        self.assertEqual(self.events[3][:2],('POST','configuration/configElements'))
        self.assertEqual(self.events[-1][1],'configuration/unlock')

    def test_duplicate_new_key_is_rejected_before_deletion(self):
        self.instances.append(ELEMENT.replace('agent1','agent2'))
        code,result=self.request()
        self.assertEqual(code,409)
        self.assertIn('already exists',result['error'])
        self.assertFalse(any(e[0]=='DELETE' for e in self.events))

    def test_failed_creation_restores_prior_editing_configuration(self):
        self.fail_create=True
        code,result=self.request()
        self.assertEqual(code,502)
        self.assertIn('was restored',result['error'])
        self.assertEqual(self.instances,[ELEMENT])
        self.assertTrue(any('action=restore' in e[1] and 'restoreSource=backupFile' in e[1] for e in self.events))

    def test_failed_recovery_reports_backup_for_manual_recovery(self):
        self.fail_create=True
        self.fail_restore=True
        code,result=self.request()
        self.assertEqual(code,502)
        self.assertIn('Recovery backup: web-before-',result['error'])

    def test_singleton_with_nested_key_is_created_then_updated(self):
        original='<configElement><elementType>system-config</elementType><subElement><subElementType>child</subElementType><attribute><name>id</name><value>old</value></attribute></subElement></configElement>'
        updated=original.replace('>old<','>new<')
        app.SNAPSHOTS['snapshot'].update(xml=original,kind='system-config',meta=[dict(name='id',scope=['child'],key=True,choices=[],ranges=[])])
        current=[original]
        def get(path):
            if path=='configuration/elementTypes':
                return app.xml('<response><data><elementType single="true"><name>system-config</name></elementType></data></response>')
            return app.xml('<response><data>'+''.join(current)+'</data></response>')
        def call(method,path,body=None):
            self.events.append((method,path,body))
            if method=='DELETE':current.clear()
            elif method=='POST' and path=='configuration/configElements':current.append(app.serial(app.xml(body)))
            elif method=='PUT' and path=='configuration/configElements':current[:]=[app.serial(app.xml(body))]
            return 200,app.xml('<response/>')
        self.sbc.get=get
        self.sbc.call=call
        self.sbc.raw=call
        req=Request('http://127.0.0.1:'+str(self.http.server_port)+'/api/update',data=json.dumps(dict(snapshot='snapshot',xml=updated)).encode(),headers={'Content-Type':'application/json','Cookie':'sbc_session=test-cookie','X-CSRF-Token':'test-csrf'})
        with urlopen(req) as r:
            self.assertEqual(r.status,200)
        self.assertEqual(self.events[2][:2],('DELETE','configuration/configElements?elementType=system-config'))
        self.assertEqual(self.events[3][:2],('POST','configuration/configElements'))
        self.assertEqual(len(app.xml(self.events[3][2])),1)
        self.assertEqual(self.events[4][:2],('PUT','configuration/configElements'))
        self.assertEqual(app.attribute_values(app.xml(current[0]))['child[1].id'],'new')


class LrtTests(unittest.TestCase):
    SAMPLE=b'<localRoutes><route><user type="E164">00123</user><next type="regex">!^.*$!sip:one@example.invalid!</next><next type="regex" priority="2">sip:two@example.invalid</next><description>Primary route</description></route><route><user type="E164">00123</user><next type="regex">sip:three@example.invalid</next></route><emsVersion><version>7</version></emsVersion></localRoutes>'

    def setUp(self):
        app.LRT_CACHE.clear()

    def test_gzip_tables_keep_duplicate_entries_and_next_hop_order(self):
        data=app.parse_lrt(app.gzip.compress(self.SAMPLE))
        self.assertEqual(data['entryCount'],2)
        self.assertEqual(data['nextHopCount'],3)
        self.assertEqual([e['match'] for e in data['entries']],['00123','00123'])
        self.assertEqual(data['entries'][0]['nextHops'][1]['attributes']['priority'],'2')
        self.assertEqual(data['version'],{'version':'7'})

    def test_plain_xml_is_supported(self):
        self.assertEqual(app.parse_lrt(self.SAMPLE)['entryCount'],2)

    def test_did_range_attributes_and_prefix_are_preserved(self):
        data=app.parse_lrt(b'<localRoutes type="range"><route><user type="range" rangePrefix="44" rangeStart="001" rangeEnd="099"/><next type="regex">sip:range@example.invalid</next></route></localRoutes>')
        self.assertEqual(data['entries'][0]['match'],'44001 – 44099')
        self.assertEqual(data['entries'][0]['userAttributes']['rangeStart'],'001')
        self.assertEqual(data['tableType'],'range')

    def test_namespaced_lrt(self):
        content=self.SAMPLE.replace(b'<localRoutes>',b'<localRoutes xmlns="urn:example:lrt">')
        self.assertEqual(app.parse_lrt(content)['entryCount'],2)

    def test_empty_table_is_distinct_from_unreadable_file(self):
        self.assertEqual(app.parse_lrt(b'<localRoutes/>')['entryCount'],0)
        with self.assertRaises(app.Problem):app.parse_lrt(b'bad file')

    def test_wrong_root_and_missing_user_are_rejected(self):
        for content in (b'<other/>',b'<localRoutes><route><next>sip:x</next></route></localRoutes>'):
            with self.assertRaises(app.Problem):app.parse_lrt(content)

    def test_entities_are_rejected(self):
        with self.assertRaises(app.Problem):
            app.parse_lrt(b'<!DOCTYPE localRoutes [<!ENTITY secret SYSTEM "file:///etc/passwd">]><localRoutes>&secret;</localRoutes>')

    def test_decompression_limit_is_enforced(self):
        with patch('server.LRT_XML_LIMIT',16):
            with self.assertRaises(app.Problem) as error:app.parse_lrt(app.gzip.compress(self.SAMPLE))
        self.assertEqual(error.exception.code,413)

    def test_filename_cannot_escape_lrt_directory(self):
        for filename in ('../secret','/etc/passwd','a/b.xml.gz','a\\b.xml.gz','..',''):
            with self.assertRaises(app.Problem):app.lrt_filename(filename)
        self.assertEqual(app.lrt_filename('routing-1.xml.gz'),'routing-1.xml.gz')

    def test_cache_and_explicit_refresh(self):
        with patch('server.read_lrt_file',return_value=(self.SAMPLE,dict(sizeBytes=len(self.SAMPLE),modifiedAt='2026-10-23T00:00:00Z'))) as read:
            app.load_lrt('test.xml.gz');app.load_lrt('test.xml.gz')
            self.assertEqual(read.call_count,1)
            app.load_lrt('test.xml.gz',refresh=True)
            self.assertEqual(read.call_count,2)

    def test_unreadable_lrt_does_not_hide_other_tables(self):
        def load(filename,refresh):
            if filename=='missing.xml.gz':raise app.Problem('Missing file',404)
            return app.parse_lrt(self.SAMPLE)
        with patch('server.lrt_configs',return_value=[{'name':'valid','file-name':'valid.xml.gz'},{'name':'missing','file-name':'missing.xml.gz'}]),patch('server.load_lrt',side_effect=load):
            data=app.lrt_overview(True)
        self.assertEqual(data['tables'][0]['entryCount'],2)
        self.assertEqual(data['tables'][1]['status'],'error')
        self.assertIsNone(data['tables'][1]['entryCount'])

    def test_search_and_pagination_preserve_file_indices(self):
        document=dict(app.parse_lrt(self.SAMPLE),fetchedAt='2026-10-23T00:00:00Z',sha256='fixture-hash')
        with patch('server.lrt_configs',return_value=[{'name':'example','file-name':'test.xml.gz'}]),patch('server.load_lrt',return_value=document):
            result=app.lrt_entries('example',True,'00123',1,1)
            self.assertEqual(result['total'],2)
            self.assertEqual(result['filtered'],2)
            self.assertEqual(result['entries'][0]['index'],2)
            self.assertEqual(app.lrt_entries('example',True,'PRIMARY')['filtered'],1)
            self.assertEqual(app.lrt_entries('example',True,'nomatch')['entries'],[])

    def test_unknown_table_does_not_trigger_file_read(self):
        with patch('server.lrt_configs',return_value=[]),patch('server.load_lrt') as load:
            with self.assertRaises(app.Problem) as error:app.lrt_entries('unknown',True)
            self.assertEqual(error.exception.code,404)
            load.assert_not_called()

    def test_sftp_requires_configured_host_key(self):
        with patch.dict(os.environ,{'SBC_SSH_FINGERPRINT':''}):
            with self.assertRaises(app.Problem):app.read_lrt_file('test.xml.gz')


class LrtMutationTests(unittest.TestCase):
    SAMPLE=LrtTests.SAMPLE

    def draft(self):
        return dict(userType='E164',match='+3400123',description='New route',nextHops=[dict(value='!^.*$!sip:new@example.invalid!',type='regex',attributes={'priority':'1'})])

    def test_add_preserves_other_entries_metadata_and_compression(self):
        content=app.gzip.compress(self.SAMPLE)
        proposed,review=app.build_lrt_change(content,'add',self.draft())
        data=app.parse_lrt(proposed)
        self.assertTrue(proposed.startswith(b'\x1f\x8b'))
        self.assertEqual(data['entryCount'],3)
        self.assertEqual(data['version'],{'version':'7'})
        self.assertEqual(data['entries'][:2],app.parse_lrt(self.SAMPLE)['entries'])
        self.assertEqual(review['entry']['match'],'+3400123')

    def test_delete_removes_only_selected_duplicate_number(self):
        proposed,review=app.build_lrt_change(self.SAMPLE,'delete',index=2)
        data=app.parse_lrt(proposed)
        self.assertEqual(data['entryCount'],1)
        self.assertEqual(len(data['entries'][0]['nextHops']),2)
        self.assertEqual(review['entry']['nextHops'][0]['value'],'sip:three@example.invalid')

    def test_delete_last_entry_is_supported(self):
        content=b'<localRoutes><route><user type="string">one</user><next>sip:a</next></route></localRoutes>'
        proposed,review=app.build_lrt_change(content,'delete',index=1)
        self.assertEqual(app.parse_lrt(proposed)['entryCount'],0)
        self.assertEqual(review['afterCount'],0)

    def test_invalid_delete_indices_are_rejected(self):
        for index in (0,-1,3,True,'1'):
            with self.assertRaises(app.Problem):app.build_lrt_change(self.SAMPLE,'delete',index=index)

    def test_add_preserves_comments_unknown_nodes_and_namespaces(self):
        content=self.SAMPLE.replace(b'<localRoutes>',b'<localRoutes xmlns="urn:example"><!--keep--><custom>keep data</custom>')
        proposed,review=app.build_lrt_change(content,'add',self.draft())
        self.assertIn(b'<!--keep-->',proposed)
        self.assertIn(b'keep data',proposed)
        self.assertEqual(app.parse_lrt(proposed)['entryCount'],3)
        self.assertIn(b'urn:example',proposed)

    def test_did_ranges_and_multiple_next_hops(self):
        draft=self.draft();draft.update(userType='range',rangeStart='001',rangeEnd='099',rangePrefix='44')
        draft['nextHops'].append(dict(value='sip:backup@example.invalid',type='regex'))
        proposed,review=app.build_lrt_change(b'<localRoutes type="range"/>','add',draft)
        self.assertEqual(review['entry']['match'],'44001 – 44099')
        self.assertEqual(len(review['entry']['nextHops']),2)

    def test_invalid_entries_are_rejected(self):
        for draft in ({**self.draft(),'match':'abc'},{**self.draft(),'nextHops':[]},{**self.draft(),'nextHops':[dict(value='',type='regex')]},{**self.draft(),'userType':'range','rangeStart':'20','rangeEnd':'10'}):
            with self.assertRaises(app.Problem):app.build_lrt_change(self.SAMPLE,'add',draft)

    def test_plain_xml_is_not_silently_compressed(self):
        proposed,_=app.build_lrt_change(self.SAMPLE,'add',self.draft())
        self.assertTrue(proposed.startswith(b'<?xml'))


class LrtWriteTests(unittest.TestCase):
    def setUp(self):
        import io,types
        self.original=app.gzip.compress(LrtTests.SAMPLE)
        self.proposed,_=app.build_lrt_change(self.original,'delete',index=2)
        self.target='/code/lrt/table.xml.gz'
        self.files={self.target:self.original}
        self.events=[];self.corrupt_temp=False;self.rename_error=False
        owner=self
        class File(io.BytesIO):
            def __init__(self,path,mode):
                self.path=path;self.writable_file='w' in mode
                if 'x' in mode and path in owner.files:raise FileExistsError(path)
                super().__init__(b'' if self.writable_file else owner.files[path])
            def close(self):
                if not self.closed and self.writable_file:
                    value=self.getvalue()
                    owner.files[self.path]=b'corrupt' if owner.corrupt_temp and 'web-lrt-tmp-' in self.path else value
                super().close()
        class SFTP:
            def normalize(self,path):return path
            def stat(self,path):return types.SimpleNamespace(st_size=len(owner.files[path]),st_mode=0o100644,st_mtime=0)
            def open(self,path,mode):owner.events.append(('open',path,mode));return File(path,mode)
            def chmod(self,path,mode):owner.events.append(('chmod',path,mode))
            def posix_rename(self,source,target):
                if owner.rename_error:raise OSError('Unsupported')
                owner.events.append(('rename',source,target));owner.files[target]=owner.files.pop(source)
            def remove(self,path):
                if path not in owner.files:raise FileNotFoundError(path)
                del owner.files[path]
        self.ftp=SFTP()

    def write(self,expected=None):
        from contextlib import nullcontext
        with patch('server.lrt_sftp',return_value=nullcontext(self.ftp)):
            return app.write_lrt_change('table.xml.gz',expected or app.hashlib.sha256(self.original).hexdigest(),self.proposed)

    def test_backup_and_verified_temp_precede_atomic_replacement(self):
        backup=self.write()
        self.assertEqual(self.files[self.target],self.proposed)
        self.assertEqual(self.files['/code/lrt/'+backup],self.original)
        self.assertEqual((app.STATE/'lrt-backups'/backup).read_bytes(),self.original)
        self.assertTrue(any(e[0]=='rename' for e in self.events))
        self.assertFalse(any(e[0]=='open' and e[1]==self.target and 'w' in e[2] for e in self.events))

    def test_stale_file_is_not_overwritten(self):
        with self.assertRaises(app.Problem) as error:self.write(expected='wrong-hash')
        self.assertEqual(error.exception.code,409)
        self.assertEqual(self.files,{self.target:self.original})

    def test_corrupt_upload_leaves_original_untouched(self):
        self.corrupt_temp=True
        with self.assertRaises(app.Problem):self.write()
        self.assertEqual(self.files[self.target],self.original)
        self.assertFalse(any(e[0]=='rename' for e in self.events))
        self.assertFalse(any('web-lrt-tmp-' in name for name in self.files))

    def test_atomic_rename_failure_does_not_truncate_live_file(self):
        self.rename_error=True
        with self.assertRaises(app.Problem) as error:self.write()
        self.assertIn('Backup:',str(error.exception))
        self.assertEqual(self.files[self.target],self.original)


class LrtRouteTests(unittest.TestCase):
    tearDown=UpdateRouteTests.tearDown

    def setUp(self):
        UpdateRouteTests.setUp(self)
        app.LRT_PLANS.clear()
        self.content=LrtTests.SAMPLE
        self.config=[{'name':'one','file-name':'one.xml.gz'},{'name':'alias','file-name':'one.xml.gz'}]
        self.writes=[]
        self.config_patch=patch('server.lrt_configs',side_effect=lambda running:self.config)
        self.load_patch=patch('server.load_lrt',side_effect=lambda filename,refresh=False:dict(app.parse_lrt(self.content),content=self.content,sha256=app.hashlib.sha256(self.content).hexdigest()))
        def write(filename,expected,proposed):
            if expected!=app.hashlib.sha256(self.content).hexdigest():raise app.Problem('Stale file',409)
            self.writes.append((filename,proposed));self.content=proposed;return 'test-backup.bak'
        self.write_patch=patch('server.write_lrt_change',side_effect=write)
        for item in (self.config_patch,self.load_patch,self.write_patch):item.start();self.addCleanup(item.stop)

    def request(self,path,body,csrf='test-csrf',cookie='test-cookie'):
        req=Request('http://127.0.0.1:'+str(self.http.server_port)+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json','Cookie':'sbc_session='+cookie,'X-CSRF-Token':csrf})
        try:
            with urlopen(req) as r:return r.status,json.load(r)
        except HTTPError as r:return r.code,json.load(r)

    def preview(self,sha=None):
        return self.request('/api/lrt/preview',dict(name='one',running=True,sha256=sha or app.hashlib.sha256(self.content).hexdigest(),action='delete',index=2))

    def test_preview_does_not_write_and_lists_affected_aliases(self):
        code,result=self.preview()
        self.assertEqual(code,200)
        self.assertEqual(result['activeTables'],['one','alias'])
        self.assertEqual(result['afterCount'],1)
        self.assertEqual(self.writes,[])

    def test_save_only_does_not_reload_or_activate(self):
        _,review=self.preview();code,result=self.request('/api/lrt/apply',dict(plan=review['plan'],reload=False))
        self.assertEqual(code,200)
        self.assertFalse(result['reloaded'])
        self.assertEqual(len(self.writes),1)
        self.assertFalse(any('refresh' in e[1] or 'activate' in e[1] for e in self.events))
        self.assertNotIn(review['plan'],app.LRT_PLANS)

    def test_save_and_reload_uses_each_active_config_name(self):
        _,review=self.preview();code,result=self.request('/api/lrt/apply',dict(plan=review['plan'],reload=True))
        self.assertEqual(code,200)
        self.assertTrue(result['reloaded'])
        self.assertEqual([e[1] for e in self.events if 'admin/refresh/lrt?' in e[1]],
                         ['admin/refresh/lrt?lrtConfig=one','admin/refresh/lrt?lrtConfig=alias'])

    def test_reload_saved_file_uses_config_names_without_writing(self):
        code,result=self.request('/api/lrt/reload',dict(name='one',running=True,filename='one.xml.gz',sha256=app.hashlib.sha256(self.content).hexdigest()))
        self.assertEqual(code,200)
        self.assertEqual(self.writes,[])
        self.assertEqual([e[1] for e in self.events if 'admin/refresh/lrt?' in e[1]],
                         ['admin/refresh/lrt?lrtConfig=one','admin/refresh/lrt?lrtConfig=alias'])

    def test_partial_reload_failure_reports_completed_configs(self):
        calls=[]
        def operation(method,path):
            calls.append(path)
            if len(calls)==2:raise app.Problem('SBC failure',502)
        self.sbc.operation=operation
        self.config.append({'name':'third','file-name':'one.xml.gz'})
        _,review=self.preview();code,result=self.request('/api/lrt/apply',dict(plan=review['plan'],reload=True))
        self.assertEqual(code,200)
        self.assertFalse(result['reloaded'])
        self.assertIn('Reloads confirmed: one.',result['reloadError'])
        self.assertEqual(len(calls),2)

    def test_reload_failure_does_not_hide_successful_file_save(self):
        self.sbc.operation=lambda *a:(_ for _ in ()).throw(app.Problem('Reload failed',502))
        _,review=self.preview();code,result=self.request('/api/lrt/apply',dict(plan=review['plan'],reload=True))
        self.assertEqual(code,200)
        self.assertFalse(result['reloaded'])
        self.assertIn('reloadError',result)
        self.assertEqual(len(self.writes),1)

    def test_stale_preview_and_stale_apply_are_rejected(self):
        self.assertEqual(self.preview('bad')[0],409)
        _,review=self.preview();self.content=self.content.replace(b'Primary route',b'Changed externally')
        self.assertEqual(self.request('/api/lrt/apply',dict(plan=review['plan']))[0],409)
        self.assertEqual(self.writes,[])

    def test_file_mapping_change_prevents_apply(self):
        _,review=self.preview();self.config[0]['file-name']='different.xml.gz'
        self.assertEqual(self.request('/api/lrt/apply',dict(plan=review['plan']))[0],409)
        self.assertEqual(self.writes,[])

    def test_plan_expiry_and_session_ownership(self):
        _,review=self.preview();app.LRT_PLANS[review['plan']]['session']='other'
        self.assertEqual(self.request('/api/lrt/apply',dict(plan=review['plan']))[0],409)
        app.LRT_PLANS[review['plan']].update(session='test-cookie',expires=0)
        self.assertEqual(self.request('/api/lrt/apply',dict(plan=review['plan']))[0],409)

    def test_csrf_protects_lrt_mutations(self):
        self.assertEqual(self.request('/api/lrt/apply',dict(plan='invalid'),csrf='bad')[0],403)
        self.assertEqual(self.writes,[])


class CreateRouteTests(unittest.TestCase):
    tearDown = UpdateRouteTests.tearDown

    def setUp(self):
        UpdateRouteTests.setUp(self)
        self.template = ELEMENT.replace('agent1', '').replace('Original', '')
        app.SNAPSHOTS['new-template'] = dict(session='test-cookie', expires=time.time()+60, xml=self.template, kind='session-agent', meta=META, creating=True)
        self.current = ELEMENT
        def get(path):
            if path == 'configuration/elementTypes':
                return app.xml('<response><data><elementType configCount="1"><name>session-agent</name></elementType><elementType single="true" configCount="1"><name>system-config</name></elementType></data></response>')
            if path.startswith('configuration/elementTypes/template?'):
                return app.xml('<response><data>'+self.template+'</data></response>')
            if path.startswith('configuration/elementTypes/metadata?'):
                return app.xml('<response><data><attributeMetadata><name>hostname</name><required>true</required><key>true</key><valueType>string</valueType></attributeMetadata></data></response>')
            return app.xml('<response><data>'+app.serial(app.xml(self.current))+'</data></response>')
        def call(method,path,body=None):
            self.events.append((method,path,body))
            if method == 'POST' and path == 'configuration/configElements':
                self.current=body
            return 200,app.xml('<response/>')
        self.sbc.get=get
        self.sbc.call=call
        self.sbc.raw=call

    def request(self, snapshot='new-template', value=None, path='/api/create', csrf='test-csrf'):
        new=app.xml(self.template)
        new.find('./attribute/value').text='agent2'
        raw=value if value is not None else app.serial(new)
        req=Request('http://127.0.0.1:'+str(self.http.server_port)+path, data=json.dumps(dict(snapshot=snapshot,xml=raw)).encode(), headers={'Content-Type':'application/json','Cookie':'sbc_session=test-cookie','X-CSRF-Token':csrf})
        try:
            with urlopen(req) as r:
                return r.status,json.load(r)
        except HTTPError as r:
            return r.code,json.load(r)

    def get_template(self, kind):
        req=Request('http://127.0.0.1:'+str(self.http.server_port)+'/api/template?type='+kind,headers={'Cookie':'sbc_session=test-cookie'})
        try:
            with urlopen(req) as r:
                return r.status,json.load(r)
        except HTTPError as r:
            return r.code,json.load(r)

    def test_new_multi_instance_template(self):
        code,result=self.get_template('session-agent')
        self.assertEqual(code,200)
        self.assertTrue(result['item']['creating'])
        self.assertTrue(app.SNAPSHOTS[result['item']['snapshot']]['creating'])

    def test_singleton_has_no_creation_template(self):
        code,result=self.get_template('system-config')
        self.assertEqual(code,409)
        self.assertIn('singleton',result['error'])

    def test_unknown_type_is_rejected(self):
        self.assertEqual(self.get_template('unknown')[0],404)

    def test_create_backs_up_then_posts_with_declaration_and_verifies(self):
        code,result=self.request()
        self.assertEqual(code,200,result)
        self.assertEqual(result['keys'],{'hostname':'agent2'})
        self.assertEqual(self.events[0][1],'configuration/lock')
        self.assertIn('action=backup',self.events[1][1])
        self.assertEqual(self.events[2][:2],('POST','configuration/configElements'))
        self.assertTrue(self.events[2][2].startswith('<?xml'))
        self.assertEqual(self.events[3][1],'configuration/unlock')
        self.assertEqual(len(self.events),4)

    def test_duplicate_keys_are_rejected_before_backup(self):
        code,result=self.request(value=ELEMENT)
        self.assertEqual(code,409)
        self.assertIn('already exists',result['error'])
        self.assertEqual([e[1] for e in self.events],['configuration/lock','configuration/unlock'])

    def test_required_key_must_be_filled(self):
        code,result=self.request(value=self.template)
        self.assertEqual(code,400)
        self.assertIn('Required field: hostname',result['error'])
        self.assertEqual(self.events,[])

    def test_preview_accepts_new_keys_and_lists_default_values(self):
        code,result=self.request(path='/api/preview')
        self.assertEqual(code,200)
        self.assertTrue(result['creating'])
        self.assertTrue(any(c['field']=='port' and c['after']=='5060' for c in result['changes']))
        self.assertEqual(self.events,[])

    def test_creation_snapshot_cannot_be_used_for_update(self):
        self.assertEqual(self.request(path='/api/update')[0],409)
        self.assertEqual(self.events,[])

    def test_existing_snapshot_cannot_create(self):
        self.assertEqual(self.request(snapshot='snapshot',value=ELEMENT.replace('Original','Updated'))[0],409)

    def test_singleton_cannot_be_created_with_forged_snapshot(self):
        snap=app.SNAPSHOTS['new-template']
        snap['kind']='system-config'
        snap['xml']=snap['xml'].replace('session-agent','system-config')
        code,result=self.request(value=ELEMENT.replace('session-agent','system-config'))
        self.assertEqual(code,409)
        self.assertIn('singleton',result['error'])
        self.assertFalse(any(e[1]=='configuration/configElements' for e in self.events))

    def test_csrf_is_required_for_creation(self):
        self.assertEqual(self.request(csrf='bad')[0],403)
        self.assertEqual(self.events,[])


if __name__ == '__main__':
    unittest.main()
