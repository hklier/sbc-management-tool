import json,os,threading,time,unittest
from unittest.mock import patch
import rest_activity as activity
import server
import test_server as existing

class ActivityTests(unittest.TestCase):
 def setUp(self):
  with activity._guard:activity._events.clear();activity._revision=0
  activity.CONTEXT.session='session-one';activity.CONTEXT.source='/api/test'
  self.addCleanup(lambda:setattr(activity.CONTEXT,'session',''))
 def test_live_running_then_completed_and_incremental_cursor(self):
  identifier=activity.begin('GET','configuration/versions');first=activity.listing('session-one')
  self.assertEqual(first['items'][0]['state'],'running')
  activity.finish(identifier,200,'<response><version>337</version></response>')
  last=activity.listing('session-one',first['cursor'])
  self.assertEqual(last['items'][0]['id'],identifier);self.assertEqual(last['items'][0]['state'],'completed');self.assertEqual(last['items'][0]['status'],200)
  self.assertEqual(activity.listing('session-one',last['cursor'])['items'],[])
  self.assertNotIn('session',last['items'][0]);self.assertNotIn('started',last['items'][0])
 def test_sessions_are_isolated_and_unattributed_commands_are_not_logged(self):
  activity.begin('GET','configuration/versions');self.assertEqual(activity.listing('session-two')['items'],[])
  activity.CONTEXT.session='';self.assertIsNone(activity.begin('GET','configuration/configElements'))
  self.assertEqual(len(activity.listing('session-one')['items']),1)
 def test_credentials_are_visible_as_requested(self):
  body='<configElement><attribute><name>admin-password</name><value>private-pw</value></attribute><field name="api-token" value="private-token"/><safe>private-pw</safe><community>private-community</community><authPassphrase>private-passphrase</authPassphrase></configElement>'
  event=activity.begin('PUT','configuration/configElements?password=url-private&elementType=session-agent',body,{'Authorization':'Bearer test-token'})
  activity.finish(event,400,body,True)
  stored=json.dumps(activity.listing('session-one'))
  for secret in ('private-pw','private-token','private-community','private-passphrase','url-private','Bearer test-token'):self.assertIn(secret,stored)
  self.assertIn('session-agent',stored);self.assertNotIn('REDACTED',stored);self.assertEqual(activity.listing('session-one')['items'][0]['state'],'failed')
 def test_authentication_and_raw_payload_values_preserved(self):
  item=activity.begin('POST','auth/token','<password>auth-private</password>',{'Authorization':'Basic dGVzdDp0ZXN0'});activity.finish(item,200,'<accessToken>bearer-private</accessToken>')
  for payload in ('plain password=plain-private','<xml malformed secret-private','<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'):
   self.assertEqual(payload,activity.preview(payload))
  text=json.dumps(activity.listing('session-one'));self.assertIn('auth-private',text);self.assertIn('bearer-private',text);self.assertIn('Basic dGVzdDp0ZXN0',text)
 def test_size_limit_and_network_failures(self):
  with patch.object(activity,'LIMIT',3):
   for _ in range(5):
    identifier=activity.begin('GET','system/version');activity.finish(identifier,failed=True)
  self.assertEqual(len(activity.listing('session-one')['items']),3)
  self.assertEqual(activity.listing('session-one')['items'][0]['state'],'failed')
  self.assertLess(len(activity.preview('<x>'+'a'*20000+'</x>')),activity.PREVIEW+40)
 def test_clear_only_removes_finished_requests_from_own_session(self):
  old=activity.begin('GET','configuration/versions');activity.finish(old,200,'<response/>')
  running=activity.begin('GET','admin/asyncstatus')
  activity.CONTEXT.session='session-two';other=activity.begin('GET','system/version');activity.finish(other,200,'<response/>')
  result=activity.clear('session-one')
  self.assertEqual(result['cleared'],1);self.assertEqual([e['id'] for e in result['items']],[running])
  self.assertEqual(len(activity.listing('session-two')['items']),1)
  activity.finish(running,200,'<response/>')
  self.assertEqual(activity.listing('session-one',result['cursor'])['items'][0]['id'],running)
  self.assertEqual(activity.clear('session-one')['items'],[])

class RawRequestTests(ActivityTests):
 def connection(self,status=200,body=b'<response/>',error=None):
  from types import SimpleNamespace
  class Connection:
   closed=False
   def __init__(self,*args,**kwargs):pass
   def connect(self):
    if error:raise error
   def request(self,*args,**kwargs):pass
   def getresponse(self):return SimpleNamespace(status=status,reason='Test response',read=lambda limit:body)
   def close(self):self.closed=True
  return patch('server.http.client.HTTPSConnection',Connection)
 def test_real_transport_wrapper_success_http_and_network_failure(self):
  sbc=server.SBC()
  sbc.token='transport-test-token'
  with self.connection():sbc.raw('GET','system/version')
  with self.connection(status=400,body=b'<response><errorMessage>Bad request</errorMessage></response>'):
   with self.assertRaises(server.Problem):sbc.raw('GET','bad-path')
  with self.connection(error=OSError('Unavailable')):
   with self.assertRaises(OSError):sbc.raw('GET','system/version')
  events=activity.listing('session-one')['items']
  self.assertEqual([(e['status'],e['state']) for e in events],[(200,'completed'),(400,'failed'),(None,'failed')])
  self.assertEqual(events[0]['requestHeaders']['Authorization'],'Bearer transport-test-token')

class ActivityHttpTests(unittest.TestCase):
 setUp=existing.UpdateRouteTests.setUp;tearDown=existing.UpdateRouteTests.tearDown;get_request=existing.DiagnosticsTests.get_request
 request=existing.LrtRouteTests.request
 def test_clear_requires_session_and_csrf_and_never_contacts_sbc(self):
  with patch('rest_activity.clear',return_value={'cleared':2,'cursor':5,'items':[]}) as clear:
   self.assertEqual(self.request('/api/rest-activity/clear',{},cookie='wrong')[0],401)
   self.assertEqual(self.request('/api/rest-activity/clear',{},csrf='wrong')[0],403)
   clear.assert_not_called()
   self.assertEqual(self.request('/api/rest-activity/clear',{})[0],200)
   clear.assert_called_once_with('test-cookie');self.assertEqual(self.events,[])
 def test_authentication_session_scoping_and_no_sbc_calls(self):
  self.assertEqual(self.get_request('/api/rest-activity',cookie='wrong')[0],401)
  with patch('rest_activity.listing',return_value={'cursor':1,'items':[]}) as listing:
   self.assertEqual(self.get_request('/api/rest-activity?after=0')[0],200)
   listing.assert_called_once_with('test-cookie',0)
  self.assertEqual(self.get_request('/api/rest-activity?after=invalid')[0],400)
  self.assertEqual(self.events,[])
 def test_stream_is_available_while_configuration_lock_is_held(self):
  entered=threading.Event();release=threading.Event()
  def hold():
   with server.GATE:entered.set();release.wait(5)
  thread=threading.Thread(target=hold);thread.start();entered.wait(2)
  try:self.assertEqual(self.get_request('/api/rest-activity')[0],200)
  finally:release.set();thread.join()
