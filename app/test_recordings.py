import io,json,os,tempfile,time,unittest,wave
from pathlib import Path
from unittest.mock import patch
import recordings_tools as r
class RecordingsTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name);self.env=patch.dict(os.environ,{'RECORDING_DIR':self.temp.name});self.env.start();self.addCleanup(self.env.stop);self.addCleanup(self.temp.cleanup)
  self.data=dict(callId='self-test-call',status='completed',createdAt='2026-10-28T10:00:00Z',updatedAt='2026-10-28T10:00:02Z',files=['call.wav'],metadata={'Participants':[{'Name':'Test source','CommunicationIDs':[{'Value':'sip:test@example.invalid'}]}]})
  (self.path/'call.recording.json').write_text(json.dumps(self.data))
  with wave.open(str(self.path/'call.wav'),'wb') as w:w.setnchannels(2);w.setsampwidth(2);w.setframerate(8000);w.writeframes(b'\0'*32000)
 def test_catalog_metadata_and_wav(self):
  listing=r.listing();self.assertEqual(listing['total'],1);self.assertEqual(r.listing('example.invalid')['filtered'],1)
  detail=r.detail('call.recording.json');self.assertEqual(detail['audio'][0]['channels'],2);self.assertEqual(detail['audio'][0]['duration'],1);self.assertEqual(detail['metadata'],self.data['metadata'])
 def test_ranges(self):
  self.assertEqual(r.byte_range('bytes=0-43',100),(0,43,True));self.assertEqual(r.byte_range('bytes=-20',100),(80,99,True));self.assertEqual(r.byte_range('bytes=70-',100),(70,99,True))
  for value in ('bytes=100-','bytes=90-20','bytes=0-1,4-5','bad','bytes=-0'):
   with self.assertRaises(r.RecordingError):r.byte_range(value,100)
 def test_path_traversal_and_cross_recording_audio(self):
  for value in ('../call.recording.json','/etc/passwd','foo/recording.json','call..json'):
   with self.assertRaises(r.RecordingError):r.detail(value)
  with self.assertRaises(r.RecordingError):r.resolve_audio('call.recording.json','other.wav')
  self.assertEqual(r.resolve_audio('call.recording.json','call.wav'),'call.wav')
 def test_active_sessions_are_not_streamed(self):
  self.data['status']='recording';(self.path/'call.recording.json').write_text(json.dumps(self.data))
  with self.assertRaises(r.RecordingError) as exc:r.resolve_audio('call.recording.json','call.wav')
  self.assertEqual(exc.exception.code,409)
 def test_corrupt_metadata_is_skipped(self):
  (self.path/'bad.recording.json').write_text('[]');data=r.listing();self.assertEqual(data['filtered'],1);self.assertEqual(data['unreadable'],1)
 def test_health_stale_and_missing(self):
  self.assertFalse(r.health()['running']);(self.path/'receiver.json').write_text(json.dumps(dict(state='running',checkedAt=time.time())));self.assertTrue(r.health()['running'])
  (self.path/'receiver.json').write_text(json.dumps(dict(state='running',checkedAt=0)));self.assertFalse(r.health()['running'])
import test_server as existing
class RecordingHttpTests(unittest.TestCase):
 setUp=existing.UpdateRouteTests.setUp;tearDown=existing.UpdateRouteTests.tearDown;get_request=existing.DiagnosticsTests.get_request
 def test_all_routes_require_session(self):
  for path in ('/api/recordings','/api/recordings/detail?id=call.recording.json','/api/recordings/audio?id=call.recording.json&file=call.wav'):
   self.assertEqual(self.get_request(path,cookie='wrong')[0],401)
 def test_invalid_ids_and_pagination(self):
  self.assertEqual(self.get_request('/api/recordings/detail?id=../private')[0],400);self.assertEqual(self.get_request('/api/recordings?limit=101')[0],400);self.assertEqual(self.events,[])
