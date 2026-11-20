import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_recordings as base
import test_server as server_tests
import recordings_tools as recordings

class RecordingManagementTests(base.RecordingsTests):
 def test_numbers_and_duration(self):
  self.data['metadata']={'Participants':[
   {'Name':'Destination','CommunicationIDs':[{'Value':'sips:+34912345678@destination.example;user=phone'}]},
   {'Name':'Caller','CommunicationIDs':[{'Value':'sip:1001@source.example'}]}],
   'ExtendedMetadata':{'ext_participant_0_extensiondata':'<apkt:callingParty>false</apkt:callingParty>',
   'ext_participant_1_extensiondata':'<apkt:callingParty>true</apkt:callingParty>'}}
  (self.path/'call.recording.json').write_text(json.dumps(self.data))
  row=recordings.listing()['recordings'][0]
  self.assertEqual((row['fromUser'],row['toUser']),('1001','+34912345678'))
  self.assertEqual(row['duration'],1)
  self.assertEqual(recordings.user_part('"Caller" <sip:123%23@host.test>;tag=abc'),'123#')
  self.assertEqual(recordings.user_part('tel:+34123;phone-context=host.test'),'+34123')
 def test_trash_preserves_all_files_and_hides_recording(self):
  transcript=self.path/'call.transcript.json';transcript.write_text('original transcript')
  audio=(self.path/'call.wav').read_bytes()
  result=recordings.remove_recording('call.recording.json')
  self.assertTrue(result['ok']);self.assertEqual(recordings.listing()['filtered'],0)
  destination=next((self.path/'.trash').iterdir())
  self.assertEqual((destination/'call.wav').read_bytes(),audio)
  self.assertEqual((destination/'call.transcript.json').read_text(),'original transcript')
  self.assertEqual(json.loads((destination/'call.recording.json').read_text())['callId'],self.data['callId'])
  with self.assertRaises(recordings.RecordingError):recordings.detail('call.recording.json')
 def test_active_and_processing_recordings_cannot_be_deleted(self):
  self.data['status']='recording';(self.path/'call.recording.json').write_text(json.dumps(self.data))
  self.assertIsNone(recordings.listing()['recordings'][0]['duration'])
  with self.assertRaises(recordings.RecordingError) as error:recordings.remove_recording('call.recording.json')
  self.assertEqual(error.exception.code,409)
  self.data['status']='completed';(self.path/'call.recording.json').write_text(json.dumps(self.data))
  with recordings.recording_lock('call.recording.json'):
   with self.assertRaises(recordings.RecordingError) as error:recordings.remove_recording('call.recording.json')
   self.assertEqual(error.exception.code,409)
  self.assertTrue((self.path/'call.wav').exists())
 def test_invalid_membership_is_rejected_before_any_move(self):
  self.data['files']=['../outside.wav'];(self.path/'call.recording.json').write_text(json.dumps(self.data))
  with self.assertRaises(recordings.RecordingError):recordings.remove_recording('call.recording.json')
  self.assertTrue((self.path/'call.recording.json').exists());self.assertTrue((self.path/'call.wav').exists())
 def test_partial_move_failure_rolls_back(self):
  replace=os.replace
  def fail_audio(source,target):
   if str(source).endswith('call.wav'):raise OSError('Test simulated failure')
   return replace(source,target)
  with patch('recordings_tools.os.replace',side_effect=fail_audio):
   with self.assertRaises(recordings.RecordingError):recordings.remove_recording('call.recording.json')
  self.assertTrue((self.path/'call.recording.json').exists());self.assertTrue((self.path/'call.wav').exists())
 def test_no_metadata_and_no_unsafe_identifier(self):
  for identifier,code in (('../call.recording.json',400),('missing.recording.json',404)):
   with self.assertRaises(recordings.RecordingError) as error:recordings.remove_recording(identifier)
   self.assertEqual(error.exception.code,code)

class RecordingDeleteHttpTests(unittest.TestCase):
 setUp=server_tests.UpdateRouteTests.setUp
 tearDown=server_tests.UpdateRouteTests.tearDown
 request=server_tests.LrtRouteTests.request
 def test_session_and_csrf_protect_deletion(self):
  with patch('recordings_tools.remove_recording') as delete:
   self.assertEqual(self.request('/api/recordings/delete',{'id':'call.recording.json'},cookie='wrong')[0],401)
   self.assertEqual(self.request('/api/recordings/delete',{'id':'call.recording.json'},csrf='wrong')[0],403)
   delete.assert_not_called()
 def test_delete_is_local_and_reports_conflicts(self):
  with patch('recordings_tools.remove_recording',return_value={'ok':True}) as delete:
   self.assertEqual(self.request('/api/recordings/delete',{'id':'call.recording.json'})[0],200)
   delete.assert_called_once_with('call.recording.json');self.assertEqual(self.events,[])
  with patch('recordings_tools.remove_recording',side_effect=recordings.RecordingError('Busy',409)):
   self.assertEqual(self.request('/api/recordings/delete',{'id':'call.recording.json'})[0],409)
