import json,time
from unittest.mock import patch
from test_recordings import RecordingsTests
import recordings_tools as r
import transcription_worker as worker

class TranscriptionTests(RecordingsTests):
 def test_transcript_names_and_source_membership(self):
  self.assertEqual(worker.transcript_name('call.recording.json'),'call.transcript.json')
  self.assertEqual([f['name'] for f in worker.sources('call.recording.json')],['call.wav'])
  self.data['files']=['../private.wav'];(self.path/'call.recording.json').write_text(json.dumps(self.data))
  self.assertEqual(worker.sources('call.recording.json'),[])
 def test_in_progress_audio_is_never_queued(self):
  self.data['status']='recording';(self.path/'call.recording.json').write_text(json.dumps(self.data))
  self.assertEqual(list(worker.pending()),[]);self.assertEqual(worker.sources('call.recording.json'),[])
  self.assertEqual(r.detail('call.recording.json')['transcription']['state'],'waiting')
 def test_offline_health_and_queue(self):
  self.assertEqual(r.detail('call.recording.json')['transcription']['state'],'disabled')
  worker.health();self.assertTrue(r.transcription_health()['running'])
  self.assertEqual(r.detail('call.recording.json')['transcription']['state'],'queued')
  worker.atomic('transcription-health.json',dict(state='ready',checkedAt=0))
  self.assertFalse(r.transcription_health()['running'])
 def test_resume_interrupted_skip_finished(self):
  worker.atomic('call.transcript.json',dict(state='processing',segments=[]))
  self.assertEqual(list(worker.pending()),['call.recording.json'])
  for state in ('completed','failed'):
   worker.atomic('call.transcript.json',dict(state=state,segments=[dict(start=0,text='hello')]))
   self.assertEqual(list(worker.pending()),[])
   self.assertEqual(r.detail('call.recording.json')['transcription']['state'],state)
 def test_atomic_files_private_and_invalid_json(self):
  worker.atomic('call.transcript.json',dict(state='completed',text='Español',segments=[]))
  self.assertEqual(r.detail('call.recording.json')['transcription']['text'],'Español')
  self.assertFalse((self.path/'call.transcript.json.tmp').exists())
  (self.path/'call.transcript.json').write_text('invalid')
  self.assertEqual(r.detail('call.recording.json')['transcription']['state'],'unavailable')
