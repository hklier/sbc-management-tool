"""Offline, serial, post-call transcription. No network or cloud provider is used.

Whisper tiny / CTranslate2 int8; bounded audio windows avoid loading long calls
into RAM. Each recording runs in a subprocess so idle memory is released.
"""
import datetime,json,os,signal,subprocess,sys,time,wave
from pathlib import Path
import recordings_tools as recordings

MODEL=os.environ.get('TRANSCRIPTION_MODEL','/opt/sbc-transcription/model')
PYTHON=os.environ.get('TRANSCRIPTION_PYTHON','/opt/sbc-transcription/venv/bin/python')
STOP=False

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def transcript_name(identifier):return recordings.name(identifier,'.recording.json')[:-15]+'.transcript.json'
def atomic(filename,data):
 directory=recordings.root();temporary=directory/(filename+'.tmp')
 descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(descriptor,'w',encoding='utf-8') as f:json.dump(data,f,ensure_ascii=False)
 os.replace(temporary,directory/filename)

def health(state='ready',**extra):atomic('transcription-health.json',dict(state=state,checkedAt=time.time(),engine='Whisper tiny · local CPU',language='Automatic',**extra))

def sources(identifier):
 data=recordings.read_json(recordings.name(identifier,'.recording.json'))
 if data.get('status')=='recording':return []
 files=[]
 for name in list(dict.fromkeys(data.get('files') or []))[:20]:
  try:
   info=recordings.wav_info(name)
   if info['playable']:files.append(info)
  except recordings.RecordingError:continue
 # Separate RTP legs retain stream identity; combined audio is the fallback.
 mono=[f for f in files if f['channels']==1]
 return mono or files[:1]

def infer(identifier):
 import numpy as np
 import audioop
 from faster_whisper import WhisperModel
 model=WhisperModel(MODEL,device='cpu',compute_type='int8',cpu_threads=1,num_workers=1,local_files_only=True)
 result=dict(state='processing',engine='Whisper tiny (int8, offline)',startedAt=now(),segments=[],languages=[],sourceFiles=[])
 filename=transcript_name(identifier);atomic(filename,result)
 for stream,info in enumerate(sources(identifier),1):
  result['sourceFiles'].append(info['name'])
  with recordings.opened(info['name'],'.wav') as source, wave.open(source,'rb') as wav:
   if wav.getsampwidth()!=2:raise ValueError('Only PCM16 WAV recordings are supported.')
   channels=wav.getnchannels();rate=wav.getframerate();offset=0
   while True:
    raw=wav.readframes(rate*28)
    if not raw:break
    samples=np.frombuffer(raw,dtype='<i2').reshape(-1,channels)
    for channel in range(channels):
     pcm=samples[:,channel].copy().tobytes()
     if audioop.rms(pcm,2)<45:continue
     pcm=audioop.ratecv(pcm,2,1,rate,16000,None)[0]
     audio=np.frombuffer(pcm,dtype='<i2').astype(np.float32)/32768
     segments,detected=model.transcribe(audio,language=None,beam_size=1,temperature=0,condition_on_previous_text=False,vad_filter=False,word_timestamps=False)
     if detected.language not in result['languages']:result['languages'].append(detected.language)
     for segment in segments:
      text=segment.text.strip()
      if text:result['segments'].append(dict(start=round(offset+segment.start,2),end=round(offset+segment.end,2),stream=stream if channels==1 else channel+1,text=text))
    offset+=len(samples)/rate
    atomic(filename,result)
 result['segments'].sort(key=lambda s:(s['start'],s['stream']))
 result.update(state='completed',completedAt=now(),text='\n'.join(s['text'] for s in result['segments']))
 atomic(filename,result)

def pending():
 candidates=[]
 for path in recordings.root().glob('*.recording.json'):
  try:candidates.append((path.stat().st_mtime,path))
  except FileNotFoundError:continue
 for _,path in sorted(candidates):
  if path.is_symlink():continue
  try:
   if recordings.read_json(path.name).get('status')=='recording':continue
   target=recordings.root()/transcript_name(path.name)
   if target.exists() and recordings.read_json(target.name).get('state') in ('completed','failed'):continue
   yield path.name
  except (OSError,recordings.RecordingError):continue

def process_recording(identifier):
 if not sources(identifier):
  atomic(transcript_name(identifier),dict(state='completed',segments=[],text='',completedAt=now(),message='No playable audio.'));return
 atomic(transcript_name(identifier),dict(state='processing',startedAt=now(),segments=[]))
 child=subprocess.Popen([PYTHON,__file__,'--infer',identifier],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 began=time.monotonic()
 while child.poll() is None and not STOP and time.monotonic()-began<86400:
  health('processing',recording=identifier);time.sleep(3)
 if child.poll() is None:child.terminate()
 try:_,error=child.communicate(timeout=10)
 except subprocess.TimeoutExpired:child.kill();_,error=child.communicate()
 if child.returncode:
  if STOP:
   atomic(transcript_name(identifier),dict(state='queued',segments=[]))
  else:
   atomic(transcript_name(identifier),dict(state='failed',message='Local transcription failed. Contact the administrator.',completedAt=now(),segments=[]))
   print('Transcription failed:',identifier,error.decode(errors='replace')[-1500:],flush=True)

def run():
 global STOP
 def stop(*_):
  global STOP
  STOP=True
 signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
 while not STOP:
  health()
  for identifier in pending():
   if STOP:break
   try:
    with recordings.recording_lock(identifier):process_recording(identifier)
   except recordings.RecordingError:continue
  for _ in range(5):
   if STOP:break
   time.sleep(1)
 health('stopped')

if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--infer':infer(sys.argv[2])
 else:run()
