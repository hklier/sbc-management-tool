"""Private local recording catalog and bounded, authenticated WAV access."""
import datetime,hashlib,json,os,re,shutil,stat,time,wave,threading,uuid
from urllib.parse import unquote
from contextlib import contextmanager
from pathlib import Path
class RecordingError(Exception):
 def __init__(self,message,code=400):super().__init__(message);self.code=code

def root():return Path(os.environ.get('RECORDING_DIR',str(Path(os.environ.get('STATE_DIR','/var/lib/sbc-console'))/'recordings')))
def name(value,suffix):
 if not isinstance(value,str) or len(value)>240 or not re.fullmatch(r'[\w-][\w.\-]*',value) or '..' in value or not value.endswith(suffix):raise RecordingError('Invalid recording identifier.')
 return value
@contextmanager
def opened(filename,suffix):
 filename=name(filename,suffix);directory=root()
 if directory.is_symlink():raise RecordingError('Recording directory must not be a symbolic link.',403)
 path=directory/filename
 if path.is_symlink():raise RecordingError('Recording links are not permitted.',403)
 try:
  descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 except FileNotFoundError:raise RecordingError('Recording file not found.',404)
 except OSError:raise RecordingError('Recording file cannot be opened safely.',403)
 with os.fdopen(descriptor,'rb') as stream:
  if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):raise RecordingError('Only regular recording files are allowed.',403)
  yield stream

def read_json(filename):
 with opened(filename,'.json') as source:
  if os.fstat(source.fileno()).st_size>4*1024*1024:raise RecordingError('Recording metadata is too large.',413)
  try:
   data=json.load(source)
   if not isinstance(data,dict):raise ValueError('Metadata must be an object')
   return data
  except (ValueError,UnicodeError):raise RecordingError('Recording metadata could not be read.',502)

def health():
 state=dict(state='not started',sip='192.168.63.190:5060',rtp='30000–30199',acceptFrom='Any IP',codecs=['PCMU','PCMA'])
 try:state.update(read_json('receiver.json'))
 except RecordingError:pass
 state['running']=state.get('state')=='running' and time.time()-state.get('checkedAt',0)<15
 try:disk=shutil.disk_usage(root());state.update(freeBytes=disk.free,totalBytes=disk.total)
 except OSError:pass
 return state

def participants(data):
 people=(data.get('metadata') or {}).get('Participants') or []
 return [dict(name=p.get('DisplayName') or p.get('Name') or p.get('ID',''),addresses=[str(c.get('Value','')) for c in (p.get('CommunicationIDs') or []) if c.get('Value')]) for p in people[:100]]

def user_part(value):
 value=str(value or '').strip()
 match=re.search(r'(?i)(?:sips?|tel):([^\s<>]+)',value)
 if match:value=match.group(1)
 elif '@' not in value and re.search(r'[<>\s]',value):return ''
 return unquote(value.split('@',1)[0].split(';',1)[0].split('?',1)[0])

def call_parties(data):
 meta=data.get('metadata') or {};people=meta.get('Participants') or [];extended=meta.get('ExtendedMetadata') or {}
 caller=None;called=None
 for index,person in enumerate(people[:100]):
  extension=str(extended.get('ext_participant_'+str(index)+'_extensiondata',''))
  flag=re.search(r'<(?:[\w.-]+:)?callingParty\b[^>]*>\s*(true|false)\s*</',extension,re.I)
  role=str(person.get('Role','')).lower()
  if person.get('CallingParty') or role in ('caller','calling') or flag and flag.group(1).lower()=='true':caller=person
  elif person.get('CalledParty') or role in ('callee','called') or flag and flag.group(1).lower()=='false':called=person
 # Preserve SIPREC participant order when a source supplies no direction hints.
 if caller is None and people:caller=next((p for p in people if p is not called),None)
 if called is None:called=next((p for p in people if p is not caller),None)
 def number(person):
  if not person:return ''
  for contact in person.get('CommunicationIDs') or []:
   value=user_part(contact.get('Value'))
   if value:return value
  return user_part(person.get('DisplayName') or person.get('Name'))
 return dict(fromUser=number(caller),toUser=number(called))

def recording_duration(data):
 if data.get('status')=='recording':return None
 durations=[]
 for filename in list(dict.fromkeys(data.get('files') or []))[:20]:
  try:durations.append(wav_info(filename)['duration'])
  except RecordingError:continue
 return max(durations,default=0)

_local_locks={};_local_locks_guard=threading.Lock()
@contextmanager
def recording_lock(identifier):
 identifier=name(identifier,'.recording.json');directory=root()/'.locks'
 if directory.is_symlink():raise RecordingError('Unsafe recording lock directory.',403)
 directory.mkdir(mode=0o700,exist_ok=True)
 key=hashlib.sha256(identifier.encode()).hexdigest()
 try:import fcntl
 except ImportError:
  with _local_locks_guard:lock=_local_locks.setdefault(str(directory/key),threading.Lock())
  if not lock.acquire(blocking=False):raise RecordingError('This recording is busy. Try again after processing finishes.',409)
  try:yield
  finally:lock.release()
 else:
  descriptor=os.open(directory/key,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
  try:
   try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError:raise RecordingError('This recording is busy. Try again after processing finishes.',409)
   try:yield
   finally:fcntl.flock(descriptor,fcntl.LOCK_UN)
  finally:os.close(descriptor)

def remove_recording(identifier):
 identifier=name(identifier,'.recording.json')
 with recording_lock(identifier):
  data=read_json(identifier)
  if data.get('status')=='recording':raise RecordingError('An active recording cannot be deleted. Wait until the call finishes.',409)
  files=list(dict.fromkeys(data.get('files') or []))
  if len(files)>20:raise RecordingError('Recording has too many audio files.',413)
  members=[identifier]+[name(f,'.wav') for f in files]
  transcript=identifier[:-15]+'.transcript.json'
  if (root()/transcript).exists() or (root()/transcript).is_symlink():members.append(transcript)
  present=[]
  for filename in members:
   try:
    with opened(filename,'.json' if filename.endswith('.json') else '.wav'):pass
    present.append(filename)
   except RecordingError as exc:
    if exc.code!=404:raise
  trash=root()/'.trash'
  if trash.is_symlink():raise RecordingError('Unsafe recording trash directory.',403)
  trash.mkdir(mode=0o700,exist_ok=True);destination=trash/uuid.uuid4().hex;destination.mkdir(mode=0o700)
  moved=[]
  try:
   for filename in present:os.replace(root()/filename,destination/filename);moved.append(filename)
  except OSError as exc:
   for filename in reversed(moved):os.replace(destination/filename,root()/filename)
   destination.rmdir()
   raise RecordingError('The recording could not be moved to trash.',500) from exc
 return dict(ok=True,id=identifier,message='Recording moved to trash.')

def wav_info(filename):
 with opened(filename,'.wav') as source:
  size=os.fstat(source.fileno()).st_size
  try:
   with wave.open(source,'rb') as wav:
    rate=wav.getframerate();frames=wav.getnframes()
    return dict(name=filename,sizeBytes=size,duration=round(frames/rate,3) if rate else 0,channels=wav.getnchannels(),sampleRate=rate,frames=frames,playable=frames>0)
  except (wave.Error,EOFError):return dict(name=filename,sizeBytes=size,playable=False,duration=0,channels=0,sampleRate=0,frames=0)

def detail(recording_id):
 name(recording_id,'.recording.json');data=read_json(recording_id)
 audio=[]
 for filename in list(dict.fromkeys(data.get('files') or []))[:20]:
  try:audio.append(wav_info(filename))
  except RecordingError:continue
 return dict(id=recording_id,**{k:data.get(k) for k in ('callId','status','createdAt','updatedAt')},**call_parties(data),participants=participants(data),audio=audio,metadata=data.get('metadata') or {},transcription=transcription(recording_id,data.get('status')))

def transcription_health():
 try:
  data=read_json('transcription-health.json')
  data['running']=data.get('state') in ('ready','processing') and time.time()-data.get('checkedAt',0)<20
  return data
 except RecordingError:return dict(state='disabled',running=False)

def transcription(recording_id,status):
 try:return read_json(name(recording_id,'.recording.json')[:-15]+'.transcript.json')
 except RecordingError as exc:
  if exc.code!=404:return dict(state='unavailable',message=str(exc),segments=[])
 if status=='recording':return dict(state='waiting',message='Transcription starts after the call finishes.',segments=[])
 return dict(state='queued' if transcription_health()['running'] else 'disabled',segments=[])

def listing(query='',offset=0,limit=50):
 if offset<0 or not 1<=limit<=100:raise RecordingError('Invalid recording pagination.')
 directory=root();items=[];errors=0;needle=query.lower()[:300]
 if directory.exists():
  with os.scandir(directory) as entries:
   candidates=[]
   for entry in entries:
    try:
     if entry.name.endswith('.recording.json') and entry.is_file(follow_symlinks=False):candidates.append((entry.stat(follow_symlinks=False).st_mtime,entry.name))
    except FileNotFoundError:continue
  candidates.sort(reverse=True)
  for _,filename in candidates[:20000]:
   try:
    data=read_json(filename);people=participants(data)
    if needle and needle not in (str(data.get('callId',''))+' '+str(people)+' '+str(data.get('status',''))).lower():continue
    files=data.get('files') or [];items.append(dict(id=filename,callId=data.get('callId',''),status=data.get('status','unknown'),createdAt=data.get('createdAt'),updatedAt=data.get('updatedAt'),participants=people,audioFiles=len(files),duration=recording_duration(data),**call_parties(data)))
   except RecordingError:errors+=1
 return dict(receiver=health(),transcription=transcription_health(),total=len(candidates) if directory.exists() else 0,filtered=len(items),offset=offset,limit=limit,recordings=items[offset:offset+limit],unreadable=errors,scanLimit=20000,directory=str(directory))

def resolve_audio(recording_id,filename):
 data=read_json(name(recording_id,'.recording.json'));name(filename,'.wav')
 if filename not in (data.get('files') or []):raise RecordingError('Audio does not belong to this recording.',404)
 if data.get('status')=='recording':raise RecordingError('The recording is still in progress. Try again when it has finished.',409)
 return filename

def byte_range(header,size):
 if not header:return 0,max(0,size-1),False
 match=re.fullmatch(r'bytes=(\d*)-(\d*)',header)
 if not match or not any(match.groups()) or size==0:raise RecordingError('Requested audio range is not available.',416)
 left,right=match.groups()
 if not left:
  count=int(right)
  if count<=0:raise RecordingError('Requested audio range is not available.',416)
  start,end=max(0,size-count),size-1
 else:start,end=int(left),min(int(right) if right else size-1,size-1)
 if start>=size or end<start:raise RecordingError('Requested audio range is not available.',416)
 return start,end,True
