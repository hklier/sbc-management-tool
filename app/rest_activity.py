"""Bounded, session-private, unmasked SBC REST activity. Memory only."""
import copy,datetime,threading,time
from collections import OrderedDict

CONTEXT=threading.local()
LIMIT=400
PREVIEW=6000
_events=OrderedDict()
_guard=threading.Lock()
_revision=0

def safe_url(path):return str(path)

def preview(value,authentication=False):
 if value is None:return ''
 if isinstance(value,bytes):value=value.decode('utf-8',errors='replace')
 if len(value)>PREVIEW:return value[:PREVIEW]+'\n… Preview truncated.'
 return value

def begin(method,path,body=None,headers=None):
 global _revision
 session=getattr(CONTEXT,'session','')
 if not session:return None
 request=preview(body)
 with _guard:
  _revision+=1;identifier=_revision
  _events[identifier]=dict(id=identifier,revision=_revision,session=session,time=datetime.datetime.now(datetime.timezone.utc).isoformat(),method=method,url=safe_url('/rest/v1.2/'+path),source=getattr(CONTEXT,'source',''),state='running',status=None,durationMs=None,request=request,requestHeaders={str(k):preview(str(v)) for k,v in (headers or {}).items()},response='',error='',started=time.monotonic())
  while len(_events)>LIMIT:_events.popitem(last=False)
 return identifier

def finish(identifier,status=None,response=None,failed=False):
 global _revision
 if identifier is None:return
 with _guard:
  event=_events.get(identifier)
  if event is None:return
 result=preview(response)
 with _guard:
  event=_events.get(identifier)
  if event is None:return
  _revision+=1
  event.update(revision=_revision,state='failed' if failed else 'completed',status=status,durationMs=round((time.monotonic()-event['started'])*1000),response=result,error=('SBC returned HTTP '+str(status) if status is not None and status>=400 else 'The SBC reported an invalid or failed response.' if status is not None else 'The SBC request failed.') if failed else '')

def listing(session,after=0):
 with _guard:
  return dict(cursor=_revision,items=[copy.deepcopy({k:v for k,v in event.items() if k not in ('session','started')}) for event in _events.values() if event['session']==session and event['revision']>after],retention='Recent requests in this sign-in session. Memory only.')

def clear(session):
 with _guard:
  identifiers=[identifier for identifier,event in _events.items() if event['session']==session and event['state']!='running']
  for identifier in identifiers:del _events[identifier]
 return dict(cleared=len(identifiers),**listing(session))
