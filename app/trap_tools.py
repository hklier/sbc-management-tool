import devices_tools
"""Bounded, persistent SNMPv1/v2c trap inbox; never sends configuration requests."""
from contextlib import contextmanager
from functools import lru_cache
import datetime
import hmac
import json
import os
import socket
import sqlite3
import time
from pathlib import Path
import snmp_tools

MAX_EVENTS=5000
TRAP_OID='1.3.6.1.6.3.1.1.4.1.0'
UPTIME_OID='1.3.6.1.2.1.1.3.0'
SEVERITIES=('emergency','critical','major','minor','warning','notice','info','trace','debug','unknown')

class TrapError(Exception):pass

def timestamp(epoch=None):
 return datetime.datetime.fromtimestamp(time.time() if epoch is None else epoch,datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')

def communities():
 raw=os.environ.get('SNMP_TRAP_COMMUNITIES','')
 values=json.loads(raw) if raw else [os.environ.get('SNMP_COMMUNITY','')]
 if not isinstance(values,list) or not values or not all(isinstance(v,str) and v for v in values):raise TrapError('Trap community credentials are not configured.')
 return [v.encode() for v in values]

def decode_packet(packet,source,allowed_communities,received=None):
 from pyasn1.codec.ber import decoder,encoder
 from pysnmp.proto import api
 if not 0<len(packet)<=65507:raise TrapError('Invalid datagram size.')
 version=int(api.decodeMessageVersion(packet))
 if version not in api.PROTOCOL_MODULES:raise TrapError('Unsupported SNMP version. This receiver supports v1 and v2c.')
 module=api.PROTOCOL_MODULES[version]
 message,remainder=decoder.decode(packet,asn1Spec=module.Message())
 if remainder:raise TrapError('Trailing data in SNMP datagram.')
 community=module.apiMessage.get_community(message).asOctets()
 if not any(hmac.compare_digest(community,allowed) for allowed in allowed_communities):raise TrapError('Unrecognized trap community.')
 pdu=module.apiMessage.get_pdu(message);reply=None;extra={}
 if version==0:
  if pdu.tagSet!=module.TrapPDU.tagSet:raise TrapError('Only notifications are accepted.')
  trap=module.apiTrapPDU;generic=int(trap.get_generic_trap(pdu));specific=int(trap.get_specific_trap(pdu));enterprise=str(trap.get_enterprise(pdu))
  if not 0<=generic<=6:raise TrapError('Invalid generic trap.')
  oid=enterprise+'.0.'+str(specific) if generic==6 else '1.3.6.1.6.3.1.1.5.'+str(generic+1)
  uptime=int(trap.get_timestamp(pdu));bindings=trap.get_varbinds(pdu);kind='TRAP'
  extra=dict(enterprise=enterprise,agentAddress=str(trap.get_agent_address(pdu)),genericTrap=generic,specificTrap=specific)
 else:
  if pdu.tagSet==module.SNMPv2TrapPDU.tagSet:kind='TRAP'
  elif pdu.tagSet==module.InformRequestPDU.tagSet:
   kind='INFORM';response=module.apiMessage.get_response(message);module.apiPDU.set_varbinds(module.apiMessage.get_pdu(response),module.apiPDU.get_varbinds(pdu));reply=encoder.encode(response)
  else:raise TrapError('Only notifications are accepted.')
  bindings=module.apiPDU.get_varbinds(pdu);values={str(oid):value for oid,value in bindings}
  if TRAP_OID not in values or UPTIME_OID not in values:raise TrapError('Missing notification OID or uptime.')
  if type(values[TRAP_OID]).__name__!='ObjectIdentifier':raise TrapError('Invalid notification OID type.')
  oid=str(values[TRAP_OID]);uptime=int(values[UPTIME_OID])
 # Community values and RFC3584 proxy-community varbinds are never retained.
 records=[];size=0;truncated=False
 for key,value in bindings:
  if str(key)=='1.3.6.1.6.3.18.1.4.0':continue
  row=snmp_tools.record(key,value)
  for field in ('value','display'):
   for secret in allowed_communities:
    text=secret.decode('utf-8',errors='replace')
    if text:row[field]=row[field].replace(text,'[redacted]')
   if len(row[field])>1024:row[field]=row[field][:1024];row['truncated']=True
  if row['type']=='ObjectIdentifier':row['referenceName']=snmp_tools.identify(row['value'])['name']
  size+=len(json.dumps(row).encode())
  if len(records)>=64 or size>32768:truncated=True;break
  records.append(row)
 metadata=snmp_tools.identify(oid);severity='unknown';summary=''
 for row in records:
  if row['name']=='apSyslogHistLevel' and row['display'].lower() in SEVERITIES:severity=row['display'].lower()
  if row['name']=='apSyslogHistContent':summary=row['value']
 event=dict(receivedAt=timestamp(received),receivedEpoch=time.time() if received is None else received,source=source[0],sourcePort=source[1],version='1' if version==0 else '2c',kind=kind,oid=oid,name=metadata['name'],module=metadata['module'],uptimeTicks=uptime,severity=severity,summary=summary,bindings=records,truncated=truncated or any(r['truncated'] for r in records),**extra)
 return event,reply

def search_text(event):
 return ' '.join([event['name'],event['oid'],event['source'],event['summary']]+[r['name']+' '+r['value']+' '+r.get('display','')+' '+r.get('referenceName','') for r in event['bindings']]).lower()

@lru_cache(maxsize=1)
def notification_catalog():
 return json.loads((Path(__file__).parent/'trap_catalog.json').read_text(encoding='utf-8'))

def present_event(event):
 # Resolve by exact notification OID, including events stored before this catalog existed.
 catalog=notification_catalog();definition=catalog['notifications'].get(event['oid'])
 return dict(event,title=definition['title'] if definition else 'Unrecognized SNMP notification',description=definition['description'] if definition else 'This notification OID is not documented in the bundled Oracle 9.3 MIB catalog. Inspect its original name, OID and parameters below.',documented=bool(definition),mibModule=definition['module'] if definition else '',mibSource=catalog['mibSource'],guideSource=catalog['guideSource'])

class Store:
 def __init__(self,path=None):self.path=Path(path) if path else Path(os.environ.get('STATE_DIR','/var/lib/sbc-console'))/'traps.sqlite3'
 @contextmanager
 def connect(self):
  self.path.parent.mkdir(parents=True,exist_ok=True)
  connection=sqlite3.connect(self.path,timeout=3);connection.row_factory=sqlite3.Row
  connection.execute('PRAGMA journal_mode=WAL');connection.execute('PRAGMA busy_timeout=3000')
  connection.executescript('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, epoch REAL NOT NULL, severity TEXT NOT NULL, version TEXT NOT NULL, search TEXT NOT NULL, brief TEXT NOT NULL, payload TEXT NOT NULL); CREATE INDEX IF NOT EXISTS event_epoch ON events(epoch); CREATE TABLE IF NOT EXISTS receiver(id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);')
  self.path.chmod(0o600)
  try:
   with connection:yield connection
  finally:connection.close()
 def append(self,event):
  search=search_text(event)
  with self.connect() as db:
   cursor=db.execute('INSERT INTO events(epoch,severity,version,search,brief,payload) VALUES(?,?,?,?,?,?)',(event['receivedEpoch'],event['severity'],event['version'],search,json.dumps({k:v for k,v in event.items() if k!='bindings'}),json.dumps(event,ensure_ascii=True)))
   event_id=cursor.lastrowid
   db.execute('DELETE FROM events WHERE id <= ?',(event_id-MAX_EVENTS,))
  return event_id
 def heartbeat(self,state):
  with self.connect() as db:db.execute('INSERT OR REPLACE INTO receiver(id,payload) VALUES(1,?)',(json.dumps(dict(**state,heartbeatEpoch=time.time(),updatedAt=timestamp())),))
 def overview(self):
  clock=time.time();buckets=[dict(time=(int(clock//60)-59+i)*60000,count=0) for i in range(60)]
  with self.connect() as db:
   events=[json.loads(r[0]) for r in db.execute('SELECT brief FROM events ORDER BY id')]
   row=db.execute('SELECT payload FROM receiver WHERE id=1').fetchone()
  current=devices_tools.CONTEXT.get()
  if current:events=[e for e in events if e['source']==current.record['management_ip']]
  state=json.loads(row[0]) if row else dict(status='waiting',error='Receiver has not started yet.')
  state['listening']=state.get('status')=='listening' and clock-state.get('heartbeatEpoch',0)<20
  if state.get('status')=='listening' and not state['listening']:state['status']='offline';state['error']='Receiver heartbeat is stale. Check the trap receiver service.'
  types={};levels={k:0 for k in SEVERITIES}
  for event in events:
   group=types.setdefault(event['oid'],dict(oid=event['oid'],name=event['name'],title=present_event(event)['title'],count=0));group['count']+=1
   levels[event['severity']]=levels.get(event['severity'],0)+1
   index=int(event['receivedEpoch']//60)-int(buckets[0]['time']//60000)
   if 0<=index<60:buckets[index]['count']+=1
  return dict(receiver=state,retained=len(events),limit=MAX_EVENTS,recent=sum(e['receivedEpoch']>=clock-900 for e in events),lastReceived=events[-1]['receivedAt'] if events else None,uniqueTypes=len(types),types=sorted(types.values(),key=lambda r:r['count'],reverse=True)[:8],severities=levels,timeline=buckets,checkedAt=timestamp())
 def query(self,query='',severity='',version='',offset=0,limit=50,details=False):
  if offset<0 or not 1<=limit<=500:raise TrapError('Invalid trap pagination.')
  if severity and severity not in SEVERITIES:raise TrapError('Invalid trap severity.')
  if version and version not in ('1','2c'):raise TrapError('Invalid trap version.')
  clauses=[];args=[]
  if severity:clauses.append('severity=?');args.append(severity)
  if version:clauses.append('version=?');args.append(version)
  where=' WHERE '+' AND '.join(clauses) if clauses else ''
  with self.connect() as db:
   rows=db.execute('SELECT id,brief,search FROM events'+where+' ORDER BY id DESC',args).fetchall()
   matches=[];needle=query.lower()[:300]
   for row in rows:
    event=present_event(dict(id=row['id'],**json.loads(row['brief'])))
    current=devices_tools.CONTEXT.get()
    if current and event['source']!=current.record['management_ip']:continue
    if not needle or needle in row['search'] or needle in (event['title']+' '+event['description']).lower():matches.append(event)
   events=matches[offset:offset+limit]
   if details:
    events=[present_event(dict(id=event['id'],**json.loads(db.execute('SELECT payload FROM events WHERE id=?',(event['id'],)).fetchone()[0]))) for event in events]
  return dict(events=events,filtered=len(matches),offset=offset,limit=limit)
 def event(self,event_id):
  with self.connect() as db:row=db.execute('SELECT payload FROM events WHERE id=?',(event_id,)).fetchone()
  if not row:return None
  event=present_event(dict(id=event_id,**json.loads(row[0])))
  current=devices_tools.CONTEXT.get()
  return None if current and event['source']!=current.record['management_ip'] else event

STORE=Store()

def receiver_socket():
 if int(os.environ.get('LISTEN_FDS','0'))==1 and int(os.environ.get('LISTEN_PID','0'))==os.getpid():
  return socket.socket(fileno=3)
 if 'TRAP_BIND_HOST' not in os.environ:
  raise TrapError('Start through systemd or explicitly configure TRAP_BIND_HOST.')
 sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
 try:sock.bind((os.environ['TRAP_BIND_HOST'],int(os.environ.get('TRAP_PORT','1162'))))
 except BaseException:sock.close();raise
 return sock

def run_receiver():
 allowed=communities();host=os.environ.get('SBC_HOST','192.168.226.193')
 profiles=None;devices=devices_tools.Store(Path(os.environ.get('STATE_DIR','/var/lib/sbc-console')))
 sock=receiver_socket();sock.settimeout(1)
 state=dict(status='listening',endpoint=sock.getsockname()[0]+':'+str(sock.getsockname()[1]),source=host,versions=['1','2c'],startedAt=timestamp(),accepted=0,rejected=0,malformed=0,storageErrors=0,error='')
 last_beat=0
 while True:
  if time.monotonic()-last_beat>=5:
   try:
    if devices.ready():profiles={r['management_ip']:r['snmp'].get('trap_communities',[]) for r in devices.records()};state['source']=', '.join(profiles) or 'No managed devices'
    state['error']=''
   except Exception:profiles={};state['error']='Device profiles could not be read; notifications are rejected until storage recovers.'
   STORE.heartbeat(state);last_beat=time.monotonic()
  try:packet,source=sock.recvfrom(65535)
  except socket.timeout:continue
  accepted=profiles.get(source[0],[]) if profiles is not None else (allowed if source[0]==host else [])
  if not accepted:state['rejected']+=1;continue
  try:event,reply=decode_packet(packet,source,accepted)
  except Exception:state['malformed']+=1;continue
  try:
   STORE.append(event);state['accepted']+=1;state['error']=''
  except Exception:
   state['storageErrors']+=1;state['error']='A notification could not be saved. Check receiver storage.';continue
  if reply:
   try:sock.sendto(reply,source)
   except OSError:state['error']='An INFORM was stored but its acknowledgment could not be sent.'

if __name__=='__main__':run_receiver()
