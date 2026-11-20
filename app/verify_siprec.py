"""End-to-end local SIPREC/RTP test. Creates an explicitly labelled self-test recording."""
import audioop,base64,json,math,os,re,socket,struct,time,uuid,wave
from pathlib import Path
HOST=os.environ.get('SELFTEST_HOST','127.0.0.1');PORT=5060
RTP_MIN=int(os.environ.get('RTP_PORT_MIN','30000'));RTP_MAX=int(os.environ.get('RTP_PORT_MAX','30199'))
call='siprec-self-test-'+uuid.uuid4().hex
control=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);control.bind((HOST,0));control.settimeout(8);local_port=control.getsockname()[1]
from_header='<sip:self-test@'+HOST+'>;tag=test-source'
to_header='<sip:recorder@'+HOST+'>'
def request(method,cseq,body=b'',ctype=None,to=None):
 headers=[f'{method} sip:recorder@{HOST}:{PORT} SIP/2.0',f'Via: SIP/2.0/UDP {HOST}:{local_port};branch=z9hG4bK{uuid.uuid4().hex};rport','Max-Forwards: 70','From: '+from_header,'To: '+(to or to_header),'Call-ID: '+call,f'CSeq: {cseq} {method}',f'Contact: <sip:self-test@{HOST}:{local_port}>;+sip.src','User-Agent: SBC-Console-SIPREC-Self-Test','Supported: siprec']
 if method=='INVITE':headers+=['Require: siprec','Accept: application/sdp, application/rs-metadata+xml']
 if ctype:headers+=['Content-Type: '+ctype]
 return ('\r\n'.join(headers)+f'\r\nContent-Length: {len(body)}\r\n\r\n').encode()+body

def final_response():
 deadline=time.time()+15
 while time.time()<deadline:
  data,_=control.recvfrom(65535)
  if data.startswith(b'SIP/2.0 ') and int(data.split(b' ',2)[1])>=200:return data.decode(errors='replace')
 raise RuntimeError('No final SIP response')
control.sendto(request('OPTIONS',1),(HOST,PORT));assert final_response().startswith('SIP/2.0 200')
tcp=socket.create_connection((HOST,PORT),timeout=5);tcp.sendall(request('OPTIONS',1).replace(b'SIP/2.0/UDP',b'SIP/2.0/TCP'));tcp.settimeout(5);assert tcp.recv(65535).startswith(b'SIP/2.0 200');tcp.close()
rtp=[socket.socket(socket.AF_INET,socket.SOCK_DGRAM),socket.socket(socket.AF_INET,socket.SOCK_DGRAM)]
for s in rtp:s.bind((HOST,0))
sdp=f'v=0\r\no=selftest 1 1 IN IP4 {HOST}\r\ns=SIPREC self-test\r\nc=IN IP4 {HOST}\r\nt=0 0\r\nm=audio {rtp[0].getsockname()[1]} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendonly\r\na=label:1\r\nm=audio {rtp[1].getsockname()[1]} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\na=label:2\r\n'
ids=[base64.b64encode(uuid.uuid4().bytes).decode() for _ in range(5)]
meta=f'''<?xml version="1.0" encoding="UTF-8"?><recording xmlns="urn:ietf:params:xml:ns:recording:1"><datamode>complete</datamode><session session_id="{ids[0]}"><sipSessionID>{call}</sipSessionID></session><participant participant_id="{ids[1]}"><nameID aor="sip:self-test-source@example.invalid"><name>SIPREC self-test source</name></nameID></participant><participant participant_id="{ids[2]}"><nameID aor="sip:self-test-destination@example.invalid"><name>SIPREC self-test destination</name></nameID></participant><stream stream_id="{ids[3]}" session_id="{ids[0]}"><label>1</label></stream><stream stream_id="{ids[4]}" session_id="{ids[0]}"><label>2</label></stream><sessionrecordingassoc session_id="{ids[0]}"/><participantsessionassoc participant_id="{ids[1]}" session_id="{ids[0]}"/><participantsessionassoc participant_id="{ids[2]}" session_id="{ids[0]}"/><participantstreamassoc participant_id="{ids[1]}" stream_id="{ids[3]}"><send>{ids[3]}</send></participantstreamassoc><participantstreamassoc participant_id="{ids[2]}" stream_id="{ids[4]}"><send>{ids[4]}</send></participantstreamassoc></recording>'''
body=('--test-boundary\r\nContent-Type: application/sdp\r\n\r\n'+sdp+'\r\n--test-boundary\r\nContent-Type: application/rs-metadata+xml\r\nContent-Disposition: recording-session\r\n\r\n'+meta+'\r\n--test-boundary--\r\n').encode()
control.sendto(request('INVITE',2,body,'multipart/mixed;boundary=test-boundary'),(HOST,PORT));response=final_response()
if not response.startswith('SIP/2.0 200'):raise RuntimeError('INVITE failed: '+response[:400])
remote_to=re.search(r'^To:\s*(.+)$',response,re.M|re.I)[1].strip();control.sendto(request('ACK',2,to=remote_to),(HOST,PORT))
answer=response.split('\r\n\r\n',1)[1];ports=[int(p) for p in re.findall(r'^m=audio (\d+)',answer,re.M)];assert len(ports)==2 and all(RTP_MIN<=p<=RTP_MAX for p in ports),answer
for index in range(100):
 for channel in range(2):
  samples=b''.join(struct.pack('<h',int(8000*math.sin(2*math.pi*(440+channel*220)*(index*160+n)/8000))) for n in range(160))
  encoded=audioop.lin2alaw(samples,2) if channel==0 else audioop.lin2ulaw(samples,2)
  packet=struct.pack('!BBHII',128,8 if channel==0 else 0,index,1000+160*index,12345+channel)+encoded
  rtp[channel].sendto(packet,(HOST,ports[channel]))
 time.sleep(.02)
control.sendto(request('BYE',3,to=remote_to),(HOST,PORT));assert final_response().startswith('SIP/2.0 200')
base=Path('/var/lib/sbc-console/recordings');sidecar=base/(call+'.recording.json');deadline=time.time()+12
while time.time()<deadline:
 if sidecar.exists():
  data=json.loads(sidecar.read_text())
  if data.get('status')!='recording' and data.get('files'):break
 time.sleep(.2)
assert data['files'],data
results=[]
for name in data['files']:
 with wave.open(str(base/name),'rb') as wav:
  frames=wav.getnframes();channels=wav.getnchannels();pcm=wav.readframes(frames)
  assert frames>8000 and any(pcm),'Missing recorded RTP audio'
  results.append(dict(file=name,channels=channels,frames=frames))
assert any(r['channels']==2 for r in results),results
Path('/tmp/siprec-self-test-result.json').write_text(json.dumps(dict(callId=call,optionsUDP=True,optionsTCP=True,files=results)))
print(json.dumps(dict(optionsUDP=True,optionsTCP=True,inviteACKBYE=True,rtpCodecs=['PCMA','PCMU'],combinedStereo=True,files=len(results))))
