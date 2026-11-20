"""Send a labelled synthetic two-leg recording through the external SIP/RTP endpoint.

Usage: python deploy/check-siprec.py 192.168.0.241
Creates a self-test recording; verify the stored WAV files separately on the server.
"""
import base64
import json
import re
import socket
import struct
import sys
import time
import uuid

target=sys.argv[1]
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
    probe.connect((target,5060));source=probe.getsockname()[0]
control=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
control.bind((source,0));control.settimeout(10)
port=control.getsockname()[1]
call='siprec-network-self-test-'+uuid.uuid4().hex
from_header=f'<sip:self-test@{source}>;tag=network-test'
to_header=f'<sip:recorder@{target}>'

def request(method,cseq,body=b'',ctype=None,to=None):
    headers=[f'{method} sip:recorder@{target}:5060 SIP/2.0',
             f'Via: SIP/2.0/UDP {source}:{port};branch=z9hG4bK{uuid.uuid4().hex};rport',
             'Max-Forwards: 70','From: '+from_header,'To: '+(to or to_header),'Call-ID: '+call,
             f'CSeq: {cseq} {method}',f'Contact: <sip:self-test@{source}:{port}>;+sip.src',
             'User-Agent: SBC-Console-Network-Self-Test','Supported: siprec']
    if method=='INVITE':headers+=['Require: siprec','Accept: application/sdp, application/rs-metadata+xml']
    if ctype:headers+=['Content-Type: '+ctype]
    return ('\r\n'.join(headers)+f'\r\nContent-Length: {len(body)}\r\n\r\n').encode()+body

def final_response():
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        packet,_=control.recvfrom(65535)
        if packet.startswith(b'SIP/2.0 ') and int(packet.split(b' ',2)[1])>=200:return packet.decode(errors='replace')
    raise RuntimeError('No final SIP response')

control.sendto(request('OPTIONS',1),(target,5060))
assert final_response().startswith('SIP/2.0 200'),'UDP OPTIONS failed'
with socket.create_connection((target,5060),timeout=10) as tcp:
    tcp.sendall(request('OPTIONS',1).replace(b'SIP/2.0/UDP',b'SIP/2.0/TCP'))
    assert tcp.recv(65535).startswith(b'SIP/2.0 200'),'TCP OPTIONS failed'
rtp=[socket.socket(socket.AF_INET,socket.SOCK_DGRAM) for _ in range(2)]
for sock in rtp:sock.bind((source,0))
sdp=f'v=0\r\no=selftest 1 1 IN IP4 {source}\r\ns=Network self-test\r\nc=IN IP4 {source}\r\nt=0 0\r\nm=audio {rtp[0].getsockname()[1]} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendonly\r\na=label:1\r\nm=audio {rtp[1].getsockname()[1]} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\na=label:2\r\n'
ids=[base64.b64encode(uuid.uuid4().bytes).decode() for _ in range(5)]
meta=f'''<?xml version="1.0" encoding="UTF-8"?><recording xmlns="urn:ietf:params:xml:ns:recording:1"><datamode>complete</datamode><session session_id="{ids[0]}"><sipSessionID>{call}</sipSessionID></session><participant participant_id="{ids[1]}"><nameID aor="sip:network-self-test-source@example.invalid"><name>Network self-test source</name></nameID></participant><participant participant_id="{ids[2]}"><nameID aor="sip:network-self-test-destination@example.invalid"><name>Network self-test destination</name></nameID></participant><stream stream_id="{ids[3]}" session_id="{ids[0]}"><label>1</label></stream><stream stream_id="{ids[4]}" session_id="{ids[0]}"><label>2</label></stream><sessionrecordingassoc session_id="{ids[0]}"/><participantsessionassoc participant_id="{ids[1]}" session_id="{ids[0]}"/><participantsessionassoc participant_id="{ids[2]}" session_id="{ids[0]}"/><participantstreamassoc participant_id="{ids[1]}" stream_id="{ids[3]}"><send>{ids[3]}</send></participantstreamassoc><participantstreamassoc participant_id="{ids[2]}" stream_id="{ids[4]}"><send>{ids[4]}</send></participantstreamassoc></recording>'''
body=('--self-test\r\nContent-Type: application/sdp\r\n\r\n'+sdp+'\r\n--self-test\r\nContent-Type: application/rs-metadata+xml\r\nContent-Disposition: recording-session\r\n\r\n'+meta+'\r\n--self-test--\r\n').encode()
control.sendto(request('INVITE',2,body,'multipart/mixed;boundary=self-test'),(target,5060))
response=final_response()
assert response.startswith('SIP/2.0 200'),response[:300]
remote_to=re.search(r'^To:\s*(.+)$',response,re.M|re.I)[1].strip()
control.sendto(request('ACK',2,to=remote_to),(target,5060))
answer=response.split('\r\n\r\n',1)[1]
ports=[int(p) for p in re.findall(r'^m=audio (\d+)',answer,re.M)]
media=re.search(r'^c=IN IP4 (\S+)',answer,re.M)[1]
assert media==target,(media,target)
assert len(ports)==2 and all(20000<=p<=20199 for p in ports),ports
payloads=[bytes([0xD5,0xC5,0xF5,0xE5])*40,bytes([0x80,0x90,0xA0,0xB0])*40]
for sequence in range(100):
    for channel in range(2):
        packet=struct.pack('!BBHII',128,8 if channel==0 else 0,sequence,1000+160*sequence,12345+channel)+payloads[channel]
        rtp[channel].sendto(packet,(media,ports[channel]))
    time.sleep(.02)
control.sendto(request('BYE',3,to=remote_to),(target,5060))
assert final_response().startswith('SIP/2.0 200'),'BYE failed'
for sock in rtp:sock.close()
control.close()
print(json.dumps({'callId':call,'source':source,'target':target,'optionsUDP':True,'optionsTCP':True,
                  'inviteACKBYE':True,'advertisedMediaIP':media,'rtpPorts':ports,'codecs':['PCMA','PCMU'],'packetsPerLeg':100}))
