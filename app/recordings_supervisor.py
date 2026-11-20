"""Supervise the SIPREC engine and publish local receiver health for the console."""
import datetime,json,os,signal,subprocess,time
from pathlib import Path
ROOT=Path(os.environ.get('RECORDING_DIR','/var/lib/sbc-console/recordings'))
ROOT.mkdir(parents=True,exist_ok=True);ROOT.chmod(0o700)
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
process=subprocess.Popen([os.environ.get('SIPREC_BINARY','/opt/siprec-runtime/siprec')],cwd=os.environ.get('SIPREC_WORKDIR','/opt/siprec-source'))
def stop(*args):
 if process.poll() is None:process.terminate()
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
try:
 while process.poll() is None:
  data=dict(state='running',pid=process.pid,startedAt=started,checkedAt=time.time(),sip=os.environ.get('EXTERNAL_IP','127.0.0.1')+':'+os.environ.get('PORTS','5060'),rtp=os.environ.get('RTP_PORT_MIN','30000')+'–'+os.environ.get('RTP_PORT_MAX','30199'),transports=['UDP','TCP'],codecs=['PCMU','PCMA'],acceptFrom='Any IP')
  temporary=ROOT/'.receiver.tmp';temporary.write_text(json.dumps(data),encoding='utf-8');temporary.chmod(0o600);temporary.replace(ROOT/'receiver.json')
  time.sleep(3)
finally:
 stop()
 try:process.wait(timeout=25)
 except subprocess.TimeoutExpired:process.kill();process.wait()
 data=dict(state='stopped',checkedAt=time.time(),startedAt=started,exitCode=process.returncode)
 (ROOT/'receiver.json').write_text(json.dumps(data),encoding='utf-8')
raise SystemExit(process.returncode or 0)
