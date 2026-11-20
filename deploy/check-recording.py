"""Verify recorded audio and produce stable hashes for a persistence check.

Run from /opt/sbc-console inside the console container, passing the self-test call ID.
"""
import hashlib
import json
import sys
import wave
import recordings_tools as recordings

identifier=recordings.name(sys.argv[1]+'.recording.json','.recording.json')
data=recordings.read_json(identifier)
assert data['status']!='recording','Recording has not finalized'
results=[]
for filename in data['files']:
    with recordings.opened(filename,'.wav') as source:
        digest=hashlib.file_digest(source,'sha256').hexdigest()
    with recordings.opened(filename,'.wav') as source,wave.open(source,'rb') as audio:
        frames=audio.getnframes();channels=audio.getnchannels();pcm=audio.readframes(frames)
        assert frames>8000 and any(pcm),'Recorded RTP audio is missing'
        results.append({'file':filename,'channels':channels,'frames':frames,'sha256':digest})
assert sum(r['channels']==1 for r in results)>=2,'Missing separate audio legs'
assert any(r['channels']==2 for r in results),'Missing combined stereo audio'
print(json.dumps({'callId':data['callId'],'status':data['status'],'files':results},indent=2))
