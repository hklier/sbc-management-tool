"""Container probes without SBC requests or exposed credentials."""
import http.client
import json
import os
from pathlib import Path
import sqlite3
import ssl
import sys
import time

kind = sys.argv[1]
root = Path(os.environ.get('RECORDING_DIR', '/var/lib/sbc-console/recordings'))
if kind == 'web':
    conn = http.client.HTTPSConnection('127.0.0.1', 8443, timeout=3,
                                       context=ssl._create_unverified_context())
    conn.request('GET', '/api/session')
    assert conn.getresponse().status in (200, 401)
elif kind == 'traps':
    state = Path(os.environ['STATE_DIR']) / 'traps.sqlite3'
    with sqlite3.connect(f'file:{state}?mode=ro', uri=True, timeout=3) as db:
        data = json.loads(db.execute('SELECT payload FROM receiver WHERE id=1').fetchone()[0])
    assert data['status'] == 'listening' and time.time() - data['heartbeatEpoch'] < 30
else:
    filename = 'receiver.json' if kind == 'recorder' else 'transcription-health.json'
    data = json.loads((root / filename).read_text())
    assert data['state'] not in ('stopped', 'failed')
    assert time.time() - data['checkedAt'] < 40
