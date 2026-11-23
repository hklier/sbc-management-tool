"""Encrypted, versioned application settings on the retained state volume."""
import json,sqlite3,threading
from pathlib import Path
import devices_tools
class Store:
    def __init__(self,directory):
        self.directory=Path(directory);self.path=self.directory/'settings.sqlite3';self.crypto=devices_tools.Store(directory);self.lock=threading.RLock()
    def connect(self):
        self.directory.mkdir(parents=True,exist_ok=True)
        if self.path.is_symlink():raise devices_tools.DeviceError('Invalid settings database path.',503)
        db=sqlite3.connect(self.path,timeout=5);self.path.chmod(0o600)
        db.execute('CREATE TABLE IF NOT EXISTS settings(name TEXT PRIMARY KEY,version INTEGER NOT NULL,payload BLOB NOT NULL)')
        return db
    def get(self,name,default=None):
        with self.lock:
            db=self.connect()
            try:
                row=db.execute('SELECT version,payload FROM settings WHERE name=?',(name,)).fetchone()
                if not row:return dict(version=0,value=default)
                try:value=json.loads(self.crypto.cipher().decrypt(row[1]))
                except Exception:raise devices_tools.DeviceError('Settings cannot be decrypted. Restore the matching device encryption key.',503) from None
                return dict(version=row[0],value=value)
            finally:db.close()
    def save(self,name,value,version):
        with self.lock:
            db=self.connect()
            try:
                db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT version FROM settings WHERE name=?',(name,)).fetchone();current=row[0] if row else 0
                if type(version) is not int or version!=current:raise devices_tools.DeviceError('Settings changed. Reload before saving.',409)
                payload=self.crypto.cipher().encrypt(json.dumps(value).encode())
                db.execute('INSERT OR REPLACE INTO settings VALUES(?,?,?)',(name,current+1,payload));db.commit()
            finally:db.close()
        return self.get(name)
