"""Persistent console accounts, separate from the SBC account."""
from contextlib import contextmanager
import datetime, hashlib, hmac, os, re, secrets, sqlite3, threading
import database_tools
from pathlib import Path

class UserError(Exception):
    def __init__(self,message,code=400):super().__init__(message);self.code=code

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')

def username(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}',value):
        raise UserError('Use 1–64 letters, numbers, periods, underscores, @ signs, or hyphens for the username.')
    return value.lower()

def password_hash(value,_bootstrap=False):
    if not isinstance(value,str) or not ((_bootstrap and value=='oracle') or 12<=len(value)<=1024):raise UserError('Choose a password between 12 and 1024 characters.')
    salt=secrets.token_bytes(24)
    return salt.hex()+':'+hashlib.pbkdf2_hmac('sha256',value.encode(),salt,600000).hex()

def verify(value,encoded):
    try:
        salt,expected=encoded.split(':');valid=isinstance(value,str) and len(value)<=1024
        candidate=hashlib.pbkdf2_hmac('sha256',(value if valid else '').encode(),bytes.fromhex(salt),600000).hex()
        return valid and hmac.compare_digest(candidate,expected)
    except (ValueError,AttributeError):return False

def valid_hash(value):return isinstance(value,str) and bool(re.fullmatch(r'(?:[0-9a-fA-F]{2}){16,64}:[0-9a-fA-F]{64}',value))
def public(row):return {key:row[key] for key in ('username','role','version','created_at','updated_at')}

def account(row):return dict(public(row),must_change_password=bool(row['must_change_password']))

class Store:
    def __init__(self,path):self.path=Path(path);self.lock=threading.RLock()

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        if self.path.is_symlink():raise UserError('The user database must not be a symbolic link.',503)
        fd=os.open(self.path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600);os.close(fd);self.path.chmod(0o600)
        db=sqlite3.connect(self.path,timeout=5);db.row_factory=sqlite3.Row
        db.execute('PRAGMA busy_timeout=5000')
        try:
            with db:yield db
        finally:db.close()

    def initialize(self,initial_username='admin',initial_hash=None):
        with self.lock,self.connect() as db:
            database_tools.configure(db)
            db.execute("CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','user')),version INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)")
            if 'must_change_password' not in {r['name'] for r in db.execute('PRAGMA table_info(users)')}:
                db.execute('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0')
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                name=username(initial_username)
                if not initial_hash:initial_hash=password_hash('oracle',_bootstrap=True)
                if not valid_hash(initial_hash):raise UserError('A valid APP_PASSWORD_HASH is required to create the first administrator.',503)
                timestamp=now();db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',(name,initial_hash,'admin',1,timestamp,timestamp,int(verify('oracle',initial_hash))))

    def authenticate(self,name,password):
        try:name=username(name)
        except UserError:name=''
        with self.connect() as db:row=db.execute('SELECT * FROM users WHERE username=?',(name,)).fetchone()
        encoded=row['password_hash'] if row else '11'*24+':'+'00'*32
        matches=verify(password,encoded)
        return account(row) if row and matches else None

    def current(self,name,version):
        with self.connect() as db:row=db.execute('SELECT * FROM users WHERE username=? AND version=?',(name,version)).fetchone()
        return account(row) if row else None

    def listing(self):
        with self.connect() as db:return [public(row) for row in db.execute('SELECT * FROM users ORDER BY role,username')]

    def create(self,name,password,role='user'):
        name=username(name)
        if role not in ('admin','user'):raise UserError('Choose Administrator or Console user.')
        encoded=password_hash(password);timestamp=now()
        try:
            with self.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',(name,encoded,role,1,timestamp,timestamp,0))
        except sqlite3.IntegrityError:raise UserError('That username already exists.',409) from None
        return self.current(name,1)

    def change_password(self,name,current_password,new_password):
        account=self.authenticate(name,current_password)
        if not account:raise UserError('Current password is incorrect.')
        return self.set_password(account['username'],new_password,account['version'])

    def set_password(self,name,new_password,expected_version=None):
        name=username(name);encoded=password_hash(new_password)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT * FROM users WHERE username=?',(name,)).fetchone()
            if not row:raise UserError('User not found.',404)
            if expected_version is not None and row['version']!=expected_version:raise UserError('This password changed in another request. Sign in again and retry.',409)
            db.execute('UPDATE users SET password_hash=?,must_change_password=0,version=version+1,updated_at=? WHERE username=?',(encoded,now(),name))
            return account(db.execute('SELECT * FROM users WHERE username=?',(name,)).fetchone())

    def recover_bootstrap(self,name,encoded):
        name=username(name)
        if not valid_hash(encoded):raise UserError('APP_PASSWORD_HASH is invalid.',503)
        self.initialize(name,encoded)
        with self.connect() as db:
            timestamp=now()
            db.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,role='admin',version=users.version+1,updated_at=excluded.updated_at,must_change_password=excluded.must_change_password",(name,encoded,'admin',1,timestamp,timestamp,int(verify('oracle',encoded))))

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description='Restore the administrator from the private YAML/bootstrap Secret. Other accounts are preserved.')
    parser.add_argument('--reset-bootstrap',action='store_true',required=True);parser.parse_args()
    Store(Path(os.environ.get('STATE_DIR','/var/lib/sbc-console'))/'users.sqlite3').recover_bootstrap(os.environ.get('APP_USER','admin'),os.environ.get('APP_PASSWORD_HASH') or password_hash('oracle',_bootstrap=True))
    print('Bootstrap administrator restored. Previous sessions for this account are invalid.')
