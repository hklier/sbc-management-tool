"""Encrypted managed-device records and request-local connection state."""
import base64, contextvars, datetime, hashlib, ipaddress, json, os, re, socket, sqlite3, struct, threading, uuid
from collections.abc import MutableMapping
from contextlib import contextmanager
from pathlib import Path
from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization

CONTEXT=contextvars.ContextVar('managed_device',default=None)
AUTH_PROTOCOLS=('MD5','SHA1','SHA224','SHA256','SHA384','SHA512')
LEVELS=('noAuthNoPriv','authNoPriv','authPriv')
class DeviceError(Exception):
    def __init__(self,message,code=400):super().__init__(message);self.code=code
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
def text(value,label,maximum=4096,required=True):
    if not isinstance(value,str) or len(value)>maximum or '\x00' in value or (required and not value.strip()):raise DeviceError('Enter a valid '+label+'.')
    return value
def host(value):
    try:address=ipaddress.IPv4Address(text(value,'management IPv4 address',64))
    except ipaddress.AddressValueError:raise DeviceError('Enter a numeric management IPv4 address.') from None
    if address.is_multicast or address.is_unspecified or address.is_link_local or address.is_loopback:raise DeviceError('Use the SBC management address, not a loopback, link-local, or multicast address.')
    return str(address)
def port(value,label):
    if type(value) is not int or not 1<=value<=65535:raise DeviceError('Enter a '+label+' between 1 and 65535.')
    return value
def ssh_key(value):
    value=text(value,'public SSH key',32768)
    if 'PRIVATE KEY' in value:raise DeviceError('Import the public host key only, never a private key.')
    try:
        if '---- BEGIN SSH2 PUBLIC KEY ----' in value:
            block=value.split('---- BEGIN SSH2 PUBLIC KEY ----',1)[1].split('---- END SSH2 PUBLIC KEY ----',1)[0]
            pieces=[];continuation=False
            for line in block.splitlines():
                line=line.strip()
                if not line:continue
                if continuation or ':' in line:continuation=line.endswith('\\');continue
                pieces.append(line)
            blob=base64.b64decode(''.join(pieces),validate=True);size=struct.unpack('!I',blob[:4])[0];kind=blob[4:4+size].decode('ascii')
            key=serialization.load_ssh_public_key(kind.encode()+b' '+base64.b64encode(blob))
        elif '-----BEGIN' in value:
            key=serialization.load_pem_public_key(value.encode())
        else:
            lines=value.splitlines();key=None
            for index,line in enumerate(lines):
                match=re.search(r'(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521))\s+([A-Za-z0-9+/=]+)',line)
                if not match:continue
                kind,encoded=match.groups()
                for extra in [None]+lines[index+1:]:
                    if extra is not None:
                        part=extra.strip().split()
                        if not part or not re.fullmatch('[A-Za-z0-9+/=]+',part[0]):break
                        encoded+=part[0]
                    try:key=serialization.load_ssh_public_key((kind+' '+encoded).encode());break
                    except (ValueError,TypeError):pass
                if key is not None:break
            if key is None:raise ValueError()
        canonical=key.public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()
        blob=base64.b64decode(canonical.split()[1])
        fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        return canonical,fingerprint
    except (ValueError,TypeError,IndexError,struct.error,UnicodeError):raise DeviceError('The public SSH key is invalid. Paste the ssh-rsa key or the complete SSH2/PEM public-key block.') from None

def ca_certificate(value):
    value=text(value,'CA certificate',131072).replace('\r\n','\n').strip()+'\n'
    if 'PRIVATE KEY' in value:raise DeviceError('Import a public CA certificate, not a private key.')
    try:
        certificates=x509.load_pem_x509_certificates(value.encode())
        if not certificates:raise ValueError()
        if not any(c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca for c in certificates):raise ValueError()
        return value,certificates[0].subject.rfc4514_string()
    except (ValueError,x509.ExtensionNotFound):raise DeviceError('Import a valid PEM CA certificate or CA certificate bundle.') from None

def normalize(data,previous=None,bootstrap=False):
    if not isinstance(data,dict):raise DeviceError('A device object is required.')
    previous=previous or {};allowed={'id','version','name','management_ip','rest_username','rest_password','ssh_port','ssh_public_key','ca_certificate','snmp'}
    if set(data)-allowed:raise DeviceError('The device contains unsupported fields.')
    result={}
    result['management_ip']=host(data.get('management_ip',previous.get('management_ip','')))
    result['name']=text(data.get('name',previous.get('name',result['management_ip'])),'device name',80).strip()
    result['rest_username']=text(data.get('rest_username',previous.get('rest_username','admin')) or 'admin','REST API username',128)
    result['rest_password']=text(data.get('rest_password') or previous.get('rest_password',''),'REST API password')
    result['ssh_port']=port(data.get('ssh_port',previous.get('ssh_port',22)),'SSH port')
    key=data.get('ssh_public_key','')
    if key:result['ssh_public_key'],result['ssh_fingerprint']=ssh_key(key)
    elif previous.get('ssh_fingerprint'):
        if result['management_ip']!=previous.get('management_ip') and not previous.get('ssh_public_key'):raise DeviceError('Import the SSH public key when changing a fingerprint-only device address.')
        result.update(ssh_public_key=previous.get('ssh_public_key',''),ssh_fingerprint=previous['ssh_fingerprint'])
    elif bootstrap:result.update(ssh_public_key='',ssh_fingerprint='')
    else:raise DeviceError('Import the SBC public SSH host key.')
    ca=data.get('ca_certificate',previous.get('ca_certificate',''))
    if ca:result['ca_certificate'],result['ca_subject']=ca_certificate(ca)
    elif bootstrap:
        result.update(ca_certificate='',ca_subject='',certificate_pin=previous.get('certificate_pin',''))
    else:raise DeviceError('Import the CA certificate used to verify the SBC server certificate.')
    old=previous.get('snmp',{});settings=data.get('snmp',old)
    if not isinstance(settings,dict) or set(settings)-{'version','port','community','username','security_level','auth_protocol','auth_password','priv_protocol','priv_password','trap_communities'}:raise DeviceError('Invalid SNMP settings.')
    version=str(settings.get('version',old.get('version','3')))
    if version not in ('disabled','1','2c','3'):raise DeviceError('Choose Disabled, SNMPv1, SNMPv2c, or SNMPv3.')
    snmp={'version':version,'port':port(settings.get('port',old.get('port',161)),'SNMP port')}
    if version in ('1','2c'):snmp['community']=text(settings.get('community') or old.get('community',''),'SNMP community')
    if version=='3':
        snmp['username']=text(settings.get('username',old.get('username','')),'SNMPv3 username',128)
        level=settings.get('security_level',old.get('security_level','authPriv'))
        if level not in LEVELS:raise DeviceError('Choose a valid SNMPv3 security level.')
        snmp['security_level']=level
        if level!='noAuthNoPriv':
            protocol=settings.get('auth_protocol',old.get('auth_protocol','SHA256'))
            if protocol not in AUTH_PROTOCOLS:raise DeviceError('Choose a supported SNMP authentication protocol.')
            snmp.update(auth_protocol=protocol,auth_password=text(settings.get('auth_password') or old.get('auth_password',''),'SNMP authentication password'))
        if level=='authPriv':
            privacy=settings.get('priv_protocol',old.get('priv_protocol','AES128'))
            if privacy!='AES128':raise DeviceError('The supported SNMP privacy protocol is AES128.')
            snmp.update(priv_protocol=privacy,priv_password=text(settings.get('priv_password') or old.get('priv_password',''),'SNMP privacy password'))
    traps=settings.get('trap_communities',old.get('trap_communities',[]))
    if not isinstance(traps,list) or len(traps)>16:raise DeviceError('Trap communities must be a list of up to 16 values.')
    snmp['trap_communities']=[text(v,'trap community') for v in traps]
    if not snmp['trap_communities'] and version in ('1','2c'):snmp['trap_communities']=[snmp['community']]
    result['snmp']=snmp
    return result

def public(record,detail=False):
    result={k:record[k] for k in ('id','version','name','management_ip','rest_username','ssh_port','ssh_fingerprint','created_at','updated_at')}
    settings=record['snmp']
    result['snmp']={k:v for k,v in settings.items() if k not in ('community','auth_password','priv_password','trap_communities')}
    result['snmp'].update(has_community=bool(settings.get('community')),has_auth_password=bool(settings.get('auth_password')),has_priv_password=bool(settings.get('priv_password')),has_trap_communities=bool(settings.get('trap_communities')))
    result.update(has_rest_password=bool(record['rest_password']),has_ssh_key=bool(record.get('ssh_public_key')),has_ca_certificate=bool(record.get('ca_certificate')),ca_subject=record.get('ca_subject',''))
    if detail:result.update(ssh_public_key=record.get('ssh_public_key',''),ca_certificate=record.get('ca_certificate',''))
    return result

class Store:
    def __init__(self,directory):
        self.directory=Path(directory);self.path=self.directory/'devices.sqlite3';self.key_path=self.directory/'device-encryption.key';self.lock=threading.RLock();self.initialized=False;self._cipher=None
    @contextmanager
    def connect(self):
        self.directory.mkdir(parents=True,exist_ok=True)
        if self.path.is_symlink():raise DeviceError('The device database must not be a symbolic link.',503)
        fd=os.open(self.path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600);os.close(fd);self.path.chmod(0o600)
        db=sqlite3.connect(self.path,timeout=5);db.row_factory=sqlite3.Row
        try:
            with db:yield db
        finally:db.close()
    def cipher(self):
        if self._cipher is None:
            if self.key_path.is_symlink():raise DeviceError('Invalid device encryption-key path.',503)
            try:self._cipher=Fernet(self.key_path.read_bytes())
            except (OSError,ValueError):raise DeviceError('The device encryption key is unavailable. Restore it with the device database.',503) from None
        return self._cipher
    def initialize(self,environment=None):
        env=os.environ if environment is None else environment
        with self.lock,self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,version INTEGER NOT NULL,payload BLOB NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS device_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
            if not self.key_path.exists():
                if (self.directory/'settings.sqlite3').exists():raise DeviceError('Restore the missing encryption key before opening saved application settings.',503)
                if db.execute('SELECT 1 FROM devices LIMIT 1').fetchone():raise DeviceError('Restore the missing device encryption key; existing credentials were not overwritten.',503)
                fd=os.open(self.key_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
                with os.fdopen(fd,'wb') as target:target.write(Fernet.generate_key())
            self.key_path.chmod(0o600);self.cipher()
            db.execute('BEGIN IMMEDIATE')
            if not db.execute("SELECT 1 FROM device_meta WHERE key='bootstrapped'").fetchone():
                if env.get('SBC_HOST') and env.get('SBC_PASSWORD'):
                    ca=''
                    if env.get('SBC_CA'):
                        try:ca=Path(env['SBC_CA']).read_text(encoding='utf-8-sig')
                        except OSError:pass
                    snmp={k:env.get(v,'') for k,v in [('username','SNMP_USER'),('auth_password','SNMP_AUTH_KEY'),('priv_password','SNMP_PRIV_KEY'),('community','SNMP_COMMUNITY')]}
                    snmp.update(version=env.get('SNMP_VERSION','2c'),port=int(env.get('SNMP_PORT','161')),security_level=env.get('SNMP_SECURITY_LEVEL','authPriv'),auth_protocol=env.get('SNMP_AUTH_PROTOCOL','SHA256'),priv_protocol='AES128',trap_communities=json.loads(env.get('SNMP_TRAP_COMMUNITIES') or '[]'))
                    if snmp['version']=='3' and not snmp['username']:snmp['version']='disabled'
                    if snmp['version'] in ('1','2c') and not snmp['community']:snmp['version']='disabled'
                    seed=dict(management_ip=env['SBC_HOST'],name=env['SBC_HOST'],rest_username=env.get('SBC_USER','admin'),rest_password=env['SBC_PASSWORD'],ssh_port=int(env.get('SBC_SSH_PORT','22')),ssh_public_key='',ssh_fingerprint=env.get('SBC_SSH_FINGERPRINT',''),ca_certificate=ca,certificate_pin=env.get('SBC_FINGERPRINT',''),snmp=snmp)
                    record=normalize({},seed,bootstrap=True);timestamp=now()
                    db.execute('INSERT INTO devices VALUES(?,?,?,?,?)',('bootstrap',1,self.cipher().encrypt(json.dumps(record).encode()),timestamp,timestamp))
                db.execute("INSERT INTO device_meta VALUES('bootstrapped','1')")
        self.initialized=True
    def ready(self):
        if not self.path.is_file():return False
        try:
            with self.connect() as db:return bool(db.execute("SELECT 1 FROM device_meta WHERE key='bootstrapped'").fetchone())
        except sqlite3.OperationalError:return False
    def decode(self,row):
        if row is None:raise DeviceError('Managed device not found.',404)
        try:result=json.loads(self.cipher().decrypt(row['payload']))
        except (InvalidToken,ValueError):raise DeviceError('Managed-device credentials could not be decrypted. Restore the matching encryption key.',503) from None
        result.update({k:row[k] for k in ('id','version','created_at','updated_at')});return result
    def get(self,identifier):
        with self.connect() as db:return self.decode(db.execute('SELECT * FROM devices WHERE id=?',(identifier,)).fetchone())
    def records(self):
        with self.connect() as db:return [self.decode(r) for r in db.execute('SELECT * FROM devices ORDER BY created_at,id')]
    def listing(self):return [public(r) for r in self.records()]
    def create(self,data):
        record=normalize(data);identifier=uuid.uuid4().hex;timestamp=now()
        with self.lock,self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if any(self.decode(r)['management_ip']==record['management_ip'] for r in db.execute('SELECT * FROM devices')):raise DeviceError('A device with that management IP already exists.',409)
            db.execute('INSERT INTO devices VALUES(?,?,?,?,?)',(identifier,1,self.cipher().encrypt(json.dumps(record).encode()),timestamp,timestamp))
        return self.get(identifier)
    def update(self,identifier,data,version):
        with self.lock,self.connect() as db:
            db.execute('BEGIN IMMEDIATE');previous=self.decode(db.execute('SELECT * FROM devices WHERE id=?',(identifier,)).fetchone())
            if type(version) is not int or previous['version']!=version:raise DeviceError('This device changed. Reload it before saving.',409)
            record=normalize(data,previous)
            if any(self.decode(r)['management_ip']==record['management_ip'] for r in db.execute('SELECT * FROM devices WHERE id<>?',(identifier,))):raise DeviceError('A device with that management IP already exists.',409)
            db.execute('UPDATE devices SET payload=?,version=version+1,updated_at=? WHERE id=?',(self.cipher().encrypt(json.dumps(record).encode()),now(),identifier))
        return self.get(identifier)
    def delete(self,identifier,version):
        with self.lock,self.connect() as db:
            removed=db.execute('DELETE FROM devices WHERE id=? AND version=?',(identifier,version)).rowcount
            if removed!=1:raise DeviceError('This device changed or was removed. Reload the device list.',409)

def environment(record):
    result={'SBC_HOST':record['management_ip'],'SBC_USER':record['rest_username'],'SBC_PASSWORD':record['rest_password'],'SBC_CA_PEM':record.get('ca_certificate',''),'SBC_FINGERPRINT':record.get('certificate_pin',''),'SBC_SSH_PORT':str(record['ssh_port']),'SBC_SSH_FINGERPRINT':record['ssh_fingerprint']}
    settings=record['snmp']
    for field,key in [('version','SNMP_VERSION'),('port','SNMP_PORT'),('community','SNMP_COMMUNITY'),('username','SNMP_USER'),('security_level','SNMP_SECURITY_LEVEL'),('auth_protocol','SNMP_AUTH_PROTOCOL'),('auth_password','SNMP_AUTH_KEY'),('priv_protocol','SNMP_PRIV_PROTOCOL'),('priv_password','SNMP_PRIV_KEY')]:result[key]=str(settings.get(field,''))
    return result

def read_ssh_key(address,ssh_port=22):
    address=host(address);ssh_port=port(ssh_port,'SSH port')
    import paramiko
    connection=None;sock=None
    try:
        sock=socket.create_connection((address,ssh_port),timeout=5);connection=paramiko.Transport(sock)
        options=connection.get_security_options();options.key_types=tuple(k for k in options.key_types if k in ('rsa-sha2-512','rsa-sha2-256','ssh-rsa'))
        connection.start_client(timeout=5);key=connection.get_remote_server_key()
        return ssh_key(key.get_name()+' '+key.get_base64())
    except Exception:raise DeviceError('Could not read the RSA host key. Check the IP and SSH port, or paste the SBC command output.',502) from None
    finally:
        if connection is not None:connection.close()
        elif sock is not None:sock.close()

class ScopedObject:
    def __init__(self,name,fallback):object.__setattr__(self,'name',name);object.__setattr__(self,'fallback',fallback)
    def target(self):return getattr(CONTEXT.get(),self.name) if CONTEXT.get() is not None else self.fallback
    def __getattr__(self,key):return getattr(self.target(),key)
    def __setattr__(self,key,value):setattr(self.target(),key,value)
    def __delattr__(self,key):delattr(self.target(),key)
    def __enter__(self):return self.target().__enter__()
    def __exit__(self,*args):return self.target().__exit__(*args)
class ScopedMap(MutableMapping,ScopedObject):
    def __getitem__(self,key):return self.target()[key]
    def __setitem__(self,key,value):self.target()[key]=value
    def __delitem__(self,key):del self.target()[key]
    def __iter__(self):return iter(self.target())
    def __len__(self):return len(self.target())
