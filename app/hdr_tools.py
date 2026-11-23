"""HDR CSV source configuration and bounded, read-only file discovery."""
import base64,io,os,re,stat,time
from pathlib import Path,PurePosixPath
from collections import deque
import devices_tools,settings_tools
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa,ec,ed25519

class HdrError(Exception):
    def __init__(self,message,code=400):super().__init__(message);self.code=code

MAX_FILES=10000
MAX_ENTRIES=100000
MAX_DIRECTORIES=5000
MAX_SEARCH_SECONDS=30

def discover(entries):
    """Breadth-first inventory; never follow links or accept path components from entries."""
    pending=deque([()]);rows=[];scanned=0;directories=0;subdirectories=0;reason=''
    deadline=time.monotonic()+MAX_SEARCH_SECONDS
    while pending and not reason:
        if time.monotonic()>=deadline:reason='Search time limit reached';break
        parts=pending.popleft();directories+=1
        iterator=entries(parts)
        try:
            for name,mode,size,modified in iterator:
                scanned+=1
                if name and name not in ('.','..') and '/' not in name and '\x00' not in name:
                    relative=parts+(name,)
                    if stat.S_ISDIR(mode):
                        subdirectories+=1
                        if subdirectories>=MAX_DIRECTORIES:reason='Directory limit reached'
                        else:pending.append(relative)
                    elif name.lower().endswith('.csv') and stat.S_ISREG(mode):
                        rows.append(dict(name='/'.join(relative),size=size,modified_at=modified))
                if len(rows)>=MAX_FILES:reason='CSV file limit reached'
                elif scanned>=MAX_ENTRIES:reason='Directory entry limit reached'
                elif time.monotonic()>=deadline:reason='Search time limit reached'
                if reason:break
        finally:
            if hasattr(iterator,'close'):iterator.close()
    return dict(files=sorted(rows,key=lambda r:r['name']),subdirectories=subdirectories,directories_searched=directories,scanned_entries=scanned,truncated=bool(reason),limit_reason=reason)
def text(value,label,limit=4096):
    if not isinstance(value,str) or not value.strip() or len(value)>limit or '\x00' in value:raise HdrError('Enter a valid '+label+'.')
    return value.strip()
class Manager:
    def __init__(self,directory,local_root=None):
        self.store=settings_tools.Store(directory);self.local_root=Path(local_root or Path(directory)/'hdr-inbox');self.local_root.mkdir(mode=0o700,parents=True,exist_ok=True)
    def raw(self):return self.store.get('hdr',dict(mode='local',path=str(self.local_root)))
    def public(self):
        record=self.raw();value=record['value'];result={k:v for k,v in value.items() if k not in ('password','private_key','key_passphrase')}
        result.update(has_password=bool(value.get('password')),has_private_key=bool(value.get('private_key')),has_key_passphrase=bool(value.get('key_passphrase')),local_root=str(self.local_root),version=record['version'])
        return result
    def local_path(self,value):
        candidate=Path(text(value,'CSV directory path')).resolve();root=self.local_root.resolve()
        if candidate!=root and root not in candidate.parents:raise HdrError('The local directory must be inside the mounted HDR root: '+str(root))
        return candidate
    def save(self,body):
        previous=self.raw()['value'];mode=body.get('mode','local')
        if mode=='local':value=dict(mode=mode,path=str(self.local_path(body.get('path',str(self.local_root)))))
        elif mode=='sftp':
            host=text(body.get('host',''),'SFTP host',253)
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*',host):raise HdrError('Enter an SFTP hostname or IPv4 address without a URL or port.')
            port=body.get('port',22)
            if type(port) is not int or not 1<=port<=65535:raise HdrError('Enter an SFTP port between 1 and 65535.')
            path=text(body.get('path',''),'remote CSV directory')
            if not PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts:raise HdrError('Enter an absolute SFTP directory without .. segments.')
            username=text(body.get('username',''),'SFTP username',128)
            same=previous.get('mode')=='sftp' and (host,port,username)==(previous.get('host'),previous.get('port'),previous.get('username'))
            value=dict(mode=mode,host=host,port=port,username=username,path=path)
            for field in ('password','private_key','key_passphrase'):
                supplied=body.get(field,'')
                if not isinstance(supplied,str) or len(supplied)>131072:raise HdrError('Invalid SFTP credential field.')
                value[field]='' if body.get('clear_'+field) else (supplied or (previous.get(field,'') if same else ''))
            if not value['password'] and not value['private_key']:raise HdrError('Provide an SFTP password, private key, or both. Re-enter credentials when changing the server or account.')
            if body.get('private_key') and not body.get('key_passphrase'):value['key_passphrase']=''
            try:
                value['host_key'],value['host_fingerprint']=devices_tools.ssh_key(body.get('host_key') or (previous.get('host_key','') if same else ''))
            except devices_tools.DeviceError as exc:raise HdrError(str(exc)) from None
            if value['private_key']:
                try:
                    payload=value['private_key'].encode();password=value['key_passphrase'].encode() or None
                    loader=serialization.load_ssh_private_key if b'BEGIN OPENSSH PRIVATE KEY' in payload else serialization.load_pem_private_key
                    key=loader(payload,password)
                    if not isinstance(key,(rsa.RSAPrivateKey,ec.EllipticCurvePrivateKey,ed25519.Ed25519PrivateKey)):raise ValueError('Unsupported key type')
                except Exception:raise HdrError('The SFTP private key or its passphrase is invalid. Use OpenSSH or PEM format; convert PuTTY .ppk keys first.') from None
        else:raise HdrError('Choose a mounted directory or SFTP source.')
        self.store.save('hdr',value,body.get('version'));return self.public()
    def listing(self):
        value=self.raw()['value']
        try:
            if value['mode']=='local':
                path=self.local_path(value['path'])
                def local_entries(parts):
                    directory=path.joinpath(*parts)
                    resolved=directory.resolve()
                    if directory.is_symlink() or (resolved!=path and path not in resolved.parents):return
                    with os.scandir(directory) as children:
                        for entry in children:
                            info=entry.stat(follow_symlinks=False)
                            yield entry.name,info.st_mode,info.st_size,info.st_mtime
                result=discover(local_entries)
            else:
                import paramiko
                host_kind,encoded=value['host_key'].split()[:2]
                trusted_key=paramiko.PKey.from_type_string(host_kind,base64.b64decode(encoded,validate=True))
                def pinned_transport(sock,**kwargs):
                    transport=paramiko.Transport(sock,**kwargs)
                    options=transport.get_security_options()
                    # Negotiate the saved key family, retaining supported RSA SHA-2 signatures.
                    options.key_types=tuple(name for name in options.key_types if name==host_kind or (host_kind=='ssh-rsa' and name in ('rsa-sha2-512','rsa-sha2-256')))
                    return transport
                key=None
                if value.get('private_key'):
                    for kind in ('Ed25519Key','RSAKey','ECDSAKey'):
                        klass=getattr(paramiko,kind,None)
                        if klass:
                            try:key=klass.from_private_key(io.StringIO(value['private_key']),password=value.get('key_passphrase') or None);break
                            except Exception:pass
                    if key is None:raise HdrError('The stored SFTP key could not be loaded.',502)
                client=paramiko.SSHClient()
                server_name=value['host'] if value['port']==22 else '[{}]:{}'.format(value['host'],value['port'])
                client.get_host_keys().add(server_name,host_kind,trusted_key)
                try:
                    client.connect(value['host'],port=value['port'],username=value['username'],password=value.get('password') or None,pkey=key,allow_agent=False,look_for_keys=False,timeout=7,banner_timeout=7,auth_timeout=7,transport_factory=pinned_transport)
                    with client.open_sftp() as sftp:
                        sftp.get_channel().settimeout(10)
                        def remote_entries(parts):
                            directory=str(PurePosixPath(value['path']).joinpath(*parts))
                            for entry in sftp.listdir_iter(directory,read_aheads=1):
                                yield entry.filename,entry.st_mode or 0,entry.st_size,entry.st_mtime
                        result=discover(remote_entries)
                except paramiko.BadHostKeyException:raise HdrError('The SFTP server host key does not match the saved public key. Verify its public key before reconnecting.',502) from None
                except paramiko.AuthenticationException:raise HdrError('SFTP authentication failed. Check the username, password or client private key.',502) from None
                except FileNotFoundError:raise HdrError('The remote CSV directory does not exist. Use the absolute path visible to this SFTP account.',502) from None
                except PermissionError:raise HdrError('The SFTP account does not have permission to list the CSV directory.',502) from None
                except TimeoutError:raise HdrError('The SFTP connection timed out. Check network access and the server response.',502) from None
                except paramiko.ssh_exception.NoValidConnectionsError:raise HdrError('Could not reach the SFTP server. Check its address, SSH port and firewall.',502) from None
                except paramiko.SSHException:raise HdrError('SSH negotiation failed. Check the saved server public key and the server SSH configuration.',502) from None
                finally:client.close()
        except HdrError:raise
        except Exception:raise HdrError('Could not list HDR files. Check the saved path, server identity, credentials, network access and directory permissions.',502) from None
        message='Connection verified. Searched {} directories, including subdirectories. CSV contents are not imported or analysed yet.'.format(result['directories_searched'])
        if not result['files']:message+=' No CSV files found.'
        result.update(checked_at=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),message=message)
        return result
