"""HDR CSV source configuration and bounded, read-only file discovery."""
import base64,io,os,re,stat,time
from pathlib import Path,PurePosixPath
import devices_tools,settings_tools
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa,ec,ed25519

class HdrError(Exception):
    def __init__(self,message,code=400):super().__init__(message);self.code=code
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
        value=self.raw()['value'];rows=[];scanned=0;subdirectories=0;limit=200;maximum=2000
        try:
            if value['mode']=='local':
                path=self.local_path(value['path'])
                with os.scandir(path) as entries:
                    for entry in entries:
                        scanned+=1
                        subdirectories+=entry.is_dir(follow_symlinks=False)
                        if entry.name.lower().endswith('.csv') and entry.is_file(follow_symlinks=False):
                            info=entry.stat(follow_symlinks=False);rows.append(dict(name=entry.name,size=info.st_size,modified_at=info.st_mtime))
                        if scanned>=maximum or len(rows)>=limit:break
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
                        for entry in sftp.listdir_iter(value['path'],read_aheads=1):
                            scanned+=1
                            subdirectories+=stat.S_ISDIR(entry.st_mode or 0)
                            if entry.filename.lower().endswith('.csv') and stat.S_ISREG(entry.st_mode or 0):rows.append(dict(name=entry.filename,size=entry.st_size,modified_at=entry.st_mtime))
                            if scanned>=maximum or len(rows)>=limit:break
                except paramiko.BadHostKeyException:raise HdrError('The SFTP server host key does not match the saved public key. Verify its public key before reconnecting.',502) from None
                except paramiko.AuthenticationException:raise HdrError('SFTP authentication failed. Check the username, password or client private key.',502) from None
                except FileNotFoundError:raise HdrError('The remote CSV directory does not exist. Use the absolute path visible to this SFTP account.',502) from None
                except PermissionError:raise HdrError('The SFTP account does not have permission to list the CSV directory.',502) from None
                except TimeoutError:raise HdrError('The SFTP connection timed out. Check network access and the server response.',502) from None
                finally:client.close()
        except HdrError:raise
        except Exception:raise HdrError('Could not list HDR files. Check the saved path, server identity, credentials, network access and directory permissions.',502) from None
        message='Connection verified. CSV contents are not imported or analysed yet.'
        if not rows and subdirectories:message='Connection verified. No CSV files in this directory; {} subdirectories found. Enter the path to the directory containing CSV files. Subdirectories are not searched.'.format(subdirectories)
        return dict(files=sorted(rows,key=lambda r:r['name']),subdirectories=subdirectories,truncated=scanned>=maximum or len(rows)>=limit,checked_at=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),message=message)
