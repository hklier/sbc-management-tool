"""Persistent WebGUI certificates, private CSR keys, and atomic TLS activation."""
import datetime as dt,hashlib,ipaddress,json,os,re,ssl,threading,uuid
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID

class CertificateError(Exception):
    def __init__(self,message,code=400):super().__init__(message);self.code=code
def now():return dt.datetime.now(dt.timezone.utc)
def private_write(path,value):
    if path.is_symlink():raise CertificateError('Invalid certificate storage path.',503)
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as target:target.write(value.encode() if isinstance(value,str) else value)
def context(cert,key):
    value=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);value.minimum_version=ssl.TLSVersion.TLSv1_2;value.load_cert_chain(str(cert),str(key));return value
def names(dns,ips):
    if not isinstance(dns,list) or not isinstance(ips,list) or len(dns)+len(ips)>50:raise CertificateError('Provide up to 50 DNS names and IP addresses.')
    result=[]
    for name in dns:
        if not isinstance(name,str) or len(name)>253 or not re.fullmatch(r'(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',name) or any(not label or len(label)>63 for label in name.split('.')):raise CertificateError('Enter valid DNS names without a URL or port.')
        result.append(x509.DNSName(name.lower()))
    for value in ips:
        try:result.append(x509.IPAddress(ipaddress.ip_address(value)))
        except (ValueError,TypeError):raise CertificateError('Enter valid certificate IP addresses.') from None
    if not result:raise CertificateError('Include at least one DNS name or IP address in the certificate.')
    return result
def details(pem):
    cert=x509.load_pem_x509_certificate(pem)
    try:san=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:san=[]
    return dict(subject=cert.subject.rfc4514_string(),issuer=cert.issuer.rfc4514_string(),not_before=cert.not_valid_before_utc.isoformat(),not_after=cert.not_valid_after_utc.isoformat(),sha256=cert.fingerprint(hashes.SHA256()).hex(),dns_names=[n.value for n in san if isinstance(n,x509.DNSName)],ip_addresses=[str(n.value) for n in san if isinstance(n,x509.IPAddress)],self_signed=cert.subject==cert.issuer)

class Manager:
    def __init__(self,directory):
        self.directory=Path(directory)/'web-tls';self.lock=threading.RLock();self.active=None;self.server=None
    def setup(self,env):
        with self.lock:
            self.directory.mkdir(mode=0o700,parents=True,exist_ok=True)
            pointer=self.directory/'active.json'
            if pointer.exists():
                record=json.loads(pointer.read_text());cert,key=self.paths(record['id']);source=record['source']
            elif env.get('TLS_CERT') or env.get('TLS_KEY'):
                if not env.get('TLS_CERT') or not env.get('TLS_KEY'):raise CertificateError('Provide both TLS_CERT and TLS_KEY, or neither for automatic HTTPS.',503)
                cert,key=Path(env['TLS_CERT']),Path(env['TLS_KEY']);source='deployment'
            else:
                key_object=rsa.generate_private_key(public_exponent=65537,key_size=3072)
                subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SBC Console')]);dns=['localhost','sbc-console'];namespace=env.get('POD_NAMESPACE')
                if namespace:dns.extend(['sbc-console.'+namespace+'.svc','sbc-console.'+namespace+'.svc.cluster.local'])
                cert_object=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key_object.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now()-dt.timedelta(minutes=5)).not_valid_after(now()+dt.timedelta(days=365)).add_extension(x509.SubjectAlternativeName(names(dns,['127.0.0.1','::1'])),False).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).sign(key_object,hashes.SHA256())
                identifier=uuid.uuid4().hex;cert,key=self.paths(identifier)
                private_write(cert,cert_object.public_bytes(serialization.Encoding.PEM));private_write(key,self.encode_key(key_object));source='generated-self-signed'
                self.pointer(identifier,source)
            self.active=dict(cert=cert,key=key,source=source)
            return context(cert,key)
    def paths(self,identifier):
        if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9]{32}',identifier):raise CertificateError('Invalid certificate request identifier.')
        return self.directory/(identifier+'.crt'),self.directory/(identifier+'.key')
    def encode_key(self,key):return key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    def pointer(self,identifier,source):
        temporary=self.directory/(uuid.uuid4().hex+'.json.tmp');private_write(temporary,json.dumps(dict(id=identifier,source=source)));os.replace(temporary,self.directory/'active.json')
    def status(self):
        with self.lock:
            if not self.active:raise CertificateError('TLS certificate management is not initialized.',503)
            result=dict(active=details(self.active['cert'].read_bytes()),source=self.active['source'],requests=[])
            for path in sorted(self.directory.glob('*.csr.json')):
                record=json.loads(path.read_text());result['requests'].append(record)
            return result
    def generate(self,body):
        common=body.get('common_name','')
        if not isinstance(common,str) or not 1<=len(common.strip())<=64:raise CertificateError('Enter a common name of up to 64 characters.')
        subject=[x509.NameAttribute(NameOID.COMMON_NAME,common.strip())]
        for field,oid in [('organization',NameOID.ORGANIZATION_NAME),('organizational_unit',NameOID.ORGANIZATIONAL_UNIT_NAME),('country',NameOID.COUNTRY_NAME),('state',NameOID.STATE_OR_PROVINCE_NAME),('locality',NameOID.LOCALITY_NAME)]:
            value=body.get(field,'')
            if not isinstance(value,str) or len(value)>128 or '\x00' in value:raise CertificateError('Invalid CSR subject field.')
            if value:
                if field=='country' and not re.fullmatch('[A-Za-z]{2}',value):raise CertificateError('Country must be a two-letter code.')
                subject.append(x509.NameAttribute(oid,value.upper() if field=='country' else value))
        sans=names(body.get('dns_names',[]),body.get('ip_addresses',[]));bits=body.get('key_size',3072)
        if type(bits) is not int or bits not in (2048,3072,4096):raise CertificateError('Choose RSA 2048, 3072 or 4096.')
        with self.lock:
            if len(list(self.directory.glob('*.csr.json')))>=10:raise CertificateError('Remove an unused request before creating another.',409)
            key=rsa.generate_private_key(public_exponent=65537,key_size=bits)
            csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject)).add_extension(x509.SubjectAlternativeName(sans),False).sign(key,hashes.SHA256());identifier=uuid.uuid4().hex;_,key_path=self.paths(identifier)
            pem=csr.public_bytes(serialization.Encoding.PEM).decode();record=dict(id=identifier,subject=csr.subject.rfc4514_string(),created_at=now().isoformat(),csr_pem=pem,key_size=bits)
            private_write(key_path,self.encode_key(key));private_write(self.directory/(identifier+'.csr.json'),json.dumps(record))
            return record
    def remove(self,identifier):
        with self.lock:
            _,key=self.paths(identifier);record=self.directory/(identifier+'.csr.json')
            if not record.is_file():raise CertificateError('Certificate request not found.',404)
            record.unlink();key.unlink(missing_ok=True)
    def install(self,identifier,pem):
        if not isinstance(pem,str) or len(pem)>262144 or 'PRIVATE KEY' in pem:raise CertificateError('Import a PEM server certificate followed by its intermediate certificates, without private keys.')
        with self.lock:
            cert_path,key_path=self.paths(identifier);request_path=self.directory/(identifier+'.csr.json')
            if not request_path.is_file():raise CertificateError('Select the pending CSR matching this certificate.',404)
            try:
                certs=x509.load_pem_x509_certificates(pem.encode());leaf=certs[0];key=serialization.load_pem_private_key(key_path.read_bytes(),None)
                public=lambda value:value.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
                if public(leaf.public_key())!=public(key.public_key()):raise ValueError('key')
                if any(c.not_valid_before_utc>now() or c.not_valid_after_utc<=now() for c in certs):raise ValueError('dates')
                csr=x509.load_pem_x509_csr(json.loads(request_path.read_text())['csr_pem'].encode())
                requested=csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                supplied=leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                if not set(requested).issubset(set(supplied)):raise ValueError('names')
                try:
                    if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:raise ValueError('CA')
                except x509.ExtensionNotFound:pass
                try:
                    if ExtendedKeyUsageOID.SERVER_AUTH not in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:raise ValueError('usage')
                except x509.ExtensionNotFound:pass
                for child,issuer in zip(certs,certs[1:]):
                    child.verify_directly_issued_by(issuer)
                    if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:raise ValueError('issuer')
            except Exception:raise CertificateError('Certificate validation failed. Check its matching CSR/key, validity dates, SAN names, server-auth usage and chain order.') from None
            canonical=b''.join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
            private_write(cert_path,canonical)
            try:new_context=context(cert_path,key_path)
            except Exception:
                cert_path.unlink(missing_ok=True);raise CertificateError('The TLS certificate could not be loaded. The current certificate remains active.') from None
            self.pointer(identifier,'imported');self.active=dict(cert=cert_path,key=key_path,source='imported')
            if self.server:self.server.tls_context=new_context
            request_path.unlink();return self.status()
