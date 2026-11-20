#!/usr/bin/env python3
"""Render one private YAML into Git-managed settings and private Kubernetes Secrets.

No passwords, certificate keys, or private input files are written into the checkout.
Argo CD performs the workload rollout after the public render is committed and pushed.
"""
import argparse
import base64
import copy
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import uuid

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = 'sbc-management-tool'


class ConfigError(ValueError):
    pass


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise ConfigError('YAML keys must be unique text names.')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def mapping(value, allowed, label):
    if not isinstance(value, dict):
        raise ConfigError(f'{label} must be a mapping.')
    unknown = set(value) - set(allowed)
    if unknown:
        raise ConfigError(f'{label} contains an unsupported field; check the example YAML.')
    return value


def text(value, label, required=True):
    if not isinstance(value, str) or (required and not value.strip()):
        raise ConfigError(f'{label} must be non-empty quoted text.')
    if 'REPLACE_' in value or 'CHANGE_ME' in value or '\x00' in value:
        raise ConfigError(f'{label} still contains a placeholder or invalid text.')
    return value


def integer(value, label, minimum=1, maximum=65535):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigError(f'{label} must be an integer between {minimum} and {maximum}.')
    return value


def ipv4(value, label):
    try:
        return str(ipaddress.IPv4Address(text(value, label)))
    except ipaddress.AddressValueError:
        raise ConfigError(f'{label} must be a numeric IPv4 address.') from None


def private_location(path, root=ROOT):
    path = Path(path).resolve()
    if path == root.resolve() or root.resolve() in path.parents:
        raise ConfigError('Keep the completed YAML and generated private files outside the repository.')
    return path


def pem_value(section, key, directory, required=False):
    inline = section.get(key + '_pem')
    filename = section.get(key + '_file')
    if inline and filename:
        raise ConfigError(f'Use either {key}_pem or {key}_file, not both.')
    if filename:
        path = (directory / text(filename, key + '_file')).resolve()
        inline = path.read_text(encoding='utf-8-sig')
    if inline:
        return text(inline, key + '_pem').replace('\r\n','\n').strip() + '\n'
    if required:
        raise ConfigError(f'Provide {key}_pem or {key}_file.')
    return ''


def password_matches(password, encoded):
    try:
        salt, expected = encoded.split(':')
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600000).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, AttributeError):
        return False


def secret_object(name, data):
    return {'apiVersion':'v1', 'kind':'Secret', 'metadata':{'name':name, 'namespace':NAMESPACE},
            'type':'kubernetes.io/tls' if name.endswith('-tls') else 'Opaque',
            'data':{key:base64.b64encode(value.encode()).decode() for key, value in data.items()}}


def previous_secret(state, name):
    for resource in state.get('secrets', {}).get('items', []):
        if resource['metadata']['name'] == name:
            return {k:base64.b64decode(v).decode() for k, v in resource['data'].items()}
    return {}


def validate_management(management, directory):
    transport=management.get('transport','local')
    if transport not in ('local','ssh'):raise ConfigError('management.transport must be local or ssh.')
    if management.get('kubectl_context'):text(management['kubectl_context'],'management.kubectl_context')
    if 'ssh' in management:
        settings=mapping(management['ssh'],['host','username','private_key_file','host_key'],'management.ssh')
        host=text(settings.get('host'),'management.ssh.host');user=text(settings.get('username'),'management.ssh.username')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*',host) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',user):raise ConfigError('Invalid SSH host or username.')
        key=(directory/text(settings.get('private_key_file'),'management.ssh.private_key_file')).resolve()
        if not key.is_file():raise ConfigError('The configured SSH key file does not exist.')
    elif transport=='ssh':raise ConfigError('management.ssh is required for SSH transport.')


def tls_material(settings, address, directory, state):
    mapping(settings, ['mode','days','dns_names','certificate_file','certificate_pem','private_key_file','private_key_pem'], 'console.tls')
    mode = settings.get('mode', 'supplied')
    if mode == 'supplied':
        state.pop('tls_request',None)
        cert = pem_value(settings, 'certificate', directory, True)
        key = pem_value(settings, 'private_key', directory, True)
    elif mode == 'self-signed':
        if any(k in settings for k in ['certificate_file','certificate_pem','private_key_file','private_key_pem']):
            raise ConfigError('Self-signed mode generates its own certificate and key.')
        days = integer(settings.get('days',365), 'console.tls.days', 1, 3650)
        names = settings.get('dns_names', ['sbc-management-tool'])
        if not isinstance(names,list) or any(not isinstance(n,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*',n) for n in names):
            raise ConfigError('console.tls.dns_names must be a list of DNS names.')
        request = {'address':address,'days':days,'names':names}
        previous = previous_secret(state, 'sbc-console-tls')
        cert, key = previous.get('tls.crt',''), previous.get('tls.key','')
        reusable = state.get('tls_request') == request and cert and key
        if reusable:
            reusable = x509.load_pem_x509_certificate(cert.encode()).not_valid_after_utc > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
        if not reusable:
            private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'sbc-management-tool')])
            now = dt.datetime.now(dt.timezone.utc)
            certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(private.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=days))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address))]+[x509.DNSName(n) for n in names]),critical=False)
                .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(private, hashes.SHA256()))
            cert = certificate.public_bytes(serialization.Encoding.PEM).decode()
            key = private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
        state['tls_request'] = request
    else:
        raise ConfigError('console.tls.mode must be supplied or self-signed.')
    try:
        certificate = x509.load_pem_x509_certificate(cert.encode())
        private = serialization.load_pem_private_key(key.encode(), password=None)
        encode = lambda k:k.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        if encode(certificate.public_key()) != encode(private.public_key()):
            raise ConfigError('Console certificate and private key do not match.')
        now = dt.datetime.now(dt.timezone.utc)
        if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
            raise ConfigError('Console certificate is not currently valid.')
        if ipaddress.ip_address(address) not in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress):
            raise ConfigError('Console certificate must include endpoint.address as an IP subject alternative name.')
    except ConfigError:
        raise
    except (ValueError, TypeError, x509.ExtensionNotFound):
        raise ConfigError('Console TLS material is invalid; use matching unencrypted PEM files with an IP SAN.') from None
    return cert, key


def build(config, directory, state=None, root=ROOT):
    state = copy.deepcopy(state or {})
    mapping(config,['version','sbc','snmp','console','endpoint','recording','management'],'configuration')
    if type(config.get('version')) is not int or config.get('version') != 1:
        raise ConfigError('Configuration version must be 1.')
    sbc = mapping(config.get('sbc'),['host','username','password','https','ssh'],'sbc')
    https = mapping(sbc.get('https'),['certificate_sha256','ca_file','ca_pem'],'sbc.https')
    ssh = mapping(sbc.get('ssh'),['port','host_key_sha256'],'sbc.ssh')
    snmp = mapping(config.get('snmp'),['version','port','username','auth_protocol','auth_password','priv_protocol','priv_password','community','trap_communities'],'snmp')
    console = mapping(config.get('console'),['username','password','password_hash','tls'],'console')
    endpoint = mapping(config.get('endpoint'),['address','https_port','trap_port'],'endpoint')
    recording = mapping(config.get('recording'),['advertised_ip','bind_ip','sip_port','rtp_port_min','rtp_port_max','max_concurrent_calls','max_duration_hours','retention_days','codecs'],'recording')
    management = mapping(config.get('management',{}),['transport','kubectl_context','ssh'],'management')
    validate_management(management,directory)
    address = ipv4(endpoint.get('address'),'endpoint.address')
    values = {'SBC_HOST':ipv4(sbc.get('host'),'sbc.host'), 'SBC_USER':text(sbc.get('username'),'sbc.username'),
              'SBC_PASSWORD':text(sbc.get('password'),'sbc.password')}
    raw_pin = https.get('certificate_sha256','')
    if not isinstance(raw_pin,str):raise ConfigError('sbc.https.certificate_sha256 must be quoted hexadecimal text.')
    pin = raw_pin.replace(':','').lower()
    if pin and not re.fullmatch('[0-9a-f]{64}',pin):
        raise ConfigError('sbc.https.certificate_sha256 must contain 64 hexadecimal characters.')
    ca = pem_value(https,'ca',directory)
    if ca:
        try:x509.load_pem_x509_certificate(ca.encode())
        except ValueError:raise ConfigError('The supplied SBC CA is not a PEM certificate.') from None
    if not pin and not ca:raise ConfigError('Supply the verified SBC certificate fingerprint or a trusted CA.')
    values['SBC_FINGERPRINT'] = pin
    sshpin = text(ssh.get('host_key_sha256'),'sbc.ssh.host_key_sha256')
    try:
        if not sshpin.startswith('SHA256:') or len(base64.b64decode(sshpin[7:]+'=',validate=True))!=32:raise ValueError()
    except ValueError:raise ConfigError('sbc.ssh.host_key_sha256 must be an OpenSSH SHA256 fingerprint.') from None
    values['SBC_SSH_FINGERPRINT'] = sshpin
    previous = previous_secret(state,'sbc-console-credentials')
    if 'password' in console and 'password_hash' in console:
        raise ConfigError('Use console.password or console.password_hash, not both.')
    generated_password = None
    if 'password_hash' in console:
        encoded = text(console['password_hash'],'console.password_hash')
        if not re.fullmatch(r'[0-9a-fA-F]{32,128}:[0-9a-fA-F]{64}',encoded) or len(encoded.split(':')[0])%2:
            raise ConfigError('console.password_hash must be salt-hex:PBKDF2-SHA256-hex, with 600000 iterations.')
    else:
        password = text(console.get('password'),'console.password')
        if password == 'generate':
            password = state.get('generated_admin_password') or secrets.token_urlsafe(24)
            generated_password = password
        encoded = previous.get('APP_PASSWORD_HASH','')
        if not password_matches(password,encoded):
            salt = secrets.token_bytes(24)
            encoded = salt.hex()+':'+hashlib.pbkdf2_hmac('sha256',password.encode(),salt,600000).hex()
    values['APP_PASSWORD_HASH'] = encoded
    version = str(snmp.get('version','3'))
    if version not in ('3','2c'):raise ConfigError('snmp.version must be "3" or "2c".')
    protocol = text(snmp.get('auth_protocol','SHA256'),'snmp.auth_protocol').upper().replace('-','')
    privacy = text(snmp.get('priv_protocol','AES128'),'snmp.priv_protocol').upper().replace('-','')
    if protocol not in ('SHA256','SHA512') or privacy != 'AES128':raise ConfigError('Use SHA256/SHA512 and AES128 for SNMPv3.')
    if version == '3':
        values.update({key:text(snmp.get(field),'snmp.'+field) for key,field in [('SNMP_USER','username'),('SNMP_AUTH_KEY','auth_password'),('SNMP_PRIV_KEY','priv_password')]})
    else:values['SNMP_COMMUNITY'] = text(snmp.get('community'),'snmp.community')
    communities = snmp.get('trap_communities','generate')
    if communities == 'generate':
        communities = json.loads(previous['SNMP_TRAP_COMMUNITIES']) if previous.get('SNMP_TRAP_COMMUNITIES') else [secrets.token_urlsafe(24)]
    if not isinstance(communities,list) or not communities:raise ConfigError('snmp.trap_communities must be generate or a non-empty list.')
    values['SNMP_TRAP_COMMUNITIES'] = json.dumps([text(v,'snmp.trap_communities') for v in communities])
    cert, key = tls_material(console.get('tls'),address,directory,state)
    private = {'apiVersion':'v1','kind':'List','items':[secret_object('sbc-console-credentials',values),secret_object('sbc-console-tls',{'tls.crt':cert,'tls.key':key}),secret_object('sbc-console-trust',{'sbc-ca.crt':ca})]}
    revision = state.get('revision') if state.get('secrets') == private else None
    revision = revision or uuid.uuid4().hex
    state.update(secrets=private, revision=revision, generated_admin_password=generated_password)
    public = json.loads((root/'deploy/kubernetes/template/resources.json').read_text())
    cm = next(r for r in public['items'] if r['kind']=='ConfigMap')['data']
    cm.update(APP_USER=text(console.get('username','admin'),'console.username'),SNMP_VERSION=version,SNMP_AUTH_PROTOCOL=protocol,SNMP_PRIV_PROTOCOL=privacy,
              SNMP_PORT=str(integer(snmp.get('port',161),'snmp.port')),SBC_SSH_PORT=str(integer(ssh.get('port',22),'sbc.ssh.port')))
    sip = integer(recording.get('sip_port',5060),'recording.sip_port')
    low = integer(recording.get('rtp_port_min',20000),'recording.rtp_port_min',1024)
    high = integer(recording.get('rtp_port_max',20199),'recording.rtp_port_max',low+1)
    if low%2:raise ConfigError('recording.rtp_port_min must be even.')
    codecs = recording.get('codecs',['PCMU','PCMA'])
    if not isinstance(codecs,list) or not codecs or len(set(codecs))!=len(codecs) or any(c not in ('PCMU','PCMA') for c in codecs):raise ConfigError('recording.codecs must contain PCMU and/or PCMA without duplicates.')
    cm.update(EXTERNAL_IP=ipv4(recording.get('advertised_ip',address),'recording.advertised_ip'),SIP_HOST=ipv4(recording.get('bind_ip','0.0.0.0'),'recording.bind_ip'),
              RTP_BIND_IP=ipv4(recording.get('bind_ip','0.0.0.0'),'recording.bind_ip'),PORTS=str(sip),UDP_PORTS=str(sip),TCP_PORTS=str(sip),RTP_PORT_MIN=str(low),RTP_PORT_MAX=str(high),
              MAX_CONCURRENT_CALLS=str(integer(recording.get('max_concurrent_calls',10),'recording.max_concurrent_calls',1,1000)),
              RECORDING_MAX_DURATION_HOURS=str(integer(recording.get('max_duration_hours',4),'recording.max_duration_hours',1,168)),
              RECORDING_CLEANUP_DAYS=str(integer(recording.get('retention_days',36500),'recording.retention_days',1,36500)),SUPPORTED_CODECS=','.join(codecs))
    svc = next(r for r in public['items'] if r['kind']=='Service')
    svc['metadata']['annotations']['metallb.io/loadBalancerIPs'] = address
    https_port = integer(endpoint.get('https_port',443),'endpoint.https_port')
    trap_port = integer(endpoint.get('trap_port',162),'endpoint.trap_port')
    if https_port==sip or low<=sip<=high or low<=trap_port<=high or sip==trap_port:
        raise ConfigError('HTTPS/SIP/trap/RTP ports conflict within the Service.')
    svc['spec']['ports'] = [{'name':'https','port':https_port,'targetPort':8443,'protocol':'TCP'},
        {'name':'sip-udp','port':sip,'targetPort':sip,'protocol':'UDP'},{'name':'sip-tcp','port':sip,'targetPort':sip,'protocol':'TCP'},
        {'name':'traps','port':trap_port,'targetPort':1162,'protocol':'UDP'}]+[{'name':f'rtp-{p}','port':p,'targetPort':p,'protocol':'UDP'} for p in range(low,high+1)]
    deployment = next(r for r in public['items'] if r['kind']=='Deployment')
    deployment['spec']['template']['metadata']['annotations'] = {'sbc-console/settings-sha256':hashlib.sha256(json.dumps(cm,sort_keys=True).encode()).hexdigest(),'sbc-console/secret-revision':revision}
    rendered = json.dumps(public,indent=2)+'\n'
    protected = [sbc['password'],*[v for k,v in values.items() if k in ('SNMP_AUTH_KEY','SNMP_PRIV_KEY','SNMP_COMMUNITY')],*communities,key]
    if 'password' in console and console['password']!='generate':protected.append(console['password'])
    if any(len(v)>=8 and v in rendered for v in protected):raise ConfigError('A private value would enter the public render; configuration was not written.')
    return public, private, state, management


def private_write(path, content):
    path.parent.mkdir(parents=True,exist_ok=True)
    if os.name!='nt':os.chmod(path.parent,0o700)
    if path.is_symlink():raise ConfigError('Generated private files must not be symbolic links.')
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(descriptor,'w',encoding='utf-8',newline='\n') as output:output.write(content)
    if os.name!='nt':os.chmod(path,0o600)


def apply_private(management, directory, resources):
    command=['kubectl']
    if management.get('kubectl_context'):command+=['--context',text(management['kubectl_context'],'management.kubectl_context')]
    command+=['apply','--server-side','--field-manager=sbc-config','--force-conflicts','-f','-']
    transport=management.get('transport','local')
    if transport=='ssh':
        settings=mapping(management.get('ssh'),['host','username','private_key_file','host_key'],'management.ssh')
        host=text(settings.get('host'),'management.ssh.host');user=text(settings.get('username'),'management.ssh.username')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*',host) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',user):raise ConfigError('Invalid SSH host or username.')
        key=(directory/text(settings.get('private_key_file'),'management.ssh.private_key_file')).resolve()
        if not key.is_file():raise ConfigError('The configured SSH key file does not exist.')
        remote=shlex.join(command)
        if key.suffix.lower()=='.ppk':
            executable=shutil.which('plink') or shutil.which('plink.exe')
            if not executable:raise ConfigError('PuTTY plink is required for a .ppk key.')
            command=[executable,'-batch','-i',str(key)]
            if settings.get('host_key'):command+=['-hostkey',text(settings['host_key'],'management.ssh.host_key')]
            command+=[user+'@'+host,remote]
        else:command=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-i',str(key),user+'@'+host,remote]
    elif transport!='local':raise ConfigError('management.transport must be local or ssh.')
    result=subprocess.run(command,input=json.dumps(resources),text=True,encoding='utf-8',capture_output=True)
    if result.returncode:
        raise ConfigError('Private Secret apply failed. Check cluster access and permissions; private payload/error text was withheld.')
    print(result.stdout.strip())


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--check',action='store_true',help='Validate without writing files or contacting Kubernetes')
    parser.add_argument('--apply-private',action='store_true',help='Apply Secrets after rendering; then commit and push the public render for Argo CD')
    args=parser.parse_args(argv)
    try:
        if args.check and args.apply_private:raise ConfigError('--check cannot be combined with --apply-private.')
        source=private_location(args.config)
        directory=private_location(source.parent/(source.stem+'.generated'))
        state_path=directory/'state.json'
        state=json.loads(state_path.read_text()) if state_path.exists() else {}
        config=yaml.load(source.read_text(encoding='utf-8-sig'),Loader=UniqueLoader)
        public,private,state,management=build(config,source.parent,state)
        if args.check:
            print('YAML, credentials, port plan, fingerprints, and TLS material validated; no files changed.')
            return 0
        private_write(directory/'secrets.json',json.dumps(private,indent=2)+'\n')
        private_write(state_path,json.dumps(state,indent=2)+'\n')
        private_write(directory/'console-certificate.crt',base64.b64decode(private['items'][1]['data']['tls.crt']).decode())
        password=state.get('generated_admin_password') or config['console'].get('password')
        private_write(directory/'admin-password.txt',(password or 'Password supplied as a hash; plaintext is not stored here.')+'\n')
        (ROOT/'deploy/kubernetes/base/resources.json').write_text(json.dumps(public,indent=2)+'\n',encoding='utf-8',newline='\n')
        if args.apply_private:apply_private(management,source.parent,private)
        print('Rendered public settings: deploy/kubernetes/base/resources.json')
        print('Private files: '+str(directory))
        print('Commit and push the public settings file; Argo CD will roll out the configuration, including Secret changes.')
        return 0
    except (ConfigError,OSError,yaml.YAMLError,ValueError,TypeError) as error:
        # YAML parser errors and crypto errors can contain input fragments. Never echo them.
        print('Configuration failed: '+(str(error) if isinstance(error,ConfigError) else 'Invalid or unreadable configuration, state, or PEM input; private details withheld.'),file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
