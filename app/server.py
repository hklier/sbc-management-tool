#!/usr/bin/env python3
"""SBC Console: standard-library HTTPS application for Oracle SBC REST v1.2."""
import base64
import copy
import hashlib
import hmac
import http.client
import gzip
import io
import json
import os
import re
from pathlib import Path
import secrets
import ssl
import threading
import stat as file_stat
import tempfile
import time
import xml.etree.ElementTree as ET
import rest_activity
import users_tools
import devices_tools
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit, quote

BASE = Path(__file__).resolve().parent
STATE = Path(os.environ.get('STATE_DIR', str(BASE / 'state')))
STATE.mkdir(parents=True, exist_ok=True)
os.chmod(str(STATE), 0o700)
GATE = threading.RLock()
SESSIONS = {}
AUTH_GATE = threading.RLock()
USERS = users_tools.Store(STATE / 'users.sqlite3')
DEVICES = devices_tools.Store(STATE)
RUNTIMES = {}
DEVICE_GATE = threading.RLock()
SNAPSHOTS = {}
ATTEMPTS = {}
LRT_CACHE = {}
LRT_PLANS = {}
LRT_COMPRESSED_LIMIT = 8 * 1024 * 1024
LRT_XML_LIMIT = 32 * 1024 * 1024


class Problem(Exception):
    def __init__(self, message, code=400, details=None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


def xml(text):
    if len(text) > 8_000_000 or '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise Problem('XML is not allowed.')
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        raise Problem('The XML is not valid.')


def text(node, path):
    return node.findtext(path, '') or ''


def serial(node):
    return ET.tostring(node, encoding='unicode')


def config_request(node):
    # SCZ9.3.0p11 rejects configElements writes without this XML declaration.
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + serial(node)


def value_of(attribute):
    value = attribute.find('value')
    if value is None:
        return ''
    return ''.join(serial(c) for c in value).strip() if len(value) else (value.text or '')


def attribute_values(node, prefix=''):
    values = {prefix + text(a, 'name'): value_of(a) for a in node.findall('attribute')}
    for i, child in enumerate(node.findall('subElement')):
        values.update(attribute_values(child, prefix + text(child, 'subElementType') + '[' + str(i + 1) + '].'))
    return values


def confirm_update(actual, requested, changes):
    if actual is None:
        raise Problem('The SBC did not return the updated element. Reload it before retrying.', 502)
    expected, received = attribute_values(requested), attribute_values(actual)
    for change in changes:
        field = change['field']
        # The SBC masks credentials on read; their values cannot be compared.
        if any(word in field.rsplit('.', 1)[-1].lower() for word in ('password', 'secret', 'passphrase', 'private-key')):
            continue
        if received.get(field) != expected.get(field):
            raise Problem('The SBC did not retain the requested value for ' + field + '. Reload the element before retrying.', 502)


def canonical(node):
    return (node.tag, tuple(sorted(node.attrib.items())), (node.text or '').strip(), tuple(canonical(c) for c in node))


def verification_report(root):
    summary = root.find('.//verifySummary')
    if summary is None:
        return None
    return dict(criticals=int(summary.get('numCriticals', '0')), errors=int(summary.get('numErrors', '0')), warnings=int(summary.get('numWarnings', '0')), items=[dict(severity=v.get('severity', 'INFO'), message=text(v, './field[@name="message"]/value')) for v in summary.findall('verify')])


def audit(action, outcome, **details):
    current = devices_tools.CONTEXT.get()
    if current:details['device_id']=current.record['id']
    record = dict(time=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), action=action, outcome=outcome, **details)
    with open(STATE / 'audit.jsonl', 'a', encoding='utf-8') as f:
        f.write(json.dumps(record, ensure_ascii=False) + '\n')


def configuration_workflow(versions):
    needs_save = False
    needs_activate = text(versions, './/currentVersion') != text(versions, './/runningVersion')
    path = STATE / 'audit.jsonl'
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            current=devices_tools.CONTEXT.get()
            if current and record.get('device_id','bootstrap')!=current.record['id']:continue
            if record.get('outcome') not in ('success', 'attention'):
                continue
            action = record.get('action')
            if action in ('create', 'replace', 'update'):
                needs_save, needs_activate = True, False
            elif action == 'save':
                needs_save, needs_activate = False, True
            elif action == 'activate':
                needs_save, needs_activate = False, False
    return dict(needsSave=needs_save, needsActivate=needs_activate)


class SBC:
    def __init__(self, settings=None):
        self.settings = os.environ if settings is None else settings
        self.host = self.settings.get('SBC_HOST', '192.168.226.193')
        self.pin = self.settings.get('SBC_FINGERPRINT', '').replace(':', '').lower()
        self.token = ''
        self.token_at = 0
        self.pending = False
        self.blocked = False

    def raw(self, method, path, body=None, auth=None):
        # A configured fingerprint authenticates the SBC even with a self-signed certificate.
        ca=self.settings.get('SBC_CA_PEM','')
        context = ssl.create_default_context(cadata=ca) if ca else (ssl._create_unverified_context() if self.pin else ssl.create_default_context(cafile=self.settings.get('SBC_CA') or None))
        conn = http.client.HTTPSConnection(self.host, timeout=25, context=context)
        headers = {'Accept': 'application/xml', 'Authorization': auth or 'Bearer ' + self.token}
        if body is not None:headers['Content-Type'] = 'application/xml'
        activity=rest_activity.begin(method,path,body,headers)
        activity_status=None;activity_response=None;activity_failed=True
        try:
            conn.connect()
            if self.pin and not ca and not hmac.compare_digest(hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest(), self.pin):
                raise Problem('The SBC certificate has changed. Review its fingerprint before connecting.', 502)
            if body is not None:
                body = body.encode('utf-8')
            conn.request(method, '/rest/v1.2/' + path, body=body, headers=headers)
            response = conn.getresponse()
            activity_status=response.status
            data = response.read(8_000_001).decode('utf-8')
            activity_response=data
            root = xml(data) if data else ET.Element('response')
            if response.status >= 400:
                errors = ' · '.join(e.text or '' for e in root.findall('.//errorMessage'))
                if response.status == 423:
                    raise Problem('The SBC configuration is locked by another session. Release that session before editing, verifying or creating backups.', 409)
                raise Problem('SBC HTTP {}: {}'.format(response.status, errors or response.reason), 502)
            errors = [e.text for e in root.findall('.//errorMessage') if e.text]
            if errors:
                raise Problem('SBC: ' + ' · '.join(errors), 502)
            activity_failed=False
            return response.status, root
        finally:
            conn.close()
            rest_activity.finish(activity,activity_status,activity_response,activity_failed)

    def call(self, method, path, body=None):
        if not self.token or (time.time() - self.token_at > 240 and not (self.pending or self.blocked)):
            if self.pending or self.blocked:
                raise Problem('An operation or unresolved lock is pending. Check the SBC before continuing.', 409)
            credentials = self.settings.get('SBC_USER', 'admin') + ':' + self.settings['SBC_PASSWORD']
            _, root = self.raw('POST', 'auth/token', auth='Basic ' + base64.b64encode(credentials.encode()).decode())
            self.token = text(root, './/accessToken')
            if not self.token:
                raise Problem('The SBC did not return an access token.', 502)
            self.token_at = time.time()
        return self.raw(method, path, body)

    def get(self, path):
        return self.call('GET', path)[1]

    def operation(self, method, path):
        status, root = self.call(method, path)
        if status != 202:
            return root
        self.pending = True
        deadline = time.time() + 90
        while time.time() < deadline:
            time.sleep(1)
            # Keep the same authentication token while the SBC holds our lock.
            _, result = self.raw('GET', 'admin/asyncstatus')
            value = text(result, './/operationState/status').lower()
            if value == 'success':
                self.pending = False
                return result
            if value in ('fail', 'failed', 'failure', 'error'):
                self.pending = False
                raise Problem('The SBC operation failed: ' + serial(result), 502)
        raise Problem('The SBC is still processing the operation. The lock is retained; check operation status before continuing.', 409)

    def transaction(self, fn):
        with GATE:
            if self.pending or self.blocked:
                raise Problem('An operation or lock is pending. Check operation status.', 409)
            # Start each lock with a fresh token; never replace its owner mid-operation.
            self.token = ''
            self.call('POST', 'configuration/lock')
            self.blocked = True
            try:
                return fn()
            finally:
                if not self.pending:
                    try:
                        self.raw('POST', 'configuration/unlock')
                        self.blocked = False
                    except Exception:
                        audit('unlock', 'failed')
                        raise Problem('The lock could not be released. The preceding operation may have completed; check its status before retrying.', 502)


SBC_CLIENT = SBC()

class DeviceRuntime:
    def __init__(self, record):
        import snmp_tools
        self.record=record;self.settings=devices_tools.environment(record)
        self.client=SBC(self.settings);self.gate=threading.RLock()
        self.snapshots={};self.lrt_cache={};self.lrt_plans={};self.cdr_cache={}
        self.monitor=snmp_tools.Monitor(self.settings)

def runtime(record):
    with DEVICE_GATE:
        # An edit may have finished after the request read the device list.
        record=DEVICES.get(record['id']) if DEVICES.initialized else record
        current=RUNTIMES.get(record['id'])
        if current is None or current.record['version']!=record['version']:
            current=RUNTIMES[record['id']]=DeviceRuntime(record)
        return current

def device_settings():
    current=devices_tools.CONTEXT.get()
    return current.settings if current else os.environ

SBC_CLIENT=devices_tools.ScopedObject('client',SBC_CLIENT)
GATE=devices_tools.ScopedObject('gate',GATE)
SNAPSHOTS=devices_tools.ScopedMap('snapshots',SNAPSHOTS)
LRT_CACHE=devices_tools.ScopedMap('lrt_cache',LRT_CACHE)
LRT_PLANS=devices_tools.ScopedMap('lrt_plans',LRT_PLANS)



def element_types():
    root = SBC_CLIENT.get('configuration/elementTypes')
    return [dict(name=text(t, 'name'), description=text(t, 'description'), single=t.get('single', 'false') == 'true', count=int(t.get('configCount', '0')), running=int(t.get('runningConfigCount', '0'))) for t in root.findall('./data/elementType')]


def creatable_type(kind):
    info = next((t for t in element_types() if t['name'] == kind), None)
    if info is None:
        raise Problem('Unknown configuration element type.', 404)
    if info['single']:
        raise Problem('This is a singleton element. Additional instances cannot be created.', 409)
    return info


def lrt_filename(filename):
    if not filename or len(filename) > 255 or filename in ('.', '..') or not re.fullmatch(r'[A-Za-z0-9_.-]+', filename):
        raise Problem('The configured LRT filename must be a filename inside /code/lrt, without directory components.')
    return filename


def parse_lrt(content):
    if len(content) > LRT_COMPRESSED_LIMIT:
        raise Problem('The LRT file exceeds the 8 MiB download limit.', 413)
    try:
        if content.startswith(b'\x1f\x8b'):
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as archive:
                data = archive.read(LRT_XML_LIMIT + 1)
        else:
            data = content
        if len(data) > LRT_XML_LIMIT:
            raise Problem('The decompressed LRT exceeds the 32 MiB limit.', 413)
        if b'\x00' in data or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
            raise Problem('LRT XML entities and document type declarations are not supported.')
        root = ET.fromstring(data)
    except (ET.ParseError, OSError, EOFError, UnicodeError):
        raise Problem('The LRT file is not valid XML or gzip data.', 502)
    for node in root.iter():
        node.tag = node.tag.rsplit('}', 1)[-1]
    if root.tag != 'localRoutes':
        raise Problem('The LRT XML must contain a localRoutes root element.', 502)
    entries = []
    for index, route in enumerate(root.findall('route'), 1):
        user = route.find('user')
        if user is None:
            raise Problem('LRT route {} has no user element.'.format(index), 502)
        attrs = dict(user.attrib)
        match = (user.text or '').strip()
        if attrs.get('type') == 'range':
            match = attrs.get('rangePrefix', '') + attrs.get('rangeStart', '') + ' – ' + attrs.get('rangePrefix', '') + attrs.get('rangeEnd', '')
        hops = [dict(value=(n.text or '').strip(), type=n.get('type', ''), attributes=dict(n.attrib)) for n in route.findall('next')]
        entries.append(dict(index=index, match=match, userType=attrs.get('type', ''), userAttributes=attrs, nextHops=hops, description=text(route, 'description'), xml=serial(route)))
    version = root.find('emsVersion')
    return dict(entries=entries, entryCount=len(entries), nextHopCount=sum(len(e['nextHops']) for e in entries), tableType=root.get('type', 'standard'), version={c.tag: c.text or '' for c in version} if version is not None else {}, uncompressedBytes=len(data))


@contextmanager
def lrt_sftp(purpose='LRT'):
    pin = device_settings().get('SBC_SSH_FINGERPRINT', '')
    if not pin:
        raise Problem('The SBC SFTP host key has not been configured.', 502)
    try:
        import paramiko
    except ImportError:
        raise Problem('The SFTP reader dependency is not installed.', 502)
    class PinnedHostKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            actual = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
            if not hmac.compare_digest(actual, pin.rstrip('=')):
                raise Problem('The SBC SSH host key has changed. Review its fingerprint before reading SBC files.', 502)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(PinnedHostKey())
    try:
        client.connect(SBC_CLIENT.host, port=int(device_settings().get('SBC_SSH_PORT', '22')), username=device_settings().get('SBC_USER', 'admin'), password=device_settings()['SBC_PASSWORD'], allow_agent=False, look_for_keys=False, timeout=12, auth_timeout=12, banner_timeout=12)
        with client.open_sftp() as sftp:
            sftp.get_channel().settimeout(15)
            yield sftp
    except Problem:
        raise
    except FileNotFoundError:
        raise Problem('The requested ' + purpose + ' file or directory was not found on the SBC.', 404)
    except PermissionError:
        raise Problem('The SBC account does not have access to this ' + purpose + ' file or directory.', 403)
    except Exception as exc:
        raise Problem('Could not access the ' + purpose + ' over SFTP: ' + type(exc).__name__, 502)
    finally:
        client.close()


def sftp_lrt_path(sftp, filename):
    path = '/code/lrt/' + lrt_filename(filename)
    if not sftp.normalize(path).startswith('/code/lrt/'):
        raise Problem('The LRT file resolves outside /code/lrt.', 403)
    return path


def sftp_read_lrt(sftp, path):
    stat = sftp.stat(path)
    if stat.st_size > LRT_COMPRESSED_LIMIT:
        raise Problem('The LRT file exceeds the 8 MiB download limit.', 413)
    with sftp.open(path, 'rb') as source:
        content = source.read(LRT_COMPRESSED_LIMIT + 1)
    if len(content) > LRT_COMPRESSED_LIMIT:
        raise Problem('The LRT file exceeds the 8 MiB download limit.', 413)
    return content, stat


def read_lrt_file(filename):
    filename = lrt_filename(filename)
    with lrt_sftp() as sftp:
        content, stat = sftp_read_lrt(sftp, sftp_lrt_path(sftp, filename))
        return content, dict(sizeBytes=len(content), modifiedAt=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(stat.st_mtime)))


def load_lrt(filename, refresh=False):
    filename = lrt_filename(filename)
    key = (SBC_CLIENT.host, filename)
    cached = LRT_CACHE.get(key)
    if cached and not refresh and time.time() - cached['cachedAt'] < 30:
        return cached
    content, stat = read_lrt_file(filename)
    document = dict(parse_lrt(content), **stat, content=content, cachedAt=time.time(), fetchedAt=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), sha256=hashlib.sha256(content).hexdigest())
    if len(LRT_CACHE) >= 8 and key not in LRT_CACHE:
        del LRT_CACHE[min(LRT_CACHE, key=lambda k: LRT_CACHE[k]['cachedAt'])]
    LRT_CACHE[key] = document
    return document


def lrt_configs(running):
    params = {'elementType': 'local-routing-config'}
    if running:
        params['running'] = 'true'
    root = SBC_CLIENT.get('configuration/configElements?' + urlencode(params))
    return [dict((text(a, 'name'), value_of(a)) for a in e.findall('attribute')) for e in root.findall('./data/configElement')]


def lrt_overview(running, refresh=False):
    tables = []
    configs = lrt_configs(running)
    active = configs if running else lrt_configs(True)
    for config in configs:
        item = dict(name=config.get('name', ''), filename=config.get('file-name', ''), config=config)
        item['activeTables'] = [c.get('name', '') for c in active if c.get('file-name') == item['filename']]
        try:
            document = load_lrt(item['filename'], refresh)
            item.update({k: v for k, v in document.items() if k not in ('entries', 'cachedAt', 'content')})
            item['status'] = 'ready'
        except Problem as exc:
            item.update(status='error', error=str(exc), entryCount=None, nextHopCount=None)
        tables.append(item)
    return dict(tables=tables, running=running)


def lrt_entries(name, running, query='', offset=0, limit=50):
    config = next((c for c in lrt_configs(running) if c.get('name') == name), None)
    if config is None:
        raise Problem('Local route table not found in the selected configuration.', 404)
    document = load_lrt(config.get('file-name', ''))
    needle = query.casefold()
    matches = document['entries'] if not needle else [e for e in document['entries'] if needle in json.dumps({k: v for k, v in e.items() if k != 'xml'}, ensure_ascii=False).casefold()]
    return dict(name=name, filename=config.get('file-name', ''), config=config, running=running, total=document['entryCount'], filtered=len(matches), offset=offset, limit=limit, entries=matches[offset:offset + limit], fetchedAt=document['fetchedAt'], sha256=document['sha256'], tableType=document['tableType'], activeTables=[c.get('name', '') for c in lrt_configs(True) if c.get('file-name') == config.get('file-name')])


def make_lrt_route(draft, table_type):
    if not isinstance(draft, dict):raise Problem('A route entry object is required.')
    user_type = draft.get('userType', 'E164')
    if user_type not in ('E164', 'string', 'range') or (table_type == 'range') != (user_type == 'range'):
        raise Problem('Range entries require a range LRT. Standard LRTs accept E164 or string entries.')
    route = ET.Element('route')
    user = ET.SubElement(route, 'user', {'type': user_type})
    if user_type == 'range':
        start, end = str(draft.get('rangeStart', '')).strip(), str(draft.get('rangeEnd', '')).strip()
        if not (re.fullmatch(r'[0-9]{1,32}', start) and re.fullmatch(r'[0-9]{1,32}', end) and len(start) == len(end) and int(start) <= int(end)):
            raise Problem('Enter a valid DID range with equally long numeric start/end values and start <= end.')
        user.attrib.update(rangeStart=start, rangeEnd=end)
        prefix = str(draft.get('rangePrefix', '')).strip()
        if len(prefix) > 255:
            raise Problem('The range prefix is too long.')
        if prefix:
            user.set('rangePrefix', prefix)
    else:
        match = str(draft.get('match', '')).strip()
        if not match or len(match) > 1024 or (user_type == 'E164' and not re.fullmatch(r'\+?[0-9]+', match)):
            raise Problem('Enter a valid number or string to match.')
        user.text = match
    description = str(draft.get('description', '')).strip()
    if len(description) > 4096:
        raise Problem('The description is too long.')
    if description:
        ET.SubElement(route, 'description').text = description
    hops = draft.get('nextHops', [])
    if not isinstance(hops, list) or not 1 <= len(hops) <= 10:
        raise Problem('Provide between 1 and 10 next hops.')
    for hop in hops:
        if not isinstance(hop, dict):raise Problem('Each next hop must be an object.')
        value = str(hop.get('value', '')).strip()
        next_type = str(hop.get('type', 'regex')).strip()
        if not value or len(value) > 8192 or not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', next_type):
            raise Problem('Every next hop needs a value and a valid type.')
        attrs = hop.get('attributes', {})
        if not isinstance(attrs, dict) or len(attrs) > 20 or any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*', str(k)) or k == 'type' or len(str(v)) > 256 for k, v in attrs.items()):
            raise Problem('Invalid next-hop attributes. Use attribute names and short string values; type is a separate field.')
        ET.SubElement(route, 'next', {'type': next_type, **{k: str(v) for k, v in attrs.items()}}).text = value
    return route


def build_lrt_change(content, action, draft=None, index=None):
    before = parse_lrt(content)
    raw = gzip.decompress(content) if content.startswith(b'\x1f\x8b') else content
    root = ET.fromstring(raw, parser=ET.XMLParser(target=ET.TreeBuilder(insert_comments=True, insert_pis=True)))
    namespace = root.tag.split('}')[0] + '}' if '}' in root.tag else ''
    routes = [c for c in root if c.tag == namespace + 'route']
    if action == 'add':
        route = make_lrt_route(draft or {}, before['tableType'])
        # Keep namespace, comments, unknown elements, metadata and original order.
        for node in route.iter():
            node.tag = namespace + node.tag
        insertion = list(root).index(routes[-1]) + 1 if routes else 0
        root.insert(insertion, route)
        selected_index = len(routes) + 1
    elif action in ('edit', 'delete'):
        if isinstance(index, bool) or not isinstance(index, int) or not 1 <= index <= len(routes):
            raise Problem('This route entry no longer exists. Refresh the table.', 409)
        original = routes[index - 1]
        if action == 'delete':
            root.remove(original)
        else:
            if any(list(hop) for hop in original.findall(namespace + 'next')):
                raise Problem('This entry contains structured next-hop XML that the form cannot safely edit. No changes were made.')
            edited = make_lrt_route(draft or {}, before['tableType'])
            for node in edited.iter():node.tag = namespace + node.tag
            # Update only the selected route, retaining unknown route/user metadata.
            user = original.find(namespace + 'user')
            replacement = edited.find(namespace + 'user')
            for key in ('type', 'rangeStart', 'rangeEnd', 'rangePrefix'):user.attrib.pop(key, None)
            user.attrib.update(replacement.attrib);user.text = replacement.text
            old_hops = original.findall(namespace + 'next')
            new_hops = edited.findall(namespace + 'next')
            for position, old_hop in enumerate(old_hops):
                at = list(original).index(old_hop)
                original.remove(old_hop)
                if position < len(new_hops):
                    new_hop = new_hops[position];new_hop.tail = old_hop.tail
                    original.insert(at, new_hop)
            if len(new_hops) > len(old_hops):
                anchors = original.findall(namespace + 'next')
                at = list(original).index(anchors[-1] if anchors else user) + 1
                for hop in new_hops[len(old_hops):]:original.insert(at, hop);at += 1
            description = original.find(namespace + 'description')
            replacement = edited.find(namespace + 'description')
            if replacement is None:
                if description is not None:original.remove(description)
            elif description is not None:description.text = replacement.text
            else:original.append(replacement)
        selected_index = index
    else:
        raise Problem('Only add, edit and delete entry operations are supported.')
    plain = ET.tostring(root, encoding='utf-8', xml_declaration=True)
    proposed = gzip.compress(plain, mtime=0) if content.startswith(b'\x1f\x8b') else plain
    after = parse_lrt(proposed)
    entry = before['entries'][index - 1] if action == 'delete' else after['entries'][selected_index - 1]
    review = dict(action=action, beforeCount=before['entryCount'], afterCount=after['entryCount'], entry=entry)
    if action == 'edit':review['previousEntry'] = before['entries'][index - 1]
    return proposed, review


def prepare_lrt_change(session, body):
    name, running = str(body.get('name', '')), body.get('running', True) is True
    config = next((c for c in lrt_configs(running) if c.get('name') == name), None)
    if config is None:
        raise Problem('Local route table not found in the selected configuration.', 404)
    filename = lrt_filename(config.get('file-name', ''))
    document = load_lrt(filename, refresh=True)
    if not hmac.compare_digest(str(body.get('sha256', '')), document['sha256']):
        raise Problem('The LRT file changed since it was displayed. Refresh the table before editing.', 409)
    proposed, review = build_lrt_change(document['content'], body.get('action'), body.get('entry'), body.get('index'))
    for token, plan in list(LRT_PLANS.items()):
        if plan['expires'] < time.time():
            del LRT_PLANS[token]
    if len(LRT_PLANS) >= 16:
        del LRT_PLANS[min(LRT_PLANS, key=lambda token: LRT_PLANS[token]['expires'])]
    token = secrets.token_urlsafe(24)
    active = [c.get('name', '') for c in lrt_configs(True) if c.get('file-name') == filename]
    LRT_PLANS[token] = dict(session=session, expires=time.time() + 600, name=name, running=running, filename=filename, sha256=document['sha256'], proposed=proposed, review=review)
    return dict(plan=token, name=name, filename=filename, activeTables=active, **review)


def write_lrt_change(filename, expected_hash, proposed):
    parse_lrt(proposed)
    filename = lrt_filename(filename)
    backup = 'web-lrt-' + time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(6) + '.bak'
    temp = '/code/lrt/web-lrt-tmp-' + secrets.token_hex(12)
    with lrt_sftp() as sftp:
        target = sftp_lrt_path(sftp, filename)
        original, stat = sftp_read_lrt(sftp, target)
        if not hmac.compare_digest(hashlib.sha256(original).hexdigest(), expected_hash):
            raise Problem('The LRT file changed after review. Refresh and review again.', 409)
        directory = STATE / 'lrt-backups'
        directory.mkdir(mode=0o700, exist_ok=True)
        (directory / backup).write_bytes(original)
        # Never truncate the live file: validate a new file, then atomically rename it.
        with sftp.open('/code/lrt/' + backup, 'wx') as destination:
            destination.write(original)
        saved, _ = sftp_read_lrt(sftp, '/code/lrt/' + backup)
        if saved != original:
            raise Problem('Could not verify the LRT backup. The original file was not changed.', 502)
        commit_attempted = False
        try:
            with sftp.open(temp, 'wx') as destination:
                destination.write(proposed)
            sftp.chmod(temp, stat.st_mode & 0o777)
            uploaded, _ = sftp_read_lrt(sftp, temp)
            if uploaded != proposed:
                raise Problem('Could not verify the uploaded LRT. The original file was not changed.', 502)
            current, _ = sftp_read_lrt(sftp, target)
            if hashlib.sha256(current).hexdigest() != expected_hash:
                raise Problem('The LRT file changed during upload. The new file was not applied.', 409)
            commit_attempted = True
            sftp.posix_rename(temp, target)
            current, _ = sftp_read_lrt(sftp, target)
            if current != proposed:
                raise Problem('The LRT write could not be confirmed. Check the SBC before retrying. Backup: ' + backup, 502)
        except Exception as exc:
            if commit_attempted:
                raise Problem('The LRT replacement outcome could not be confirmed. Refresh the table before retrying. Backup: /code/lrt/' + backup, 502) from exc
            raise
        finally:
            if commit_attempted:
                LRT_CACHE.pop((SBC_CLIENT.host, filename), None)
            try:
                sftp.remove(temp)
            except OSError:
                pass
    LRT_CACHE.pop((SBC_CLIENT.host, filename), None)
    return backup


def refresh_lrt_configs(names):
    completed = []
    for name in dict.fromkeys(names):
        try:
            SBC_CLIENT.operation('POST', 'admin/refresh/lrt?' + urlencode({'lrtConfig': name}))
        except Exception as exc:
            audit('lrt-reload', 'failed', table=name)
            detail = ' Reloads confirmed: ' + ', '.join(completed) + '.' if completed else ''
            raise Problem('Reload could not be confirmed for ' + name + '.' + detail + ' ' + str(exc), 502) from exc
        completed.append(name)
        audit('lrt-reload', 'success', table=name)
    return completed


def apply_lrt_change(session, body):
    token = body.get('plan', '')
    plan = LRT_PLANS.get(token)
    if not plan or plan['session'] != session or plan['expires'] < time.time():
        raise Problem('The LRT review has expired. Review the change again.', 409)
    reload_requested = body.get('reload') is True
    def apply():
        config = next((c for c in lrt_configs(plan['running']) if c.get('name') == plan['name']), None)
        if config is None or config.get('file-name') != plan['filename']:
            raise Problem('The LRT configuration changed after review. Refresh before editing.', 409)
        active = [c.get('name', '') for c in lrt_configs(True) if c.get('file-name') == plan['filename']]
        if reload_requested and not active:
            raise Problem('This file is not used by a running LRT. Save the file and activate its configuration before reloading.', 409)
        backup = write_lrt_change(plan['filename'], plan['sha256'], plan['proposed'])
        del LRT_PLANS[token]
        audit('lrt-' + plan['review']['action'], 'success', table=plan['name'], filename=plan['filename'], backup=backup)
        result = dict(message='LRT file saved. Reload the table in the SBC to apply its entries to live routing.', backup='/code/lrt/' + backup, reloaded=False)
        if reload_requested:
            try:
                refresh_lrt_configs(active)
                result.update(message='LRT file saved and reloaded in the SBC.', reloaded=True)
                audit('lrt-reload', 'success', filename=plan['filename'])
            except Exception as exc:
                result.update(message='LRT file saved, but reloading could not be confirmed. Check operation status before retrying.', reloadError=str(exc))
                audit('lrt-reload', 'failed', filename=plan['filename'])
        return result
    return SBC_CLIENT.transaction(apply)


def reload_lrt(body):
    def reload():
        config = next((c for c in lrt_configs(body.get('running', True) is True) if c.get('name') == body.get('name')), None)
        if config is None:
            raise Problem('Local route table not found.', 404)
        filename = lrt_filename(config.get('file-name', ''))
        if filename != body.get('filename'):
            raise Problem('The LRT filename changed. Refresh before reloading.', 409)
        document = load_lrt(filename, refresh=True)
        if document['sha256'] != body.get('sha256'):
            raise Problem('The LRT file changed. Refresh and review it before reloading.', 409)
        active = [c.get('name', '') for c in lrt_configs(True) if c.get('file-name') == filename]
        if not active:
            raise Problem('This file is not used by a running LRT.', 409)
        refresh_lrt_configs(active)
        audit('lrt-reload', 'success', filename=filename)
        return dict(message='LRT reloaded in the SBC. Tables using this file: ' + ', '.join(active))
    return SBC_CLIENT.transaction(reload)



CDR_GATE = threading.Lock()
CDR_CACHE = devices_tools.ScopedMap('cdr_cache',{})

def cdr_list():
    import cdr_tools as cdr
    with lrt_sftp('CDR') as sftp:
        if sftp.normalize('/opt/cdr').rstrip('/')!='/opt/cdr':raise Problem('CDR directory resolves outside /opt/cdr.',403)
        entries=[]
        for info in sftp.listdir_attr('/opt/cdr'):
            if not file_stat.S_ISREG(info.st_mode):continue
            try:cdr.filename(info.filename)
            except cdr.CdrError:continue
            entries.append(dict(name=info.filename,sizeBytes=info.st_size,modifiedAt=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(info.st_mtime)),version=trace_version(info),active=info.filename.startswith('temp-'),canAnalyze=info.st_size<=cdr.MAX_BYTES))
    return dict(directory='/opt/cdr',files=sorted(entries,key=lambda r:r['modifiedAt'],reverse=True),limitBytes=cdr.MAX_BYTES,recordLimit=cdr.MAX_RECORDS,guide=cdr.catalog()['source'])

@contextmanager
def cdr_copy(name,version):
    import cdr_tools as cdr
    try:cdr.filename(name)
    except cdr.CdrError as exc:raise Problem(str(exc),exc.code)
    if not version:raise Problem('Refresh the CDR list before opening a file.',409)
    with tempfile.TemporaryFile() as target:
        with lrt_sftp('CDR') as sftp:
            if sftp.normalize('/opt/cdr').rstrip('/')!='/opt/cdr':raise Problem('CDR directory resolves outside /opt/cdr.',403)
            path='/opt/cdr/'+name
            if sftp.normalize(path)!=path or not file_stat.S_ISREG(sftp.lstat(path).st_mode):raise Problem('CDR links and paths outside /opt/cdr are not permitted.',403)
            info=sftp.stat(path)
            if info.st_size>cdr.MAX_BYTES:raise Problem('This CDR file exceeds the 32 MiB limit.',413)
            if trace_version(info)!=version:raise Problem('The CDR file changed. Refresh the file list.',409)
            with sftp.open(path,'rb') as source:
                remaining=info.st_size
                while remaining:
                    chunk=source.read(min(1024*1024,remaining))
                    if not chunk:raise Problem('CDR file changed while reading. Refresh and retry.',409)
                    target.write(chunk);remaining-=len(chunk)
                if trace_version(source.stat())!=version or trace_version(sftp.stat(path))!=version:raise Problem('The SBC is still writing this CDR file. Refresh and retry.',409)
        target.seek(0);yield target,info.st_size

def cdr_data(query):
    import cdr_tools as cdr
    name,version=query.get('name',''),query.get('version','')
    try:cdr.filename(name)
    except cdr.CdrError as exc:raise Problem(str(exc),exc.code)
    if not CDR_GATE.acquire(blocking=False):raise Problem('Another CDR file is being read. Try again shortly.',429)
    try:
        cached=CDR_CACHE.get('snapshot')
        if cached and cached['name']==name and cached['version']==version and cached['expires']>time.time():return cached['data']
        with cdr_copy(name,version) as (source,size):data=cdr.parse(source.read(),name)
        CDR_CACHE.clear();CDR_CACHE['snapshot']=dict(name=name,version=version,expires=time.time()+120,data=data)
        return data
    except cdr.CdrError as exc:raise Problem(str(exc),exc.code) from exc
    finally:CDR_GATE.release()

TRACE_GATE = threading.Lock()
TRACE_DOWNLOAD_LIMIT = 512 * 1024 * 1024
TRACE_ANALYSIS_LIMIT = 64 * 1024 * 1024


def trace_filename(name):
    if not isinstance(name, str) or not name or len(name) > 255 or '/' in name or '\\' in name or any(ord(c)<32 or ord(c)==127 for c in name) or not name.lower().endswith(('.pcap', '.pcapng', '.cap')):
        raise Problem('Select a PCAP filename inside /opt/traces.')
    return name


def trace_version(info):
    return str(info.st_size) + ':' + str(info.st_mtime)


def trace_list():
    with lrt_sftp('trace') as sftp:
        if sftp.normalize('/opt/traces').rstrip('/') != '/opt/traces':
            raise Problem('The trace directory resolves outside /opt/traces.', 403)
        entries = []
        for item in sftp.listdir_attr('/opt/traces'):
            if not file_stat.S_ISREG(item.st_mode) or not item.filename.lower().endswith(('.pcap', '.pcapng', '.cap')):
                continue
            try:
                trace_filename(item.filename)
            except Problem:
                continue
            entries.append(dict(name=item.filename, sizeBytes=item.st_size,
                modifiedAt=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(item.st_mtime)),
                version=trace_version(item), canAnalyze=item.st_size<=TRACE_ANALYSIS_LIMIT,
                canDownload=item.st_size<=TRACE_DOWNLOAD_LIMIT))
    return dict(files=sorted(entries,key=lambda item:item['modifiedAt'],reverse=True), directory='/opt/traces',
                analysisLimitBytes=TRACE_ANALYSIS_LIMIT, downloadLimitBytes=TRACE_DOWNLOAD_LIMIT)


@contextmanager
def trace_copy(name, version, limit):
    name = trace_filename(name)
    if not version:
        raise Problem('Refresh the trace list before opening a file.', 409)
    with tempfile.TemporaryFile() as target:
        with lrt_sftp('trace') as sftp:
            path = '/opt/traces/' + name
            if sftp.normalize(path) != path or not file_stat.S_ISREG(sftp.lstat(path).st_mode):
                raise Problem('Trace links and paths outside /opt/traces are not allowed.', 403)
            info = sftp.stat(path)
            if info.st_size > limit:
                raise Problem('This capture exceeds the ' + str(limit//(1024*1024)) + ' MiB limit for this operation.', 413)
            if trace_version(info) != version:
                raise Problem('The capture changed. Refresh the file list before retrying.', 409)
            with sftp.open(path, 'rb') as source:
                remaining = info.st_size
                while remaining:
                    chunk = source.read(min(1024*1024,remaining))
                    if not chunk:
                        raise Problem('The capture changed while reading. Refresh and retry.', 409)
                    target.write(chunk)
                    remaining -= len(chunk)
                if trace_version(source.stat()) != version or trace_version(sftp.stat(path)) != version:
                    raise Problem('The capture is still being written. Refresh and retry after recording has stopped.', 409)
        target.seek(0)
        yield target, info.st_size


def trace_flow(query):
    if not TRACE_GATE.acquire(blocking=False):
        raise Problem('Another capture is being analyzed. Try again shortly.', 429)
    try:
        with trace_copy(query.get('name', ''), query.get('version', ''), TRACE_ANALYSIS_LIMIT) as (source, size):
            content = source.read()
        from trace_tools import parse_capture
        try:
            result = parse_capture(content)
        except ValueError as exc:
            raise Problem(str(exc), 422) from exc
        result.update(name=query['name'], sizeBytes=size, sha256=hashlib.sha256(content).hexdigest(), version=query['version'])
        audit('trace-analysis', 'success', filename=query['name'])
        return result
    finally:
        TRACE_GATE.release()


DIAGNOSTIC_KPIS = ('sysCPUUtil', 'sysMemoryUtil', 'globalSessions', 'sipRegistrations',
                   'sessCapacityUtil', 'dosThresholdCounters', 'SipInviteDetailStats')


def diagnostic_fields(root, limit=500):
    fields = []
    def walk(node, path):
        if not len(node):
            if len(fields) < limit:
                fields.append(dict(name=path, value=node.text or ''))
            return
        counts = {}
        for child in node:
            counts[child.tag] = counts.get(child.tag, 0) + 1
            suffix = '[' + str(counts[child.tag]) + ']' if sum(c.tag == child.tag for c in node) > 1 else ''
            walk(child, (path + '.' if path else '') + child.tag + suffix)
    data = root.find('data')
    if data is not None:
        for child in data:
            walk(child, child.tag)
    return fields


def diagnostics_snapshot():
    sections = {}
    def collect(name, path):
        try:
            root = SBC_CLIENT.get(path)
            sections[name] = dict(ok=True, fields=diagnostic_fields(root), xml=serial(root))
            return root
        except (Problem, OSError, http.client.HTTPException) as exc:
            sections[name] = dict(ok=False, error=str(exc))
            return None
    for name, path in [('system', 'system/status'), ('information', 'system/information'),
                       ('storage', 'system/storage')]:
        collect(name, path)
    discovery = collect('discovery', 'statistics/kpiTypes')
    available = set()
    if discovery is not None:
        for link in discovery.findall('./links/link'):
            parsed = urlsplit(link.text or '')
            # Extract type names only; never request URLs supplied by discovery.
            if parsed.path == '/rest/v1.2/statistics/kpiTypes':
                available.update(parse_qs(parsed.query).get('type', []))
    for kind in DIAGNOSTIC_KPIS:
        if kind in available:
            collect(kind, 'statistics/kpis?' + urlencode({'type': kind}))
        else:
            sections[kind] = dict(ok=False, error='This metric is not advertised by the SBC.' if discovery is not None else 'Metric discovery failed.')
    try:
        tables = [c.get('name', '') for c in lrt_configs(True)]
        table_error = ''
    except (Problem, OSError, http.client.HTTPException) as exc:
        tables, table_error = [], str(exc)
    return dict(checkedAt=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), host=SBC_CLIENT.host,
                sections=sections, lrtTables=tables, lrtError=table_error)


def diagnostic_route(query):
    name, user = query.get('name', ''), query.get('user', '').strip()
    if not user or len(user) > 256 or any(ord(c) < 32 for c in user):
        raise Problem('Enter a number or user, up to 256 characters.')
    if name not in [c.get('name') for c in lrt_configs(True)]:
        raise Problem('Select a running local route table.', 404)
    root = SBC_CLIENT.get('admin/test/lrt?' + urlencode(dict(lrtName=name, user=user, maxElements=100, offset=1)))
    return dict(name=name, user=user, fields=diagnostic_fields(root), xml=serial(root),
                checkedAt=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))


def metadata(kind):
    root = SBC_CLIENT.get('configuration/elementTypes/metadata?' + urlencode({'elementType': kind}))
    attrs = []
    def walk(node, scope):
        for a in node.findall('attributeMetadata'):
            attrs.append(dict(name=text(a, 'name'), scope=scope, help=' '.join(a.find('descriptions').itertext()).strip() if a.find('descriptions') is not None else text(a, 'help'), key=text(a, 'key') == 'true', required=text(a, 'required') == 'true', type=text(a, 'valueType'), choices=[v.text or '' for v in a.findall('./validValues/validValue')], ranges=[dict(min=text(v, 'min'), max=text(v, 'max')) for v in a.findall('.//validNumericRange') if v.find('min') is not None]))
        for sub in node.findall('subAttributeMetadata'):
            walk(sub, scope + [text(sub, 'subElementName')])
    walk(root.find('data'), [])
    return attrs


def keys_for(element, meta):
    attrs = {text(a, 'name'): value_of(a) for a in element.findall('attribute')}
    return {m['name']: attrs.get(m['name'], '') for m in meta if m['key'] and not m.get('scope')}


def clean_payload(new, old):
    result = copy.deepcopy(new)
    old_attrs = {text(a, 'name'): value_of(a) for a in old.findall('attribute')}
    for a in list(result.findall('attribute')):
        name = text(a, 'name')
        if name.startswith('last-modified-') or (any(word in name.lower() for word in ('password', 'secret', 'passphrase', 'private-key')) and old_attrs.get(name) == value_of(a)):
            result.remove(a)
    for i, child in enumerate(list(result.findall('subElement'))):
        previous = old.findall('subElement')
        if i < len(previous):
            cleaned = clean_payload(child, previous[i])
            result.remove(child)
            result.append(cleaned)
    return result


def replacement_required(snap, changes):
    return not snap.get('creating', False) and any(c.get('key', False) for c in changes)


def check_replacement_secrets(old, new):
    previous, requested = attribute_values(old), attribute_values(new)
    for field, value in previous.items():
        if value and any(word in field.rsplit('.', 1)[-1].lower() for word in ('password', 'secret', 'passphrase', 'private-key')) and requested.get(field) == value:
            raise Problem('Changing key fields replaces the instance. Re-enter the secret field ' + field + ' because the SBC may return a masked value. Other edits can be applied without re-entering it.')


def prepare(session, body):
    snap = SNAPSHOTS.get(body.get('snapshot'))
    if not snap or snap['session'] != session or time.time() > snap['expires']:
        raise Problem('This snapshot has expired. Reload the element.', 409)
    old = xml(snap['xml'])
    new = xml(body.get('xml', ''))
    creating = snap.get('creating', False)
    if new.tag != 'configElement' or text(new, 'elementType') != snap['kind']:
        raise Problem('The document must contain a configElement of the same type.')
    changes = []
    def walk(a, b, path, scope):
        if a.tag != b.tag or a.attrib != b.attrib or [c.tag for c in a] != [c.tag for c in b]:
            raise Problem('Preserve the XML structure; edit parameter values.')
        aa = {text(x, 'name'): value_of(x) for x in a.findall('attribute')}
        bb = {text(x, 'name'): value_of(x) for x in b.findall('attribute')}
        if len(bb) != len(b.findall('attribute')) or set(aa) != set(bb):
            raise Problem('Preserve existing attributes while editing; change their values.')
        for m in snap['meta']:
            if m.get('scope', []) == scope and (m['key'] or (creating and m.get('required'))) and not bb.get(m['name'], '').strip():
                raise Problem('Required field: ' + path + m['name'])
        for name in aa:
            if aa[name] != bb[name] or (creating and bb[name] and not name.startswith('last-modified-')):
                m = next((m for m in snap['meta'] if m['name'] == name and m.get('scope', []) == scope), None)
                if name.startswith('last-modified-'):
                    raise Problem('The last-modified fields are read only.')
                if m and m.get('type') == 'enum' and m['choices'] and bb[name] not in m['choices'] and not (bb[name] == '' and '""' in m['choices']):
                    raise Problem('Invalid value for ' + path + name)
                if m and m['ranges']:
                    try:
                        valid = any(int(r['min']) <= int(bb[name]) <= int(r['max']) for r in m['ranges'])
                    except ValueError:
                        valid = False
                    if not valid:
                        raise Problem('Value out of range for ' + path + name)
                secret = any(x in name.lower() for x in ('password', 'secret', 'passphrase', 'private-key'))
                changes.append(dict(field=path + name, before='Not present' if creating else ('••••' if secret else aa[name]), after='••••' if secret else bb[name], key=bool(m and m['key'])))
        sa, sb = a.findall('subElement'), b.findall('subElement')
        if len(sa) != len(sb):
            raise Problem('This version edits existing subelements. Preserve their structure.')
        for i, (ca, cb) in enumerate(zip(sa, sb)):
            sub_type = text(ca, 'subElementType')
            if sub_type != text(cb, 'subElementType'):
                raise Problem('Preserve subelement types and order.')
            walk(ca, cb, path + sub_type + '[' + str(i + 1) + '].', scope + [sub_type])
    walk(old, new, '', [])
    if not changes:
        raise Problem('There are no changes to apply.')
    if replacement_required(snap, changes):
        check_replacement_secrets(old, new)
    return snap, old, new, changes


class Handler(BaseHTTPRequestHandler):
    server_version = 'SBCConsole'

    def log_message(self, fmt, *args):
        pass  # Request bodies, credentials and configuration are never logged.

    def send(self, status, value, cookie=None, content_type='application/json; charset=utf-8'):
        data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(data)

    def download_trace(self, query):
        with trace_copy(query.get('name', ''), query.get('version', ''), TRACE_DOWNLOAD_LIMIT) as (source, size):
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(size))
            self.send_header('Content-Disposition', "attachment; filename*=UTF-8''" + quote(query['name'], safe=''))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
            self.end_headers()
            while True:
                chunk = source.read(1024*1024)
                if not chunk:break
                self.wfile.write(chunk)
        audit('trace-download', 'success', filename=query['name'])

    def session(self):
        devices_tools.CONTEXT.set(None)
        rest_activity.CONTEXT.session=''
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', ''))
            sid = cookie['sbc_session'].value
        except Exception:
            raise Problem('Sign in to continue.', 401)
        item = SESSIONS.get(sid)
        if not item or item['expires'] < time.time():
            raise Problem('Your session has expired.', 401)
        user = USERS.current(item.get('username'), item.get('auth_version'))
        if not user:
            raise Problem('Your session has expired. Sign in again.', 401)
        item['user'] = user
        rest_activity.CONTEXT.session=sid
        rest_activity.CONTEXT.source=urlsplit(self.path).path
        if DEVICES.initialized:
            records=DEVICES.records()
            chosen=next((r for r in records if r['id']==item.get('device_id')),None)
            if chosen is None:chosen=next((r for r in records if r['id']=='bootstrap'),records[0] if records else None)
            item['device_id']=chosen['id'] if chosen else None
            if chosen:devices_tools.CONTEXT.set(runtime(chosen))
        return sid, item

    def guard_device(self,path,write=False):
        if not DEVICES.initialized:return
        if path in ('/api/session','/api/login','/api/logout','/api/audit') or path.startswith(('/api/users','/api/recordings','/api/rest-activity')):return
        current=devices_tools.CONTEXT.get()
        if current is None:raise Problem('Add or select a managed device first.',409)
        if write:
            try:latest=DEVICES.get(current.record['id'])
            except devices_tools.DeviceError:raise Problem('The device was removed. Reload the page.',409) from None
            if latest['version']!=current.record['version']:raise Problem('The device settings changed. Reload the page.',409)
        identifier=self.headers.get('X-Device-ID')
        version=self.headers.get('X-Device-Version')
        if (write or identifier is not None) and (identifier!=current.record['id'] or version!=str(current.record['version'])):
            raise Problem('The selected device changed. Reload the page before continuing.',409)

    def body(self):
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length <= 2_000_000:
            raise Problem('Invalid request size.', 413)
        if not self.headers.get('Content-Type', '').startswith('application/json'):
            raise Problem('JSON is required.', 415)
        try:
            result = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeError):
            raise Problem('The JSON request is invalid.', 400) from None
        if not isinstance(result, dict):raise Problem('A JSON object is required.', 400)
        return result

    def issue_session(self, user, previous=None):
        with AUTH_GATE:
            if previous:SESSIONS.pop(previous, None)
            sid = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(32)
            SESSIONS[sid] = dict(csrf=csrf, expires=time.time()+8*3600, username=user['username'], auth_version=user['version'], user=user)
        secure = '; Secure' if isinstance(self.connection, ssl.SSLSocket) else ''
        return csrf, 'sbc_session='+sid+'; Path=/; HttpOnly; SameSite=Strict'+secure

    def auth_attempt(self, key):
        with AUTH_GATE:
            now = time.time()
            attempts = [t for t in ATTEMPTS.get(key, []) if t > now-300]
            if len(attempts) >= 10:raise Problem('Too many attempts. Wait five minutes.', 429)
            ATTEMPTS[key] = attempts+[now]

    def do_GET(self):
        devices_tools.CONTEXT.set(None)
        try:
            parsed = urlsplit(self.path)
            p = parsed.path
            if p in ('/', '/app.js', '/rest-activity.js', '/lrt.js', '/diagnostics.js', '/diagnostic-charts.js', '/traces.js', '/snmp.js', '/traps.js', '/cdr.js', '/recordings.js', '/users.js', '/devices.js', '/style.css'):
                name = 'index.html' if p == '/' else p[1:]
                mime = {'index.html': 'text/html', 'app.js': 'text/javascript', 'rest-activity.js':'text/javascript', 'lrt.js': 'text/javascript', 'diagnostics.js': 'text/javascript', 'diagnostic-charts.js': 'text/javascript', 'traces.js': 'text/javascript', 'snmp.js': 'text/javascript', 'traps.js': 'text/javascript', 'cdr.js': 'text/javascript', 'recordings.js': 'text/javascript', 'users.js': 'text/javascript', 'devices.js':'text/javascript', 'style.css': 'text/css'}[name]
                return self.send(200, (BASE / 'static' / name).read_bytes(), content_type=mime + '; charset=utf-8')
            sid, session = self.session()
            q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            if p in ('/api/devices','/api/devices/detail'):
                if p.endswith('/detail'):
                    if session['user']['role']!='admin':raise Problem('Only administrators can edit devices.',403)
                    return self.send(200,dict(device=devices_tools.public(DEVICES.get(q.get('id','')),True)))
                return self.send(200,dict(devices=DEVICES.listing(),selected=session.get('device_id')))
            self.guard_device(p)
            if p == '/api/users':
                if session['user']['role'] != 'admin':raise Problem('Only administrators can manage users.', 403)
                return self.send(200, dict(users=USERS.listing()))
            if p == '/api/rest-activity':
                try:after=int(q.get('after','0'))
                except ValueError:raise Problem('Invalid activity cursor.',400)
                return self.send(200,rest_activity.listing(sid,max(0,after)))
            # Trace transfers and offline parsing do not hold the configuration lock.
            if p == '/api/traces':
                return self.send(200, trace_list())
            if p == '/api/traces/flow':
                return self.send(200, trace_flow(q))
            if p == '/api/traces/download':
                return self.download_trace(q)
            if p == '/api/recordings' or p.startswith('/api/recordings/'):
                import recordings_tools as recordings
                try:
                    if p == '/api/recordings':
                        try:offset,limit=int(q.get('offset','0')),int(q.get('limit','50'))
                        except ValueError:raise Problem('Invalid recording pagination.',400)
                        return self.send(200,recordings.listing(q.get('q',''),offset,limit))
                    if p == '/api/recordings/detail':return self.send(200,recordings.detail(q.get('id','')))
                    if p == '/api/recordings/audio':
                        filename=recordings.resolve_audio(q.get('id',''),q.get('file',''))
                        with recordings.opened(filename,'.wav') as source:
                            size=os.fstat(source.fileno()).st_size
                            start,end,partial=recordings.byte_range(self.headers.get('Range',''),size)
                            length=end-start+1 if size else 0
                            self.send_response(206 if partial else 200);self.send_header('Content-Type','audio/wav');self.send_header('Content-Length',str(length));self.send_header('Accept-Ranges','bytes');self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Disposition',('attachment' if q.get('download')=='true' else 'inline')+"; filename*=UTF-8''"+quote(filename,safe=''))
                            if partial:self.send_header('Content-Range',f'bytes {start}-{end}/{size}')
                            self.end_headers();source.seek(start);remaining=length
                            while remaining:
                                chunk=source.read(min(1024*1024,remaining))
                                if not chunk:break
                                self.wfile.write(chunk);remaining-=len(chunk)
                        return
                    raise Problem('Resource not found.',404)
                except recordings.RecordingError as exc:raise Problem(str(exc),exc.code) from exc
            if p == '/api/cdr' or p.startswith('/api/cdr/'):
                import cdr_tools as cdr
                if p == '/api/cdr':return self.send(200,cdr_list())
                if p == '/api/cdr/download':
                    with cdr_copy(q.get('name',''),q.get('version','')) as (source,size):
                        self.send_response(200);self.send_header('Content-Type','application/octet-stream');self.send_header('Content-Length',str(size));self.send_header('Content-Disposition',"attachment; filename*=UTF-8''"+quote(q['name'],safe=''));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'none'");self.end_headers()
                        while True:
                            chunk=source.read(1024*1024)
                            if not chunk:break
                            self.wfile.write(chunk)
                    return
                if p not in ('/api/cdr/records','/api/cdr/record'):raise Problem('Resource not found.',404)
                data=cdr_data(q)
                try:
                    if p == '/api/cdr/records':result=cdr.page(data,q.get('q',''),q.get('type',''),int(q.get('offset','0')),int(q.get('limit','50')))
                    else:
                        record_id=int(q.get('id','0'))
                        if not 1<=record_id<=len(data['records']):raise Problem('CDR record not found.',404)
                        result=cdr.detail(data['records'][record_id-1])
                except ValueError:raise Problem('Invalid CDR pagination or record ID.',400)
                except cdr.CdrError as exc:raise Problem(str(exc),exc.code) from exc
                return self.send(200,result)
            if p == '/api/traps' or p.startswith('/api/traps/'):
                import trap_tools
                try:
                    if p == '/api/traps':data=trap_tools.STORE.overview()
                    elif p in ('/api/traps/events','/api/traps/export'):
                        try:offset,limit=int(q.get('offset','0')),int(q.get('limit','50'))
                        except ValueError:raise Problem('Invalid trap pagination.',400)
                        if p == '/api/traps/export':offset,limit=0,500
                        data=trap_tools.STORE.query(q.get('q','')[:300],q.get('severity',''),q.get('version',''),offset,limit,details=p.endswith('/export'))
                    elif p == '/api/traps/event':
                        try:event_id=int(q.get('id','0'))
                        except ValueError:raise Problem('Invalid trap event ID.',400)
                        data=trap_tools.STORE.event(event_id)
                        if not data:raise Problem('Trap event not found or no longer retained.',404)
                    else:raise Problem('Resource not found.',404)
                except trap_tools.TrapError as exc:raise Problem(str(exc),400) from exc
                return self.send(200,data)
            if p.startswith('/api/snmp'):
                import snmp_tools
                try:
                    if p == '/api/snmp':
                        data=(devices_tools.CONTEXT.get().monitor if devices_tools.CONTEXT.get() else snmp_tools.MONITOR).status(refresh=q.get('refresh')=='true',discover=q.get('discover')=='true')
                    elif p == '/api/snmp/objects':
                        try:offset,limit=int(q.get('offset','0')),int(q.get('limit','100'))
                        except ValueError:raise Problem('Invalid SNMP pagination.',400)
                        if offset<0 or not 1<=limit<=200:raise Problem('Invalid SNMP pagination.',400)
                        data=(devices_tools.CONTEXT.get().monitor if devices_tools.CONTEXT.get() else snmp_tools.MONITOR).objects(q.get('q','')[:500],q.get('module','')[:100],offset,limit)
                    elif p == '/api/snmp/get':data=(devices_tools.CONTEXT.get().monitor if devices_tools.CONTEXT.get() else snmp_tools.MONITOR).get_one(q.get('oid',''))
                    elif p == '/api/snmp/export':data=(devices_tools.CONTEXT.get().monitor if devices_tools.CONTEXT.get() else snmp_tools.MONITOR).export()
                    else:raise Problem('Resource not found.',404)
                except snmp_tools.SnmpError as exc:raise Problem(str(exc),exc.code) from exc
                return self.send(200,data)
            with GATE:
                if p == '/api/session':
                    data = dict(csrf=session['csrf'], host=SBC_CLIENT.host if not DEVICES.initialized or devices_tools.CONTEXT.get() else '', user=session['user']['username'], role=session['user']['role'], device=devices_tools.public(devices_tools.CONTEXT.get().record) if devices_tools.CONTEXT.get() else None)
                elif p == '/api/status':
                    versions = SBC_CLIENT.get('configuration/versions')
                    data = dict(version=serial(SBC_CLIENT.get('system/version')), versions=serial(versions), workflow=configuration_workflow(versions), pending=SBC_CLIENT.pending, blocked=SBC_CLIENT.blocked)
                elif p == '/api/diagnostics':
                    data = diagnostics_snapshot()
                elif p == '/api/diagnostics/route':
                    data = diagnostic_route(q)
                elif p == '/api/types':
                    data = element_types()
                elif p == '/api/template':
                    kind = q['type']
                    creatable_type(kind)
                    template = SBC_CLIENT.get('configuration/elementTypes/template?' + urlencode({'elementType': kind})).find('./data/configElement')
                    if template is None:
                        raise Problem('The SBC did not return a configuration template.', 502)
                    meta = metadata(kind)
                    identity = secrets.token_urlsafe(24)
                    raw = serial(template)
                    SNAPSHOTS[identity] = dict(session=sid, expires=time.time() + 1800, xml=raw, kind=kind, meta=meta, creating=True)
                    data = dict(item=dict(snapshot=identity, xml=raw, keys={}, creating=True), metadata=meta)
                elif p == '/api/elements':
                    kind = q['type']
                    running = q.get('running') == 'true'
                    params = {'elementType': kind}
                    if running:
                        params['running'] = 'true'
                    root = SBC_CLIENT.get('configuration/configElements?' + urlencode(params))
                    meta = metadata(kind)
                    entries = []
                    for key, snap in list(SNAPSHOTS.items()):
                        if snap['expires'] < time.time():
                            del SNAPSHOTS[key]
                    for e in root.findall('./data/configElement'):
                        identity = secrets.token_urlsafe(24)
                        raw = serial(e)
                        if not running:
                            SNAPSHOTS[identity] = dict(session=sid, expires=time.time() + 1800, xml=raw, kind=kind, meta=meta)
                        keys = keys_for(e, meta)
                        entries.append(dict(snapshot=identity if not running else None, xml=raw, keys=keys))
                    data = dict(items=entries, metadata=meta, running=running)
                elif p == '/api/audit':
                    path = STATE / 'audit.jsonl'
                    data = [json.loads(s) for s in path.read_text(encoding='utf-8').splitlines()[-100:]][::-1] if path.exists() else []
                elif p == '/api/backups':
                    data = dict(xml=serial(SBC_CLIENT.get('configuration/management/files')))
                elif p == '/api/lrt':
                    data = lrt_overview(q.get('running', 'true') == 'true', q.get('refresh') == 'true')
                elif p == '/api/lrt/entries':
                    try:
                        offset, limit = int(q.get('offset', '0')), int(q.get('limit', '50'))
                    except ValueError:
                        raise Problem('Invalid LRT pagination.')
                    if offset < 0 or not 1 <= limit <= 500:
                        raise Problem('Invalid LRT pagination.')
                    data = lrt_entries(q.get('name', ''), q.get('running', 'true') == 'true', q.get('q', '')[:500], offset, limit)
                else:
                    raise Problem('Resource not found.', 404)
            self.send(200, data)
        except Exception as exc:
            self.fail(exc)

    def do_POST(self):
        devices_tools.CONTEXT.set(None)
        try:
            path = urlsplit(self.path).path
            body = self.body()
            origin = self.headers.get('Origin')
            expected = ('https' if isinstance(self.connection, ssl.SSLSocket) else 'http') + '://' + self.headers.get('Host', '')
            if origin and origin != expected:
                raise Problem('Origin is not allowed.', 403)
            if path == '/api/login':
                address = self.client_address[0]
                now = time.time()
                self.auth_attempt(address)
                user = USERS.authenticate(body.get('username'), body.get('password'))
                if not user:
                    raise Problem('Incorrect username or password.', 401)
                with AUTH_GATE:
                    ATTEMPTS[address] = []
                    for s,v in list(SESSIONS.items()):
                        if v['expires'] < now:SESSIONS.pop(s,None)
                _, cookie = self.issue_session(user)
                audit('login', 'success', address=address, user=user['username'])
                return self.send(200, {'ok': True}, cookie=cookie)
            sid, session = self.session()
            if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
                raise Problem('Your editing session is not valid. Reload the page.', 403)
            if path.startswith('/api/devices'):
                if path=='/api/devices/select':
                    record=DEVICES.get(body.get('id',''))
                    session['device_id']=record['id']
                    return self.send(200,dict(ok=True))
                if session['user']['role']!='admin':raise Problem('Only administrators can manage devices.',403)
                if path=='/api/devices/read-ssh-key':
                    key,fingerprint=devices_tools.read_ssh_key(body.get('management_ip'),body.get('ssh_port',22))
                    return self.send(200,dict(public_key=key,fingerprint=fingerprint,verified=False))
                with DEVICE_GATE:
                    if path=='/api/devices':record=DEVICES.create(body)
                    elif path in ('/api/devices/update','/api/devices/delete'):
                        identifier=body.get('id','');previous=DEVICES.get(identifier);active=runtime(previous)
                        with active.gate:
                            if active.client.pending or active.client.blocked:raise Problem('Complete the pending SBC operation before changing this device.',409)
                            if path.endswith('/delete'):
                                DEVICES.delete(identifier,body.get('version'));record=None
                            else:record=DEVICES.update(identifier,body,body.get('version'))
                        RUNTIMES.pop(identifier,None)
                    else:raise Problem('Resource not found.',404)
                audit('device.'+('create' if path=='/api/devices' else path.rsplit('/',1)[1]),'success',user=session['user']['username'],target=record['id'] if record else identifier)
                return self.send(201 if path=='/api/devices' else 200,dict(device=devices_tools.public(record) if record else None))
            self.guard_device(path,write=True)
            if path in ('/api/users','/api/users/password','/api/users/reset-password'):
                actor = session['user']
                try:
                    if path == '/api/users':
                        if actor['role'] != 'admin':raise Problem('Only administrators can add users.',403)
                        user = USERS.create(body.get('username'),body.get('password'),body.get('role','user'))
                        audit('user.create','success',user=actor['username'],target=user['username'],role=user['role'])
                        return self.send(201,dict(user=user))
                    if path == '/api/users/reset-password' and actor['role'] != 'admin':
                        raise Problem('Only administrators can reset other users\' passwords.',403)
                    attempt_key = 'password:'+actor['username']+':'+self.client_address[0]
                    self.auth_attempt(attempt_key)
                    if path == '/api/users/password':
                        user = USERS.change_password(actor['username'],body.get('current_password'),body.get('new_password'))
                    else:
                        if not USERS.authenticate(actor['username'],body.get('current_password')):
                            raise Problem('Your current administrator password is incorrect.',400)
                        user = USERS.set_password(body.get('username'),body.get('new_password'))
                    with AUTH_GATE:ATTEMPTS.pop(attempt_key,None)
                    audit('user.password','success',user=actor['username'],target=user['username'])
                    if user['username'] == actor['username']:
                        token,cookie = self.issue_session(user,previous=sid)
                        return self.send(200,dict(ok=True,csrf=token),cookie=cookie)
                    return self.send(200,dict(ok=True))
                except users_tools.UserError as exc:
                    raise Problem(str(exc),exc.code) from exc
            if path == '/api/rest-activity/clear':
                return self.send(200,rest_activity.clear(sid))
            if path == '/api/recordings/delete':
                import recordings_tools as recordings
                try:
                    result=recordings.remove_recording(body.get('id',''))
                    audit('recording.delete','success',recording=body.get('id',''))
                    return self.send(200,result)
                except recordings.RecordingError as exc:raise Problem(str(exc),exc.code) from exc
            with GATE:
                self.guard_device(path,write=True)
                if path == '/api/logout':
                    SESSIONS.pop(sid,None)
                    result = {'ok': True}
                elif path == '/api/lrt/preview':
                    result = prepare_lrt_change(sid, body)
                elif path == '/api/lrt/apply':
                    result = apply_lrt_change(sid, body)
                elif path == '/api/lrt/reload':
                    result = reload_lrt(body)
                elif path in ('/api/preview', '/api/update', '/api/create'):
                    snap, old, new, changes = prepare(sid, body)
                    creating = snap.get('creating', False)
                    if path != '/api/preview' and creating != (path == '/api/create'):
                        raise Problem('This form belongs to a different operation. Reload it.', 409)
                    if path == '/api/preview':
                        result = dict(changes=changes, creating=creating, replacement=replacement_required(snap, changes))
                    else:
                        def update():
                            replacing = replacement_required(snap, changes)
                            params = dict(elementType=snap['kind'], **keys_for(new if creating else old, snap['meta']))
                            if creating:
                                creatable_type(snap['kind'])
                                candidates = SBC_CLIENT.get('configuration/configElements?' + urlencode({'elementType': snap['kind']})).findall('./data/configElement')
                                if any(keys_for(e, snap['meta']) == keys_for(new, snap['meta']) for e in candidates):
                                    raise Problem('An instance with these keys already exists. Choose different keys.', 409)
                            else:
                                current = SBC_CLIENT.get('configuration/configElements?' + urlencode(params)).find('./data/configElement')
                                if current is None or canonical(current) != canonical(old):
                                    raise Problem('The element has changed since you opened it. Reload before editing.', 409)
                                if replacing and keys_for(new, snap['meta']) != keys_for(old, snap['meta']):
                                    candidates = SBC_CLIENT.get('configuration/configElements?' + urlencode({'elementType': snap['kind']})).findall('./data/configElement')
                                    if any(keys_for(e, snap['meta']) == keys_for(new, snap['meta']) for e in candidates):
                                        raise Problem('An instance with the requested keys already exists.', 409)
                            backup = 'web-before-' + time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3) + '.gz'
                            SBC_CLIENT.operation('POST', 'configuration/management?' + urlencode(dict(action='backup', backupSource='editing', filename=backup)))
                            if not creating:
                                (STATE / (backup + '.xml')).write_text(serial(old), encoding='utf-8')
                            if replacing:
                                info = next((t for t in element_types() if t['name'] == snap['kind']), None)
                                if info is None:
                                    raise Problem('The SBC no longer supports this element type.', 409)
                                try:
                                    SBC_CLIENT.call('DELETE', 'configuration/configElements?' + urlencode(params))
                                    if info['single']:
                                        shell = ET.Element('configElement')
                                        ET.SubElement(shell, 'elementType').text = snap['kind']
                                        SBC_CLIENT.call('POST', 'configuration/configElements', config_request(shell))
                                        SBC_CLIENT.call('PUT', 'configuration/configElements', config_request(clean_payload(new, old)))
                                    else:
                                        SBC_CLIENT.call('POST', 'configuration/configElements', config_request(clean_payload(new, old)))
                                    params = dict(elementType=snap['kind'], **keys_for(new, snap['meta']))
                                    actual = SBC_CLIENT.get('configuration/configElements?' + urlencode(params)).find('./data/configElement')
                                    confirm_update(actual, new, changes)
                                except Exception:
                                    try:
                                        SBC_CLIENT.operation('PUT', 'configuration/management?' + urlencode(dict(action='restore', restoreSource='backupFile', filename=backup)))
                                    except Exception:
                                        audit('replace-recovery', 'failed', type=snap['kind'], backup=backup)
                                        raise Problem('Instance replacement failed and automatic recovery could not be confirmed. Check the SBC editing configuration before retrying. Recovery backup: ' + backup, 502)
                                    audit('replace-recovery', 'success', type=snap['kind'], backup=backup)
                                    raise Problem('Instance replacement failed. The previous editing configuration was restored from backup. Reload the instance before retrying.', 502)
                            else:
                                SBC_CLIENT.call('POST' if creating else 'PUT', 'configuration/configElements', config_request(clean_payload(new, old)))
                                actual = SBC_CLIENT.get('configuration/configElements?' + urlencode(params)).find('./data/configElement')
                                confirm_update(actual, new, changes)
                            audit('create' if creating else 'replace' if replacing else 'update', 'success', type=snap['kind'], fields=[c['field'] for c in changes], backup=backup)
                            del SNAPSHOTS[body['snapshot']]
                            return dict(message='Instance created in the editing configuration. Save and activate when ready.' if creating else 'Changes applied to the editing configuration. Verify and save before activating.', backup=backup, keys=keys_for(new, snap['meta']))
                        result = SBC_CLIENT.transaction(update)
                elif path == '/api/action':
                    action = body.get('action')
                    if action not in ('verify', 'save', 'activate', 'backup'):
                        raise Problem('Action is not allowed.')
                    def perform():
                        params = {'action': action}
                        report = None
                        if action == 'backup':
                            params.update(backupSource='running', filename='web-running-' + time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3) + '.gz')
                        if action in ('save', 'activate'):
                            verified = SBC_CLIENT.operation('PUT', 'configuration/management?action=verify')
                            report = verification_report(verified)
                        if action == 'activate':
                            SBC_CLIENT.operation('POST', 'configuration/management?' + urlencode(dict(action='backup', backupSource='running', filename='web-pre-activate-' + time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3) + '.gz')))
                            SBC_CLIENT.operation('PUT', 'configuration/management?action=save')
                        response = SBC_CLIENT.operation('POST' if action in ('activate', 'backup') else 'PUT', 'configuration/management?' + urlencode(params))
                        report = verification_report(response) or report
                        attention = report and (report['errors'] or report['criticals'] or report['warnings'])
                        audit(action, 'attention' if attention else 'success')
                        return dict(message='Verification completed. Review the results below.' if action == 'verify' else 'Operation completed: ' + action, xml=serial(response), verification=report)
                    result = SBC_CLIENT.transaction(perform)
                elif path == '/api/check-operation':
                    _, root = SBC_CLIENT.raw('GET', 'admin/asyncstatus')
                    status = text(root, './/operationState/status').lower()
                    if status in ('success', 'fail', 'failed', 'failure', 'error') and (SBC_CLIENT.pending or SBC_CLIENT.blocked):
                        SBC_CLIENT.raw('POST', 'configuration/unlock')
                        SBC_CLIENT.pending = False
                        SBC_CLIENT.blocked = False
                    result = dict(xml=serial(root), pending=SBC_CLIENT.pending, blocked=SBC_CLIENT.blocked)
                else:
                    raise Problem('Resource not found.', 404)
            self.send(200, result)
        except Exception as exc:
            self.fail(exc)

    def fail(self, exc):
        if isinstance(exc,devices_tools.DeviceError):exc=Problem(str(exc),exc.code)
        code = exc.code if isinstance(exc, Problem) else 502
        message = str(exc) if isinstance(exc, Problem) else 'The request could not be completed: ' + type(exc).__name__
        if self.command == 'POST' and self.path != '/api/login':
            audit('request', 'failed', path=urlsplit(self.path).path, error=type(exc).__name__, status=code)
        self.send(code, dict(error=message, **(exc.details if isinstance(exc, Problem) else {})))


def main():
    for required in ('APP_PASSWORD_HASH',):
        if not os.environ.get(required):
            raise SystemExit('Missing environment variable ' + required)
    USERS.initialize(os.environ.get('APP_USER','admin'),os.environ['APP_PASSWORD_HASH'])
    DEVICES.initialize()
    host = os.environ.get('BIND_HOST', '127.0.0.1')
    cert = os.environ.get('TLS_CERT')
    if host not in ('127.0.0.1', 'localhost') and not cert:
        raise SystemExit('HTTPS is required to listen on the network.')
    server = ThreadingHTTPServer((host, int(os.environ.get('PORT', '8443'))), Handler)
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, os.environ['TLS_KEY'])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print('SBC Console ready', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
