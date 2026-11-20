"""Bounded offline PCAP decoding. Does not open sockets or execute commands."""
import hashlib
import io
import re
import socket
import struct
import time
from collections import defaultdict

MAX_PACKETS = 200000
MAX_MESSAGES = 2000
MAX_TEXT = 8 * 1024 * 1024
SIP_START = re.compile(rb'(?:SIP/2\.0 [1-6][0-9]{2}[^\r\n]*|[A-Z][A-Z0-9_.-]{1,30} [^\s]+ SIP/2\.0)\r?\n')


def sip_messages(data, tcp=False):
    """Yield complete SIP PDUs; consume bodies before searching for the next PDU."""
    offset = 0
    while offset < len(data):
        start = SIP_START.search(data, offset)
        if not start:
            return
        if start.start() != offset and data[start.start()-1:start.start()] not in (b'\n', b'\r'):
            offset = start.end()
            continue
        match = re.search(rb'\r?\n\r?\n', data[start.start():])
        if not match:
            return
        header_end = start.start() + match.end()
        header = data[start.start():header_end].decode('utf-8', 'replace')
        lines = re.split(r'\r?\n', header.rstrip('\r\n'))
        headers = {}
        key = ''
        for line in lines[1:]:
            if line[:1] in (' ', '\t') and key:
                headers[key] += ' ' + line.strip()
            elif ':' in line:
                key, value = line.split(':', 1)
                key = key.lower().strip()
                if key not in headers:
                    headers[key] = value.strip()
        length = headers.get('content-length', headers.get('l'))
        if length is not None:
            if not length.isdigit() or int(length) > 1024 * 1024:
                offset = header_end
                continue
            end = header_end + int(length)
        elif tcp:
            end = header_end
        else:
            end = len(data)
        if end > len(data):
            return
        raw = data[start.start():end]
        call_id = headers.get('call-id', headers.get('i', ''))[:1024]
        if call_id:
            yield dict(callId=call_id, label=lines[0][:512], cseq=headers.get('cseq', '')[:256],
                       fromHeader=headers.get('from', headers.get('f', ''))[:1024],
                       toHeader=headers.get('to', headers.get('t', ''))[:1024],
                       raw=raw[:65536].decode('utf-8', 'replace'), rawTruncated=len(raw)>65536,
                       fingerprint=hashlib.sha256(raw).hexdigest(), offset=start.start())
        offset = max(end, header_end)


def related_call_groups(calls, messages):
    """Infer Oracle B2BUA legs conservatively; preserve every original Call-ID."""
    first = {}
    for message in messages:
        if not message['label'].startswith('SIP/'):
            first.setdefault(message['callId'], message)
    parent = {call['callId']:call['callId'] for call in calls}
    def root(key):
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key
    buckets = defaultdict(list)
    def uri(value):
        match = re.search(r'(?i)\b(sips?:[^>\s;]+)', value)
        return match.group(1) if match else ''
    for call in calls:
        message = first.get(call['callId'])
        if message is None:continue
        tag = re.search(r'(?:^|;)\s*tag=("[^"]+"|[^;\s]+)', message['fromHeader'], re.I)
        cseq = re.match(r'\s*(\d+)\s+(\S+)', message['cseq'])
        if not tag or not cseq:continue
        tag = tag.group(1).strip('"')
        oracle = re.match(r'^(SD[A-Za-z0-9]+-)(.+)$', tag)
        rewritten = bool(oracle and call['callId'].startswith(oracle.group(1)))
        canonical = oracle.group(2) if rewritten else tag
        caller, callee = uri(message['fromHeader']), uri(message['toHeader'])
        if not caller or not callee:continue
        key = (canonical, caller, callee, cseq.group(1), cseq.group(2))
        buckets[key].append((message['timestamp'], call['callId'], rewritten, set(call['participants'])))
    for bucket in buckets.values():
        bucket.sort(key=lambda item:item[0])
        for index, left in enumerate(bucket):
            for right in bucket[index+1:]:
                if right[0]-left[0] > 5:break
                if not (left[2] or right[2]) or left[3] == right[3]:continue
                parent[root(right[1])] = root(left[1])
    groups = defaultdict(list)
    for call in calls:groups[root(call['callId'])].append(call['callId'])
    return [dict(callIds=ids, reason='Inferred from Oracle From-tag rewriting, matching caller/callee and CSeq within 5 seconds.') for ids in groups.values() if len(ids)>1]


def parse_capture(content):
    try:
        import dpkt
    except ImportError:
        raise ValueError('The PCAP decoder dependency is not installed.')
    started = time.monotonic()
    source = io.BytesIO(content)
    try:
        if content.startswith(b'\x0a\x0d\x0d\x0a'):
            reader = dpkt.pcapng.Reader(source)
            # dpkt exposes one link type. Reject captures with multiple interface types.
            endian = '<' if content[8:12] == b'\x4d\x3c\x2b\x1a' else '>'
            pos, links = 0, set()
            while pos + 12 <= len(content):
                kind, size = struct.unpack_from(endian+'II', content, pos)
                if size < 12 or size % 4 or pos + size > len(content):
                    raise ValueError('The PCAPNG block is truncated or invalid.')
                if kind == 1:
                    links.add(struct.unpack_from(endian+'H', content, pos+8)[0])
                if len(links) > 1:
                    raise ValueError('PCAPNG captures with mixed interface link types require Wireshark. Download this file to inspect it.')
                pos += size
        else:
            reader = dpkt.pcap.Reader(source)
        link = reader.datalink()
    except (ValueError, struct.error, dpkt.dpkt.UnpackError) as exc:
        raise ValueError('Cannot read capture: ' + str(exc)) from exc
    if link not in (0, 1, 12, 101, 108, 113, 228, 229, 276):
        raise ValueError('Unsupported capture link type '+str(link)+'. Download this file to inspect it in Wireshark.')
    messages, streams, epochs = [], defaultdict(list), defaultdict(int)
    warning_counts = defaultdict(int)
    packets = 0
    total_text = 0
    limited = False

    def add(data, timestamp, frame, src, dst, transport, tcp=False, spans=None):
        nonlocal total_text, limited
        for message in sip_messages(data, tcp):
            if len(messages) >= MAX_MESSAGES or total_text >= MAX_TEXT:
                limited = True
                return
            if spans:
                timestamp, frame = next(((ts, fr) for end, ts, fr in spans if end > message['offset']), (timestamp, frame))
            message.pop('offset')
            total_text += len(message['raw'].encode('utf-8'))
            message.update(timestamp=timestamp, frame=frame, src=src, dst=dst, transport=transport)
            messages.append(message)

    try:
        for timestamp, raw in reader:
            packets += 1
            if packets > MAX_PACKETS or time.monotonic()-started > 20:
                limited = True
                break
            try:
                if link == 1:
                    ip = dpkt.ethernet.Ethernet(raw).data
                elif link == 113:
                    ip = dpkt.sll.SLL(raw).data
                elif link == 276:
                    if len(raw) < 20:raise ValueError('Short SLL2 header')
                    ip = dpkt.ip.IP(raw[20:]) if raw[20] >> 4 == 4 else dpkt.ip6.IP6(raw[20:])
                elif link in (0, 108):
                    ip = dpkt.loopback.Loopback(raw).data
                else:
                    ip = dpkt.ip.IP(raw) if raw[0] >> 4 == 4 else dpkt.ip6.IP6(raw)
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                if isinstance(ip, dpkt.ip.IP) and (ip.offset or ip.mf):
                    warning_counts['Fragmented IP packets were omitted'] += 1
                    continue
                if isinstance(ip, dpkt.ip6.IP6) and 44 in getattr(ip, 'extension_hdrs', {}):
                    warning_counts['Fragmented IP packets were omitted'] += 1
                    continue
                family = socket.AF_INET if len(ip.src) == 4 else socket.AF_INET6
                src_ip, dst_ip = socket.inet_ntop(family, ip.src), socket.inet_ntop(family, ip.dst)
                packet = ip.data
                if not isinstance(packet, (dpkt.udp.UDP, dpkt.tcp.TCP)):
                    continue
                src = ('['+src_ip+']' if family==socket.AF_INET6 else src_ip)+':'+str(packet.sport)
                dst = ('['+dst_ip+']' if family==socket.AF_INET6 else dst_ip)+':'+str(packet.dport)
                payload = bytes(packet.data)
                if isinstance(packet, dpkt.udp.UDP):
                    if payload:
                        add(payload, float(timestamp), packets, src, dst, 'UDP')
                else:
                    key = (src, dst)
                    if packet.flags & dpkt.tcp.TH_SYN:
                        epochs[key] += 1
                    if payload:
                        streams[(src, dst, epochs[key])].append((packet.seq + bool(packet.flags & dpkt.tcp.TH_SYN), payload, float(timestamp), packets))
            except (ValueError, IndexError, struct.error, dpkt.dpkt.UnpackError):
                warning_counts['Undecodable packets were omitted'] += 1
            if limited:
                break
    except (ValueError, struct.error, dpkt.dpkt.UnpackError) as exc:
        warning_counts['Capture ended with incomplete packet data'] += 1
    # Reassemble each direction by sequence number; preserve UDP retransmissions.
    # A gap starts a new contiguous chunk, so bytes across missing segments are never joined.
    for (src, dst, epoch), segments in streams.items():
        if limited or time.monotonic()-started > 25:
            limited = True
            break
        base = segments[0][0]
        ordered = sorted(((((seq-base+2**31) % 2**32)-2**31, payload, ts, frame) for seq,payload,ts,frame in segments), key=lambda item:(item[0],item[3]))
        chunk, spans, end = bytearray(), [], None
        for seq, payload, ts, frame in ordered:
            if end is not None and seq > end:
                add(bytes(chunk), ts, frame, src, dst, 'TCP', True, spans)
                chunk, spans = bytearray(), []
                warning_counts['TCP gaps: incomplete SIP messages may be omitted'] += 1
                end = seq
            if end is None:
                end = seq
            overlap = max(0, end-seq)
            fresh = payload[overlap:]
            if fresh:
                chunk.extend(fresh)
                spans.append((len(chunk), ts, frame))
                end = seq+len(payload)
        if chunk:
            add(bytes(chunk), segments[0][2], segments[0][3], src, dst, 'TCP', True, spans)
    messages.sort(key=lambda m:(m['timestamp'], m['frame']))
    calls, seen = {}, set()
    for number, message in enumerate(messages, 1):
        signature = (message['src'], message['dst'], message.pop('fingerprint'))
        message['retransmission'] = signature in seen
        seen.add(signature)
        message['id'] = number
        call = calls.setdefault(message['callId'], dict(callId=message['callId'], fromHeader=message['fromHeader'], toHeader=message['toHeader'], start=message['timestamp'], messageCount=0, participants=[]))
        call['messageCount'] += 1
        for participant in (message['src'],message['dst']):
            if participant not in call['participants']:call['participants'].append(participant)
    warnings = [name+' ('+str(count)+').' for name,count in warning_counts.items()]
    if limited:warnings.append('Analysis limit reached: showing up to 200,000 packets, 2,000 SIP messages or 25 seconds of processing. Download the PCAP for the full capture.')
    return dict(calls=list(calls.values()), callGroups=related_call_groups(list(calls.values()), messages), messages=messages, packetCount=min(packets, MAX_PACKETS), warnings=warnings,
                limitations='Shows cleartext SIP over UDP/TCP. Encrypted SIP, RTP media and IP fragments are not decoded. Related Oracle SBC call legs are inferred where matching evidence is available. Use Single Call-ID or All SIP traffic to inspect the original dialogs. TCP retransmitted bytes are reassembled once.')
