"""Offline capture tests. Never connect to the SBC."""
import io
import os
import socket
import stat
import tempfile
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch
import dpkt
import server as app
from trace_tools import parse_capture


def sip(call='one', line='INVITE sip:b@example.invalid SIP/2.0', body=b''):
    return (line+'\r\nFrom: <sip:a@example.invalid>\r\nTo: <sip:b@example.invalid>\r\nCall-ID: '+call+'\r\nCSeq: 1 INVITE\r\nContent-Length: '+str(len(body))+'\r\n\r\n').encode()+body


def packet(data, tcp=False, seq=1):
    transport=dpkt.tcp.TCP(sport=5060,dport=5070,seq=seq,flags=dpkt.tcp.TH_ACK,data=data) if tcp else dpkt.udp.UDP(sport=5060,dport=5070,data=data)
    if not tcp:transport.ulen=len(transport)
    ip=dpkt.ip.IP(src=socket.inet_aton('192.0.2.1'),dst=socket.inet_aton('192.0.2.2'),p=6 if tcp else 17,data=transport)
    ip.len=len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b'\x01'*6,dst=b'\x02'*6,type=0x0800,data=ip))


def capture(packets, ng=False):
    target=io.BytesIO();writer=dpkt.pcapng.Writer(target) if ng else dpkt.pcap.Writer(target)
    for i,p in enumerate(packets):writer.writepkt(p,ts=1700000000+i*.1)
    return target.getvalue()


class CaptureParserTests(unittest.TestCase):
    def test_udp_dialogs_and_repeated_messages_preserve_timeline(self):
        result=parse_capture(capture([packet(sip()),packet(sip()),packet(sip('two', 'SIP/2.0 200 OK'))]))
        self.assertEqual(len(result['calls']),2)
        self.assertEqual(len(result['messages']),3)
        self.assertTrue(result['messages'][1]['retransmission'])
        self.assertEqual(result['messages'][0]['src'],'192.0.2.1:5060')
        self.assertIn('INVITE',result['messages'][0]['raw'])
        self.assertEqual(result['messages'][2]['frame'],3)

    def test_tcp_out_of_order_segments_retransmission_and_multiple_pdus(self):
        content=sip(body=b'hello')+sip('two','SIP/2.0 200 OK')
        result=parse_capture(capture([packet(content[75:150],True,175),packet(content[:75],True,100),packet(content[:75],True,100),packet(content[150:],True,250)]))
        self.assertEqual(len(result['calls']),2)
        self.assertEqual(len(result['messages']),2)
        self.assertTrue(all(m['transport']=='TCP' for m in result['messages']))
        self.assertIn('hello',next(m['raw'] for m in result['messages'] if m['callId']=='one'))

    def test_tcp_gap_never_joins_missing_bytes(self):
        content=sip()
        result=parse_capture(capture([packet(content[:65],True,100),packet(content[100:],True,200)]))
        self.assertEqual(result['messages'],[])
        self.assertTrue(any('TCP gaps' in w for w in result['warnings']))

    def test_sip_body_is_not_decoded_as_another_message(self):
        result=parse_capture(capture([packet(sip(body=sip('fake')))]))
        self.assertEqual([c['callId'] for c in result['calls']],['one'])

    def test_compact_headers_and_non_standard_ports_are_detected(self):
        data=b'OPTIONS sip:b SIP/2.0\r\ni: compact\r\nf: caller\r\nt: callee\r\nl: 0\r\n\r\n'
        result=parse_capture(capture([packet(data)]))
        self.assertEqual(result['calls'][0]['callId'],'compact')
        self.assertEqual(result['calls'][0]['fromHeader'],'caller')

    def test_pcapng_and_no_sip(self):
        self.assertEqual(len(parse_capture(capture([packet(sip())],True))['messages']),1)
        self.assertEqual(parse_capture(capture([packet(b'other traffic')]))['messages'],[])

    def test_corrupt_capture_is_reported(self):
        with self.assertRaises(ValueError):parse_capture(b'not a pcap')

    def test_message_limit_is_explicit(self):
        with patch('trace_tools.MAX_MESSAGES',1):
            result=parse_capture(capture([packet(sip()),packet(sip('two'))]))
        self.assertEqual(len(result['messages']),1)
        self.assertTrue(any('limit reached' in w for w in result['warnings']))


class RelatedLegTests(unittest.TestCase):
    def group(self, tag='original', delay=0.01, original_tag='original', target='b'):
        from trace_tools import related_call_groups
        calls=[dict(callId='original-id',participants=['caller:5070','sbc-in:5060']),dict(callId='SDtoken-outgoing',participants=['sbc-out:5060','callee:5090'])]
        common=dict(label='INVITE sip:b SIP/2.0',cseq='1 INVITE',toHeader='<sip:b@example.invalid>')
        messages=[dict(common,callId='original-id',timestamp=100,fromHeader='<sip:a@example.invalid>;tag='+original_tag),dict(common,callId='SDtoken-outgoing',timestamp=100+delay,fromHeader='<sip:a@example.invalid>;tag=SDtoken-'+tag,toHeader='<sip:'+target+'@example.invalid>')]
        return related_call_groups(calls,messages)
    def test_oracle_rewritten_tag_links_distinct_call_ids(self):
        self.assertEqual(self.group()[0]['callIds'],['original-id','SDtoken-outgoing'])
    def test_other_calls_and_distant_requests_are_not_merged(self):
        self.assertEqual(self.group(tag='different'),[])
        self.assertEqual(self.group(delay=10),[])
        self.assertEqual(self.group(target='another-user'),[])
    def test_matching_uris_alone_do_not_link_calls(self):
        self.assertEqual(self.group(tag='reuse',original_tag='other'),[])


class FakeFile(io.BytesIO):
    def stat(self):return self.info


class FakeSFTP:
    def __init__(self):
        self.content=b'capture bytes'
        self.info=SimpleNamespace(filename='call one.pcap',st_size=len(self.content),st_mtime=1234,st_mode=stat.S_IFREG|0o644)
        self.resolve=None;self.symlink=False;self.changed=False
    def normalize(self,path):return self.resolve or path
    def lstat(self,path):return SimpleNamespace(st_mode=stat.S_IFLNK) if self.symlink else self.info
    def stat(self,path):return SimpleNamespace(**{**vars(self.info),'st_mtime':1235}) if self.changed else self.info
    def open(self,path,mode):
        result=FakeFile(self.content);result.info=self.info;return result
    def listdir_attr(self,path):
        return [self.info,SimpleNamespace(filename='private.key',st_mode=stat.S_IFREG),SimpleNamespace(filename='link.pcap',st_mode=stat.S_IFLNK)]


class TraceFileTests(unittest.TestCase):
    def setUp(self):
        self.sftp=FakeSFTP()
        @contextmanager
        def connection(*args):yield self.sftp
        self.patcher=patch('server.lrt_sftp',connection);self.patcher.start();self.addCleanup(self.patcher.stop)
    def test_list_only_regular_capture_files(self):
        result=app.trace_list()
        self.assertEqual([f['name'] for f in result['files']],['call one.pcap'])
        self.assertTrue(result['files'][0]['canDownload'])
    def test_snapshot_matches_exact_original_bytes(self):
        with app.trace_copy('call one.pcap','13:1234',100) as (file,size):
            self.assertEqual(file.read(),self.sftp.content)
            self.assertEqual(size,13)
    def test_path_traversal_and_control_characters_are_rejected(self):
        for name in ['../other.pcap','dir/file.pcap','dir\\file.pcap','test\r\n.pcap','test.key','']:
            with self.assertRaises(app.Problem):app.trace_filename(name)
    def test_symlinks_and_resolved_paths_are_rejected(self):
        self.sftp.symlink=True
        with self.assertRaises(app.Problem):
            with app.trace_copy('call one.pcap','13:1234',100):pass
        self.sftp.symlink=False;self.sftp.resolve='/secret.pcap'
        with self.assertRaises(app.Problem):
            with app.trace_copy('call one.pcap','13:1234',100):pass
    def test_stale_capture_and_size_limit_are_rejected(self):
        for version,limit in [('13:1230',100),('13:1234',5),('',100)]:
            with self.assertRaises(app.Problem):
                with app.trace_copy('call one.pcap',version,limit):pass
    def test_analysis_busy_is_reported_without_reading(self):
        app.TRACE_GATE.acquire()
        try:
            with self.assertRaises(app.Problem) as error:app.trace_flow({})
            self.assertEqual(error.exception.code,429)
        finally:app.TRACE_GATE.release()


if __name__=='__main__':unittest.main()
