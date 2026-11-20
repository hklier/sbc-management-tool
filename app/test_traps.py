"""Offline trap decoder, persistence, retention and authentication tests."""
import os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import trap_tools as t
from pysnmp.proto.api import v1,v2c
from pyasn1.codec.ber import encoder,decoder

SECRET=b'test-trap-community'
def packet(version='2c',kind='trap',extras=()):
 m=v1 if version=='1' else v2c
 msg=m.Message();m.apiMessage.set_defaults(msg);m.apiMessage.set_community(msg,SECRET)
 pdu=m.TrapPDU() if version=='1' else m.InformRequestPDU() if kind=='inform' else m.GetRequestPDU() if kind=='get' else m.SNMPv2TrapPDU()
 if version=='1':
  m.apiTrapPDU.set_defaults(pdu);m.apiTrapPDU.set_enterprise(pdu,'1.3.6.1.4.1.9148.3.2.3');m.apiTrapPDU.set_generic_trap(pdu,6);m.apiTrapPDU.set_specific_trap(pdu,1);m.apiTrapPDU.set_timestamp(pdu,12345);m.apiTrapPDU.set_varbinds(pdu,extras)
 else:
  m.apiPDU.set_defaults(pdu);m.apiPDU.set_varbinds(pdu,[(t.UPTIME_OID,m.TimeTicks(12345)),(t.TRAP_OID,m.ObjectIdentifier('1.3.6.1.4.1.9148.3.2.3.0.1'))]+list(extras))
 m.apiMessage.set_pdu(msg,pdu);return encoder.encode(msg)

def event():return t.decode_packet(packet(),('192.168.226.193',161),[SECRET])[0]
class DecoderTests(unittest.TestCase):
 def test_v2_trap_name_uptime_and_no_community(self):
  result,ack=t.decode_packet(packet(extras=[('1.3.6.1.2.1.1.5.0',v2c.OctetString('SBC'))]),('192.168.226.193',161),[SECRET])
  self.assertEqual(result['name'],'apSysMgmtGroupTrap');self.assertEqual(result['uptimeTicks'],12345);self.assertEqual(len(result['bindings']),3);self.assertIsNone(ack);self.assertNotIn(SECRET.decode(),str(result));self.assertEqual(result['severity'],'unknown')
 def test_v1_enterprise_and_generic_traps(self):
  result,_=t.decode_packet(packet('1'),('192.168.226.193',161),[SECRET]);self.assertEqual(result['name'],'apSysMgmtGroupTrap');self.assertEqual(result['genericTrap'],6);self.assertEqual(result['bindings'],[])
 def test_inform_response_keeps_request_id_and_bindings(self):
  data=packet(kind='inform');result,ack=t.decode_packet(data,('192.168.226.193',161),[SECRET]);self.assertEqual(result['kind'],'INFORM')
  req,_=decoder.decode(data,asn1Spec=v2c.Message());resp,_=decoder.decode(ack,asn1Spec=v2c.Message());pdu=v2c.apiMessage.get_pdu(resp)
  self.assertEqual(pdu.tagSet,v2c.ResponsePDU.tagSet);self.assertEqual(v2c.apiPDU.get_request_id(pdu),v2c.apiPDU.get_request_id(v2c.apiMessage.get_pdu(req)));self.assertEqual(len(v2c.apiPDU.get_varbinds(pdu)),2)
 def test_invalid_packets_community_and_non_notifications(self):
  for data,allowed in [(b'garbage',[SECRET]),(packet(),[b'wrong']),(packet()+b'extra',[SECRET]),(packet(kind='get'),[SECRET])]:
   with self.assertRaises(Exception):t.decode_packet(data,('192.168.226.193',161),allowed)
 def test_proxy_community_is_removed_and_values_bounded(self):
  data=packet(extras=[('1.3.6.1.6.3.18.1.4.0',v2c.OctetString(SECRET)),('1.3.6.1.2.1.1.5.0',v2c.OctetString('x'*3000+SECRET.decode()))])
  result,_=t.decode_packet(data,('192.168.226.193',161),[SECRET]);self.assertNotIn(SECRET.decode(),str(result));self.assertTrue(result['truncated']);self.assertEqual(len(result['bindings']),3);self.assertLessEqual(len(result['bindings'][-1]['value']),1024)
 def test_explicit_syslog_severity_only(self):
  lookup={r['name']:oid for oid,r in t.snmp_tools.catalog().items()}
  data=packet(extras=[(lookup['apSyslogHistLevel']+'.1',v2c.Integer32(5)),(lookup['apSyslogHistContent']+'.1',v2c.OctetString('Test warning'))])
  result,_=t.decode_packet(data,('192.168.226.193',161),[SECRET]);self.assertEqual(result['severity'],'warning');self.assertEqual(result['summary'],'Test warning')
class StoreTests(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.store=t.Store(Path(self.temp.name)/'traps.sqlite3')
 def tearDown(self):self.temp.cleanup()
 def test_persistence_search_detail_export_and_retention(self):
  with patch.object(t,'MAX_EVENTS',3):
   for i in range(5):self.store.append(event())
  data=t.Store(self.store.path).query();self.assertEqual(data['filtered'],3);self.assertEqual(data['events'][0]['id'],5);self.assertNotIn('bindings',data['events'][0]);self.assertIsNone(self.store.event(1));self.assertIn('bindings',self.store.event(5));self.assertEqual(self.store.query('apSysMgmtGroupTrap')['filtered'],3);self.assertEqual(self.store.query("' OR 1=1 --")['filtered'],0);self.assertEqual(len(self.store.query(limit=1)['events']),1);self.assertIn('bindings',self.store.query(details=True)['events'][0])
 def test_listener_liveness_and_actual_counts(self):
  self.store.heartbeat(dict(status='listening',startedAt=t.timestamp()));self.store.append(event());data=self.store.overview();self.assertTrue(data['receiver']['listening']);self.assertEqual(data['recent'],1);self.assertEqual(sum(r['count'] for r in data['timeline']),1);self.assertEqual(data['uniqueTypes'],1)
  with patch('trap_tools.time.time',return_value=time.time()+30):self.assertFalse(self.store.overview()['receiver']['listening'])
 def test_search_includes_decoded_enum_labels(self):
  sample=event();sample['bindings'].append(dict(name='apSysMgmtRadiusDown',value='2',display='all-servers-down'));self.store.append(sample)
  self.assertEqual(self.store.query('all-servers-down')['filtered'],1)
 def test_validation_and_missing_event(self):
  for kw in [dict(offset=-1),dict(limit=501),dict(severity='fake'),dict(version='3')]:
   with self.assertRaises(t.TrapError):self.store.query(**kw)
  self.assertIsNone(self.store.event(999))


class PresentationTests(unittest.TestCase):
 def test_catalog_covers_mib_notifications_with_readable_titles(self):
  catalog=t.notification_catalog()['notifications'];self.assertGreaterEqual(len(catalog),227)
  for oid,definition in catalog.items():
   self.assertNotEqual(definition['name'],definition['title']);self.assertTrue(definition['description'],oid);self.assertTrue(definition['module'])
 def test_radius_title_and_original_reference_are_preserved(self):
  original=dict(oid='1.3.6.1.4.1.9148.3.2.6.0.11',name='apSysMgmtRadiusDownTrap')
  shown=t.present_event(original);self.assertEqual(shown['title'],'RADIUS accounting server timeout');self.assertIn('accounting',shown['description']);self.assertEqual(shown['name'],original['name']);self.assertTrue(shown['documented']);self.assertNotIn('title',original)
 def test_unknown_oid_is_not_given_a_parent_notification_description(self):
  shown=t.present_event(dict(oid='1.3.6.1.4.1.9148.3.2.6.0.11.999',name='unknown'))
  self.assertFalse(shown['documented']);self.assertEqual(shown['title'],'Unrecognized SNMP notification')
 def test_old_events_get_labels_and_search_works_without_reindexing(self):
  with tempfile.TemporaryDirectory() as folder:
   store=t.Store(Path(folder)/'events.db');sample=event();sample.update(oid='1.3.6.1.4.1.9148.3.2.6.0.11',name='apSysMgmtRadiusDownTrap');stored=store.append(sample)
   # Inserted payloads deliberately contain no presentation metadata.
   with store.connect() as db:self.assertNotIn('title',db.execute('SELECT payload FROM events').fetchone()[0])
   self.assertEqual(store.query('RADIUS accounting server timeout')['filtered'],1);self.assertEqual(store.query('haved timed out')['filtered'],1);self.assertEqual(store.query('apSysMgmtRadiusDownTrap')['filtered'],1)
   self.assertEqual(store.event(stored)['title'],'RADIUS accounting server timeout');self.assertIn('description',store.query(details=True)['events'][0]);self.assertEqual(store.overview()['types'][0]['title'],'RADIUS accounting server timeout')
   self.assertEqual(store.query('RADIUS accounting',severity='warning')['filtered'],0)

import test_server as existing
class TrapHttpTests(unittest.TestCase):
 setUp=existing.UpdateRouteTests.setUp;tearDown=existing.UpdateRouteTests.tearDown;get_request=existing.DiagnosticsTests.get_request
 def test_authentication_and_read_only_routes(self):
  for path in ('/api/traps','/api/traps/events','/api/traps/export','/api/traps/event?id=1'):self.assertEqual(self.get_request(path,cookie='wrong')[0],401)
  with tempfile.TemporaryDirectory() as directory,patch.object(t,'STORE',t.Store(Path(directory)/'inbox.db')):
   self.assertEqual(self.get_request('/api/traps')[0],200);self.assertEqual(self.get_request('/api/traps/events')[0],200);self.assertEqual(self.get_request('/api/traps/events?limit=-1')[0],400);self.assertEqual(self.get_request('/api/traps/event?id=bad')[0],400);self.assertEqual(self.get_request('/api/traps/event?id=1')[0],404)
  self.assertEqual(self.events,[])
