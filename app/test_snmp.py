import asyncio,time,unittest
from unittest.mock import patch,AsyncMock
import snmp_tools as s

class SnmpTests(unittest.TestCase):
 def test_numeric_zero_missing_large_counter_and_enum(self):
  self.assertEqual(s.record(s.COMMON['cpu'],'0','Gauge32')['numeric'],0)
  self.assertFalse(s.record(s.COMMON['cpu'],'missing','NoSuchInstance')['available'])
  large=s.record(s.COMMON['cpu'],'18446744073709551615','Counter64')
  self.assertIsNone(large['numeric']);self.assertEqual(large['value'],'18446744073709551615')
  self.assertEqual(s.record(s.COMMON['state'],'0','Integer')['display'],'online')
 def test_oid_scope_and_validation(self):
  self.assertEqual(s.validate_oid('.1.3.6.1.2.1.1.1.0'),'1.3.6.1.2.1.1.1.0')
  for oid in ('1.3.6.1.4.1.9148.4.1','1.3.6.1.6.3.15','localhost','1.3.6.1.2.1;reboot','1.3.6.1.2.1.4294967296'):
   with self.assertRaises(s.SnmpError):s.validate_oid(oid)
 def test_storage_units_and_table_indexes(self):
  by_name={v['name']:k for k,v in s.catalog().items()}
  rows=[s.record(by_name[name]+'.1',value,kind) for name,value,kind in [('apSysVolumeName','/opt','OctetString'),('apSysVolumeTotalSpace','17020','Unsigned32'),('apSysVolumeAvailSpace','9956937','Unsigned32')]]
  storage=s.build_tables(rows)['storage'][0]
  self.assertAlmostEqual(storage['usedPercent'],41.4986,places=3)
 def test_bounded_walk_nonincreasing_and_outside_subtree(self):
  c=s.Client();c.engine=c.auth=c.target=c.context=None
  class Fake:
   ObjectType=staticmethod(lambda x:x);ObjectIdentity=staticmethod(lambda x:x)
   bulk_cmd=AsyncMock(return_value=(None,0,0,[(s.ROOTS[0]+'.1','a'),(s.ROOTS[0]+'.1','b')]))
  c.snmp=Fake
  rows,done,error=asyncio.run(c.walk(s.ROOTS[0],time.monotonic()+5,50))
  self.assertEqual(len(rows),1);self.assertFalse(done);self.assertIn('non-increasing',error)
  Fake.bulk_cmd.return_value=(None,0,0,[(s.ROOTS[1]+'.1','a')])
  self.assertTrue(asyncio.run(c.walk(s.ROOTS[0],time.monotonic()+5,50))[1])
  Fake.bulk_cmd.reset_mock();rows,done,error=asyncio.run(c.walk(s.ROOTS[0],time.monotonic()-1,50))
  Fake.bulk_cmd.assert_not_called();self.assertFalse(done)
 def test_refresh_single_worker_and_no_secrets(self):
  monitor=s.Monitor()
  with patch.dict('os.environ',{'SNMP_COMMUNITY':'private-test'}),patch('snmp_tools.threading.Thread') as thread:
   result=monitor.status();monitor.status(refresh=True,discover=True)
   self.assertTrue(result['busy']);self.assertEqual(thread.call_count,1)
   self.assertNotIn('private-test',str(result))
 def test_failed_collection_preserves_last_good_sample(self):
  monitor=s.Monitor();monitor.sample={'old':True};monitor.inventory=[{'old':True}]
  with patch.object(s.Client,'open',AsyncMock(side_effect=s.SnmpError('timeout'))),patch.object(s.Client,'close'):
   monitor._worker(True)
  self.assertEqual(monitor.sample,{'old':True});self.assertEqual(monitor.inventory,[{'old':True}]);self.assertFalse(monitor.busy);self.assertEqual(monitor.error,'timeout')
 def test_inventory_search_pagination_and_export_copy(self):
  monitor=s.Monitor();monitor.inventory=[s.record(s.COMMON['cpu'],'0','Gauge32'),s.record(s.COMMON['memory'],'39','Gauge32')]
  self.assertEqual(monitor.objects('CPU')['filtered'],1)
  self.assertEqual(len(monitor.objects(limit=1)['objects']),1)
  monitor.export()['objects'].clear();self.assertEqual(len(monitor.inventory),2)
 def test_get_one_is_read_only_and_releases_lock(self):
  monitor=s.Monitor()
  with patch.object(s.Client,'open',AsyncMock()),patch.object(s.Client,'get',AsyncMock(return_value=[{'numeric':0}])) as get,patch.object(s.Client,'close') as close:
   self.assertEqual(monitor.get_one(s.COMMON['cpu'])['object']['numeric'],0);get.assert_awaited_once_with([s.COMMON['cpu']]);close.assert_called_once()
  self.assertFalse(monitor.custom_lock.locked())

import test_server as existing
class SnmpHttpTests(unittest.TestCase):
 setUp=existing.UpdateRouteTests.setUp;tearDown=existing.UpdateRouteTests.tearDown;get_request=existing.DiagnosticsTests.get_request
 def test_authenticated_routes_and_validation(self):
  with patch.object(s.MONITOR,'status',return_value={'configured':True}) as status:
   self.assertEqual(self.get_request('/api/snmp')[0],200);status.assert_called_once()
  for path in ('/api/snmp/objects?offset=-1','/api/snmp/objects?limit=201','/api/snmp/get?oid=1.3.6.1.6.3'):
   self.assertEqual(self.get_request(path)[0],400)
  self.assertEqual(self.events,[])
 def test_all_snmp_routes_require_session(self):
  for path in ('/api/snmp','/api/snmp/objects','/api/snmp/get?oid='+s.COMMON['cpu'],'/api/snmp/export'):
   self.assertEqual(self.get_request(path,cookie='unknown')[0],401)
