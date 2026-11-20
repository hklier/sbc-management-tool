import io,gzip,json,stat,unittest,zipfile
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch
import server as app
import cdr_tools as c

def record(status='2',layout=None):
 layout=layout or {'1':'radius-start','2':'radius-stop','3':'radius-interim','15':'radius-message'}[status]
 columns=c.catalog()['layouts'][layout]['columns'];values=['']*len(columns);values[0]=status
 for col in columns:
  if col['name']=='Calling Station ID':values[col['position']-1]='"sip:alice@example.invalid"'
  if col['name']=='Called Station ID':values[col['position']-1]='"sip:bob@example.invalid"'
  if col['name']=='Accounting Session Time':values[col['position']-1]='12'
 return ','.join(values).encode()

class ParserTests(unittest.TestCase):
 def test_all_eight_documented_layouts(self):
  for layout in c.catalog()['layouts']:
   kind=next(k for k,v in c.LAYOUT_TYPES.items() if layout.endswith('-'+v))
   parsed=c.parse(record(kind,layout)+b'\n');row=parsed['records'][0];detail=c.detail(row)
   self.assertTrue(row['mapped'],layout);self.assertEqual(row['layout'],layout);self.assertEqual(len(detail['fields']),len(c.catalog()['layouts'][layout]['columns']));self.assertEqual(detail['fields'][0]['position'],1)
 def test_start_stop_fields_summary_and_empty_values(self):
  parsed=c.parse(record('1')+b'\n'+record()+b'\n');page=c.page(parsed);self.assertEqual(page['total'],2);self.assertEqual(page['records'][1]['duration'],'12');self.assertEqual(page['records'][1]['calling'],'sip:alice@example.invalid');self.assertEqual(len(c.detail(parsed['records'][1])['fields']),217);self.assertEqual(c.detail(parsed['records'][1])['fields'][1]['value'],'');self.assertNotIn('values',page['records'][0]);self.assertNotIn('raw',page['records'][0])
 def test_oracle_nested_quotes_embedded_commas_and_trailing_empty(self):
  self.assertEqual(c.split_fields('1,"<sip:a>;reason="unconditional",<sip:b>;reason="alias"",0,0,112,'),['1','<sip:a>;reason="unconditional",<sip:b>;reason="alias"','0','0','112',''])
  self.assertEqual(c.split_fields('1,"a""b,c",0'),['1','a""b,c','0'])
 def test_unmapped_count_never_assigns_shifted_names(self):
  parsed=c.parse(record()+b',extra\n');self.assertFalse(parsed['records'][0]['mapped']);self.assertTrue(parsed['warnings']);self.assertEqual(c.detail(parsed['records'][0])['fields'][1]['name'],'CSV field 2')
 def test_record_type_and_search_pagination(self):
  parsed=c.parse(record('1')+b'\n'+record()+b'\n');self.assertEqual(c.page(parsed,record_type='STOP')['filtered'],1);self.assertEqual(c.page(parsed,query='bob@example.invalid')['filtered'],2);self.assertEqual(len(c.page(parsed,offset=1,limit=1)['records']),1)
 def test_open_file_omits_partial_tail_and_multiline_strings(self):
  parsed=c.parse(record('1')+b'\n'+record(),name='temp-cdr20261027');self.assertEqual(parsed['recordCount'],1);self.assertTrue(parsed['warnings']);self.assertEqual(c.parse(record())['recordCount'],1)
  parsed=c.parse(b'1,"one\ntwo",3\n');self.assertEqual(parsed['recordCount'],1);self.assertEqual(c.detail(parsed['records'][0])['fields'][1]['value'],'one\ntwo')
  self.assertEqual(c.parse(b'1,"unterminated')['recordCount'],0)
 def test_zip_gzip_and_limits(self):
  data=record()+b'\n';self.assertEqual(c.parse(gzip.compress(data))['recordCount'],1)
  stream=io.BytesIO()
  with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('../ignored-member-name',data)
  self.assertEqual(c.parse(stream.getvalue())['recordCount'],1)
  with patch.object(c,'MAX_BYTES',100):
   with self.assertRaises(c.CdrError):c.parse(gzip.compress(b'x'*200))
  with patch.object(c,'MAX_RECORDS',1):self.assertEqual(c.parse(data+data)['recordCount'],1)
 def test_paths_pagination_and_encoding(self):
  for name in ('../cdr','/opt/cdr/cdr1','cdr..csv','cdr1\n','cdr1/evil','anything.txt'):
   with self.assertRaises(c.CdrError):c.filename(name)
  for kw in (dict(offset=-1),dict(limit=101),dict(record_type='bad')):
   with self.assertRaises(c.CdrError):c.page(c.parse(b''),**kw)
  with self.assertRaises(c.CdrError):c.parse(b'\xff')

import test_server as existing
class HttpTests(unittest.TestCase):
 setUp=existing.UpdateRouteTests.setUp;tearDown=existing.UpdateRouteTests.tearDown;get_request=existing.DiagnosticsTests.get_request
 def test_all_cdr_routes_require_session(self):
  for path in ('/api/cdr','/api/cdr/records','/api/cdr/record','/api/cdr/download'):
   self.assertEqual(self.get_request(path,cookie='wrong')[0],401)
 def test_record_detail_validation_and_no_mutations(self):
  data=c.parse(record()+b'\n')
  with patch('server.cdr_data',return_value=data):
   self.assertEqual(self.get_request('/api/cdr/records')[1]['total'],1);self.assertEqual(len(self.get_request('/api/cdr/record?id=1')[1]['fields']),217);self.assertEqual(self.get_request('/api/cdr/records?offset=bad')[0],400);self.assertEqual(self.get_request('/api/cdr/record?id=99')[0],404)
  self.assertEqual(self.events,[])
import test_traces as traces
class FileSafetyTests(unittest.TestCase):
 def setUp(self):
  self.sftp=traces.FakeSFTP();self.sftp.content=record()+b'\n';self.sftp.info.filename='cdr202610270936';self.sftp.info.st_size=len(self.sftp.content)
  @contextmanager
  def connection(*args):yield self.sftp
  self.patcher=patch('server.lrt_sftp',connection);self.patcher.start();self.addCleanup(self.patcher.stop);app.CDR_CACHE.clear()
 def test_only_cdr_files_and_exact_original_snapshot(self):
  self.assertEqual(len(app.cdr_list()['files']),1)
  with app.cdr_copy(self.sftp.info.filename,app.trace_version(self.sftp.info)) as (source,size):self.assertEqual(source.read(),self.sftp.content)
 def test_symlinks_stale_versions_and_directory_escape(self):
  for change in ('symlink','changed','resolve'):
   self.sftp.symlink=False;self.sftp.changed=False;self.sftp.resolve=None
   setattr(self.sftp,change,'/outside' if change=='resolve' else True)
   with self.assertRaises(app.Problem):
    with app.cdr_copy(self.sftp.info.filename,app.trace_version(self.sftp.info)):pass
 def test_cache_is_versioned_and_parser_has_separate_lock(self):
  query=dict(name=self.sftp.info.filename,version=app.trace_version(self.sftp.info))
  self.assertEqual(app.cdr_data(query)['recordCount'],1)
  self.sftp.open=lambda *args: (_ for _ in ()).throw(RuntimeError('Cache should avoid rereading'))
  self.assertEqual(app.cdr_data(query)['recordCount'],1)
  app.CDR_GATE.acquire()
  try:
   with self.assertRaises(app.Problem) as error:app.cdr_data(query)
   self.assertEqual(error.exception.code,429)
  finally:app.CDR_GATE.release()
