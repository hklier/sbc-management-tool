"""Read-only local CDR decoding using Oracle SCZ9.3.0 inclusive layouts."""
import gzip
import io
import json
import re
import zipfile
from functools import lru_cache
from pathlib import Path

MAX_BYTES=32*1024*1024
MAX_RECORDS=10000
MAX_RECORD_BYTES=1024*1024
TYPES={'1':'START','2':'STOP','3':'INTERIM','15':'EVENT'}
LAYOUT_TYPES={'1':'start','2':'stop','3':'interim','15':'message'}
class CdrError(Exception):
 def __init__(self,message,code=400):super().__init__(message);self.code=code

def filename(name):
 if not isinstance(name,str) or len(name)>240 or not re.fullmatch(r'(?:temp-)?cdr[A-Za-z0-9_.-]+',name) or '..' in name:raise CdrError('Select a CDR file inside /opt/cdr.')
 return name

@lru_cache(maxsize=1)
def catalog():return json.loads((Path(__file__).parent/'cdr_catalog.json').read_text(encoding='utf-8'))

def unpack(data,name):
 if len(data)>MAX_BYTES:raise CdrError('This CDR file exceeds the 32 MiB analysis limit.',413)
 try:
  if data.startswith(b'PK\x03\x04'):
   with zipfile.ZipFile(io.BytesIO(data)) as archive:
    members=[m for m in archive.infolist() if not m.is_dir()]
    if len(members)!=1:raise CdrError('A CDR archive must contain exactly one file.')
    if members[0].file_size>MAX_BYTES:raise CdrError('Uncompressed CDR data exceeds 32 MiB.',413)
    with archive.open(members[0]) as source:content=source.read(MAX_BYTES+1)
  elif data.startswith(b'\x1f\x8b'):
   with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:content=source.read(MAX_BYTES+1)
  else:content=data
 except (OSError,EOFError,zipfile.BadZipFile,RuntimeError) as exc:raise CdrError('The CDR archive could not be read.') from exc
 if len(content)>MAX_BYTES:raise CdrError('Uncompressed CDR data exceeds 32 MiB.',413)
 try:return content.decode('utf-8-sig')
 except UnicodeDecodeError:raise CdrError('CDR text is not valid UTF-8/ASCII. Download the original to inspect its encoding.')

def split_fields(raw):
 fields=[];quoted=False;start=0
 for index,char in enumerate(raw):
  if char=='"':quoted=not quoted
  elif char==',' and not quoted:fields.append(raw[start:index]);start=index+1
 if quoted:raise CdrError('Unterminated quoted field.')
 fields.append(raw[start:])
 if len(fields)>2000:raise CdrError('Record contains too many CSV fields.')
 return [f[1:-1] if len(f)>=2 and f.startswith('"') and f.endswith('"') else f for f in fields]

def describe(values):
 kind=LAYOUT_TYPES.get(values[0]);candidates=[(key,item) for key,item in catalog()['layouts'].items() if key.endswith('-'+str(kind)) and len(item['columns'])==len(values)]
 if len(candidates)==1:
  key,layout=candidates[0];columns=layout['columns'];mapped=True
 else:key='unmapped';columns=[dict(position=i+1,name='CSV field '+str(i+1),vendor='',attribute='') for i in range(len(values))];layout={};mapped=False
 return dict(layout=key,mapped=mapped,source=layout.get('source',catalog()['source']))

def summary(record):
 named={f['name']:value for f,value in zip(catalog()['layouts'][record['layout']]['columns'],record['values'])} if record['mapped'] else {}
 def pick(*keys):return next((named[k] for k in keys if named.get(k) is not None),'')
 return {**{k:v for k,v in record.items() if k not in ('values','fields','raw')},'sessionId':pick('Accounting Session ID'),'callId':pick('Ingress Session ID'),'calling':pick('Calling Station ID'),'called':pick('Called Station ID'),'setup':pick('Cisco Setup Time'),'connect':pick('Cisco Connect Time'),'disconnect':pick('Cisco Disconnect Time'),'duration':pick('Accounting Session Time'),'cause':pick('Cisco Disconnect Cause'),'ingressRealm':pick('Ingress Realm'),'egressRealm':pick('Egress Realm')}

def parse(data,name='cdr-file'):
 text=unpack(data,name);records=[];warnings=[];start=0;line=1;record_line=1;quoted=False;active=name.startswith('temp-');unknown=0
 def add(raw,number):
  nonlocal unknown
  raw=raw.rstrip('\r')
  if not raw.strip():return
  if len(raw.encode('utf-8'))>MAX_RECORD_BYTES:raise CdrError('A CDR record exceeds the 1 MiB record limit.',413)
  values=split_fields(raw);details=describe(values);unknown+=not details['mapped']
  records.append(dict(id=len(records)+1,line=number,type=TYPES.get(values[0],'UNKNOWN ('+values[0][:32]+')'),status=values[0],fieldCount=len(values),raw=raw,values=values,**details))
 for index,char in enumerate(text):
  if char=='"':quoted=not quoted
  if char=='\n':
   if not quoted:
    add(text[start:index],record_line);start=index+1;record_line=line+1
    if len(records)>=MAX_RECORDS and start<len(text):warnings.append('Record limit reached: only the first 10,000 records are shown.');break
   line+=1
 else:
  tail=text[start:]
  if tail.strip():
   if quoted or active:warnings.append('The incomplete final record was omitted. Refresh after the SBC finishes writing it.')
   else:add(tail,record_line)
 if unknown:warnings.append(str(unknown)+' record(s) do not match an exact Oracle 9.3 inclusive layout. All values remain visible by CSV position without guessing field names.')
 return dict(records=records,recordCount=len(records),counts={label:sum(r['type']==label for r in records) for label in TYPES.values()},warnings=warnings,active=active,uncompressedBytes=len(text.encode('utf-8')))

def page(parsed,query='',record_type='',offset=0,limit=50):
 if offset<0 or not 1<=limit<=100:raise CdrError('Invalid CDR pagination.')
 if record_type and record_type not in TYPES.values():raise CdrError('Invalid CDR record type.')
 needle=query.lower()[:300]
 matching=[r for r in parsed['records'] if (not record_type or r['type']==record_type) and (not needle or needle in r['raw'].lower())]
 return dict(total=parsed['recordCount'],filtered=len(matching),offset=offset,limit=limit,records=[summary(r) for r in matching[offset:offset+limit]],counts=parsed['counts'],warnings=parsed['warnings'],active=parsed['active'],uncompressedBytes=parsed['uncompressedBytes'])


def detail(record):
 columns=catalog()['layouts'][record['layout']]['columns'] if record['mapped'] else [dict(position=i+1,name='CSV field '+str(i+1),vendor='',attribute='') for i in range(len(record['values']))]
 return dict(**{k:v for k,v in record.items() if k!='values'},fields=[dict(**column,value=value) for column,value in zip(columns,record['values'])])
