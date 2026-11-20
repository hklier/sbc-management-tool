"""Read-only SNMP diagnostics for the configured SBC. No SNMP SET operations."""
import asyncio
import copy
import json
import os
import re
import threading
import time
from functools import lru_cache
from pathlib import Path

ROOTS = ('1.3.6.1.2.1', '1.3.6.1.4.1.9148.3')
PREFIX = '1.3.6.1.4.1.9148.3.2.1.1.'
COMMON = {
 'description':'1.3.6.1.2.1.1.1.0', 'uptime':'1.3.6.1.2.1.1.3.0', 'hostname':'1.3.6.1.2.1.1.5.0',
 **{key:PREFIX+str(n)+'.0' for key,n in [('cpu',1),('memory',2),('health',3),('redundancy',4),('sessions',5),('cps',6),('nat',7),('arp',8),('state',9),('license',10),('registrations',11),('applicationCpu',16),('rejected',18),('trustDemotions',19),('deniedDemotions',20),('callsRejected',25),('deniedEndpoints',26),('subscriptions',27),('transcoding',34),('cpuOneMinute',43),('cpuFiveMinutes',44),('cpuFifteenMinutes',45)]}}

class SnmpError(Exception):
    def __init__(self,message,code=502):super().__init__(message);self.code=code

def now():return time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
def oid_tuple(oid):return tuple(int(v) for v in oid.split('.'))
def validate_oid(value):
    if not isinstance(value,str) or len(value)>250 or not re.fullmatch(r'\.?\d+(?:\.\d+){2,39}',value):raise SnmpError('Enter a numeric diagnostic OID.',400)
    value=value.lstrip('.')
    if any(int(v)>4294967295 for v in value.split('.')):raise SnmpError('OID component out of range.',400)
    if not any(value==r or value.startswith(r+'.') for r in ROOTS):raise SnmpError('Only MIB-II and Oracle management diagnostic OIDs are permitted.',400)
    return '.'.join(str(int(v)) for v in value.split('.'))

@lru_cache(maxsize=1)
def catalog():return json.loads((Path(__file__).parent/'snmp_catalog.json').read_text(encoding='utf-8'))['objects']

def identify(oid):
    parts=oid.split('.');objects=catalog()
    for length in range(len(parts),0,-1):
        prefix='.'.join(parts[:length])
        if prefix in objects:
            item=objects[prefix]
            return dict(name=item['name'],objectOid=prefix,index='.'.join(parts[length:]),module=item.get('module','Standard MIB' if oid.startswith(ROOTS[0]+'.') else 'Oracle MIB'),syntax=item.get('syntax',''),enums=item.get('enums',{}))
    return dict(name=oid,objectOid=oid,index='',module='Other',syntax='',enums={})

def record(oid,value,type_name=None):
    oid=str(oid);kind=type_name or type(value).__name__
    available=kind not in ('NoSuchObject','NoSuchInstance','EndOfMibView')
    rendered=value.prettyPrint() if hasattr(value,'prettyPrint') else str(value)
    metadata=identify(oid);enum=metadata.pop('enums',{})
    number=None
    if available and kind in ('Integer','Integer32','Counter32','Counter64','Gauge32','Unsigned32','TimeTicks'):
        try:
            candidate=int(rendered)
            if abs(candidate)<=9007199254740991:number=candidate
        except ValueError:pass
    return dict(oid=oid,type=kind,value=rendered[:4096],truncated=len(rendered)>4096,numeric=number,available=available,display=enum.get(rendered,rendered[:4096]),**metadata)

def config():
    version=os.environ.get('SNMP_VERSION','2c');host=os.environ.get('SBC_HOST','192.168.226.193')
    if version not in ('2c','3'):raise SnmpError('Configure SNMP_VERSION as 2c or 3 on the application server.',503)
    configured=bool(os.environ.get('SNMP_COMMUNITY')) if version=='2c' else all(os.environ.get(k) for k in ('SNMP_USER','SNMP_AUTH_KEY','SNMP_PRIV_KEY'))
    return dict(host=host,port=int(os.environ.get('SNMP_PORT','161')),version=version,configured=configured)

class Client:
    async def open(self):
        from pysnmp.hlapi.v3arch import asyncio as snmp
        self.snmp=snmp;self.engine=snmp.SnmpEngine();settings=config()
        if not settings['configured']:raise SnmpError('SNMP credentials are not configured on the application server.',503)
        if settings['version']=='2c':
            self.auth=snmp.CommunityData(os.environ['SNMP_COMMUNITY'],mpModel=1)
        else:
            algorithms={'SHA256':snmp.USM_AUTH_HMAC192_SHA256,'SHA512':snmp.USM_AUTH_HMAC384_SHA512}
            algorithm=os.environ.get('SNMP_AUTH_PROTOCOL','SHA256').upper().replace('-','')
            privacy=os.environ.get('SNMP_PRIV_PROTOCOL','AES128').upper().replace('-','')
            if algorithm not in algorithms or privacy!='AES128':
                raise SnmpError('Supported SNMPv3 profiles are SHA256/SHA512 with AES128.',503)
            self.auth=snmp.UsmUserData(os.environ['SNMP_USER'],os.environ['SNMP_AUTH_KEY'],os.environ['SNMP_PRIV_KEY'],authProtocol=algorithms[algorithm],privProtocol=snmp.USM_PRIV_CFB128_AES)
        self.target=await snmp.UdpTransportTarget.create((settings['host'],settings['port']),timeout=1.5,retries=1)
        self.context=snmp.ContextData()
        return self
    def close(self):
        if hasattr(self,'engine'):self.engine.close_dispatcher()
    async def get(self,oids):
        s=self.snmp
        err,status,index,bindings=await s.get_cmd(self.engine,self.auth,self.target,self.context,*[s.ObjectType(s.ObjectIdentity(oid)) for oid in oids],lookupMib=False)
        if err:raise SnmpError('SNMP GET failed: '+str(err))
        if status:raise SnmpError('SNMP GET error: '+status.prettyPrint())
        return [record(oid,value) for oid,value in bindings]
    async def walk(self,root,deadline,remaining):
        s=self.snmp;cursor=root;rows=[];repetitions=30
        for _ in range(1000):
            if time.monotonic()>deadline or len(rows)>=remaining:return rows,False,'Discovery limit reached; the returned inventory is partial.'
            err,status,index,bindings=await s.bulk_cmd(self.engine,self.auth,self.target,self.context,0,repetitions,s.ObjectType(s.ObjectIdentity(cursor)),lookupMib=False)
            if err:return rows,False,'SNMP discovery failed: '+str(err)
            if status:
                if int(status)==1 and repetitions>5:repetitions=max(5,repetitions//2);continue
                return rows,False,'SNMP discovery error: '+status.prettyPrint()
            if not bindings:return rows,True,''
            for oid,value in bindings:
                current=str(oid)
                if type(value).__name__=='EndOfMibView' or not current.startswith(root+'.'):return rows,True,''
                if oid_tuple(current)<=oid_tuple(cursor):return rows,False,'The SBC returned a non-increasing OID; discovery stopped.'
                cursor=current;rows.append(record(oid,value))
                if len(rows)>=remaining:return rows,False,'Discovery limit reached; the returned inventory is partial.'
        return rows,False,'Discovery request limit reached; the returned inventory is partial.'


def table_rows(records,columns):
    grouped={}
    for item in records:
        if not item['available']:continue
        if item['name'] in columns and item['index']:
            column=columns[item['name']]
            grouped.setdefault(item['index'],dict(index=item['index']))[column]=item['display'] if column=='status' else item['numeric'] if item['numeric'] is not None else item['value']
    return list(grouped.values())

def build_tables(records):
    storage=table_rows(records,{'apSysVolumeName':'name','apSysVolumeTotalSpace':'totalMB','apSysVolumeAvailSpace':'availableKB'})
    for row in storage:
        total,available=row.get('totalMB'),row.get('availableKB')
        row['usedPercent']=max(0,min(100,100*(1-available/(total*1000)))) if isinstance(total,(int,float)) and total>0 and isinstance(available,(int,float)) and 0<=available<=total*1000 else None
    interfaces=table_rows(records,{'ifDescr':'name','ifName':'shortName','ifOperStatus':'operStatus','ifAdminStatus':'adminStatus','ifSpeed':'speed','ifInOctets':'inOctets','ifOutOctets':'outOctets','ifInErrors':'inErrors','ifOutErrors':'outErrors','ifInDiscards':'inDiscards','ifOutDiscards':'outDiscards'})
    realms=table_rows(records,{'apSigRealmStatsRealmName':'name','apSigRealmStatsCurrentActiveSessionsInbound':'inbound','apSigRealmStatsCurrentActiveSessionsOutbound':'outbound'})
    agents=table_rows(records,{'apSipSAStatsSessionAgentHostname':'name','apSipSAStatsSessionAgentStatus':'status','apSipSAStatsCurrentActiveSessionsInbound':'inbound','apSipSAStatsCurrentActiveSessionsOutbound':'outbound'})
    return dict(storage=storage,interfaces=interfaces,realms=realms,agents=agents)

class Monitor:
    def __init__(self):
        self.lock=threading.RLock();self.busy=False;self.last_start=0;self.sample=None;self.inventory=[];self.inventory_at='';self.discovery_time=0;self.discovery_complete=False;self.discovery_errors=[];self.error='';self.stage='idle';self.generation=0;self.tables={};self.custom_lock=threading.Lock()
    def status(self,refresh=False,discover=False):
        settings=config()
        with self.lock:
            due=not self.sample or time.time()-self.last_start>=30
            if settings['configured'] and not self.busy and time.time()-self.last_start>=5 and (refresh or discover or due):
                full=discover or time.time()-self.discovery_time>=300
                self.busy=True;self.last_start=time.time();self.stage='Reading live metrics';self.error=''
                threading.Thread(target=self._worker,args=(full,),daemon=True).start()
            return dict(**settings,busy=self.busy,stage=self.stage,error=self.error,sample=copy.deepcopy(self.sample),inventory=dict(count=len(self.inventory),checkedAt=self.inventory_at,complete=self.discovery_complete,errors=self.discovery_errors[:],generation=self.generation),tables=copy.deepcopy(self.tables))
    def _worker(self,full):
        try:asyncio.run(self._collect(full))
        except SnmpError as exc:
            with self.lock:self.error=str(exc)
        except Exception as exc:
            with self.lock:self.error='SNMP diagnostics could not be completed ('+type(exc).__name__+').'
        finally:
            with self.lock:self.busy=False;self.stage='idle'
    async def _collect(self,full):
        client=Client()
        try:
            await client.open();rows=await client.get(list(COMMON.values()));by_oid={r['oid']:r for r in rows}
            with self.lock:self.sample=dict(checkedAt=now(),values={name:by_oid.get(oid,dict(oid=oid,available=False,numeric=None,value='',display='Unavailable')) for name,oid in COMMON.items()})
            if full:
                records=[];errors=[];complete=True;deadline=time.monotonic()+40
                for root in ROOTS:
                    with self.lock:self.stage='Discovering '+root
                    found,done,error=await client.walk(root,deadline,20000-len(records));records.extend(found);complete &= done
                    if error:errors.append(dict(root=root,error=error))
                with self.lock:
                    if records:
                        self.inventory=records;self.inventory_at=now();self.generation+=1;self.tables=build_tables(records)
                    self.discovery_complete=complete;self.discovery_errors=errors;self.discovery_time=time.time()
        finally:client.close()
    def objects(self,query='',module='',offset=0,limit=100):
        with self.lock:
            needle=query.lower();rows=[r for r in self.inventory if (not module or r['module']==module) and (not needle or needle in (r['name']+' '+r['oid']+' '+r['value']+' '+r['module']).lower())]
            return dict(total=len(self.inventory),filtered=len(rows),offset=offset,limit=limit,objects=copy.deepcopy(rows[offset:offset+limit]),modules=sorted({r['module'] for r in self.inventory}),generation=self.generation,checkedAt=self.inventory_at)
    def export(self):
        with self.lock:return dict(host=config()['host'],protocol='SNMP '+config()['version'],sample=copy.deepcopy(self.sample),checkedAt=self.inventory_at,complete=self.discovery_complete,errors=copy.deepcopy(self.discovery_errors),objects=copy.deepcopy(self.inventory))
    def get_one(self,oid):
        oid=validate_oid(oid)
        if not self.custom_lock.acquire(blocking=False):raise SnmpError('Another OID lookup is in progress. Try again shortly.',429)
        async def run():
            client=Client()
            try:
                await client.open();rows=await client.get([oid]);return dict(checkedAt=now(),object=rows[0])
            finally:client.close()
        try:return asyncio.run(run())
        finally:self.custom_lock.release()

MONITOR=Monitor()
