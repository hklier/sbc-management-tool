"""Read-only SBC connectivity checks; run inside the console container."""
import asyncio
import json
import server
import snmp_tools

results={}
for label,check in [('rest_version',lambda: server.SBC_CLIENT.get('system/version')),
                    ('configuration_types',server.element_types)]:
    try:
        value=check()
        results[label]={'ok':True}
        if isinstance(value,list):results[label]['count']=len(value)
    except Exception as exc:results[label]={'ok':False,'error':str(exc)}
try:
    with server.lrt_sftp('read-only connectivity test') as sftp:
        results['sftp']={'ok':True,'directories':{}}
        for directory in ['/code/lrt','/opt/cdr','/opt/traces']:
            try:results['sftp']['directories'][directory]={'ok':True,'entries':len(sftp.listdir(directory))}
            except Exception as exc:results['sftp']['directories'][directory]={'ok':False,'error':type(exc).__name__}
except Exception as exc:results['sftp']={'ok':False,'error':str(exc)}

async def snmp():
    client=snmp_tools.Client()
    try:
        await client.open()
        values=await client.get([snmp_tools.COMMON['description'],snmp_tools.COMMON['uptime']])
        return {'ok':all(v['available'] for v in values),'objects':len(values)}
    finally:client.close()
try:results['snmp_v3']=asyncio.run(snmp())
except Exception as exc:results['snmp_v3']={'ok':False,'error':str(exc)}
print(json.dumps(results,indent=2))
raise SystemExit(0 if all(v['ok'] for v in results.values()) else 1)
