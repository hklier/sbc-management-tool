'use strict';
let snmpLatest=null,snmpHistory=[],snmpHost='',snmpBusy=false,snmpTimer=null,snmpOffset=0,snmpFiltered=0,snmpGeneration=-1,snmpObjectRequest=0,snmpSearchTimer=null,snmpCustomOid='',snmpCustomHistory=[],snmpCustomBusy=false;
const snmpLimit=100;
function resetSnmpView(){clearTimeout(snmpTimer);snmpHistory=[];snmpHost='';snmpLatest=null;snmpGeneration=-1;snmpCustomHistory=[];snmpCustomOid=''}
function snmpValue(key){const value=snmpLatest?.sample?.values[key];return value?.available?value:null}
function snmpNumeric(key,percent=false){const n=snmpValue(key)?.numeric;return typeof n==='number'&&Number.isFinite(n)&&n>=0&&(!percent||n<=100)?n:null}
function snmpCounter(value){if(value===undefined||value===null)return 'Unavailable';try{if(typeof value==='string'&&/^-?\d+$/.test(value))return BigInt(value).toLocaleString('en-GB')}catch{}return typeof value==='number'?value.toLocaleString('en-GB'):String(value)}
function snmpMetricCard(title,value,note){const card=el('div',{class:'snmp-metric-card'});card.append(el('small',{},title),el('strong',{},value),el('span',{},note));return card}
function snmpUptime(value){if(typeof value!=='number')return 'Unavailable';const seconds=Math.floor(value/100);return Math.floor(seconds/86400)+'d '+Math.floor(seconds%86400/3600)+'h '+Math.floor(seconds%3600/60)+'m'}
function snmpSample(){
  const report=snmpLatest;if(!report.sample)return;
  const stamp=Date.parse(report.sample.checkedAt);if(!Number.isFinite(stamp))return;
  const point={time:stamp,cpu:snmpNumeric('cpu',true),memory:snmpNumeric('memory',true),sessions:snmpNumeric('sessions'),cps:snmpNumeric('cps'),uptime:snmpNumeric('uptime')};
  if(snmpHistory.at(-1)?.uptime>point.uptime&&point.uptime!==null)snmpHistory=[];
  if(snmpHistory.at(-1)?.time===stamp)snmpHistory[snmpHistory.length-1]=point;else if(!snmpHistory.length||stamp>snmpHistory.at(-1).time)snmpHistory.push(point);
  snmpHistory=snmpHistory.slice(-180);
}
function renderSnmp(){
  const data=snmpLatest;if(!data)return;
  if(snmpHost!==data.host){snmpHistory=[];snmpHost=data.host}snmpSample();
  $('snmp-target').textContent=data.host+':'+data.port+' · SNMP '+data.version+' · Read only';
  $('snmp-error').hidden=!data.error&&data.configured;$('snmp-error').textContent=data.error||'Configure private SNMP credentials on the application server to start collecting metrics.';
  $('snmp-status').textContent=(data.busy?data.stage+'… · ':'')+(data.sample?'Last successful sample: '+new Date(data.sample.checkedAt).toLocaleString('en-GB'):'Waiting for the first SNMP sample')+' · '+data.inventory.count.toLocaleString('en-GB')+' discovered objects'+(data.error?' · Last refresh failed':'');
  $('snmp-refresh').disabled=data.busy;$('snmp-discover').disabled=data.busy;$('snmp-export').disabled=!data.inventory.count;
  $('snmp-rings').replaceChildren(diagnosticRing('CPU utilization',snmpNumeric('cpu',true),'#0c9d8c'),diagnosticRing('Memory utilization',snmpNumeric('memory',true),'#6588d0'),diagnosticRing('Health score',snmpNumeric('health',true),'#29865e'),diagnosticRing('Licensed session usage',snmpNumeric('license',true),'#b78c3b'));
  $('snmp-kpis').replaceChildren(snmpMetricCard('CONCURRENT SESSIONS',snmpCounter(snmpNumeric('sessions')),'SBC global sessions'),snmpMetricCard('CALLS PER SECOND',snmpCounter(snmpNumeric('cps')),'Instantaneous CPS'),snmpMetricCard('SIP REGISTRATIONS',snmpCounter(snmpNumeric('registrations')),'Cached local contacts'),snmpMetricCard('SYSTEM UPTIME',snmpUptime(snmpNumeric('uptime')),(snmpValue('state')?.display||'State unavailable')+' · '+(snmpValue('redundancy')?.display||'HA state unavailable')));
  $('snmp-history-note').textContent=snmpHistory.length+' real samples in this tab · up to 180 retained · no values are fabricated when an OID is unavailable.';
  $('snmp-trends').replaceChildren(diagnosticLineChart('CPU & memory',[{key:'cpu',label:'CPU',color:'#0c9d8c'},{key:'memory',label:'Memory',color:'#6588d0'}],true,snmpHistory),diagnosticLineChart('Concurrent sessions',[{key:'sessions',label:'Sessions',color:'#b78c3b'}],false,snmpHistory),diagnosticLineChart('Calls per second',[{key:'cps',label:'CPS',color:'#0c9d8c'}],false,snmpHistory));
  const tables=data.tables||{};$('snmp-storage').replaceChildren();
  (tables.storage||[]).forEach(volume=>{const block=el('div',{class:'snmp-volume'}),percentage=volume.usedPercent;block.append(el('strong',{},volume.name||'Volume '+volume.index),el('span',{},percentage===null?'Usage unavailable':percentage.toFixed(1)+'% used'));if(percentage!==null)block.append(el('progress',{max:100,value:percentage,'aria-label':volume.name+' used space'}));block.append(el('small',{},snmpCounter(volume.totalMB)+' MB total · '+snmpCounter(volume.availableKB)+' KB available'));$('snmp-storage').append(block)});
  if(!tables.storage?.length)$('snmp-storage').append(el('p',{class:'muted'},'No storage table has been discovered yet.'));
  const protection=[['Rejected messages','rejected'],['Rejected calls','callsRejected'],['Denied endpoints','deniedEndpoints'],['Trusted to untrusted','trustDemotions'],['Untrusted to denied','deniedDemotions']];const max=Math.max(1,...protection.map(([,key])=>snmpNumeric(key)||0));$('snmp-protection').replaceChildren();
  protection.forEach(([label,key])=>{const n=snmpNumeric(key),row=el('div',{class:'snmp-counter-bar'});row.append(el('span',{},label),el('strong',{},snmpCounter(n)));if(n!==null)row.append(el('progress',{max,value:n,'aria-label':label}));$('snmp-protection').append(row)});
  renderSnmpInterfaces(tables.interfaces||[]);renderSnmpRouting(tables);
  $('snmp-table-time').textContent=data.inventory.checkedAt?'Table snapshot: '+new Date(data.inventory.checkedAt).toLocaleString('en-GB')+' · tables refresh during discovery, every five minutes or on demand.':'Waiting for table discovery.';
  $('snmp-inventory-note').textContent=(data.inventory.checkedAt?'Discovered '+new Date(data.inventory.checkedAt).toLocaleString('en-GB')+' · ':'')+(data.inventory.complete?'Complete scan of MIB-II and Oracle management subtrees.':'Discovery is incomplete or has not run yet.')+(data.inventory.errors.length?' '+data.inventory.errors.map(e=>e.error).join(' '):'')+' GETBULK discovers available instances; trap-only and unsupported objects are not counted.';
}
function renderSnmpInterfaces(interfaces){
  const table=el('table',{class:'trace-files snmp-interface-table'}),head=el('tr');['Interface','Admin / link','Speed','Received bytes','Transmitted bytes','RX / TX errors'].forEach(label=>head.append(el('th',{},label)));const thead=el('thead');thead.append(head);table.append(thead);const body=el('tbody'),states={1:'up',2:'down',3:'testing',4:'unknown',5:'dormant',6:'not present',7:'lower layer down'};
  interfaces.forEach(iface=>{const row=el('tr'),state=el('td');state.append(el('span',{class:'snmp-link '+(iface.operStatus===1?'is-up':'is-down')},(states[iface.adminStatus]||'unknown')+' / '+(states[iface.operStatus]||'unknown')));row.append(el('td',{},iface.name||iface.shortName||iface.index),state,el('td',{},typeof iface.speed==='number'?(iface.speed===4294967295?'See ifHighSpeed':(iface.speed/1e6).toLocaleString('en-GB')+' Mbps'):'Unavailable'),el('td',{},snmpCounter(iface.inOctets)),el('td',{},snmpCounter(iface.outOctets)),el('td',{},snmpCounter(iface.inErrors)+' / '+snmpCounter(iface.outErrors)));body.append(row)});table.append(body);$('snmp-interfaces').replaceChildren(interfaces.length?table:el('p',{class:'muted'},'No interface data has been discovered yet.'));
}
function renderSnmpRouting(tables){
  $('snmp-routing').replaceChildren();
  for(const [title,list]of [['Realms',tables.realms||[]],['SIP session agents',tables.agents||[]]]){const part=el('section',{class:'snmp-routing-group'});part.append(el('h3',{},title));if(!list.length)part.append(el('p',{class:'muted'},'No rows returned by this SBC.'));else{const items=el('div',{class:'snmp-routing-cards'});list.forEach(item=>{const card=el('div');card.append(el('strong',{},item.name||item.index),el('small',{},'Inbound: '+snmpCounter(item.inbound)+' · Outbound: '+snmpCounter(item.outbound)+(item.status!==undefined?' · '+item.status:'')));items.append(card)});part.append(items)}$('snmp-routing').append(part)}
}
async function loadSnmp(refresh=false,discover=false){
  if(snmpBusy)return;snmpBusy=true;clearTimeout(snmpTimer);
  try{const data=await api('/api/snmp?'+new URLSearchParams({refresh:String(refresh),discover:String(discover)}));snmpLatest=data;renderSnmp();if(data.inventory.generation!==snmpGeneration){snmpGeneration=data.inventory.generation;await loadSnmpObjects()}}
  catch(error){$('snmp-error').textContent=error.message;$('snmp-error').hidden=false}
  finally{snmpBusy=false;if(snmpLatest?.busy&&!$('snmp-view').hidden&&!$('shell').hidden)snmpTimer=setTimeout(()=>loadSnmp(),2000)}
}
async function loadSnmpObjects(){
  const token=++snmpObjectRequest;try{const data=await api('/api/snmp/objects?'+new URLSearchParams({q:$('snmp-search').value,module:$('snmp-module').value,offset:snmpOffset,limit:snmpLimit}));if(token!==snmpObjectRequest)return;snmpFiltered=data.filtered;const selected=$('snmp-module').value;$('snmp-module').replaceChildren(el('option',{value:''},'All MIB modules'));data.modules.forEach(module=>$('snmp-module').append(el('option',{value:module},module)));if(data.modules.includes(selected))$('snmp-module').value=selected;
    $('snmp-objects').replaceChildren();data.objects.forEach(item=>{const row=el('tr'),label=el('td');label.append(el('strong',{},item.name),el('small',{class:'muted'},item.module+' · '+item.type));const value=el('td',{},item.available?item.display:'Unavailable');const oid=el('td',{class:'snmp-oid-cell'},item.oid);if(item.truncated)value.append(el('small',{class:'muted'},'Value truncated at 4096 characters'));const action=el('td'),button=el('button',{type:'button'},'Inspect');button.onclick=()=>{$('snmp-oid').value=item.oid;getSnmpOid()};action.append(button);row.append(label,oid,value,action);$('snmp-objects').append(row)});
    $('snmp-page').textContent=data.filtered?'Showing '+(data.offset+1)+'–'+Math.min(data.offset+data.objects.length,data.filtered)+' of '+data.filtered.toLocaleString('en-GB')+' objects':'No matching objects';$('snmp-prev').disabled=data.offset===0;$('snmp-next').disabled=data.offset+snmpLimit>=data.filtered;
  }catch(error){if(token===snmpObjectRequest){$('snmp-error').textContent=error.message;$('snmp-error').hidden=false}}
}
async function getSnmpOid(){
  if(snmpCustomBusy)return;const requested=$('snmp-oid').value.trim();if(!requested)return;snmpCustomBusy=true;$('snmp-get').disabled=true;
  try{const result=await api('/api/snmp/get?'+new URLSearchParams({oid:requested})),item=result.object;if(snmpCustomOid!==item.oid){snmpCustomOid=item.oid;snmpCustomHistory=[]}
    const point={time:Date.parse(result.checkedAt),value:item.available?item.numeric:null};if(snmpCustomHistory.at(-1)?.time===point.time)snmpCustomHistory[snmpCustomHistory.length-1]=point;else snmpCustomHistory.push(point);snmpCustomHistory=snmpCustomHistory.slice(-180);
    $('snmp-get-result').replaceChildren(el('strong',{},item.name),el('p',{},item.oid+' · '+item.type+' · '+new Date(result.checkedAt).toLocaleString('en-GB')),el('p',{class:'snmp-object-value'},item.available?item.display:'This OID is not available on the SBC.'));
    $('snmp-custom-chart').replaceChildren(typeof item.numeric==='number'?diagnosticLineChart(item.name,[{key:'value',label:item.type.startsWith('Counter')?'Cumulative counter':'Value',color:'#6588d0'}],false,snmpCustomHistory):el('p',{class:'muted'},'This value cannot be plotted. Large counters retain their exact text representation.'));
  }catch(error){$('snmp-get-result').replaceChildren(el('p',{class:'error'},error.message));$('snmp-custom-chart').replaceChildren()}finally{snmpCustomBusy=false;$('snmp-get').disabled=false}
}
$('nav-snmp').onclick=()=>{showWorkspace('snmp');loadSnmp()};$('snmp-refresh').onclick=()=>{loadSnmp(true);if(snmpCustomOid)getSnmpOid()};$('snmp-discover').onclick=()=>loadSnmp(true,true);
$('snmp-search').oninput=()=>{clearTimeout(snmpSearchTimer);snmpSearchTimer=setTimeout(()=>{snmpOffset=0;loadSnmpObjects()},250)};$('snmp-module').onchange=()=>{snmpOffset=0;loadSnmpObjects()};$('snmp-prev').onclick=()=>{snmpOffset=Math.max(0,snmpOffset-snmpLimit);loadSnmpObjects()};$('snmp-next').onclick=()=>{if(snmpOffset+snmpLimit<snmpFiltered){snmpOffset+=snmpLimit;loadSnmpObjects()}};
$('snmp-get-form').onsubmit=event=>{event.preventDefault();getSnmpOid()};
$('snmp-export').onclick=()=>task(async()=>{const report=await api('/api/snmp/export');report.chartSamples=snmpHistory;const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'})),link=el('a',{href:url,download:'sbc-snmp-diagnosis-'+new Date().toISOString().replace(/:/g,'-')+'.json'});link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)});
setInterval(()=>{if($('snmp-auto').checked&&!$('snmp-view').hidden&&!$('shell').hidden&&!document.hidden){loadSnmp();if(snmpCustomOid)getSnmpOid()}},30000);
const snmpHeaderRefresh=$('refresh').onclick;$('refresh').onclick=()=>!$('snmp-view').hidden?loadSnmp(true):snmpHeaderRefresh();
