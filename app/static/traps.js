'use strict';
let trapOffset=0,trapFiltered=0,trapBusy=false,trapSearchTimer=null,trapRequest=0,trapDetailRequest=0,trapEpoch=0;
function resetTrapsView(){trapEpoch++;trapRequest++;trapDetailRequest++;trapOffset=0;$('traps-events').replaceChildren();$('traps-detail').hidden=true;clearTimeout(trapSearchTimer)}
function trapParams(){return new URLSearchParams({q:$('traps-search').value,severity:$('traps-severity').value,version:$('traps-version').value,offset:trapOffset,limit:50})}
function trapDate(value){return value?new Date(value).toLocaleString('en-GB'):'No events yet'}
function renderTrapOverview(data){
 const receiver=data.receiver;$('traps-listener').textContent=(receiver.listening?'● Listening':'○ '+receiver.status)+' · '+(receiver.endpoint||'UDP :162')+' · SBC '+(receiver.source||$('sbc-host').textContent);
 $('traps-listener').classList.toggle('traps-offline',!receiver.listening);
 $('traps-status').textContent='Receiver started: '+trapDate(receiver.startedAt)+' · Updated '+trapDate(data.checkedAt)+' · '+(receiver.accepted||0)+' accepted since receiver start · '+(receiver.rejected||0)+' from other sources · '+(receiver.malformed||0)+' invalid or unauthenticated';
 $('traps-error').hidden=!receiver.error;$('traps-error').textContent=receiver.error||'';
 $('traps-kpis').replaceChildren(snmpMetricCard('RETAINED NOTIFICATIONS',data.retained.toLocaleString('en-GB'),'Latest '+data.limit.toLocaleString('en-GB')+' retained'),snmpMetricCard('LAST 15 MINUTES',data.recent.toLocaleString('en-GB'),'From the retained inbox'),snmpMetricCard('NOTIFICATION TYPES',data.uniqueTypes.toLocaleString('en-GB'),'Different notification OIDs'),snmpMetricCard('LAST RECEIVED',data.lastReceived?new Date(data.lastReceived).toLocaleTimeString('en-GB'):'Waiting',data.lastReceived?new Date(data.lastReceived).toLocaleDateString('en-GB'):'SBC notifications will appear here'));
 const samples=data.timeline.map(point=>({time:point.time,count:point.count}));$('traps-timeline').replaceChildren(diagnosticLineChart('Received notifications',[{key:'count',label:'Traps / minute',color:'#8b6bc5'}],false,samples));
 const types=$('traps-types');types.replaceChildren();const max=Math.max(1,...data.types.map(row=>row.count));for(const row of data.types){const bar=el('div',{class:'snmp-counter-bar trap-type-bar'});bar.append(el('span',{title:row.name+' · '+row.oid},row.title||row.name),el('strong',{},row.count.toLocaleString('en-GB')),el('progress',{max,value:row.count,'aria-label':row.title||row.name}));types.append(bar)}if(!data.types.length)types.append(el('p',{class:'muted'},'Notification types will appear when events arrive.'));
}
async function loadTraps(){
 if(trapBusy)return;trapBusy=true;const epoch=trapEpoch;
 try{const data=await api('/api/traps');if(epoch!==trapEpoch)return;renderTrapOverview(data);await loadTrapEvents()}
 catch(error){if(epoch===trapEpoch){$('traps-error').textContent=error.message;$('traps-error').hidden=false}}
 finally{trapBusy=false}
}
async function loadTrapEvents(){
 const request=++trapRequest;
 try{const data=await api('/api/traps/events?'+trapParams());if(request!==trapRequest)return;trapFiltered=data.filtered;
  if(trapOffset&&trapOffset>=data.filtered){trapOffset=0;return loadTrapEvents()}
  $('traps-events').replaceChildren();for(const item of data.events){const row=el('tr'),name=el('td'),level=el('td'),details=el('td');name.append(el('strong',{},item.title||item.name),el('small',{class:'trap-description',title:item.description||''},item.description||''),el('small',{class:'muted trap-technical'},item.name+' · '+item.oid));if(item.summary)name.append(el('small',{},item.summary));level.append(el('span',{class:'trap-severity level-'+item.severity},item.severity));const button=el('button',{type:'button'},'View #'+item.id);button.onclick=()=>showTrapEvent(item.id);details.append(button);row.append(el('td',{},trapDate(item.receivedAt)),name,el('td',{},item.source+':'+item.sourcePort),level,el('td',{},'v'+item.version+' '+item.kind),details);$('traps-events').append(row)}
  $('traps-empty').hidden=!!data.filtered;$('traps-empty').textContent=$('traps-search').value||$('traps-severity').value||$('traps-version').value?'No notifications match these filters.':'No notifications have arrived yet. New traps sent by the SBC to UDP port 162 will appear here.';
  $('traps-page').textContent=data.filtered?'Showing '+(data.offset+1)+'–'+Math.min(data.offset+data.events.length,data.filtered)+' of '+data.filtered.toLocaleString('en-GB')+' events':'0 events';$('traps-prev').disabled=data.offset===0;$('traps-next').disabled=data.offset+50>=data.filtered;
 }catch(error){if(request===trapRequest){$('traps-error').hidden=false;$('traps-error').textContent=error.message}}
}
async function showTrapEvent(id){
 const request=++trapDetailRequest;
 try{const item=await api('/api/traps/event?'+new URLSearchParams({id}));if(request!==trapDetailRequest)return;
 $('traps-detail-title').textContent=(item.title||item.name)+' · #'+item.id;
 $('traps-detail-description').textContent=item.description||'';$('traps-detail-reference').textContent='Technical name: '+item.name+(item.mibModule?' · '+item.mibModule:'');$('traps-mib-source').hidden=!item.documented;$('traps-detail-meta').textContent=trapDate(item.receivedAt)+' · '+item.source+':'+item.sourcePort+' · SNMPv'+item.version+' '+item.kind+' · '+item.oid;
 $('traps-detail-note').textContent='SBC uptime at event: '+snmpUptime(item.uptimeTicks)+' · Severity: '+item.severity+(item.enterprise?' · Enterprise: '+item.enterprise+' · Generic / specific: '+item.genericTrap+' / '+item.specificTrap:'')+(item.truncated?' · Some values or bindings were truncated to the receiver limits.':'');
 $('traps-bindings').replaceChildren();for(const binding of item.bindings){const row=el('tr'),value=el('td',{},binding.display);if(binding.referenceName&&binding.referenceName!==binding.value)value.append(el('small',{class:'muted'},binding.referenceName));if(binding.truncated)value.append(el('small',{class:'error'},'Truncated value'));row.append(el('td',{},binding.name),el('td',{},binding.oid),el('td',{},binding.type),value);$('traps-bindings').append(row)}
 if(!item.bindings.length){const row=el('tr');row.append(el('td',{colspan:4},'This SNMPv1 trap has no additional parameters.'));$('traps-bindings').append(row)}$('traps-detail').hidden=false;$('traps-detail').scrollIntoView({behavior:'smooth',block:'start'});
 }catch(error){if(request===trapDetailRequest){$('traps-error').hidden=false;$('traps-error').textContent=error.message}}
}
$('nav-traps').onclick=()=>{showWorkspace('traps');loadTraps()};$('traps-refresh').onclick=loadTraps;$('traps-close').onclick=()=>{trapDetailRequest++;$('traps-detail').hidden=true};
$('traps-search').oninput=()=>{clearTimeout(trapSearchTimer);trapSearchTimer=setTimeout(()=>{trapOffset=0;loadTrapEvents()},250)};
for(const id of ['traps-severity','traps-version'])$(id).onchange=()=>{trapOffset=0;loadTrapEvents()};
$('traps-prev').onclick=()=>{trapOffset=Math.max(0,trapOffset-50);loadTrapEvents()};$('traps-next').onclick=()=>{if(trapOffset+50<trapFiltered){trapOffset+=50;loadTrapEvents()}};
$('traps-export').onclick=()=>task(async()=>{const data=await api('/api/traps/export?'+trapParams());data.note='Up to the latest 500 matching retained notifications; newest first.';const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'})),link=el('a',{href:url,download:'sbc-snmp-traps-'+new Date().toISOString().replace(/:/g,'-')+'.json'});link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)});
setInterval(()=>{if(!$('shell').hidden&&!$('traps-view').hidden&&!document.hidden&&$('traps-auto').checked)loadTraps()},5000);
const trapHeaderRefresh=$('refresh').onclick;$('refresh').onclick=()=>!$('traps-view').hidden?loadTraps():trapHeaderRefresh();
