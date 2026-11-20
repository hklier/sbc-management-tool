'use strict';
let diagnosticReport=null,diagnosticLoading=false,diagnosticRouteLoading=false;
const diagnosticLabels={sysCPUUtil:'CPU utilization',sysMemoryUtil:'Memory utilization',globalSessions:'Sessions',sipRegistrations:'SIP registrations',sessCapacityUtil:'Session capacity',dosThresholdCounters:'Protection threshold counters',SipInviteDetailStats:'SIP INVITE statistics'};
function diagnosticLabel(name){const labels={sipReg:'Active SIP registrations',percentCap:'Session capacity used (%)'};const leaf=name.split('.').pop();if(labels[leaf])return labels[leaf];return name.replace(/\[\d+\]/g,'').split('.').pop().replace(/([a-z0-9])([A-Z])/g,'$1 $2').replace(/^sys /,'').replace(/^./,c=>c.toUpperCase())}
function diagnosticValue(section,name){return section?.ok?section.fields.find(f=>f.name===name)?.value:undefined}
function diagnosticFields(section){
  const wrap=el('div');
  if(!section?.ok){wrap.append(el('p',{class:'error'},section?.error||'Measurement unavailable.'));return wrap}
  const fields=section.fields.filter(f=>f.value!=='');
  if(!fields.length)wrap.append(el('p',{class:'muted'},'No data returned by the SBC.'));
  else{const list=el('dl',{class:'diagnostic-fields'});fields.forEach(f=>{list.append(el('dt',{},diagnosticLabel(f.name)),el('dd',{},f.value))});wrap.append(list)}
  if(section.fields.length>=500)wrap.append(el('p',{class:'muted'},'Showing the first 500 fields. The full response is included below and in the report.'));
  const details=el('details');details.append(el('summary',{},'View SBC response'),el('pre',{},section.xml));wrap.append(details);return wrap;
}
function diagnosticCard(title,value,note){const card=el('div',{class:'stat diagnostic-card'});card.append(el('span',{},title),el('strong',{},value===undefined||value===''?'Unavailable':value),el('small',{},note));return card}
function diagnosticDuration(value){const n=Number(value);if(value===undefined||!Number.isFinite(n))return undefined;return Math.floor(n/86400)+'d '+Math.floor(n%86400/3600)+'h '+Math.floor(n%3600/60)+'m'}
function renderDiagnostics(data){
  renderDiagnosticCharts(data);
  const s=data.sections,summary=$('diagnostics-summary');summary.replaceChildren();
  const health=diagnosticValue(s.system,'healthScorePercent'),cpu=diagnosticValue(s.sysCPUUtil,'sysCPUUtilPercent.percentUsed'),memory=diagnosticValue(s.sysMemoryUtil,'sysMemoryUtil.percentUsed');
  summary.append(diagnosticCard('SYSTEM STATE',diagnosticValue(s.system,'systemState'),[diagnosticValue(s.system,'hostName'),diagnosticValue(s.system,'role')].filter(Boolean).join(' · ')||'System status unavailable'),diagnosticCard('HEALTH SCORE',health===undefined?undefined:health+'%','Reported by the SBC'),diagnosticCard('UPTIME',diagnosticDuration(diagnosticValue(s.system,'uptimeSeconds')),'Time since last start'),diagnosticCard('CPU',cpu===undefined?undefined:cpu+'%','Current utilization'),diagnosticCard('MEMORY',memory===undefined?undefined:memory+'%','Current utilization'),diagnosticCard('CONCURRENT SESSIONS',diagnosticValue(s.globalSessions,'globalSessions.sysGlobalConSessions'),'Calls per second: '+(diagnosticValue(s.globalSessions,'globalSessions.sysGlobalCPS')??'Unavailable')));
  $('diagnostics-storage').replaceChildren();
  if(s.storage?.ok){const root=parse(s.storage.xml),volumes=[...root.querySelectorAll('data > storage')];
    if(!volumes.length)$('diagnostics-storage').append(el('p',{class:'muted'},'No volume data returned.'));
    volumes.forEach(v=>{const total=Number(txt(v,'totalBytes')),used=Number(txt(v,'usedBytes')),free=Number(txt(v,'availableBytes')),percent=total>0?100*used/total:null;const row=el('div',{class:'diagnostic-volume'});row.append(el('strong',{},txt(v,'volume')),el('span',{},percent===null?'Usage unavailable':percent.toFixed(1)+'% used'),el('small',{},(used/1073741824).toFixed(2)+' GiB used · '+(free/1073741824).toFixed(2)+' GiB available'));if(percent!==null){const meter=el('progress',{max:'100',value:String(percent),'aria-label':txt(v,'volume')+' space used'});row.append(meter)}$('diagnostics-storage').append(row)});
  }else $('diagnostics-storage').append(diagnosticFields(s.storage));
  $('diagnostics-metrics').replaceChildren();
  Object.entries(diagnosticLabels).filter(([k])=>!['sysCPUUtil','sysMemoryUtil','globalSessions'].includes(k)).forEach(([kind,title])=>{const box=el('section',{class:'diagnostic-metric'});box.append(el('h3',{},title),diagnosticFields(s[kind]));$('diagnostics-metrics').append(box)});
  // Include unavailable summary sources so a missing measurement always has an explanation.
  ['system','sysCPUUtil','sysMemoryUtil','globalSessions'].filter(k=>!s[k]?.ok).forEach(k=>{const box=el('section',{class:'diagnostic-metric'});box.append(el('h3',{},diagnosticLabels[k]||'System status'),diagnosticFields(s[k]));$('diagnostics-metrics').append(box)});
  $('diagnostics-information').replaceChildren(diagnosticFields(s.information));
  const selector=$('diagnostics-route-table'),previous=selector.value;selector.replaceChildren(el('option',{value:''},'Select a table'));
  data.lrtTables.forEach(name=>selector.append(el('option',{value:name},name)));if(data.lrtTables.includes(previous))selector.value=previous;
  selector.disabled=!data.lrtTables.length;$('diagnostics-route-test').disabled=!data.lrtTables.length||diagnosticRouteLoading;
  const issues=Object.entries(s).filter(([,v])=>!v.ok).length+(data.lrtError?1:0);
  $('diagnostics-updated').textContent='Last successful refresh: '+new Date(data.checkedAt).toLocaleString('en-GB')+' · '+data.host+(issues?' · '+issues+' unavailable data sources':' · All data sources available');
  if(data.lrtError)$('diagnostics-route-result').replaceChildren(el('p',{class:'error'},'Cannot list running LRTs: '+data.lrtError));
}
async function loadDiagnostics(){
  if(diagnosticLoading)return;diagnosticLoading=true;$('diagnostics-refresh').disabled=true;$('diagnostics-error').hidden=true;
  try{const report=await api('/api/diagnostics');diagnosticReport=report;renderDiagnostics(report);$('diagnostics-export').disabled=false}
  catch(error){$('diagnostics-error').textContent='Refresh failed. Any displayed measurements are from the previous refresh. '+error.message;$('diagnostics-error').hidden=false}
  finally{diagnosticLoading=false;$('diagnostics-refresh').disabled=false}
}
$('nav-diagnostics').onclick=()=>{showWorkspace('diagnostics');loadDiagnostics()};
$('diagnostics-refresh').onclick=loadDiagnostics;
setInterval(()=>{if($('diagnostics-auto').checked&&!$('diagnostics-view').hidden&&!$('shell').hidden&&!document.hidden)loadDiagnostics()},30000);
$('diagnostics-export').onclick=()=>{if(!diagnosticReport)return;const url=URL.createObjectURL(new Blob([JSON.stringify(diagnosticReport,null,2)],{type:'application/json'}));const link=el('a',{href:url,download:'sbc-diagnostics-'+diagnosticReport.checkedAt.replace(/[:]/g,'-')+'.json'});link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)};
$('diagnostics-route-form').onsubmit=async event=>{
  event.preventDefault();if(diagnosticRouteLoading)return;diagnosticRouteLoading=true;$('diagnostics-route-test').disabled=true;$('diagnostics-route-result').replaceChildren(el('p',{class:'muted'},'Looking up route…'));
  try{const result=await api('/api/diagnostics/route?'+new URLSearchParams({name:$('diagnostics-route-table').value,user:$('diagnostics-route-user').value}));const heading=el('p',{},'Loaded LRT: '+result.name+' · User: '+result.user+' · '+new Date(result.checkedAt).toLocaleString('en-GB'));$('diagnostics-route-result').replaceChildren(heading,diagnosticFields({...result,ok:true}));if(diagnosticReport)diagnosticReport.lastRouteTest=result}
  catch(error){$('diagnostics-route-result').replaceChildren(el('p',{class:'error'},error.message))}
  finally{diagnosticRouteLoading=false;$('diagnostics-route-test').disabled=!diagnosticReport?.lrtTables.length}
};
const diagnosticHeaderRefresh=$('refresh').onclick;
$('refresh').onclick=()=>!$('diagnostics-view').hidden?loadDiagnostics():diagnosticHeaderRefresh();
