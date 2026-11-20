'use strict';
let traceFiles=[],traceCurrent=null,traceSelected='',tracePage=0,traceLoading=false,traceListLoading=false;
const tracePageSize=100;
function traceSize(n){return n<1048576?(n/1024).toFixed(1)+' KiB':(n/1048576).toFixed(1)+' MiB'}
function traceUrl(path,file){return '/api/traces/'+path+'?'+new URLSearchParams({name:file.name,version:file.version})}
async function downloadTrace(file){
  loading++;$('busy').hidden=false;
  try{const response=await fetch(traceUrl('download',file));if(!response.ok){const error=await response.json();if(response.status===401)showLogin();throw Error(error.error||'Download failed')}
    const blob=await response.blob(),url=URL.createObjectURL(blob),link=el('a',{href:url,download:file.name});link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)
  }finally{loading--;$('busy').hidden=loading===0}
}
function traceDownloadLink(file){const link=el('a',{href:traceUrl('download',file),class:'trace-download'},'Download');link.onclick=event=>{event.preventDefault();task(()=>downloadTrace(file))};return link}
function traceFileRows(){
  $('traces-files').replaceChildren();
  traceFiles.forEach(file=>{const row=el('tr');const name=el('button',{class:'trace-name',type:'button'},file.name);name.disabled=!file.canAnalyze||traceLoading;name.title=file.canAnalyze?'View SIP call flow':'This file exceeds the 64 MiB analysis limit';name.onclick=()=>openTrace(file);const cell=el('td');cell.append(name);row.append(cell,el('td',{},traceSize(file.sizeBytes)),el('td',{},new Date(file.modifiedAt).toLocaleString('en-GB')));const download=el('td');if(file.canDownload)download.append(traceDownloadLink(file));else download.append(el('span',{class:'muted'},'Exceeds 512 MiB'));row.append(download);$('traces-files').append(row)})
}
async function loadTraces(){
  if(traceListLoading)return;traceListLoading=true;$('traces-refresh').disabled=true;$('traces-error').hidden=true;
  try{const data=await api('/api/traces');traceFiles=data.files;traceFileRows();$('traces-status').textContent=traceFiles.length?traceFiles.length+' capture file'+(traceFiles.length===1?'':'s')+' in '+data.directory:'No PCAP files found in '+data.directory;
    if(traceCurrent&&!traceFiles.some(f=>f.name===traceCurrent.name&&f.version===traceCurrent.version)){$('traces-analysis').hidden=true;traceCurrent=null;$('traces-status').textContent+=' · The previously opened capture has changed or was removed.'}}
  catch(error){$('traces-error').textContent='Could not refresh the file list. '+error.message;$('traces-error').hidden=false}
  finally{traceListLoading=false;$('traces-refresh').disabled=false}
}
async function openTrace(file){
  if(traceLoading)return;traceLoading=true;traceFileRows();$('traces-error').hidden=true;$('traces-analysis').hidden=true;$('traces-status').textContent='Reading and analyzing '+file.name+'…';
  try{traceCurrent=await api(traceUrl('flow',file));traceSelected=(traceCurrent.calls.find(c=>traceCurrent.messages.some(m=>m.callId===c.callId&&m.label.startsWith('INVITE ')))||traceCurrent.calls[0])?.callId||'';tracePage=0;$('traces-title').textContent=file.name;$('traces-summary').textContent=traceCurrent.packetCount+' packets inspected · '+traceCurrent.calls.length+' SIP dialogs · '+traceCurrent.messages.length+' messages';$('traces-current-download').href=traceUrl('download',file);$('traces-current-download').onclick=event=>{event.preventDefault();task(()=>downloadTrace(file))};$('traces-warnings').textContent=traceCurrent.warnings.join('\n');$('traces-warnings').hidden=!traceCurrent.warnings.length;$('traces-limitations').textContent=traceCurrent.limitations;$('traces-call').replaceChildren();traceCurrent.calls.forEach(call=>{const first=traceCurrent.messages.find(m=>m.callId===call.callId&&!m.label.startsWith('SIP/'));const type=first?.label.split(' ')[0]||'SIP';$('traces-call').append(el('option',{value:call.callId},type+' · '+call.callId+' · '+call.messageCount+' messages'))});$('traces-call').value=traceSelected;$('traces-call').disabled=!traceCurrent.calls.length;$('traces-analysis').hidden=false;$('traces-status').textContent='Analysis complete: '+file.name;renderTraceFlow()}
  catch(error){traceCurrent=null;$('traces-error').textContent=error.message;$('traces-error').hidden=false;$('traces-status').textContent='Could not analyze '+file.name;}
  finally{traceLoading=false;traceFileRows()}
}
function traceSvg(tag,attrs={},text){const n=document.createElementNS('http://www.w3.org/2000/svg',tag);Object.entries(attrs).forEach(([key,value])=>n.setAttribute(key,String(value)));if(text!==undefined)n.textContent=text;return n}
function traceMessageDetails(message){$('traces-message-info').textContent='Frame '+message.frame+' · '+new Date(message.timestamp*1000).toLocaleString('en-GB')+' · '+message.transport+' · '+message.src+' → '+message.dst+(message.retransmission?' · Repeated SIP message':'')+(message.rawTruncated?' · Message text truncated to 64 KiB':'');$('traces-message').textContent=message.raw;document.querySelectorAll('.trace-arrow').forEach(n=>n.classList.toggle('selected',n.dataset.message===String(message.id)))}
function renderTraceFlow(){
  $('traces-flow').replaceChildren();$('traces-message').textContent='';$('traces-message-info').textContent='Click a message arrow in the diagram to inspect it.';
  const selected=traceCurrent?.calls.find(c=>c.callId===traceSelected),scope=$('traces-scope').value,group=traceCurrent?.callGroups?.find(g=>g.callIds.includes(traceSelected));
  const ids=scope==='all'?traceCurrent?.calls.map(c=>c.callId):scope==='related'&&group?group.callIds:[traceSelected];
  const messages=traceCurrent?.messages.filter(m=>ids.includes(m.callId))||[],participants=[...new Set(messages.flatMap(m=>[m.src,m.dst]))];
  const call=selected?{...selected,participants,start:messages[0]?.timestamp||selected.start}:null;
  $('traces-call').disabled=scope==='all'||!traceCurrent?.calls.length;
  $('traces-empty').hidden=messages.length>0;$('traces-prev').disabled=tracePage===0;$('traces-next').disabled=(tracePage+1)*tracePageSize>=messages.length;
  $('traces-page').textContent=messages.length?'Messages '+(tracePage*tracePageSize+1)+'–'+Math.min((tracePage+1)*tracePageSize,messages.length)+' of '+messages.length:'No messages';
  $('traces-call-info').textContent=call?(scope==='all'?'All SIP traffic · '+ids.length+' Call-IDs':'From: '+call.fromHeader+'\nTo: '+call.toHeader+'\nCall-ID'+(ids.length>1?'s':'')+': '+ids.join(' · ')+(scope==='related'?'\n'+(group?group.reason:'No related leg identified. Use All SIP traffic to inspect other dialogs.') : '')):'';
  if(!call)return;
  const page=messages.slice(tracePage*tracePageSize,(tracePage+1)*tracePageSize),left=150,width=Math.max(760,left+(participants.length-1)*240+90),step=(width-left-90)/Math.max(1,participants.length-1),height=100+page.length*52;
  const svg=traceSvg('svg',{width,height,role:'group','aria-label':'SIP call flow for '+call.callId});
  svg.append(traceSvg('text',{x:12,y:28,class:'trace-time'},'Time / frame'));
  participants.forEach((participant,index)=>{const x=left+index*step;svg.append(traceSvg('text',{x,y:28,'text-anchor':'middle',class:'trace-endpoint'},participant),traceSvg('line',{x1:x,y1:46,x2:x,y2:height-12,stroke:'#c9d9d5','stroke-dasharray':'4 5'}))});
  page.forEach((message,index)=>{
    const y=82+index*52,source=left+participants.indexOf(message.src)*step,dest=left+participants.indexOf(message.dst)*step;
    const response=message.label.startsWith('SIP/'),status=response?Number(message.label.split(' ')[1]):0,color=message.retransmission?'#a56815':status>=400?'#b83a2c':status>=200?'#25804e':response?'#647d80':'#087f72';
    const group=traceSvg('g',{class:'trace-arrow',tabindex:'0',role:'button','aria-label':message.label+' from '+message.src+' to '+message.dst,'data-message':message.id});
    group.append(traceSvg('title',{},message.label+' · '+message.cseq+(message.retransmission?' · repeated SIP message':'')));
    const maxLabel=Math.max(16,Math.floor((Math.abs(dest-source)-24)/7));let label=message.label;if(label.length>maxLabel)label=label.slice(0,maxLabel-1)+'…';
    group.append(traceSvg('rect',{x:Math.min(source,dest)-8,y:y-26,width:Math.abs(dest-source)+16,height:42,fill:'transparent',rx:4}),traceSvg('line',{x1:source,y1:y,x2:dest,y2:y,stroke:color,'stroke-width':1.8,'stroke-dasharray':response?'6 4':'none'}),traceSvg('path',{d:dest>source?'M '+(dest-8)+' '+(y-5)+' L '+dest+' '+y+' L '+(dest-8)+' '+(y+5):'M '+(dest+8)+' '+(y-5)+' L '+dest+' '+y+' L '+(dest+8)+' '+(y+5),fill:'none',stroke:color,'stroke-width':1.8}),traceSvg('text',{x:(source+dest)/2,y:y-10,'text-anchor':'middle',fill:color,class:'trace-label'},label));
    const stamp=traceSvg('text',{x:12,y:y-6,class:'trace-time'},'+'+(message.timestamp-call.start).toFixed(3)+'s');stamp.append(traceSvg('tspan',{x:12,dy:15},'#'+message.frame+' '+message.transport+(message.retransmission?' ↻':'')));svg.append(stamp);
    group.onclick=()=>traceMessageDetails(message);group.onkeydown=event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();traceMessageDetails(message)}};svg.append(group)
  });$('traces-flow').append(svg)
}
$('nav-traces').onclick=()=>{showWorkspace('traces');loadTraces()};$('traces-refresh').onclick=loadTraces;
$('traces-scope').onchange=()=>{tracePage=0;renderTraceFlow()};
$('traces-call').onchange=()=>{traceSelected=$('traces-call').value;tracePage=0;renderTraceFlow()};
$('traces-prev').onclick=()=>{if(tracePage>0){tracePage--;renderTraceFlow()}};
$('traces-next').onclick=()=>{tracePage++;renderTraceFlow()};
const tracesHeaderRefresh=$('refresh').onclick;
$('refresh').onclick=()=>!$('traces-view').hidden?loadTraces():tracesHeaderRefresh();
