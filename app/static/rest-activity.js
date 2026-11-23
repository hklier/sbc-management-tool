'use strict';
let restActivityCursor=0,restActivityEvents=new Map(),restActivitySelected=null,restActivityTimer=null,restActivityGeneration=0,restActivityBusy=false,restActivityAutoOpen=false;
function resetRestActivity(){configureRestActivityPreferences({});restActivityGeneration++;clearTimeout(restActivityTimer);restActivityCursor=0;restActivityEvents.clear();restActivitySelected=null;minimizeRestActivity(false);$('rest-activity-panel').hidden=true;$('rest-activity-toggle').hidden=true;$('rest-activity-list').replaceChildren();$('rest-activity-detail').replaceChildren();$('rest-activity-count').textContent='0';$('rest-activity-mini-count').textContent='0'}
function startRestActivity(){clearTimeout(restActivityTimer);$('rest-activity-toggle').hidden=false;restActivityTimer=setTimeout(pollRestActivity,100)}
async function pollRestActivity(){
 if($('shell').hidden)return;if(restActivityBusy){restActivityTimer=setTimeout(pollRestActivity,250);return}const generation=restActivityGeneration;restActivityBusy=true;
 try{
  const response=await fetch('/api/rest-activity?'+new URLSearchParams({after:restActivityCursor}),{cache:'no-store'});
  if(response.status===401){resetRestActivity();return}
  if(!response.ok)throw Error('REST activity is temporarily unavailable.');
  const data=await response.json();if(generation!==restActivityGeneration)return;
  restActivityCursor=data.cursor;let fresh=false;
  for(const event of data.items){if(!restActivityEvents.has(event.id))fresh=true;restActivityEvents.set(event.id,event)}
  while(restActivityEvents.size>200)restActivityEvents.delete(restActivityEvents.keys().next().value);
  if(data.items.length){
   if(!restActivityEvents.has(restActivitySelected))restActivitySelected=data.items[data.items.length-1].id;
   renderRestActivity();if(fresh&&restActivityAutoOpen)$('rest-activity-panel').hidden=false;
  }
  $('rest-activity-state').textContent='Live · full values · current session only';
 }catch(error){if(generation===restActivityGeneration)$('rest-activity-state').textContent=error.message}
 finally{restActivityBusy=false;if(generation===restActivityGeneration&&!$('shell').hidden)restActivityTimer=setTimeout(pollRestActivity,1000)}
}
function renderRestActivity(){
 const opened=new Set([...$('rest-activity-detail').querySelectorAll('details[open]')].map(node=>node.dataset.payload)),scroll=$('rest-activity-list').scrollTop;
 const events=[...restActivityEvents.values()].reverse();$('rest-activity-count').textContent=String(events.length);$('rest-activity-mini-count').textContent=String(events.length);$('rest-activity-list').replaceChildren();
 for(const event of events){const row=el('button',{type:'button',class:'rest-activity-row'+(event.id===restActivitySelected?' selected':''),'aria-pressed':String(event.id===restActivitySelected)});
  const status=event.state==='running'?'Running…':(event.status?'HTTP '+event.status:event.state==='failed'?'Failed':'Completed');
  row.append(el('span',{class:'rest-method'},event.method),el('span',{class:'rest-url'},event.url),el('span',{class:'rest-result '+event.state},status));
  row.onclick=()=>{restActivitySelected=event.id;renderRestActivity()};$('rest-activity-list').append(row)
 }
 $('rest-activity-list').scrollTop=scroll;
 $('rest-activity-detail').replaceChildren();const event=restActivityEvents.get(restActivitySelected);if(!event)return;
 const detail=$('rest-activity-detail');detail.append(el('p',{class:'rest-detail-heading'},event.method+' '+event.url),el('p',{class:'muted'},new Date(event.time).toLocaleTimeString('en-GB')+' · '+(event.durationMs==null?'In progress':event.durationMs+' ms')+' · '+(event.source||'Console')));
 if(event.error)detail.append(el('p',{class:'error'},event.error));
 for(const [label,value]of [['Request headers',Object.entries(event.requestHeaders||{}).map(([name,value])=>name+': '+value).join('\n')||'No request headers.'],['Request body',event.request||'No request body.'],['Response',event.state==='running'?'Waiting for the SBC…':event.response||'No response body.']]){const block=el('details',{class:'rest-payload','data-payload':label});block.open=opened.has(label);block.append(el('summary',{},label),el('pre',{},value));detail.append(block)}
}
function minimizeRestActivity(value){$('rest-activity-panel').classList.toggle('minimized',value);$('rest-activity-minimize').textContent=value?'□':'−';$('rest-activity-minimize').setAttribute('aria-label',value?'Restore REST activity':'Minimize REST activity');$('rest-activity-minimize').title=value?'Restore':'Minimize'}
$('rest-activity-toggle').onclick=()=>{if($('rest-activity-panel').classList.contains('minimized')){$('rest-activity-panel').hidden=false;minimizeRestActivity(false)}else $('rest-activity-panel').hidden=!$('rest-activity-panel').hidden;if(!restActivityEvents.size)$('rest-activity-state').textContent='Waiting for SBC REST requests…'};
$('rest-activity-minimize').onclick=()=>minimizeRestActivity(!$('rest-activity-panel').classList.contains('minimized'));
$('rest-activity-clear').onclick=async()=>{const generation=++restActivityGeneration;clearTimeout(restActivityTimer);$('rest-activity-clear').disabled=true;try{const data=await api('/api/rest-activity/clear',{});if(generation!==restActivityGeneration)return;restActivityCursor=data.cursor;restActivityEvents=new Map(data.items.map(event=>[event.id,event]));restActivitySelected=data.items[0]?.id??null;renderRestActivity();$('rest-activity-state').textContent=data.items.length?'History cleared · running requests kept':'History cleared · waiting for new requests…'}catch(error){if(generation===restActivityGeneration)$('rest-activity-state').textContent=error.message}finally{$('rest-activity-clear').disabled=false;if(generation===restActivityGeneration&&!$('shell').hidden)startRestActivity()}};
$('rest-activity-close').onclick=()=>$('rest-activity-panel').hidden=true;
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!$('shell').hidden)startRestActivity()});
if(!$('shell').hidden)startRestActivity();

function configureRestActivityPreferences(value={}){
 restActivityAutoOpen=value.rest_activity_auto_open===true;
 $('rest-activity-auto').checked=restActivityAutoOpen;
 if(!restActivityAutoOpen)$('rest-activity-panel').hidden=true;
}
async function loadPreferences(){
 const session=window.consoleSession;$('preferences-feedback').textContent='';
 try{const data=await api('/api/preferences');if(window.consoleSession===session)configureRestActivityPreferences(data)}
 catch(error){if(window.consoleSession===session)$('preferences-feedback').textContent=error.message}
}
$('nav-settings').onclick=()=>{if(!mayLeave())return;showWorkspace('settings');loadPreferences()};
$('preferences-form').onsubmit=async event=>{
 event.preventDefault();const session=window.consoleSession,button=$('preferences-save');button.disabled=true;
 try{const data=await api('/api/preferences',{rest_activity_auto_open:$('rest-activity-auto').checked});if(window.consoleSession===session){configureRestActivityPreferences(data);$('preferences-feedback').textContent='Settings saved for your account.'}}
 catch(error){if(window.consoleSession===session)$('preferences-feedback').textContent=error.message}
 finally{button.disabled=false}
};
