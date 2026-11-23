'use strict';
let lrtTables=[],lrtSelected='',lrtOffset=0,lrtFiltered=0,lrtRequest=0,lrtSearchTimer;
let lrtCurrent=null,lrtChange=null,lrtOverviewRequest=0,lrtEditEntry=null,lrtDraftContext=null;

function showWorkspace(view){
  ['config','history','lrt','diagnostics','traces','snmp','traps','cdr','recordings','users','devices','hdr','certificates','settings'].forEach(name=>{$(name+'-view').hidden=name!==view;$('nav-'+name).classList.toggle('active',name===view)});
  $('config-actions').hidden=view==='lrt'||view==='diagnostics'||view==='traces'||view==='snmp'||view==='traps'||view==='cdr'||view==='recordings'||view==='users'||view==='devices'||view==='hdr'||view==='certificates'||view==='settings';
  $('page-title').textContent={config:'Configuration',history:'History',lrt:'Local route tables',diagnostics:'Diagnostics',traces:'Packet captures',snmp:'SNMP diagnosis',traps:'SNMP traps',cdr:'Call detail records',recordings:'Recordings',users:'Users & passwords',devices:'Devices',hdr:'HDR Reporting',certificates:'WebGUI certificate',settings:'Settings'}[view];
}
function lrtRunning(){return $('lrt-source').value==='running'}
function renderLrtCards(){
  $('lrt-cards').replaceChildren();
  lrtTables.forEach(table=>{
    const button=el('button',{class:'lrt-card'+(table.name===lrtSelected?' selected':'')});
    button.append(el('strong',{},table.name),el('small',{},table.filename||'No file configured'));
    button.append(el('span',{class:table.status==='ready'?'lrt-card-count':'error'},table.status==='ready'?table.entryCount+' entries · '+table.nextHopCount+' next hops':'Unable to read file'));
    button.onclick=()=>task(()=>selectLrt(table.name));$('lrt-cards').append(button);
  });
}
async function loadLrtOverview(force=false){
  const request=++lrtOverviewRequest,running=lrtRunning();++lrtRequest;lrtCurrent=null;$('lrt-add').disabled=true;$('lrt-reload').disabled=true;$('lrt-rows').replaceChildren();
  $('lrt-summary').textContent='Reading local route tables…';
  const data=await api('/api/lrt?'+new URLSearchParams({running:String(running),refresh:String(force)}));
  if(request!==lrtOverviewRequest||running!==lrtRunning())return;lrtTables=data.tables;
  const ready=lrtTables.filter(t=>t.status==='ready');
  $('lrt-summary').textContent=lrtTables.length+' configured tables · '+ready.reduce((n,t)=>n+t.entryCount,0)+' entries read'+(ready.length!==lrtTables.length?' · '+(lrtTables.length-ready.length)+' files unavailable':'');
  if(!lrtTables.length){lrtSelected='';$('lrt-detail').hidden=true;renderLrtCards();$('lrt-summary').textContent='No local-routing-config instances in this configuration.';return}
  const selected=lrtTables.find(t=>t.name===lrtSelected)||ready[0]||lrtTables[0];
  await selectLrt(selected.name);
}
async function selectLrt(name){
  lrtCurrent=null;$('lrt-rows').replaceChildren();lrtSelected=name;lrtOffset=0;$('lrt-search').value='';renderLrtCards();$('lrt-detail').hidden=false;
  const table=lrtTables.find(t=>t.name===name);$('lrt-title').textContent=name;$('lrt-file').textContent=table.filename?'SBC file: /code/lrt/'+table.filename:'No file configured';
  $('lrt-settings').replaceChildren();
  ['prefix-length','match-mode','string-lookup','retarget-requests'].forEach(key=>{if(table.config[key]!==undefined)$('lrt-settings').append(el('span',{},key+': '+table.config[key]))});
  if(table.version?.version)$('lrt-settings').append(el('span',{},'File version: '+table.version.version));
  if(table.modifiedAt)$('lrt-settings').append(el('span',{},'Modified: '+new Date(table.modifiedAt).toLocaleString('en-GB')));
  $('lrt-count').textContent=table.status==='ready'?table.entryCount+' entries':'';
  $('lrt-error').hidden=table.status==='ready';$('lrt-error').textContent=table.error||'';
  $('lrt-table-wrap').hidden=table.status!=='ready';$('lrt-empty').hidden=true;$('lrt-fetched').textContent='';
  $('lrt-add').disabled=true;$('lrt-reload').disabled=true;if(table.status!=='ready'){++lrtRequest;$('lrt-rows').replaceChildren();$('lrt-page-info').textContent='File contents unavailable';$('lrt-prev').disabled=true;$('lrt-next').disabled=true;return}
  await loadLrtEntries();
}
async function loadLrtEntries(){
  if(!lrtSelected)return;
  const revision=++lrtRequest;
  const data=await api('/api/lrt/entries?'+new URLSearchParams({name:lrtSelected,running:String(lrtRunning()),q:$('lrt-search').value,offset:String(lrtOffset),limit:$('lrt-page-size').value}));
  if(revision!==lrtRequest)return;
  lrtCurrent=data;$('lrt-add').disabled=false;$('lrt-reload').disabled=!data.activeTables?.length;lrtFiltered=data.filtered;$('lrt-count').textContent=data.total+' entries';$('lrt-rows').replaceChildren();
  $('lrt-error').hidden=true;$('lrt-empty').hidden=data.entries.length>0;$('lrt-table-wrap').hidden=data.entries.length===0;
  $('lrt-empty').textContent=data.total?'No entries match your search.':'This LRT file contains no route entries.';
  data.entries.forEach(entry=>{
    const row=el('tr');row.append(el('td',{class:'lrt-index'},String(entry.index)));
    const match=el('td',{class:'lrt-match'});match.append(el('strong',{},entry.match||'(empty)'),el('small',{},entry.userType||'Unspecified type'));row.append(match);
    const hops=el('td',{class:'lrt-hops'});
    entry.nextHops.forEach((hop,index)=>{const block=el('div',{class:'lrt-hop'});block.append(el('code',{},hop.value));const attributes=Object.entries(hop.attributes).map(([key,value])=>key+': '+value).join(' · ');block.append(el('small',{},(entry.nextHops.length>1?'Next hop '+(index+1)+' · ':'')+attributes));hops.append(block)});
    if(!entry.nextHops.length)hops.append(el('span',{class:'muted'},'No next hop'));
    row.append(hops,el('td',{},entry.description||'—'));
    const cell=el('td'),details=el('details');details.append(el('summary',{},'View XML'),el('pre',{},entry.xml));cell.append(details);const edit=el('button',{class:'lrt-edit-entry',type:'button'},'Edit');edit.onclick=()=>openLrtEntry(entry);cell.append(edit);const remove=el('button',{class:'lrt-delete-entry',type:'button'},'Delete');remove.onclick=()=>task(()=>reviewLrtDeletion(entry));cell.append(remove);row.append(cell);$('lrt-rows').append(row);
  });
  $('lrt-page-info').textContent=data.filtered?'Showing '+(data.offset+1)+'–'+(data.offset+data.entries.length)+' of '+data.filtered+(data.filtered!==data.total?' matching entries ('+data.total+' total)':' entries'):'0 matching entries';
  $('lrt-prev').disabled=data.offset===0;$('lrt-next').disabled=data.offset+data.limit>=data.filtered;
  $('lrt-fetched').textContent='File read: '+new Date(data.fetchedAt).toLocaleString('en-GB')+' · Original file order and duplicate matches are preserved.';
}
$('nav-lrt').onclick=()=>task(async()=>{showWorkspace('lrt');await loadLrtOverview()});
$('nav-config').addEventListener('click',()=>showWorkspace('config'));
$('nav-history').addEventListener('click',()=>showWorkspace('history'));
$('lrt-refresh').onclick=()=>task(()=>loadLrtOverview(true));
$('lrt-source').onchange=()=>task(()=>loadLrtOverview());
$('lrt-search').oninput=()=>{clearTimeout(lrtSearchTimer);lrtSearchTimer=setTimeout(()=>task(async()=>{lrtOffset=0;await loadLrtEntries()}),250)};
$('lrt-page-size').onchange=()=>task(async()=>{lrtOffset=0;await loadLrtEntries()});
$('lrt-prev').onclick=()=>task(async()=>{lrtOffset=Math.max(0,lrtOffset-Number($('lrt-page-size').value));await loadLrtEntries()});
$('lrt-next').onclick=()=>task(async()=>{if(lrtOffset+Number($('lrt-page-size').value)<lrtFiltered){lrtOffset+=Number($('lrt-page-size').value);await loadLrtEntries()}});
const configurationRefresh=$('refresh').onclick;
$('refresh').onclick=()=>{if(!$('lrt-view').hidden)return task(async()=>{await refresh();await loadLrtOverview(true)});return configurationRefresh()};

function lrtEntryDraft(){
  return {userType:$('lrt-entry-type').value,match:$('lrt-entry-match').value,rangeStart:$('lrt-range-start').value,rangeEnd:$('lrt-range-end').value,rangePrefix:$('lrt-range-prefix').value,description:$('lrt-entry-description').value,nextHops:[...$('lrt-hop-inputs').children].map(row=>{
    let attributes;try{attributes=JSON.parse(row.querySelector('.hop-attributes').value||'{}')}catch{throw Error('Next-hop attributes must be a JSON object. Example: {"priority":"1"}')}
    return {value:row.querySelector('.hop-value').value,type:row.querySelector('.hop-type').value,attributes};
  })};
}
function lrtTypeFields(){
  const range=$('lrt-entry-type').value==='range';$('lrt-range-fields').hidden=!range;$('lrt-match-label').hidden=range;$('lrt-entry-match').disabled=range;
  ['lrt-range-start','lrt-range-end','lrt-range-prefix'].forEach(id=>$(id).disabled=!range);
  $('lrt-range-start').required=range;$('lrt-range-end').required=range;
}
function addLrtHop(hop=null){
  if($('lrt-hop-inputs').children.length>=10)return;
  const row=el('div',{class:'lrt-hop-editor'}),label=el('label',{},'Next-hop expression / URI');
  const value=el('textarea',{class:'hop-value',rows:'2',required:'',maxlength:'8192',placeholder:'!^.*$!sip:1000@example.invalid!'});value.value=hop?.value||'';label.append(value);
  const advanced=el('details');advanced.append(el('summary',{},'Type and optional attributes'));
  const typeLabel=el('label',{},'Type'),type=el('input',{class:'hop-type',required:'',maxlength:'32'});type.value=hop?.type||'regex';typeLabel.append(type);
  const attrsLabel=el('label',{},'Optional XML attributes as JSON'),attrs=el('textarea',{class:'hop-attributes',rows:'2'});attrs.value=JSON.stringify(Object.fromEntries(Object.entries(hop?.attributes||{}).filter(([key])=>key!=='type')));attrsLabel.append(attrs);advanced.append(typeLabel,attrsLabel);
  const remove=el('button',{type:'button'},'Remove next hop');remove.onclick=()=>{row.remove();updateLrtHopButtons()};row.append(label,advanced,remove);$('lrt-hop-inputs').append(row);updateLrtHopButtons();
}
function updateLrtHopButtons(){const count=$('lrt-hop-inputs').children.length;$('lrt-add-hop').disabled=count>=10;[...$('lrt-hop-inputs').children].forEach(row=>row.querySelector('button').disabled=count===1)}
function openLrtEntry(entry=null){
  if(entry?.nextHops.length>10){notify('This entry has more than 10 next hops and cannot be safely edited with this form.',true);return}
  if(!lrtCurrent)return;lrtEditEntry=entry;lrtDraftContext={name:lrtCurrent.name,running:lrtRunning(),sha256:lrtCurrent.sha256};$('lrt-add-form').reset();$('lrt-add-error').textContent='';$('lrt-hop-inputs').replaceChildren();
  const range=lrtCurrent.tableType==='range';[...$('lrt-entry-type').options].forEach(option=>option.disabled=(option.value==='range')!==range);$('lrt-entry-type').value=entry?.userType||(range?'range':'E164');lrtTypeFields();
  if(entry){
    $('lrt-entry-match').value=range?'':entry.match;$('lrt-entry-description').value=entry.description||'';
    for(const [id,key] of [['lrt-range-start','rangeStart'],['lrt-range-end','rangeEnd'],['lrt-range-prefix','rangePrefix']])$(id).value=entry.userAttributes?.[key]||'';
    entry.nextHops.forEach(hop=>addLrtHop(hop));updateLrtHopButtons();
  }else addLrtHop();
  $('lrt-entry-dialog-title').textContent=entry?'Edit route entry':'Add route entry';$('lrt-review-add').textContent=entry?'Review changes →':'Review addition →';
  $('lrt-add-context').textContent=lrtCurrent.name+' · '+lrtCurrent.filename+(entry?' · Entry '+entry.index:'');$('lrt-add-dialog').showModal();
}
$('lrt-add').onclick=()=>openLrtEntry();
$('lrt-entry-type').onchange=lrtTypeFields;$('lrt-add-hop').onclick=()=>addLrtHop();$('lrt-cancel-add').onclick=()=>$('lrt-add-dialog').close();
function showLrtReview(review){
  lrtChange=review;$('lrt-change-error').textContent='';$('lrt-change-title').textContent=review.action==='add'?'Add this entry?':review.action==='edit'?'Save these entry changes?':'Delete this entry?';
  $('lrt-change-description').textContent=review.name+' · '+review.filename+'. The original file will be backed up on the SBC and on this server before saving. Other route entries are preserved.';
  const block=el('div',{class:'lrt-change-block'});
  function entryPreview(label,entry){const section=el('section');section.append(el('h3',{},label),el('strong',{},entry.match),el('p',{},entry.userType));entry.nextHops.forEach(hop=>{section.append(el('pre',{},hop.value));const attributes=Object.entries(hop.attributes||{}).map(([key,value])=>key+': '+value).join(' · ');if(attributes)section.append(el('small',{},attributes))});if(entry.description)section.append(el('p',{},entry.description));return section}
  if(review.previousEntry)block.append(entryPreview('Before',review.previousEntry));
  block.append(entryPreview(review.action==='edit'?'After':'Entry',review.entry),el('p',{},'Entries: '+review.beforeCount+' → '+review.afterCount));
  if(review.afterCount===0)block.append(el('p',{class:'error'},'This will leave the table empty.'));
  $('lrt-change-summary').replaceChildren(block);$('lrt-change-reload-label').hidden=false;$('lrt-change-reload').checked=false;$('lrt-change-reload').disabled=!review.activeTables.length;
  $('lrt-shared-note').textContent=review.activeTables.length?'Active LRTs using this file: '+review.activeTables.join(', ')+'. Reloading applies the file to live routing.':'This file is not used by a running LRT yet. Save the file and activate the relevant configuration before reloading.';
  $('lrt-confirm-change').textContent='Save file';$('lrt-change-dialog').showModal();
}
$('lrt-add-form').onsubmit=async event=>{
  event.preventDefault();$('lrt-add-error').textContent='';$('lrt-review-add').disabled=true;
  try{const review=await api('/api/lrt/preview',{...lrtDraftContext,action:lrtEditEntry?'edit':'add',index:lrtEditEntry?.index,entry:lrtEntryDraft()});$('lrt-add-dialog').close();showLrtReview(review)}catch(error){$('lrt-add-error').textContent=error.message}finally{$('lrt-review-add').disabled=false}
};
async function reviewLrtDeletion(entry){
  if(!lrtCurrent)return;
  const review=await api('/api/lrt/preview',{name:lrtCurrent.name,running:lrtRunning(),sha256:lrtCurrent.sha256,action:'delete',index:entry.index});showLrtReview(review);
}
$('lrt-change-reload').onchange=()=>{$('lrt-confirm-change').textContent=$('lrt-change-reload').checked?'Save & reload':'Save file'};
$('lrt-cancel-change').onclick=()=>$('lrt-change-dialog').close();
$('lrt-reload').onclick=()=>{
  if(!lrtCurrent)return;lrtChange={action:'reload',name:lrtCurrent.name,running:lrtRunning(),filename:lrtCurrent.filename,sha256:lrtCurrent.sha256};$('lrt-change-error').textContent='';
  $('lrt-change-title').textContent='Reload this LRT in the SBC?';$('lrt-change-description').textContent='This loads the current source file into live routing. No global configuration save or activation is performed.';
  $('lrt-change-summary').replaceChildren(el('strong',{},lrtCurrent.name+' · '+lrtCurrent.filename));$('lrt-change-reload-label').hidden=true;
  $('lrt-shared-note').textContent='Active LRTs using this file: '+lrtCurrent.activeTables.join(', ');$('lrt-confirm-change').textContent='Reload in SBC';$('lrt-change-dialog').showModal();
};
$('lrt-confirm-change').onclick=async()=>{
  $('lrt-confirm-change').disabled=true;$('lrt-change-error').textContent='';
  try{const result=lrtChange.action==='reload'?await api('/api/lrt/reload',lrtChange):await api('/api/lrt/apply',{plan:lrtChange.plan,reload:$('lrt-change-reload').checked});$('lrt-change-dialog').close();notify(result.message+(result.backup?'\nBackup: '+result.backup:'')+(result.reloadError?'\n'+result.reloadError:''),!!result.reloadError);await loadLrtOverview(true)}catch(error){$('lrt-change-error').textContent=error.message}finally{$('lrt-confirm-change').disabled=false}
};
