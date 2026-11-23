'use strict';
let hdrVersion=0;
function resetSetupView(){if($('hdr-error-dialog').open)$('hdr-error-dialog').close();hdrVersion=0;$('hdr-form').reset();$('cert-csr-form').reset();$('cert-import-form').reset();clearHdrFiles();$('cert-requests').replaceChildren();$('first-password-form').reset()}
function showInitialPasswordChange(){for(const dialog of document.querySelectorAll('dialog[open]'))dialog.close();$('login').hidden=true;$('shell').hidden=true;$('first-password').hidden=false;$('first-password-form').reset();$('first-password-feedback').textContent=''}
$('first-password-form').onsubmit=async event=>{event.preventDefault();const f=event.target.elements,button=event.submitter;$('first-password-feedback').textContent='';if(f.new_password.value!==f.confirm_password.value){$('first-password-feedback').textContent='The new passwords do not match.';return}button.disabled=true;try{const result=await api('/api/users/password',{current_password:f.current_password.value,new_password:f.new_password.value});csrf=result.csrf;event.target.reset();await start()}catch(error){$('first-password-feedback').textContent=error.message}finally{button.disabled=false}};
$('first-password-logout').onclick=async()=>{try{await api('/api/logout',{})}finally{showLogin()}};
function hdrFields(){const remote=$('hdr-form').elements.mode.value==='sftp';$('hdr-remote').hidden=!remote;$('hdr-local-help').hidden=remote;for(const node of $('hdr-remote').querySelectorAll('input,textarea'))node.disabled=!remote||window.consoleSession?.role!=='admin'}
async function loadHdr(){try{const data=await api('/api/hdr');hdrVersion=data.version;const f=$('hdr-form').elements;for(const key of ['mode','path','host','port','username','host_key'])f[key].value=data[key]??(key==='port'?22:'');for(const key of ['password','private_key','key_passphrase'])f[key].value='';for(const key of ['clear_password','clear_private_key','clear_key_passphrase'])f[key].checked=false;$('hdr-local-help').textContent='Local paths must be inside the mounted HDR root: '+data.local_root;$('hdr-stored').textContent='Stored authentication: '+[data.has_password?'password':'',data.has_private_key?'private key':'',data.has_key_passphrase?'key passphrase':''].filter(Boolean).join(', ')+'. Blank fields retain these values for the same server/account.';$('hdr-fields').disabled=window.consoleSession.role!=='admin';$('hdr-save').hidden=window.consoleSession.role!=='admin';hdrFields();$('hdr-feedback').textContent=''}catch(error){$('hdr-feedback').textContent=error.message}}
$('hdr-form').elements.mode.onchange=hdrFields;
$('nav-hdr').onclick=()=>{if(!mayLeave())return;showWorkspace('hdr');loadHdr()};
$('hdr-form').onsubmit=async event=>{event.preventDefault();const f=event.target.elements,button=event.submitter;button.disabled=true;try{const body={version:hdrVersion,mode:f.mode.value,path:f.path.value};if(body.mode==='sftp'){for(const key of ['host','username','password','private_key','key_passphrase','host_key'])body[key]=f[key].value;body.port=Number(f.port.value);for(const key of ['clear_password','clear_private_key','clear_key_passphrase'])body[key]=f[key].checked}await api('/api/hdr',body);await loadHdr();$('hdr-feedback').textContent='HDR source saved. Use Test connection & list CSV files to verify access.'}catch(error){$('hdr-feedback').textContent=error.message}finally{button.disabled=false}};
$('hdr-list').onclick=async()=>{
  const button=$('hdr-list');button.disabled=true;
  clearHdrFiles();$('hdr-file-status').textContent='Checking the saved source and searching subdirectories…';
  try{
    const data=await api('/api/hdr/files');
    renderHdrFiles(data.files);
    $('hdr-file-status').textContent=data.message+' '+data.files.length+' CSV files shown.'+(data.truncated?' Partial results: '+(data.limit_reason||'search limit reached')+'.':'');
  }catch(error){
    const message=error.message||'The source could not be reached. Check the saved connection settings.';
    $('hdr-file-status').textContent=message;$('hdr-error-message').textContent=message;
    if(!$('hdr-error-dialog').open)$('hdr-error-dialog').showModal();
  }finally{button.disabled=false}
};
async function readTextFile(input,target,max){try{const file=input.files[0];if(!file)return;if(file.size>max)throw Error('The selected file is too large.');target.value=await file.text()}finally{input.value=''}}
$('hdr-key-file').onchange=event=>readTextFile(event.target,$('hdr-form').elements.private_key,131072).catch(error=>$('hdr-feedback').textContent=error.message);
function downloadText(name,text){const url=URL.createObjectURL(new Blob([text],{type:'application/x-pem-file'}));const link=el('a',{href:url,download:name});document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)}
async function loadCertificates(provided=null){try{const data=provided||await api('/api/certificates'),a=data.active;$('cert-active').textContent='Source: '+data.source+'\nSubject: '+a.subject+'\nIssuer: '+a.issuer+'\nValid from: '+a.not_before+'\nValid until: '+a.not_after+'\nDNS: '+a.dns_names.join(', ')+'\nIP: '+a.ip_addresses.join(', ')+'\nSHA256: '+a.sha256;$('cert-requests').replaceChildren();const select=$('cert-import-form').elements.id;select.replaceChildren();for(const request of data.requests){const item=el('div',{class:'certificate-request'});item.append(el('strong',{},request.subject),el('p',{class:'muted'},request.created_at));const download=el('button',{type:'button'},'Download CSR');download.onclick=()=>downloadText('sbc-console-'+request.id+'.csr',request.csr_pem);const remove=el('button',{type:'button'},'Remove unused request');remove.onclick=()=>task(async()=>{await api('/api/certificates/remove',{id:request.id});await loadCertificates()});item.append(download,remove);$('cert-requests').append(item);select.append(el('option',{value:request.id},request.subject+' · '+request.id.slice(0,8)))}if(!data.requests.length)$('cert-requests').textContent='No pending requests.';$('cert-import-form').querySelector('button').disabled=!data.requests.length}catch(error){$('cert-feedback').textContent=error.message}}
function openCertificates(){if(!mayLeave())return;showWorkspace('certificates');loadCertificates()}
$('nav-certificates').onclick=openCertificates;$('account-certificates').onclick=()=>{$('account-menu').hidden=true;openCertificates()};
$('cert-csr-form').onsubmit=async event=>{event.preventDefault();const f=event.target.elements,button=event.submitter;button.disabled=true;$('cert-feedback').textContent='';try{const body={};for(const key of ['common_name','organization','organizational_unit','country','state','locality'])body[key]=f[key].value;for(const key of ['dns_names','ip_addresses'])body[key]=f[key].value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean);body.key_size=Number(f.key_size.value);const data=await api('/api/certificates/csr',body);await loadCertificates();$('cert-import-form').elements.id.value=data.id;$('cert-feedback').textContent='CSR generated. Download it below and submit it to your CA. The current certificate remains active.'}catch(error){$('cert-feedback').textContent=error.message}finally{button.disabled=false}};
$('cert-file').onchange=event=>readTextFile(event.target,$('cert-import-form').elements.certificate_pem,262144).catch(error=>$('cert-feedback').textContent=error.message);
$('cert-import-form').onsubmit=async event=>{event.preventDefault();const f=event.target.elements,button=event.submitter;button.disabled=true;try{const result=await api('/api/certificates/install',{id:f.id.value,certificate_pem:f.certificate_pem.value});event.target.reset();$('cert-feedback').textContent='Certificate activated for new HTTPS connections. Reconnect using a covered DNS name or IP; your browser must trust its CA.';await loadCertificates(result)}catch(error){$('cert-feedback').textContent=error.message}finally{button.disabled=false}};
const setupRefresh=$('refresh').onclick;$('refresh').onclick=()=>!$('settings-view').hidden?loadPreferences():!$('hdr-view').hidden?loadHdr():!$('certificates-view').hidden?loadCertificates():setupRefresh();

function clearHdrFiles(){
 $('hdr-files').replaceChildren();$('hdr-expand-all').disabled=true;$('hdr-collapse-all').disabled=true;
}
function renderHdrFiles(files){
 clearHdrFiles();
 const root={folders:new Map(),files:[],count:0};
 for(const file of files){
  const parts=file.name.split('/');let node=root;node.count++;
  for(const name of parts.slice(0,-1)){if(!node.folders.has(name))node.folders.set(name,{folders:new Map(),files:[],count:0});node=node.folders.get(name);node.count++}
  node.files.push({...file,basename:parts.at(-1)});
 }
 function appendNode(node,target,path){
  for(const [name,child] of [...node.folders].sort(([a],[b])=>a.localeCompare(b))){
   const relative=path+name+'/',folder=el('details',{class:'hdr-folder','data-path':relative});
   folder.append(el('summary',{},name+'/ ('+child.count+(child.count===1?' CSV file)':' CSV files)')));
   const contents=el('div',{class:'hdr-folder-contents'});appendNode(child,contents,relative);folder.append(contents);target.append(folder);
  }
  if(!node.files.length)return;
  const wrap=el('div',{class:'users-table-wrap'}),table=el('table',{class:'users-table'}),head=el('thead'),labels=el('tr'),body=el('tbody');
  for(const title of ['Filename','Bytes','Modified'])labels.append(el('th',{},title));head.append(labels);table.append(head,body);
  for(const file of node.files.sort((a,b)=>a.basename.localeCompare(b.basename))){const row=el('tr',{'data-file-path':file.name});row.append(el('td',{},file.basename),el('td',{},String(file.size)),el('td',{},file.modified_at?new Date(file.modified_at*1000).toLocaleString():''));body.append(row)}
  wrap.append(table);target.append(wrap);
 }
 appendNode(root,$('hdr-files'),'');
 $('hdr-expand-all').disabled=!root.folders.size;$('hdr-collapse-all').disabled=!root.folders.size;
}
$('hdr-expand-all').onclick=()=>{$('hdr-files').querySelectorAll('details').forEach(folder=>folder.open=true)};
$('hdr-collapse-all').onclick=()=>{$('hdr-files').querySelectorAll('details').forEach(folder=>folder.open=false)};
