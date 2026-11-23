'use strict';
let deviceEditing=null,deviceDeleting=null;
function deviceMessage(id,message){$(id).textContent=message}
async function configureDevicesSession(session){
 const data=await api('/api/devices');const select=$('device-selector');select.replaceChildren();
 for(const device of data.devices)select.append(el('option',{value:device.id},device.name+' · '+device.management_ip));
 if(!data.devices.length)select.append(el('option',{value:''},'No managed devices'));
 select.value=data.selected||'';select.disabled=!data.devices.length;$('device-add').hidden=session.role!=='admin';
}
async function chooseDevice(id){if(!mayLeave()){$('device-selector').value=window.consoleSession?.device?.id||'';return}await api('/api/devices/select',{id});location.reload()}
$('device-selector').onchange=()=>task(()=>chooseDevice($('device-selector').value));
async function loadDevices(){
 try{const data=await api('/api/devices');$('device-rows').replaceChildren();
  for(const device of data.devices){const row=el('tr'),name=el('td');name.append(el('strong',{},device.name),el('div',{class:'muted'},device.management_ip));const actions=el('td'),select=el('button',{type:'button'},device.id===data.selected?'Selected':'Select');select.disabled=device.id===data.selected;select.onclick=()=>task(()=>chooseDevice(device.id));actions.append(select);
   if(window.consoleSession.role==='admin'){const edit=el('button',{type:'button'},'Edit'),remove=el('button',{type:'button'},'Delete');edit.onclick=()=>task(()=>openDevice(device.id));remove.onclick=()=>{deviceDeleting=device;$('device-delete-description').textContent=device.name+' ('+device.management_ip+')';deviceMessage('device-delete-feedback','');$('device-delete-dialog').showModal()};actions.append(edit,remove)}
   row.append(name,el('td',{},device.rest_username),el('td',{},device.snmp.version==='disabled'?'Disabled':'v'+device.snmp.version),actions);$('device-rows').append(row)
  }deviceMessage('devices-feedback',data.devices.length?data.devices.length+' managed device'+(data.devices.length===1?'':'s'):'No devices yet. An administrator can add the first device.');
 }catch(error){deviceMessage('devices-feedback',error.message)}
}
function openDevices(){if(!mayLeave())return;showWorkspace('devices');loadDevices()}
$('nav-devices').onclick=openDevices;$('account-devices').onclick=()=>{$('account-menu').hidden=true;openDevices()};
function snmpFields(){const f=$('device-form').elements,v=f.snmp_version.value,level=f.security_level.value;for(const node of document.querySelectorAll('[data-snmp]')){const kind=node.dataset.snmp;node.hidden=!(kind==='enabled'?v!=='disabled':kind==='community'?v==='1'||v==='2c':kind==='v3'?v==='3':kind==='auth'?v==='3'&&level!=='noAuthNoPriv':v==='3'&&level==='authPriv');for(const field of node.querySelectorAll('input,select'))field.disabled=node.hidden}}
async function openDevice(id=null){
 const form=$('device-form');form.reset();deviceEditing=null;deviceMessage('device-form-feedback','');deviceMessage('device-key-status','');
 if(id){const data=await api('/api/devices/detail?id='+encodeURIComponent(id));deviceEditing=data.device;const d=deviceEditing,s=d.snmp,f=form.elements;for(const key of ['name','management_ip','rest_username','ssh_port','ssh_public_key','ca_certificate'])f[key].value=d[key]??'';f.snmp_version.value=s.version;f.snmp_port.value=s.port;f.snmp_username.value=s.username||'';f.security_level.value=s.security_level||'authPriv';f.auth_protocol.value=s.auth_protocol||'SHA256';f.priv_protocol.value=s.priv_protocol||'AES128';deviceMessage('device-key-status',d.ssh_fingerprint?'Stored fingerprint: '+d.ssh_fingerprint:'Import the SBC public key.');}
 form.elements.rest_password.required=!id;$('device-form-title').textContent=id?'Edit device':'Add device';snmpFields();$('device-dialog').showModal();
}
$('device-add').onclick=()=>task(()=>openDevice());$('device-form').elements.snmp_version.onchange=snmpFields;$('device-form').elements.security_level.onchange=snmpFields;
$('device-cancel').onclick=()=>$('device-dialog').close();$('device-dialog').addEventListener('close',()=>{$('device-form').reset();deviceEditing=null});
async function importDeviceFile(input,target){try{const file=input.files[0];if(!file)return;if(file.size>131072)throw Error('Choose a public key or certificate file smaller than 128 KB.');$('device-form').elements[target].value=await file.text();if(target==='ssh_public_key')deviceMessage('device-key-status','Imported. Compare this public key with the SBC command output before saving.')}catch(error){deviceMessage('device-form-feedback',error.message)}finally{input.value=''}}
$('device-key-file').onchange=event=>importDeviceFile(event.target,'ssh_public_key');$('device-ca-file').onchange=event=>importDeviceFile(event.target,'ca_certificate');
$('device-read-key').onclick=async()=>{const f=$('device-form').elements,button=$('device-read-key');button.disabled=true;try{const data=await api('/api/devices/read-ssh-key',{management_ip:f.management_ip.value,ssh_port:Number(f.ssh_port.value)});f.ssh_public_key.value=data.public_key;deviceMessage('device-key-status','Unverified network key: '+data.fingerprint+'. Compare with the SBC command output before saving.')}catch(error){deviceMessage('device-form-feedback',error.message)}finally{button.disabled=false}};
$('device-form').onsubmit=async event=>{event.preventDefault();const f=event.target.elements,button=$('device-save');button.disabled=true;deviceMessage('device-form-feedback','');try{
 const snmp={version:f.snmp_version.value,port:Number(f.snmp_port.value)};if(['1','2c'].includes(snmp.version))snmp.community=f.community.value;
 if(snmp.version==='3'){Object.assign(snmp,{username:f.snmp_username.value,security_level:f.security_level.value});if(snmp.security_level!=='noAuthNoPriv')Object.assign(snmp,{auth_protocol:f.auth_protocol.value,auth_password:f.auth_password.value});if(snmp.security_level==='authPriv')Object.assign(snmp,{priv_protocol:f.priv_protocol.value,priv_password:f.priv_password.value})}
 if(f.trap_communities.value.trim())snmp.trap_communities=f.trap_communities.value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean);
 const body={name:f.name.value,management_ip:f.management_ip.value,rest_username:f.rest_username.value,rest_password:f.rest_password.value,ssh_port:Number(f.ssh_port.value),ssh_public_key:f.ssh_public_key.value,ca_certificate:f.ca_certificate.value,snmp};
 const changedSelected=deviceEditing?.id===window.consoleSession?.device?.id;
 if(deviceEditing)Object.assign(body,{id:deviceEditing.id,version:deviceEditing.version});
 const result=await api(deviceEditing?'/api/devices/update':'/api/devices',body);$('device-dialog').close();
 if(changedSelected||!window.consoleSession.device){await api('/api/devices/select',{id:result.device.id});location.reload();return}
 await configureDevicesSession(window.consoleSession);await loadDevices();deviceMessage('devices-feedback','Device saved.');
 }catch(error){deviceMessage('device-form-feedback',error.message)}finally{button.disabled=false}};
$('device-delete-cancel').onclick=()=>$('device-delete-dialog').close();$('device-delete-dialog').addEventListener('close',()=>{deviceDeleting=null});
$('device-delete-form').onsubmit=async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;try{const d=deviceDeleting;await api('/api/devices/delete',{id:d.id,version:d.version});$('device-delete-dialog').close();if(d.id===window.consoleSession.device?.id){location.reload();return}await configureDevicesSession(window.consoleSession);await loadDevices()}catch(error){deviceMessage('device-delete-feedback',error.message)}finally{button.disabled=false}};
$('user-management-toggle').onclick=()=>{const open=$('account-menu').hidden;$('account-menu').hidden=!open;$('user-management-toggle').setAttribute('aria-expanded',String(open))};
document.addEventListener('click',event=>{if(!event.target.closest('.account-control')){$('account-menu').hidden=true;$('user-management-toggle').setAttribute('aria-expanded','false')}});
document.addEventListener('keydown',event=>{if(event.key==='Escape'){$('account-menu').hidden=true;$('user-management-toggle').setAttribute('aria-expanded','false')}});
const deviceHeaderRefresh=$('refresh').onclick;$('refresh').onclick=()=>!$('devices-view').hidden?loadDevices():deviceHeaderRefresh();
