'use strict';
let token = '', timer = null, chart = null, busy = false;
const $ = id => document.getElementById(id);
const text = (tag, value, cls) => { const e=document.createElement(tag); e.textContent=value; if(cls)e.className=cls; return e; };
const time = value => new Date(value*1000).toLocaleString();
async function api(path, method='GET', body=null) {
  const headers = { Authorization: 'Bearer ' + token };
  if (body) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, { method, headers, body });
  if(!response.ok) { if(response.status===401)disconnect(); throw new Error(response.status===401?'Invalid administrator token.':'Request failed ('+response.status+').'); }
  return response.json();
}
function disconnect(){token='';clearInterval(timer);timer=null;$('workspace').hidden=true;$('login').hidden=false;$('status').textContent='Authentication required';if(chart){chart.destroy();chart=null;}}
$('logout').addEventListener('click',disconnect);
$('login').addEventListener('submit',async event=>{
  event.preventDefault();token=$('token').value.trim();$('token').value='';
  try{await refresh();$('workspace').hidden=false;$('login').hidden=true;clearInterval(timer);timer=setInterval(()=>refresh().catch(showError),5000);}catch(e){showError(e);}
});
const regForm = $('register-device-form');
if (regForm) {
  regForm.addEventListener('submit', async event => {
    event.preventDefault();
    const devInput = $('new-device-id');
    const device_id = devInput.value.trim();
    const regStatus = $('reg-status');
    regStatus.textContent = 'Registering...';
    try {
      const res = await api('/api/devices/register', 'POST', JSON.stringify({ device_id }));
      regStatus.textContent = 'Registered: ' + res.device_id;
      $('new-device-token-val').textContent = res.token;
      $('new-device-token-card').hidden = false;
      devInput.value = '';
      await refresh();
    } catch (err) {
      regStatus.textContent = err.message;
    }
  });
}
const copyBtn = $('copy-token-btn');
if (copyBtn) {
  copyBtn.addEventListener('click', () => {
    const val = $('new-device-token-val').textContent;
    if (val) {
      navigator.clipboard.writeText(val);
      copyBtn.textContent = 'Copied!';
      setTimeout(() => { copyBtn.textContent = 'Copy Token'; }, 2000);
    }
  });
}
function showError(error){$('status').textContent=error.message+' Displayed data may be stale.';}
$('device-select').addEventListener('change',()=>history().catch(showError));
async function refresh(){
  if(busy)return;busy=true;
  try{
    const data=await api('/api/overview');
    $('total').textContent=data.devices.length;$('online').textContent=data.devices.filter(d=>d.online).length;
    $('alerts-count').textContent=data.open_alerts;$('trained').textContent=data.devices.filter(d=>d.model).length;
    $('updated').textContent='Last updated '+time(data.server_time);$('status').textContent='Connected · polling every 5 seconds';
    $('devices').replaceChildren();$('no-devices').hidden=!!data.devices.length;
    const selected=$('device-select').value;$('device-select').replaceChildren();
    for(const d of data.devices){
      const row=text('tr','');row.append(text('td',d.id));const state=text('td','');state.append(text('span',d.online?'Online':'Offline',d.online?'pill online':'pill'));row.append(state);
      row.append(text('td',d.latest?d.latest.cpu.toFixed(1)+'%':'—'),text('td',d.latest?d.latest.ram.toFixed(1)+'%':'—'),text('td',d.latest?.connections??'Unavailable'),text('td',d.model?'Trained · '+d.model.sample_count+' samples':'Not trained'));
      const actionTd=text('td','');
      const delBtn=text('button','Delete','secondary');
      delBtn.style.padding='4px 8px';delBtn.style.fontSize='11px';delBtn.style.color='#ff9999';delBtn.style.borderColor='#ff444455';
      delBtn.addEventListener('click',async e=>{
        e.stopPropagation();
        if(confirm('Remove endpoint "'+d.id+'" from Sentinel?')){
          delBtn.disabled=true;
          try{await api('/api/devices/'+encodeURIComponent(d.id),'DELETE');await refresh();}catch(err){delBtn.disabled=false;showError(err);}
        }
      });
      actionTd.append(delBtn);row.append(actionTd);
      $('devices').append(row);const option=text('option',d.id);option.value=d.id;$('device-select').append(option);
    }
    if(data.devices.some(d=>d.id===selected))$('device-select').value=selected;
    $('alert-list').replaceChildren();$('no-alerts').hidden=!!data.alerts.length;
    for(const a of data.alerts){
      const row=text('div','','alert'),copy=text('div','');copy.append(text('span',a.severity,'severity'),text('strong',a.device_id),text('p',a.message),text('small',time(a.created)+' · '+a.kind));
      const button=text('button',a.acknowledged?'Reviewed':'Acknowledge',a.acknowledged?'secondary':'');button.disabled=!!a.acknowledged;
      button.addEventListener('click',async()=>{button.disabled=true;try{await api('/api/alerts/'+a.id+'/ack','POST');await refresh();}catch(e){button.disabled=false;showError(e);}});
      row.append(copy,button);$('alert-list').append(row);
    }
    await history();
  }finally{busy=false;}
}
async function history(){
  const device=$('device-select').value;
  if(!device){$('chart-message').textContent='Select a registered endpoint to see its metrics.';$('coverage').replaceChildren();$('processes').replaceChildren();return;}
  const {samples}=await api('/api/devices/'+encodeURIComponent(device)+'/history');
  if(device!==$('device-select').value)return;
  $('chart-message').textContent=samples.length?'Last '+samples.length+' samples · CPU / RAM (%)':'Waiting for this endpoint’s first sample.';
  const latest=samples.at(-1);$('coverage').replaceChildren();
  for(const warning of latest?.warnings??[])$('coverage').append(text('div',warning));
  $('processes').replaceChildren();for(const p of latest?.processes??[])$('processes').append(text('li',p.pid+' · '+p.name));
  if(!window.Chart){$('chart-message').textContent+=' Chart library unavailable (CDN needs internet); current values remain visible above.';return;}
  const data={labels:samples.map(s=>new Date(s.observed*1000).toLocaleTimeString()),datasets:[{label:'CPU %',data:samples.map(s=>s.cpu),borderColor:'#86e1b3',backgroundColor:'#86e1b311',fill:true,pointRadius:0,tension:.2},{label:'RAM %',data:samples.map(s=>s.ram),borderColor:'#91b4ff',pointRadius:0,tension:.2}]};
  if(chart){chart.data=data;chart.update('none');}else{chart=new Chart($('metrics'),{type:'line',data,options:{responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{labels:{color:'#96a9ba'}}},scales:{y:{min:0,max:100,ticks:{color:'#96a9ba'},grid:{color:'#273442'}},x:{ticks:{color:'#96a9ba',maxTicksLimit:8},grid:{display:false}}}}});}
}
