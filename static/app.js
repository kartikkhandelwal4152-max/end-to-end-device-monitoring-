'use strict';
let token = '', timer = null, chart = null, busy = false;
const $ = id => document.getElementById(id);
const text = (tag, value, cls) => { const e=document.createElement(tag); e.textContent=value; if(cls)e.className=cls; return e; };
const time = value => new Date(value*1000).toLocaleString();

const THREAT_LIST = [
  'wireshark', 'tshark', 'tcpdump', 'nmap', 'zenmap', 'mimikatz',
  'xmrig', 'minerd', 'netcat', 'nc', 'ncat', 'tor', 'hydra', 'john',
  'hashcat', 'powersploit'
];

async function api(path, method='GET', body=null) {
  const headers = { Authorization: 'Bearer ' + token };
  if (body) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, { method, headers, body });
  if(!response.ok) {
    if(response.status===401) disconnect();
    let msg = 'Request failed ('+response.status+').';
    try { const data = await response.json(); if(data.error) msg = data.error; } catch(e){}
    throw new Error(msg);
  }
  return response.json();
}

function disconnect(){
  token='';
  clearInterval(timer);
  timer=null;
  $('workspace').hidden=true;
  $('login').hidden=false;
  $('status').textContent='Authentication required';
  if(chart){chart.destroy();chart=null;}
}

$('logout').addEventListener('click', disconnect);

$('login').addEventListener('submit', async event => {
  event.preventDefault();
  token = $('token').value.trim();
  $('token').value = '';
  try {
    await refresh();
    $('workspace').hidden = false;
    $('login').hidden = true;
    clearInterval(timer);
    timer = setInterval(() => refresh().catch(showError), 5000);
  } catch(e) {
    showError(e);
  }
});

const openReportBtn = $('open-report-btn');
if (openReportBtn) {
  openReportBtn.addEventListener('click', () => {
    if (!token) return;
    window.open('/reports/audit?token=' + encodeURIComponent(token), '_blank');
  });
}

const tgCard = $('telegram-card');
const openTgBtn = $('open-telegram-btn');
const closeTgBtn = $('close-telegram-btn');
const tgForm = $('telegram-form');
const tgTestBtn = $('tg-test-btn');
const tgStatus = $('tg-status');

if (openTgBtn && tgCard) {
  openTgBtn.addEventListener('click', async () => {
    tgCard.hidden = !tgCard.hidden;
    if (!tgCard.hidden) {
      tgStatus.textContent = 'Checking configuration...';
      try {
        const data = await api('/api/settings/telegram');
        if (data.configured) {
          tgStatus.textContent = 'Status: Configured (Token ' + data.masked_token + ')';
        } else {
          tgStatus.textContent = 'Status: Not configured';
        }
        if (data.chat_id) $('tg-chat').value = data.chat_id;
      } catch (err) {
        tgStatus.textContent = 'Error: ' + err.message;
      }
    }
  });
}

if (closeTgBtn && tgCard) {
  closeTgBtn.addEventListener('click', () => { tgCard.hidden = true; });
}

if (tgForm) {
  tgForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const bot_token = $('tg-token').value.trim();
    const chat_id = $('tg-chat').value.trim();
    tgStatus.textContent = 'Saving...';
    try {
      await api('/api/settings/telegram', 'POST', JSON.stringify({ bot_token, chat_id }));
      tgStatus.textContent = 'Settings saved!';
      $('tg-token').value = '';
    } catch (err) {
      tgStatus.textContent = 'Failed: ' + err.message;
    }
  });
}

if (tgTestBtn) {
  tgTestBtn.addEventListener('click', async () => {
    tgStatus.textContent = 'Sending test notification...';
    try {
      await api('/api/settings/telegram', 'POST', JSON.stringify({ test: true }));
      tgStatus.textContent = 'Test alert dispatched to Telegram!';
    } catch (err) {
      tgStatus.textContent = 'Test failed: ' + err.message;
    }
  });
}

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

function showError(error){
  $('status').textContent = error.message + ' Displayed data may be stale.';
}

$('device-select').addEventListener('change', () => history().catch(showError));

async function refresh(){
  if(busy) return;
  busy = true;
  try {
    const data = await api('/api/overview');
    $('total').textContent = data.devices.length;
    $('online').textContent = data.devices.filter(d => d.online).length;
    $('alerts-count').textContent = data.open_alerts;
    $('trained').textContent = data.devices.filter(d => d.model).length;
    $('updated').textContent = 'Last updated ' + time(data.server_time);
    $('status').textContent = 'Connected · polling every 5 seconds';
    $('devices').replaceChildren();
    $('no-devices').hidden = !!data.devices.length;

    const selected = $('device-select').value;
    $('device-select').replaceChildren();

    for(const d of data.devices){
      const row = text('tr', '');
      row.append(text('td', d.id));

      const osHost = d.latest ? ((d.latest.os_info || 'Unknown OS') + (d.latest.hostname ? ' (' + d.latest.hostname + ')' : '')) : '—';
      const osTd = text('td', osHost);
      osTd.style.fontSize = '12px';
      row.append(osTd);

      const state = text('td', '');
      state.append(text('span', d.online ? 'Online' : 'Offline', d.online ? 'pill online' : 'pill'));
      row.append(state);

      row.append(
        text('td', d.latest ? d.latest.cpu.toFixed(1) + '%' : '—'),
        text('td', d.latest ? d.latest.ram.toFixed(1) + '%' : '—'),
        text('td', (d.latest && d.latest.disk != null) ? d.latest.disk.toFixed(1) + '%' : '—'),
        text('td', (d.latest && d.latest.battery != null) ? (d.latest.battery + '% ' + (d.latest.is_plugged ? '⚡' : '🔋')) : '—'),
        text('td', d.model ? 'Trained · ' + d.model.sample_count + ' samples' : 'Not trained')
      );

      const actionTd = text('td', '');
      const warnBtn = text('button', '📢 Warn', 'secondary');
      warnBtn.style.padding = '4px 8px';
      warnBtn.style.fontSize = '11px';
      warnBtn.style.marginRight = '6px';
      warnBtn.style.color = '#ffc085';
      warnBtn.style.borderColor = '#ffc08555';
      warnBtn.title = 'Send real-time popup security warning to ' + d.id;
      warnBtn.addEventListener('click', async e => {
        e.stopPropagation();
        const defaultMsg = 'SECURITY WARNING: Restricted web browsing / policy violation detected. Activity is logged by Security Operations.';
        const msg = prompt('Enter security warning to display on ' + d.id + ':', defaultMsg);
        if (msg && msg.trim()) {
          warnBtn.disabled = true;
          try {
            await api('/api/devices/' + encodeURIComponent(d.id) + '/send_alert', 'POST', JSON.stringify({ message: msg.trim() }));
            alert('Security warning dispatched to ' + d.id + '! It will pop up on their screen on the next heartbeat.');
          } catch(err) {
            alert('Failed: ' + err.message);
          } finally {
            warnBtn.disabled = false;
          }
        }
      });
      actionTd.append(warnBtn);

      const delBtn = text('button', 'Delete', 'secondary');
      delBtn.style.padding = '4px 8px';
      delBtn.style.fontSize = '11px';
      delBtn.style.color = '#ff9999';
      delBtn.style.borderColor = '#ff444455';
      delBtn.addEventListener('click', async e => {
        e.stopPropagation();
        if(confirm('Remove endpoint "' + d.id + '" from Sentinel?')){
          delBtn.disabled = true;
          try {
            await api('/api/devices/' + encodeURIComponent(d.id), 'DELETE');
            await refresh();
          } catch(err) {
            delBtn.disabled = false;
            showError(err);
          }
        }
      });
      actionTd.append(delBtn);
      row.append(actionTd);

      $('devices').append(row);
      const option = text('option', d.id);
      option.value = d.id;
      $('device-select').append(option);
    }

    if(data.devices.some(d => d.id === selected)) $('device-select').value = selected;

    $('alert-list').replaceChildren();
    $('no-alerts').hidden = !!data.alerts.length;

    for(const a of data.alerts){
      const row = text('div', '', 'alert');
      const copy = text('div', '');
      copy.append(
        text('span', a.severity, 'severity'),
        text('strong', a.device_id),
        text('p', a.message),
        text('small', time(a.created) + ' · ' + a.kind)
      );
      const button = text('button', a.acknowledged ? 'Reviewed' : 'Acknowledge', a.acknowledged ? 'secondary' : '');
      button.disabled = !!a.acknowledged;
      button.addEventListener('click', async () => {
        button.disabled = true;
        try {
          await api('/api/alerts/' + a.id + '/ack', 'POST');
          await refresh();
        } catch(e) {
          button.disabled = false;
          showError(e);
        }
      });
      row.append(copy, button);
      $('alert-list').append(row);
    }
    await history();
  } finally {
    busy = false;
  }
}

async function history(){
  const device = $('device-select').value;
  if(!device){
    $('chart-message').textContent = 'Select a registered endpoint to see its metrics.';
    $('coverage').replaceChildren();
    $('processes').replaceChildren();
    return;
  }
  const {samples} = await api('/api/devices/' + encodeURIComponent(device) + '/history');
  if(device !== $('device-select').value) return;

  $('chart-message').textContent = samples.length ? 'Last ' + samples.length + ' samples · CPU / RAM (%)' : 'Waiting for this endpoint’s first sample.';
  const latest = samples.at(-1);

  const actElem = $('active-window-title');
  if (actElem) {
    const actVal = latest?.active_window || 'Desktop / Inactive';
    actElem.textContent = actVal;
    const actLower = actVal.toLowerCase();
    const badKws = ['porn', 'xxx', 'torrent', 'gambling', 'casino', 'bet365'];
    if (badKws.some(kw => actLower.includes(kw))) {
      actElem.style.color = '#ff7b72';
      actElem.textContent += ' ⚠️ [RESTRICTED CONTENT]';
    } else {
      actElem.style.color = '#86e1b3';
    }
  }

  $('coverage').replaceChildren();
  for(const warning of latest?.warnings ?? []) {
    $('coverage').append(text('div', warning));
  }

  $('processes').replaceChildren();
  for(const p of latest?.processes ?? []) {
    const li = text('li', '');
    li.style.display = 'flex';
    li.style.alignItems = 'center';
    li.style.gap = '8px';
    li.style.padding = '4px 0';

    const pName = p.name || '';
    const baseName = pName.split(/[\/\\]/).pop().toLowerCase().replace(/\.exe$/, '');
    const isThreat = THREAT_LIST.includes(baseName);

    const spanText = text('span', p.pid + ' · ' + pName);
    li.append(spanText);

    if (isThreat) {
      const threatBadge = text('span', '🚨 SUSPICIOUS TOOL', 'pill');
      threatBadge.style.background = '#491819';
      threatBadge.style.color = '#ff7b72';
      threatBadge.style.fontSize = '10px';
      threatBadge.style.padding = '2px 6px';
      li.append(threatBadge);
    }

    const killBtn = text('button', 'Kill', 'secondary');
    killBtn.style.padding = '2px 6px';
    killBtn.style.fontSize = '10px';
    killBtn.style.color = '#ff7b72';
    killBtn.style.borderColor = '#ff7b7255';
    killBtn.style.marginLeft = 'auto';
    killBtn.title = 'Remote Active Response: Dispatch terminate signal to endpoint';

    killBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      if (confirm(`Active Response: Send kill signal to terminate PID ${p.pid} (${pName}) on ${device}?`)) {
        killBtn.disabled = true;
        try {
          await api('/api/devices/' + encodeURIComponent(device) + '/kill_process', 'POST', JSON.stringify({ pid: p.pid, name: pName }));
          alert(`Remote kill command queued for PID ${p.pid} (${pName}). The agent will terminate it on its next heartbeat.`);
        } catch (err) {
          killBtn.disabled = false;
          alert('Failed to queue kill command: ' + err.message);
        }
      }
    });
    li.append(killBtn);

    $('processes').append(li);
  }

  if(!window.Chart){
    $('chart-message').textContent += ' Chart library unavailable (CDN needs internet); current values remain visible above.';
    return;
  }
  const data = {
    labels: samples.map(s => new Date(s.observed * 1000).toLocaleTimeString()),
    datasets: [
      {
        label: 'CPU %',
        data: samples.map(s => s.cpu),
        borderColor: '#86e1b3',
        backgroundColor: '#86e1b311',
        fill: true,
        pointRadius: 0,
        tension: .2
      },
      {
        label: 'RAM %',
        data: samples.map(s => s.ram),
        borderColor: '#91b4ff',
        pointRadius: 0,
        tension: .2
      }
    ]
  };
  if(chart){
    chart.data = data;
    chart.update('none');
  } else {
    chart = new Chart($('metrics'), {
      type: 'line',
      data,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
          legend: { labels: { color: '#96a9ba' } }
        },
        scales: {
          y: { min: 0, max: 100, ticks: { color: '#96a9ba' }, grid: { color: '#273442' } },
          x: { ticks: { color: '#96a9ba', maxTicksLimit: 8 }, grid: { display: false } }
        }
      }
    });
  }
}
