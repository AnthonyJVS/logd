'use strict';

/* ───────────────────────── bridge ───────────────────────── */
const TA = window.__TAURI__;
const api = TA ? {
  invoke: (cmd, args) => TA.core.invoke(cmd, args),
  listen: (ev, cb) => TA.event.listen(ev, e => cb(e.payload)),
  win: TA.window.getCurrentWindow(),
} : window.MOCK;
if (!TA) document.body.classList.add('mock');

/* ───────────────────────── helpers ───────────────────────── */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const pad = (n, w = 2) => String(n).padStart(w, '0');
const now = () => Date.now();
const fmtTime = (ms, withMs) => {
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` + (withMs ? '.' + pad(d.getMilliseconds(), 3) : '');
};
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const fmtDate = ms => { const d = new Date(ms); return `${MON[d.getMonth()]} ${pad(d.getDate())} ${fmtTime(ms)}`; };
const fmtBytes = b => {
  if (b == null) return '–';
  const u = ['B', 'K', 'M', 'G', 'T']; let i = 0;
  while (b >= 1024 && i < 4) { b /= 1024; i++; }
  return (i ? b.toFixed(b < 10 ? 1 : 0) : Math.round(b)) + u[i];
};
const fmtDur = ms => {
  if (ms == null || ms < 0) return '–';
  if (ms < 1000) return Math.round(ms) + 'ms';
  const s = ms / 1000; if (s < 60) return s.toFixed(s < 10 ? 2 : 1) + 's';
  const m = Math.floor(s / 60); if (m < 60) return `${m}m${pad(Math.floor(s % 60))}s`;
  const h = Math.floor(m / 60); if (h < 48) return `${h}h${pad(m % 60)}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
};
const fmtNum = n => n.toLocaleString('en-US');
const cpuBar = v => `<span class="cbar"><i class="${v > 60 ? 'hi' : v > 25 ? 'mid' : ''}" style="width:${Math.min(100, v)}%"></i></span>`;
const flagList = f => (f || '').split(',').filter(Boolean);
const flagHtml = f => flagList(f).map(x => `<span class="flag f-${x}">!${x}</span>`).join('');
const FLAG_DESC = {
  temp: 'launched from a Temp folder — typical for installers and malware',
  downloads: 'launched straight from Downloads',
  'odd-path': 'unusual location (Recycle Bin / Public)',
  masquerade: 'system process name outside C:\\Windows — possible masquerading',
  encoded: 'PowerShell with an encoded command (-EncodedCommand)',
  hidden: 'PowerShell with a hidden window',
  'double-ext': 'double extension like .pdf.exe',
  self: 'started by logd itself (scheduler scanner)',
  unsigned: 'no digital signature, running from a user-writable folder',
  'bad-sig': 'signature is broken or not trusted — file may have been tampered with',
};
const RISKY_DIR = /\\(appdata|temp|downloads|programdata|users\\public|desktop)\\/i;
/** Backend flags plus the ones derived from the signature verdict. */
const allFlags = (flags, sig, exe) => {
  const f = flagList(flags);
  if (sig === 'unsigned' && RISKY_DIR.test(exe || '')) f.push('unsigned');
  if (sig === 'invalid' || sig === 'untrusted') f.push('bad-sig');
  return f.join(',');
};
const sigBadge = (sig, signer, os, exe = '') => {
  if (!sig) return '<span class="dim2">…</span>';
  // Store apps are signed at the package level, not inside the exe
  if (sig === 'unsigned' && /\\windowsapps\\/i.test(exe)) return '<span class="sig ok" title="MSIX package signature">◇ <span class="who">store package</span></span>';
  if (sig === 'valid') return `<span class="sig ok${os ? ' os' : ''}" title="signed by ${esc(signer)}">✓ <span class="who">${esc(signer.length > 26 ? signer.slice(0, 25) + '…' : signer)}</span></span>`;
  if (sig === 'unsigned') return '<span class="sig no">✗ unsigned</span>';
  if (sig === 'error') return '<span class="dim2">?</span>';
  return `<span class="sig bad" title="${esc(signer)}">⚠ ${sig}</span>`;
};
const PORTS = { 20: 'ftp', 21: 'ftp', 22: 'ssh', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3', 123: 'ntp', 135: 'rpc', 137: 'netbios', 138: 'netbios', 139: 'netbios',
  143: 'imap', 443: 'https', 445: 'smb', 465: 'smtps', 587: 'smtp', 993: 'imaps', 995: 'pop3s', 1900: 'ssdp', 3389: 'rdp', 5353: 'mdns', 5355: 'llmnr', 8080: 'http-alt', 27015: 'steam' };
const fmtPort = p => PORTS[p] ? `${p}<span class="dim2">/${PORTS[p]}</span>` : String(p);
const isRemote = c => c.proto.startsWith('tcp') && !['LISTEN', 'CLOSED', 'DELETE_TCB'].includes(c.state) && !/^(127\.|::1$|0\.0\.0\.0$|::$)/.test(c.raddr);
const fmtAddr = (a, p) => a.includes(':') ? `[${esc(a)}]:${fmtPort(p)}` : `${esc(a)}:${fmtPort(p)}`;
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
const store = {
  get(k, d) { try { const v = localStorage.getItem('logd.' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('logd.' + k, JSON.stringify(v)); } catch { } },
};

/* ───────────────────────── theme ───────────────────────── */
const THEMES = { arch: 'Arch', nord: 'Nord', gruvbox: 'Gruvbox', catppuccin: 'Catppuccin Mocha', tokyonight: 'Tokyo Night', dracula: 'Dracula' };
/** Theme palette for canvas drawing (CSS variables resolved). */
const TC = {};
function applyTheme(name, alpha) {
  document.documentElement.dataset.theme = THEMES[name] ? name : 'arch';
  document.documentElement.style.setProperty('--alpha', alpha);
  const cs = getComputedStyle(document.documentElement);
  for (const k of ['acc', 'acc2', 'ok', 'err', 'warn', 'vio', 'cyan', 'dim', 'dim2', 'fg']) TC[k] = cs.getPropertyValue('--' + k).trim();
}
applyTheme(store.get('theme', 'arch'), store.get('alpha', .78));

/* ───────────────────────── state ───────────────────────── */
const S = {
  info: null,
  snap: null,
  procs: new Map(),
  events: [],
  recent: new Map(),       // row id -> row, for the dash timeline
  upcoming: { items: [], scanned_ms: 0 },
  ws: store.get('ws', 'dash'),
  sel: null,               // { pid, id }
  sort: store.get('sort', { key: 'cpu', dir: -1 }),
  paused: false,
  pending: [],
  hist: { cpu: [], mem: [], rx: [], tx: [] },
  collapsed: new Set(),
  hideSelf: store.get('hideSelf', true),
  rules: [],
  alerts: [],
  unread: 0,
  histRows: [],
};
const LOG_CAP = { dash: 250, full: 3000 };

/* ───────────────────────── workspaces ───────────────────────── */
function setWs(ws) {
  S.ws = ws; store.set('ws', ws);
  $$('#wsnav button').forEach(b => b.classList.toggle('on', b.dataset.ws === ws));
  $$('.ws').forEach(s => s.classList.toggle('on', s.id === 'ws-' + ws));
  renderActive(true);
  renderBar();
  if (ws === 'hist') loadHistory();
  if (ws === 'rules') { setUnread(0); renderAlerts(); }
  if (ws === 'sched') renderAutoruns();
}
$$('#wsnav button').forEach(b => b.onclick = () => setWs(b.dataset.ws));

function renderActive(force) {
  if (!S.snap) return;
  if (S.ws === 'dash') { renderFetch(); renderGraphs(); renderTop(); renderNext(); drawDashTimeline(); }
  else if (S.ws === 'ps') renderPs();
  else if (S.ws === 'tree' && (force || ++treeTick % 3 === 0)) renderTree();
  else if (S.ws === 'sched') renderSched();
  else if (S.ws === 'net') renderNet(force);
  else if (S.ws === 'hist') drawHistTimeline();
}
let treeTick = 0;

/* ───────────────────────── top bar + status ───────────────────────── */
function renderBar() {
  const s = S.snap; if (!s) return;
  $('#m-cpu').innerHTML = `cpu <b>${s.cpu.toFixed(0)}%</b>`;
  $('#m-mem').innerHTML = `mem <b>${fmtBytes(s.mem_used)}</b>/${fmtBytes(s.mem_total)}`;
  $('#m-net').innerHTML = `↓<b>${fmtBytes(s.net_rx)}</b> ↑<b>${fmtBytes(s.net_tx)}</b>`;
  $('#m-etw').innerHTML = s.etw ? `<span class="ok">● etw</span>` : `<span class="dim">○ poll</span>`;
  $('#m-etw').title = s.etw ? 'ETW: catches even processes that live for milliseconds' : 'Polling once per interval. Run as admin for ETW.';
  const set = S.settings || {};
  $('#status').innerHTML =
    `<span class="mode">${S.ws.toUpperCase()}</span>` +
    `<span>procs <b class="acc">${s.procs.length}</b></span>` +
    `<span>events/min <b class="acc">${s.ev_per_min}</b></span>` +
    `<span>connections <b class="acc">${(s.conns || []).filter(isRemote).length}</b></span>` +
    `<span>history <b class="acc">${fmtNum(s.db_rows)}</b> rows</span>` +
    `<span>poll ${set.interval_ms ?? '?'}ms</span>` +
    `<span>${S.info?.admin ? '<span class="ok">admin</span>' : '<span class="warn">user</span>'}</span>` +
    `<span class="keys"><b>1-8</b> tabs  <b>/</b> search  <b>␣</b> pause  <b>k</b> kill  <b>esc</b> close</span>`;
}
setInterval(() => {
  const d = new Date();
  $('#clock').textContent = `${['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][d.getDay()]} ${MON[d.getMonth()]} ${pad(d.getDate())}  ${fmtTime(d)}`;
}, 250);

/* ───────────────────────── neofetch ───────────────────────── */
const ART = [
  '        /\\',
  '       /  \\',
  '      /\\   \\',
  '     /      \\',
  '    /   ,,   \\',
  '   /   |  |  -\\',
  '  /_-\'\'    \'\'-_\\',
].join('\n');
function renderFetch() {
  const i = S.info, s = S.snap; if (!i || !s) return;
  const kv = (k, v) => `<span class="k">${k}</span>${v}`;
  const colors = [TC.dim2, TC.err, TC.ok, TC.warn, TC.acc, TC.vio, TC.cyan, TC.fg];
  $('#fetch').innerHTML = `<div class="art">${esc(ART)}</div><div class="kv">` + [
    `<span class="hdr"><span class="acc">${esc(i.user)}</span>@<span class="acc">${esc(i.host)}</span></span>`,
    `<span class="dim2">${'─'.repeat(Math.min(28, (i.user + i.host).length + 1))}</span>`,
    kv('os', esc(i.os)),
    kv('kernel', esc(i.kernel)),
    kv('uptime', fmtDur(now() - i.boot_ms)),
    kv('cpu', esc(i.cpu_brand.replace(/\(R\)|\(TM\)|CPU|Processor/g, '').replace(/\s+/g, ' ').trim()) + ` <span class="dim">(${i.cores})</span>`),
    kv('memory', `${fmtBytes(s.mem_used)} / ${fmtBytes(s.mem_total)}`),
    kv('procs', `${s.procs.length}  <span class="dim">·</span> ${s.ev_per_min} ev/min`),
    kv('monitor', s.etw ? '<span class="ok">ETW kernel</span>' : '<span class="warn">polling</span>'),
    `<span class="blocks">${colors.map(c => `<span style="background:${c}"></span>`).join('')}</span>`,
  ].join('\n') + '</div>';
}

/* ───────────────────────── htop graphs ───────────────────────── */
function pushHist(s) {
  const H = S.hist, max = 120;
  H.cpu.push(s.cpu); H.mem.push(s.mem_used / s.mem_total * 100); H.rx.push(s.net_rx); H.tx.push(s.net_tx);
  for (const k in H) if (H[k].length > max) H[k].shift();
}
function sizeCanvas(cv) {
  const dpr = devicePixelRatio || 1, w = cv.clientWidth, h = cv.clientHeight;
  if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) { cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr); }
  const c = cv.getContext('2d'); c.setTransform(dpr, 0, 0, dpr, 0, 0); c.clearRect(0, 0, w, h);
  return [c, w, h];
}
function spark(cv, data, color, fixedMax) {
  const [c, w, h] = sizeCanvas(cv); if (!data.length) return;
  const max = fixedMax ?? Math.max(1, ...data) * 1.15, n = 120, step = w / (n - 1), x0 = w - (data.length - 1) * step;
  c.beginPath(); c.moveTo(x0, h);
  data.forEach((v, i) => c.lineTo(x0 + i * step, h - (v / max) * (h - 2) - 1));
  c.lineTo(w, h); c.closePath();
  const g = c.createLinearGradient(0, 0, 0, h); g.addColorStop(0, color + '55'); g.addColorStop(1, color + '08');
  c.fillStyle = g; c.fill();
  c.beginPath(); data.forEach((v, i) => c[i ? 'lineTo' : 'moveTo'](x0 + i * step, h - (v / max) * (h - 2) - 1));
  c.strokeStyle = color; c.lineWidth = 1.2; c.stroke();
}
function renderGraphs() {
  const s = S.snap, H = S.hist;
  spark($('#sp-cpu'), H.cpu, TC.acc, 100); $('#sv-cpu').textContent = s.cpu.toFixed(1) + '%';
  spark($('#sp-mem'), H.mem, TC.vio, 100); $('#sv-mem').textContent = (s.mem_used / s.mem_total * 100).toFixed(1) + '%';
  spark($('#sp-rx'), H.rx, TC.ok); $('#sv-rx').textContent = fmtBytes(s.net_rx) + '/s';
  spark($('#sp-tx'), H.tx, TC.warn); $('#sv-tx').textContent = fmtBytes(s.net_tx) + '/s';
  $('#core-meta').textContent = `${s.cores.length} threads`;
  const W = 12;
  $('#cores').innerHTML = s.cores.map((v, i) => {
    const n = Math.round(v / 100 * W), col = v > 60 ? 'err' : v > 25 ? 'warn' : 'ok';
    return `<div class="core"><span class="n">${i}</span><span class="dim2">[</span><span class="m"><b class="${col}">${'|'.repeat(n)}</b>${' '.repeat(W - n)}</span><span class="dim">${v.toFixed(0).padStart(3)}%</span><span class="dim2">]</span></div>`;
  }).join('');
}

/* ───────────────────────── top + upcoming (dash) ───────────────────────── */
function renderTop() {
  const list = [...S.procs.values()].filter(p => p.pid > 4).sort((a, b) => b.cpu - a.cpu || b.mem - a.mem).slice(0, 40);
  $('#dtop').innerHTML = `<table class="tbl"><thead><tr><th class="r">PID</th><th>NAME</th><th class="r">CPU</th><th class="r">MEM</th></tr></thead><tbody>` +
    list.map(p => `<tr data-pid="${p.pid}" class="${isSel(p) ? 'sel' : ''} ${p.flags && !onlySelf(p.flags) ? 'flagged' : ''}"><td class="r dim">${p.pid}</td><td class="nm">${esc(p.name)}</td><td class="r">${cpuBar(p.cpu)}${p.cpu.toFixed(1)}</td><td class="r">${fmtBytes(p.mem)}</td></tr>`).join('') +
    `</tbody></table>`;
}
const onlySelf = f => f === 'self';
const isSel = p => S.sel && S.sel.pid === p.pid;

function upcomingTasks() {
  const t = now();
  return S.upcoming.items.filter(u => u.kind === 'task' && u.next_ms && u.next_ms > t - 5000).sort((a, b) => a.next_ms - b.next_ms);
}
function renderNext() {
  const t = now(), tasks = upcomingTasks();
  const pend = S.upcoming.items.filter(u => u.kind === 'service' && /pending/i.test(u.state));
  $('#dnext-meta').textContent = S.upcoming.scanning ? 'scanning…' : (S.upcoming.scanned_ms ? `scanned ${fmtTime(S.upcoming.scanned_ms)}` : '');
  let h = '';
  if (pend.length) h += `<div class="sub">services in transition</div>` + pend.map(u => `<div class="nx"><span class="in soon">${esc(u.state.replace('Pending', '…'))}</span><span class="t">${esc(u.path || u.name)}</span></div>`).join('');
  h += `<div class="sub">scheduled tasks</div>`;
  h += tasks.slice(0, 30).map(u => {
    const d = u.next_ms - t;
    return `<div class="nx" title="${esc(u.path + u.name)}\n${esc(u.exe)}"><span class="in ${d < 120000 ? 'soon' : ''}">${d <= 0 ? 'now' : fmtDur(d)}</span><span class="t">${esc(u.name)}<small>${esc(shortExe(u.exe))}</small></span></div>`;
  }).join('') || `<div class="empty">${S.upcoming.scanning ? 'scanning task scheduler…' : 'no scheduled tasks'}</div>`;
  $('#dnext').innerHTML = h;
}
const shortExe = e => { const m = String(e || '').match(/([^\\/"]+?\.(exe|cmd|bat|ps1|dll|vbs|js))/i); return m ? m[1] : String(e || '').slice(0, 40); };

/* ───────────────────────── log ───────────────────────── */
function evMatch(ev, q, f) {
  const r = ev.row;
  if (S.hideSelf && flagList(r.flags).includes('self')) return false;
  if (f) {
    if (ev.kind === 'start' && !f.start) return false;
    if (ev.kind === 'stop' && !f.stop) return false;
    if (f.flag && !flagList(r.flags).some(x => x !== 'self')) return false;
  }
  if (!q) return true;
  return (r.name + ' ' + r.exe + ' ' + r.cmd + ' ' + r.parent).toLowerCase().includes(q) || String(r.pid) === q;
}
function evHtml(ev, isNew) {
  const r = ev.row, st = ev.kind === 'start';
  const fl = flagList(r.flags).filter(x => x !== 'self').length;
  const tail = st
    ? `<span class="dim">←</span> <span class="par">${esc(r.parent || '?')}</span><span class="dim">[${r.ppid ?? '?'}]</span><span class="cmd">${esc((r.cmd || r.exe).slice(0, 400))}</span>`
    : `<span class="${(r.exit_code ?? 0) !== 0 ? 'err' : 'dim'}">code=${r.exit_code ?? '?'}</span> <span class="dim">lived</span> ${fmtDur(ev.lifetime_ms)}${r.peak_mem ? ` <span class="dim">peak</span> ${fmtBytes(r.peak_mem)}` : ''}`;
  return `<div class="ln ${st ? 'ln-start' : 'ln-stop'}${fl ? ' flagged' : ''}${isNew ? ' new' : ''}${S.sel && S.sel.id === r.id ? ' sel' : ''}" data-id="${r.id}" data-pid="${r.pid}">` +
    `<span class="ts">${fmtTime(ev.ts, true)}</span><span class="kind">${st ? '▲ spawn' : '▼ exit '}</span>` +
    `<span class="nm">${esc(r.name)}</span><span class="pid">[${r.pid}]</span>${flagHtml(r.flags)} ${tail}</div>`;
}
function logFilter() {
  return { q: $('#log-q').value.trim().toLowerCase(), start: $('#log-start').checked, stop: $('#log-stop').checked, flag: $('#log-flag').checked };
}
function appendLog(box, evs, cap, f, isNew) {
  const q = f ? f.q : '';
  const html = evs.filter(e => evMatch(e, q, f)).map(e => evHtml(e, isNew)).join('');
  if (!html) return;
  const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.insertAdjacentHTML('beforeend', html);
  let extra = box.querySelectorAll('.ln').length - cap;
  while (extra-- > 0) box.querySelector('.ln').remove();
  if (stick) box.scrollTop = box.scrollHeight;
}
function rebuildFullLog() {
  const box = $('#flog'); box.innerHTML = '';
  appendLog(box, S.events.slice(-LOG_CAP.full), LOG_CAP.full, logFilter(), false);
  box.scrollTop = box.scrollHeight;
}
function addEvents(evs, isNew = true) {
  for (const ev of evs) {
    S.events.push(ev);
    S.recent.set(ev.row.id, ev.row);
  }
  if (S.events.length > 6000) S.events.splice(0, S.events.length - 5000);
  if (S.paused) { S.pending.push(...evs); updatePause(); return; }
  appendLog($('#dlog'), evs, LOG_CAP.dash, null, isNew);
  appendLog($('#flog'), evs, LOG_CAP.full, logFilter(), isNew);
  $('#dlog-meta').textContent = `${S.events.length} events`;
}
function setPaused(p) {
  S.paused = p;
  $('#log-pause').classList.toggle('on', p);
  if (!p && S.pending.length) { const evs = S.pending; S.pending = []; S.paused = false; addEvents2(evs); }
  updatePause();
}
function addEvents2(evs) {
  appendLog($('#dlog'), evs, LOG_CAP.dash, null, false);
  appendLog($('#flog'), evs, LOG_CAP.full, logFilter(), false);
}
function updatePause() {
  for (const id of ['#dlog', '#flog']) {
    const box = $(id); let b = box.querySelector('.log-paused');
    if (S.paused) { if (!b) { b = document.createElement('div'); b.className = 'log-paused'; box.prepend(b); } b.textContent = `⏸ paused — ${S.pending.length} events buffered (space to resume)`; }
    else if (b) b.remove();
  }
}
$('#log-pause').onclick = () => setPaused(!S.paused);
$('#log-clear').onclick = () => { $('#flog').innerHTML = ''; $('#dlog').innerHTML = ''; };
['#log-start', '#log-stop', '#log-flag'].forEach(id => $(id).onchange = rebuildFullLog);
$('#log-q').oninput = debounce(rebuildFullLog, 150);

/* ───────────────────────── notifications ───────────────────────── */
function toast(html, cls = '', onClick) {
  const t = document.createElement('div'); t.className = 'toast ' + cls; t.innerHTML = html;
  t.onclick = () => { onClick?.(); t.remove(); };
  $('#toasts').append(t);
  setTimeout(() => t.remove(), 7000);
  while ($('#toasts').children.length > 5) $('#toasts').firstChild.remove();
}

/* ───────────────────────── ps table ───────────────────────── */
function procMatch(p, q) { return !q || (p.name + ' ' + p.exe + ' ' + p.user + ' ' + p.cmd).toLowerCase().includes(q) || String(p.pid) === q; }
function renderPs() {
  const q = $('#ps-q').value.trim().toLowerCase();
  const { key, dir } = S.sort;
  const list = [...S.procs.values()].filter(p => procMatch(p, q)).sort((a, b) => {
    const x = a[key], y = b[key];
    return (typeof x === 'string' ? x.localeCompare(y) : (x ?? 0) - (y ?? 0)) * dir;
  });
  $('#ps-count').textContent = `${list.length} / ${S.procs.size}`;
  $$('#ps-tbl th').forEach(th => { th.classList.toggle('sorted', th.dataset.k === key); th.classList.toggle('asc', dir > 0); });
  const t = now();
  $('#ps-body').innerHTML = list.map(p => `<tr data-pid="${p.pid}" class="${isSel(p) ? 'sel' : ''} ${p.flags && !onlySelf(p.flags) ? 'flagged' : ''}">` +
    `<td class="r dim">${p.pid}</td><td class="nm">${esc(p.name)}${p.suspended ? '<span class="frozen">⏸</span>' : ''} ${flagHtml(p.flags)}</td><td class="r">${cpuBar(p.cpu)}${p.cpu.toFixed(1)}</td>` +
    `<td class="r">${fmtBytes(p.mem)}</td><td class="r dim">${p.dr ? fmtBytes(p.dr) : '·'}</td><td class="r dim">${p.dw ? fmtBytes(p.dw) : '·'}</td>` +
    `<td class="r ${p.net ? 'cyan' : 'dim2'}">${p.net || (p.listen ? '<span class="acc">L</span>' : '·')}</td><td>${p.exe ? sigBadge(p.sig, p.signer, p.sig_os, p.exe) : '<span class="dim2">—</span>'}</td>` +
    `<td class="dim">${esc(p.user)}</td><td class="r dim">${fmtDur(t - p.start_ms)}</td><td class="path" title="${esc(p.exe)}">${esc(p.exe)}</td></tr>`).join('');
}
$$('#ps-tbl th').forEach(th => th.onclick = () => {
  const k = th.dataset.k; if (!k) return;
  S.sort = { key: k, dir: S.sort.key === k ? -S.sort.dir : (typeof [...S.procs.values()][0]?.[k] === 'string' ? 1 : -1) };
  store.set('sort', S.sort); renderPs();
});
$('#ps-q').oninput = debounce(renderPs, 100);

/* ───────────────────────── tree ───────────────────────── */
function renderTree() {
  const procs = S.procs, kids = new Map(), roots = [];
  for (const p of procs.values()) {
    const par = p.ppid != null ? procs.get(p.ppid) : null;
    // a parent that started after its child is a recycled pid, not the real parent
    if (par && par.pid !== p.pid && par.start_ms <= p.start_ms + 1000) { if (!kids.has(par.pid)) kids.set(par.pid, []); kids.get(par.pid).push(p); }
    else roots.push(p);
  }
  const byName = (a, b) => a.name.localeCompare(b.name) || a.pid - b.pid;
  roots.sort((a, b) => a.pid - b.pid);
  const q = $('#tree-q').value.trim().toLowerCase();
  let show = null;
  if (q) {
    show = new Set();
    for (const p of procs.values()) if (procMatch(p, q)) {
      let c = p, guard = 0;
      while (c && guard++ < 64) { show.add(c.pid); c = c.ppid != null ? procs.get(c.ppid) : null; }
    }
  }
  const out = [], seen = new Set();
  const walk = (p, prefix, last, depth) => {
    if (seen.has(p.pid) || (show && !show.has(p.pid))) return;
    seen.add(p.pid);
    const ch = (kids.get(p.pid) || []).filter(c => !show || show.has(c.pid)).sort(byName);
    const col = S.collapsed.has(p.pid) && !q;
    const br = depth === 0 ? '' : prefix + (last ? '└─ ' : '├─ ');
    const hit = q && procMatch(p, q);
    out.push(`<div class="tn ${isSel(p) ? 'sel' : ''} ${hit ? 'hit' : ''} ${p.flags && !onlySelf(p.flags) ? 'flagged' : ''}" data-pid="${p.pid}">` +
      `<span class="br">${br}</span><span class="tg2" data-tog="${p.pid}">${ch.length ? (col ? '▸' : '▾') : ' '}</span>` +
      `<span class="nm">${esc(p.name)}</span><span class="pid">(${p.pid})</span>${col ? `<span class="dim"> +${ch.length}</span>` : ''}` +
      `<span class="meta">${p.cpu >= 0.1 ? p.cpu.toFixed(1) + '%  ' : ''}${fmtBytes(p.mem)}</span></div>`);
    if (!col) ch.forEach((c, i) => walk(c, depth === 0 ? '' : prefix + (last ? '   ' : '│  '), i === ch.length - 1, depth + 1));
  };
  roots.forEach((r, i) => walk(r, '', i === roots.length - 1, 0));
  $('#tree').innerHTML = out.join('');
  $('#tree-meta').textContent = `${roots.length} roots · ${procs.size} processes`;
}
$('#tree').addEventListener('click', e => {
  const tog = e.target.closest('[data-tog]');
  if (tog && tog.textContent.trim()) {
    const pid = +tog.dataset.tog; S.collapsed.has(pid) ? S.collapsed.delete(pid) : S.collapsed.add(pid); renderTree(); e.stopPropagation();
  }
}, true);
$('#tree-q').oninput = debounce(renderTree, 120);
$('#tree-exp').onclick = () => { S.collapsed.clear(); renderTree(); };
$('#tree-col').onclick = () => { for (const p of S.procs.values()) S.collapsed.add(p.pid); renderTree(); };

/* ───────────────────────── timeline ───────────────────────── */
const TICKS = [1e3, 5e3, 1e4, 3e4, 6e4, 3e5, 6e5, 9e5, 18e5, 36e5, 108e5, 216e5, 432e5, 864e5];
function drawTimeline(cv, rows, from, to, opts = {}) {
  const [c, w, h] = sizeCanvas(cv);
  const axisH = 16, t = now(), X = v => (v - from) / (to - from) * w;
  c.font = '10.5px ' + getComputedStyle(document.body).fontFamily;
  const step = TICKS.find(s => w / ((to - from) / s) > 80) || TICKS.at(-1);
  if (t < to && t > from) { c.fillStyle = TC.vio + '10'; c.fillRect(X(t), 0, w - X(t), h - axisH); }
  c.fillStyle = 'rgba(0,0,0,.18)'; c.fillRect(0, h - axisH, w, axisH);
  for (let v = Math.ceil(from / step) * step; v <= to; v += step) {
    const x = Math.round(X(v)) + .5;
    c.strokeStyle = TC.dim + '18'; c.beginPath(); c.moveTo(x, 0); c.lineTo(x, h - axisH); c.stroke();
    c.fillStyle = TC.dim;
    const d = new Date(v), lbl = step >= 864e5 ? `${MON[d.getMonth()]} ${pad(d.getDate())}` : step >= 6e4 ? `${pad(d.getHours())}:${pad(d.getMinutes())}` : fmtTime(v);
    c.fillText(lbl, x + 3, h - 4);
  }
  const rowH = opts.rowH || 11, gap = 2, lanes = Math.max(1, Math.floor((h - axisH - 18) / (rowH + gap)));
  const top0 = 16;
  const vis = rows.slice(0, lanes), hits = [];
  vis.forEach((r, i) => {
    const y = top0 + i * (rowH + gap);
    const end = r.end_ms ?? t;
    const x1 = Math.max(0, X(Math.max(from, r.start_ms))), x2 = Math.max(x1 + 2, X(Math.min(to, end)));
    const flagged = flagList(r.flags).some(x => x !== 'self');
    const alive = r.end_ms == null;
    const col = flagged ? TC.warn : alive ? TC.ok : (r.exit_code ?? 0) !== 0 ? TC.err : TC.acc;
    c.fillStyle = col + (alive ? 'cc' : '88'); c.fillRect(x1, y, x2 - x1, rowH);
    if (alive) { c.fillStyle = col; c.fillRect(x2 - 2, y, 2, rowH); }
    const label = `${r.name} ${r.end_ms != null ? fmtDur(r.end_ms - r.start_ms) : ''}`;
    const tw = c.measureText(label).width;
    c.fillStyle = (x2 - x1 > tw + 8) ? '#0f1114' : TC.fg;
    c.fillText(label, (x2 - x1 > tw + 8) ? x1 + 4 : x2 + 4, y + rowH - 2);
    hits.push({ x1, x2: Math.max(x2, x2 + (x2 - x1 > tw + 8 ? 0 : tw + 6)), y, h: rowH, row: r });
  });
  if (rows.length > lanes) { c.fillStyle = TC.dim; c.fillText(`+${rows.length - lanes} more`, 4, h - axisH - 3); }
  // scheduled launches
  const up = (opts.upcoming || []).filter(u => u.next_ms >= from && u.next_ms <= to);
  up.forEach((u, i) => {
    const x = Math.round(X(u.next_ms)) + .5;
    c.strokeStyle = TC.vio + '8c'; c.setLineDash([3, 3]); c.beginPath(); c.moveTo(x, 10); c.lineTo(x, h - axisH); c.stroke(); c.setLineDash([]);
    c.fillStyle = TC.vio; c.beginPath(); c.moveTo(x, 3); c.lineTo(x + 4, 7); c.lineTo(x, 11); c.lineTo(x - 4, 7); c.fill();
    const lbl = u.name.length > 22 ? u.name.slice(0, 21) + '…' : u.name;
    if (i < 12) { c.fillText(lbl, Math.min(x + 6, w - c.measureText(lbl).width - 4), 11); }
    hits.push({ x1: x - 5, x2: x + 5, y: 0, h: h - axisH, up: u });
  });
  if (t >= from && t <= to) {
    const x = Math.round(X(t)) + .5;
    c.strokeStyle = TC.acc; c.lineWidth = 1.5; c.beginPath(); c.moveTo(x, 0); c.lineTo(x, h - axisH); c.stroke(); c.lineWidth = 1;
    c.fillStyle = TC.acc; c.fillRect(x - 15, h - axisH, 30, axisH); c.fillStyle = '#0e1114'; c.fillText('now', x - 10, h - 4);
  }
  cv._hits = hits;
}
function tlHit(cv, e) {
  const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
  return (cv._hits || []).find(h => x >= h.x1 && x <= h.x2 && y >= h.y && y <= h.y + h.h);
}
function bindTimeline(cv) {
  cv.addEventListener('mousemove', e => {
    const h = tlHit(cv, e), tip = $('#tip');
    if (!h) { tip.style.display = 'none'; cv.style.cursor = ''; return; }
    cv.style.cursor = 'pointer';
    if (h.row) {
      const r = h.row;
      tip.innerHTML = `<b>${esc(r.name)}</b> [${r.pid}] ${flagHtml(r.flags)}\n<span class="dim">start</span> ${fmtDate(r.start_ms)}\n<span class="dim">end</span> ${r.end_ms ? fmtDate(r.end_ms) + `  (${fmtDur(r.end_ms - r.start_ms)}, code=${r.exit_code ?? '?'})` : '<span class="ok">alive</span>'}\n<span class="dim">parent</span> ${esc(r.parent)} [${r.ppid ?? '?'}]\n<span class="dim">${esc((r.cmd || r.exe).slice(0, 300))}</span>`;
    } else {
      const u = h.up;
      tip.innerHTML = `<span class="vio">◆ scheduled</span> <b>${esc(u.name)}</b>\n<span class="dim">when</span> ${fmtDate(u.next_ms)} (in ${fmtDur(u.next_ms - now())})\n<span class="dim">${esc(u.exe)}</span>`;
    }
    tip.style.display = 'block';
    tip.style.left = Math.min(e.clientX + 14, innerWidth - tip.offsetWidth - 8) + 'px';
    tip.style.top = Math.min(e.clientY + 14, innerHeight - tip.offsetHeight - 8) + 'px';
  });
  cv.addEventListener('mouseleave', () => $('#tip').style.display = 'none');
  cv.addEventListener('click', e => { const h = tlHit(cv, e); if (h?.row) openDetails({ pid: h.row.pid, id: h.row.id, row: h.row }); });
}
function drawDashTimeline() {
  const t = now(), from = t - 15 * 60e3, to = t + 15 * 60e3;
  for (const [id, r] of S.recent) if (r.end_ms != null && r.end_ms < from - 60e3) S.recent.delete(id);
  const rows = [...S.recent.values()]
    .filter(r => !(r.existing && r.end_ms == null) && (r.end_ms ?? t) >= from)
    .filter(r => !(S.hideSelf && flagList(r.flags).includes('self')))
    .sort((a, b) => b.start_ms - a.start_ms);
  drawTimeline($('#tl-dash'), rows, from, to, { upcoming: upcomingTasks() });
}
bindTimeline($('#tl-dash'));
bindTimeline($('#tl-hist'));

/* ───────────────────────── history ───────────────────────── */
function histRange() {
  const v = $('#hist-range').value;
  if (v === 'custom') {
    const f = Date.parse($('#hist-from').value), t = Date.parse($('#hist-to').value);
    return { from: isNaN(f) ? now() - 36e5 : f, to: isNaN(t) ? now() : t };
  }
  const t = now(); return { from: t - +v, to: t };
}
async function loadHistory() {
  const { from, to } = histRange(), q = $('#hist-q').value.trim();
  $('#hist-meta').textContent = 'loading…';
  try {
    const [rows, samples] = await Promise.all([
      api.invoke('query_history', { fromMs: from, toMs: to, search: q, limit: 5000, hideLong: $('#hist-hl').checked }),
      api.invoke('get_samples', { fromMs: from, toMs: to, buckets: 400 }),
    ]);
    for (const r of rows) r.flags = allFlags(r.flags, r.sig, r.exe);
    S.histRows = rows; S.histRange = { from, to }; S.histSamples = samples;
    $('#hist-meta').textContent = `${fmtNum(rows.length)} processes${rows.length >= 5000 ? ' (limit)' : ''} · ${fmtDate(from)} → ${fmtDate(to)}`;
    $('#hist-body').innerHTML = rows.map(r => {
      const life = (r.end_ms ?? now()) - r.start_ms;
      return `<tr data-id="${r.id}" data-pid="${r.pid}" class="${r.end_ms != null ? 'dead' : ''} ${flagList(r.flags).some(x => x !== 'self') ? 'flagged' : ''}">` +
        `<td>${r.existing ? '<span class="dim2">≤</span>' : ''}${fmtDate(r.start_ms)}</td><td>${r.end_ms != null ? fmtDate(r.end_ms) : '<span class="ok">● alive</span>'}</td>` +
        `<td class="r">${fmtDur(life)}</td><td class="nm">${esc(r.name)} ${flagHtml(r.flags)}</td><td class="r dim">${r.pid}</td>` +
        `<td class="r ${(r.exit_code ?? 0) !== 0 ? 'err' : 'dim'}">${r.exit_code ?? '·'}</td><td class="dim">${esc(r.parent)}</td>` +
        `<td class="r dim">${r.peak_mem ? fmtBytes(r.peak_mem) : '·'}</td><td class="path" title="${esc(r.cmd)}">${esc(r.cmd || r.exe)}</td></tr>`;
    }).join('') || `<tr><td colspan="9" class="empty">nothing found for this period</td></tr>`;
    drawHistTimeline(); drawSamples();
  } catch (e) { $('#hist-meta').textContent = 'error: ' + e; }
}
function drawHistTimeline() {
  if (!S.histRange) return;
  drawTimeline($('#tl-hist'), S.histRows, S.histRange.from, S.histRange.to, { rowH: 10 });
}
function drawSamples() {
  const cv = $('#hist-samples'), [c, w, h] = sizeCanvas(cv), s = S.histSamples || [], R = S.histRange;
  c.font = '10.5px ' + getComputedStyle(document.body).fontFamily;
  if (!s.length) { c.fillStyle = TC.dim2; c.fillText('no samples for this period (recorded every 5 s)', 10, 20); return; }
  const X = t => (t - R.from) / (R.to - R.from) * w, memMax = Math.max(...s.map(v => v.mem)) || 1;
  const line = (key, max, col) => {
    c.beginPath(); s.forEach((v, i) => c[i ? 'lineTo' : 'moveTo'](X(v.ts), h - 4 - (v[key] / max) * (h - 18))); c.strokeStyle = col; c.lineWidth = 1.3; c.stroke();
  };
  c.beginPath(); c.moveTo(X(s[0].ts), h); s.forEach(v => c.lineTo(X(v.ts), h - 4 - (v.cpu / 100) * (h - 18))); c.lineTo(X(s.at(-1).ts), h); c.closePath();
  c.fillStyle = TC.acc + '26'; c.fill();
  line('cpu', 100, TC.acc); line('mem', memMax * 1.1, TC.vio);
  c.fillStyle = TC.acc; c.fillText('cpu %', 8, 12); c.fillStyle = TC.vio; c.fillText('mem', 52, 12);
  c.fillStyle = TC.dim; c.fillText(`max cpu ${Math.max(...s.map(v => v.cpu)).toFixed(0)}%  ·  max mem ${fmtBytes(memMax)}`, 90, 12);
}
$('#hist-range').onchange = () => {
  const custom = $('#hist-range').value === 'custom';
  $('#hist-from').classList.toggle('hide', !custom); $('#hist-to').classList.toggle('hide', !custom);
  if (custom) {
    const iso = ms => { const d = new Date(ms - new Date().getTimezoneOffset() * 6e4); return d.toISOString().slice(0, 16); };
    if (!$('#hist-from').value) $('#hist-from').value = iso(now() - 36e5);
    if (!$('#hist-to').value) $('#hist-to').value = iso(now());
  }
  loadHistory();
};
['#hist-from', '#hist-to', '#hist-hl'].forEach(id => $(id).onchange = loadHistory);
$('#hist-q').oninput = debounce(loadHistory, 300);
$('#hist-go').onclick = loadHistory;
$('#hist-csv').onclick = async () => {
  const { from, to } = histRange();
  try { const p = await api.invoke('export_csv', { fromMs: from, toMs: to, search: $('#hist-q').value.trim() }); toast(`CSV saved<br><span class="dim">${esc(p)}</span>`, '', () => api.invoke('open_location', { path: p })); }
  catch (e) { toast('export failed: ' + esc(e), 'err'); }
};

/* ───────────────────────── sched ───────────────────────── */
function renderSched() {
  const U = S.upcoming, t = now(), q = $('#sch-q').value.trim().toLowerCase();
  const m = u => !q || (u.name + ' ' + u.path + ' ' + u.exe).toLowerCase().includes(q);
  const tasks = U.items.filter(u => u.kind === 'task' && m(u)).sort((a, b) => (a.next_ms ?? 9e15) - (b.next_ms ?? 9e15));
  $('#sch-meta').textContent = (U.scanning ? 'scanning… ' : '') + (U.scanned_ms ? `${tasks.length} tasks · scanned ${fmtTime(U.scanned_ms)}` : '') + (U.error ? ' · error: ' + U.error : '');
  const res = r => r == null ? '' : r === 0 ? '<span class="ok">ok</span>' : r === 267011 ? '<span class="dim">never ran</span>' : r === 267009 ? '<span class="acc">running</span>' : `<span class="err">0x${(r >>> 0).toString(16)}</span>`;
  $('#sch-tasks').innerHTML = tasks.map(u => {
    const d = u.next_ms ? u.next_ms - t : null;
    const off = u.state === 'Disabled';
    return `<tr title="${esc(u.path + u.name)}" class="${off ? 'off' : ''}"><td><span class="sw ${off ? '' : 'on'}" data-task="${esc(u.path + u.name)}"></span></td><td class="r ${d != null && d < 3e5 ? 'warn' : 'vio'}">${d == null ? '<span class="dim2">—</span>' : d <= 0 ? 'now' : fmtDur(d)}</td>` +
      `<td class="dim">${u.next_ms ? fmtDate(u.next_ms) : (u.info || '').includes('Logon') ? 'at logon' : (u.info || '').includes('Boot') ? 'at boot' : '·'}</td>` +
      `<td class="nm">${esc(u.name)} <span class="dim2">${esc(u.path)}</span></td><td class="dim">${esc(u.info)}</td>` +
      `<td>${u.last_ms ? `<span class="dim">${fmtDate(u.last_ms)}</span> ` : ''}${res(u.last_result)}</td><td class="path">${esc(u.exe)}</td></tr>`;
  }).join('') || `<tr><td colspan="7" class="empty">${U.scanning ? 'scanning task scheduler…' : 'no data'}</td></tr>`;
  $('#sch-svc').innerHTML = U.items.filter(u => u.kind === 'service' && m(u)).sort((a, b) => /pending/i.test(b.state) - /pending/i.test(a.state)).map(u =>
    `<tr><td class="${/pending/i.test(u.state) ? 'warn' : 'dim'}">${esc(u.state)}</td><td class="nm" title="${esc(u.name)}">${esc(u.path || u.name)}</td><td class="dim">${esc(u.info)}</td><td class="path">${esc(u.exe)}</td></tr>`).join('') || `<tr><td colspan="4" class="empty">—</td></tr>`;
}
$('#sch-q').oninput = debounce(renderSched, 120);
$('#sch-refresh').onclick = () => { api.invoke('refresh_upcoming'); S.upcoming.scanning = true; renderSched(); };

/* ───────────────────────── details drawer ───────────────────────── */
async function openDetails(sel) {
  S.sel = { pid: sel.pid, id: sel.id ?? S.procs.get(sel.pid)?.row_id };
  markSel();
  $('#drawer').classList.add('on');
  await renderDetails(sel.row);
}
function closeDetails() { $('#drawer').classList.remove('on'); S.sel = null; markSel(); }
function markSel() {
  $$('.ln.sel, tr.sel, .tn.sel').forEach(e => e.classList.remove('sel'));
  if (!S.sel) return;
  $$(`[data-pid="${S.sel.pid}"]`).forEach(e => { if (!e.dataset.id || +e.dataset.id === S.sel.id) e.classList.add('sel'); });
}
async function renderDetails(rowHint) {
  const sel = S.sel; if (!sel) return;
  const live = S.procs.get(sel.pid);
  const isLive = live && (!sel.id || live.row_id === sel.id);
  let row = rowHint;
  if (!row && sel.id) row = await api.invoke('get_row', { id: sel.id }).catch(() => null);
  const p = isLive ? live : null;
  const name = p?.name ?? row?.name ?? '?', exe = p?.exe || row?.exe || '', cmd = row?.cmd || p?.cmd || '';
  const start = p?.start_ms ?? row?.start_ms, end = isLive ? null : row?.end_ms;
  const ppid = p?.ppid ?? row?.ppid, parent = S.procs.get(ppid)?.name ?? row?.parent ?? '';
  const children = [...S.procs.values()].filter(c => c.ppid === sel.pid && isLive);
  const sig = p?.sig ?? row?.sig, signer = p?.signer || row?.signer || '';
  const flags = flagList(p ? p.flags : allFlags(row?.flags, sig, exe));
  const kv = (k, v) => `<span class="k">${k}</span><span class="v">${v}</span>`;
  const conns = isLive ? (S.snap?.conns || []).filter(c => c.pid === sel.pid) : [];
  let h = `<div class="dh"><span class="dot ${isLive ? 'on' : 'off'}"></span><span class="nm">${esc(name)}</span><span class="dim">[${sel.pid}]</span>${flagHtml(flags.join(','))}<button class="btn x" id="d-x">esc ✕</button></div><div class="db">`;
  h += `<div class="kvt">` +
    kv('status', isLive ? (p.suspended ? '<span class="cyan">⏸ suspended by Logd</span>' : `<span class="ok">running</span> <span class="dim">${esc(p.status)}</span>`) : end ? `<span class="err">exited</span> code=${row?.exit_code ?? '?'}` : '<span class="dim">unknown</span>') +
    kv('path', exe ? `<span class="code v">${esc(exe)}</span>` : '<span class="dim">access denied (system)</span>') +
    (exe ? kv('signature', sig === 'valid' ? `<span class="sig ok${p?.sig_os ? ' os' : ''}">✓</span> ${esc(signer)}` : sigBadge(sig, signer, false, exe)) : '') +
    kv('cmd', cmd ? `<span class="code v">${esc(cmd)}</span>` : '<span class="dim">—</span>') +
    kv('parent', ppid != null ? `<a data-goto="${ppid}">${esc(parent || '?')} [${ppid}]</a>` : '—') +
    kv('user', esc(p?.user || row?.user || '—')) +
    kv('started', start ? `${fmtDate(start)} <span class="dim">(${row?.existing ? 'already running when logd started' : row?.source === 'etw' ? 'caught by ETW' : 'caught by polling'})</span>` : '—') +
    kv(isLive ? 'running for' : 'lived', start ? fmtDur((end ?? now()) - start) : '—') +
    (p ? kv('cpu', `${cpuBar(p.cpu)}${p.cpu.toFixed(1)}%`) + kv('memory', `${fmtBytes(p.mem)} <span class="dim">· virt ${fmtBytes(p.vmem)}</span>`) + kv('disk', `↓${fmtBytes(p.dr)}/s ↑${fmtBytes(p.dw)}/s`) : '') +
    (row?.peak_mem ? kv('peak', `${fmtBytes(row.peak_mem)} · cpu ${row.peak_cpu.toFixed(1)}%`) : '') +
    `</div>`;
  if (flags.length) h += `<div class="sect"><b>flags</b></div>` + flags.map(f => `<div class="flagdesc">!${f} — ${FLAG_DESC[f] || f}</div>`).join('');
  h += `<div class="acts">` +
    (isLive ? `<button class="btn danger" id="d-kill">✕ kill</button>` : '') +
    (exe ? `<button class="btn" id="d-open">📂 folder</button>` : '') +
    (cmd || exe ? `<button class="btn" id="d-copy">⧉ copy cmd</button>` : '') +
    `<button class="btn" id="d-hist">⌕ in history</button></div>`;
  if (children.length) h += `<div class="sect"><b>children</b> ${children.length}</div>` + children.map(c => `<div class="nx"><span class="in dim">${c.pid}</span><span class="t"><a class="cyan" data-goto="${c.pid}" style="cursor:pointer">${esc(c.name)}</a><small>${fmtBytes(c.mem)}</small></span></div>`).join('');
  if (isLive) {
    const remote = conns.filter(isRemote), listen = conns.filter(c => c.state === 'LISTEN' || c.proto.startsWith('udp'));
    h += `<div class="sect"><b>network now</b> ${remote.length} connections · ${listen.length} open ports</div>` +
      (remote.map(c => `<div class="nx" style="grid-template-columns:96px 1fr"><span class="dim st-${c.state}">${c.state.toLowerCase()}</span><span class="t">→ ${fmtAddr(c.raddr, c.rport)} <span class="host">${esc(c.host)}</span></span></div>`).join('') +
        listen.slice(0, 12).map(c => `<div class="nx" style="grid-template-columns:96px 1fr"><span class="acc">${c.proto} listen</span><span class="t">${fmtAddr(c.laddr, c.lport)}</span></div>`).join('') ||
        '<div class="dim2" style="padding:0 8px">no sockets</div>');
  }
  h += `<div class="sect"><b>contacted hosts</b> <span id="d-nh">…</span></div><div id="d-nhl"></div>`;
  h += `<div class="sect"><b>launch history</b> <span id="d-eh">…</span></div><div id="d-ehl"></div></div>`;
  $('#drawer').innerHTML = h;
  $('#d-x').onclick = closeDetails;
  $$('#drawer [data-goto]').forEach(a => a.onclick = () => openDetails({ pid: +a.dataset.goto }));
  $('#d-kill') && ($('#d-kill').onclick = () => confirmKill(sel.pid, name));
  $('#d-open') && ($('#d-open').onclick = () => api.invoke('open_location', { path: exe }));
  $('#d-copy') && ($('#d-copy').onclick = () => { navigator.clipboard.writeText(cmd || exe); toast('copied'); });
  $('#d-hist').onclick = () => { $('#hist-q').value = name; setWs('hist'); };
  try {
    const eh = await api.invoke('exe_history', { exe, name, limit: 25 });
    if (S.sel !== sel) return;
    $('#d-eh').innerHTML = `${eh.launches} launches${eh.avg_life_ms ? ` · avg lifetime ${fmtDur(eh.avg_life_ms)}` : ''}${eh.first_ms ? ` · first seen ${fmtDate(eh.first_ms)}` : ''}`;
    $('#d-ehl').innerHTML = eh.rows.map(r => `<div class="nx" style="grid-template-columns:110px 1fr"><span class="dim">${fmtDate(r.start_ms)}</span><span class="t">${r.end_ms != null ? fmtDur(r.end_ms - r.start_ms) : '<span class="ok">alive</span>'} <small>pid ${r.pid} · code ${r.exit_code ?? '·'} · ← ${esc(r.parent)}</small></span></div>`).join('');
  } catch { $('#d-eh').textContent = ''; }
  try {
    const nh = await api.invoke('net_history', { exe, name, limit: 60 });
    if (S.sel !== sel) return;
    $('#d-nh').textContent = nh.length ? `${nh.length} endpoints` : 'none recorded';
    $('#d-nhl').innerHTML = nh.map(n => `<div class="nx" style="grid-template-columns:110px 1fr" title="first ${fmtDate(n.first_ms)} · last ${fmtDate(n.last_ms)} · ${n.runs} runs">` +
      `<span class="dim">${fmtDate(n.last_ms)}</span><span class="t">${fmtAddr(n.raddr, n.rport)} <span class="host">${esc(n.host)}</span><small>${n.runs > 1 ? n.runs + ' runs' : ''}</small></span></div>`).join('');
  } catch { $('#d-nh').textContent = ''; }
}

/* ───────────────────────── netstat ───────────────────────── */
let freshTick = 0;
function renderNet(force) {
  const all = S.snap?.conns || [], view = $('#net-view').value, pub = $('#net-pub').checked;
  const q = $('#net-q').value.trim().toLowerCase();
  const pname = pid => S.procs.get(pid)?.name || (pid === 0 ? 'idle' : pid === 4 ? 'System' : '?');
  let list = all.filter(c =>
    view === 'all' ? true : view === 'remote' ? isRemote(c) : view === 'listen' ? c.state === 'LISTEN' : c.proto.startsWith('udp'));
  if (pub) list = list.filter(c => c.public);
  if (q) list = list.filter(c => `${pname(c.pid)} ${c.pid} ${c.laddr}:${c.lport} ${c.raddr}:${c.rport} ${c.host} ${c.state}`.toLowerCase().includes(q));
  list.sort((a, b) => pname(a.pid).localeCompare(pname(b.pid)) || a.pid - b.pid || a.rport - b.rport);
  const t = now();
  $('#net-meta').textContent = `${list.length} shown · ${all.filter(isRemote).length} connections · ${all.filter(c => c.state === 'LISTEN').length} listening`;
  $('#net-body').innerHTML = list.slice(0, 1500).map(c => {
    const p = S.procs.get(c.pid);
    return `<tr data-pid="${c.pid}" class="${S.sel?.pid === c.pid ? 'sel' : ''} ${p?.flags && !onlySelf(p.flags) ? 'flagged' : ''}">` +
      `<td class="dim">${c.proto}</td><td class="nm">${esc(pname(c.pid))}</td><td class="r dim">${c.pid}</td><td class="dim">${fmtAddr(c.laddr, c.lport)}</td>` +
      `<td>${c.raddr === '*' ? '<span class="dim2">*</span>' : fmtAddr(c.raddr, c.rport)}</td><td class="host">${esc(c.host)}</td>` +
      `<td class="st-${c.state}">${c.state || '·'}</td><td class="r dim">${fmtDur(t - c.first_ms)}</td>` +
      `<td>${p?.exe ? sigBadge(p.sig, p.signer, p.sig_os, p.exe) : ''}</td></tr>`;
  }).join('') || `<tr><td colspan="9" class="empty">no matching sockets</td></tr>`;
  const lis = all.filter(c => c.state === 'LISTEN' || (c.proto.startsWith('udp'))).sort((a, b) => a.lport - b.lport);
  const exposed = c => /^(0\.0\.0\.0|::)$/.test(c.laddr);
  $('#lis-meta').textContent = `${lis.filter(exposed).length} on all interfaces`;
  $('#lis-body').innerHTML = lis.map(c => `<tr data-pid="${c.pid}"><td class="dim">${c.proto}</td><td class="r ${exposed(c) ? 'warn' : ''}">${fmtPort(c.lport)}</td>` +
    `<td class="dim">${esc(c.laddr)}</td><td class="nm">${esc(pname(c.pid))} <span class="dim">[${c.pid}]</span></td></tr>`).join('');
  if (force || ++freshTick % 10 === 0) loadFresh();
}
async function loadFresh() {
  try {
    const rows = await api.invoke('net_recent', { onlyNovel: true, limit: 200 });
    $('#fresh').innerHTML = rows.map(n => `<div class="nx" style="grid-template-columns:110px 1fr" title="${esc(n.exe)}">` +
      `<span class="dim">${fmtDate(n.first_ms)}</span><span class="t"><span class="nm">${esc(n.name)}</span> → ${fmtAddr(n.raddr, n.rport)} <span class="host">${esc(n.host)}</span></span></div>`).join('')
      || '<div class="empty">nothing yet — new hosts appear here</div>';
  } catch (e) { $('#fresh').textContent = 'error: ' + e; }
}
$('#net-view').onchange = () => renderNet(false);
$('#net-pub').onchange = () => renderNet(false);
$('#net-q').oninput = debounce(() => renderNet(false), 120);

/* ───────────────────────── modal ───────────────────────── */
function modal(title, body, buttons) {
  const m = $('#modal');
  m.innerHTML = `<div class="mbox"><div class="mh">${title}</div><div class="mc">${body}</div><div class="mf">${buttons.map((b, i) => `<button class="btn ${b.cls || ''}" data-i="${i}">${b.label}</button>`).join('')}</div></div>`;
  m.classList.add('on');
  $$('.mf button', m).forEach(b => b.onclick = () => { const r = buttons[+b.dataset.i].onClick?.(); if (r !== false) closeModal(); });
  m.onclick = e => { if (e.target === m) closeModal(); };
  setTimeout(() => (m.querySelector('input,select') || m.querySelector('.mf button:last-child'))?.focus(), 30);
}
function closeModal() { $('#modal').classList.remove('on'); }
function confirmKill(pid, name) {
  modal('kill', `<div class="prompt">$ taskkill /F /PID ${pid}</div><div>Terminate <b>${esc(name)}</b>[${pid}]? Any unsaved data in that process will be lost.</div>`, [
    { label: 'cancel' },
    { label: 'kill -9', cls: 'danger', onClick: async () => { try { await api.invoke('kill_process', { pid }); toast(`${esc(name)}[${pid}] terminated`); } catch (e) { toast('failed: ' + esc(e), 'err'); } } },
  ]);
}
async function openSettings() {
  const st = await api.invoke('get_settings');
  const auto = await api.invoke('get_autostart').catch(() => 'off');
  const i = S.info || {};
  modal('⚙ settings', `
    <div class="row"><span>theme</span><select id="s-theme">${Object.entries(THEMES).map(([k, l]) => `<option value="${k}" ${k === document.documentElement.dataset.theme ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
    <div class="row"><span>window opacity</span><span style="display:flex;gap:8px;align-items:center"><input type="range" id="s-alpha" min="0.35" max="1" step="0.01" value="${store.get('alpha', .78)}" style="flex:1;height:auto;accent-color:var(--acc)"><span id="s-alpha-v" class="dim"></span></span></div>
    <div class="row"><span>poll interval</span><select id="s-int">${[250, 500, 1000, 2000, 5000].map(v => `<option value="${v}" ${v === st.interval_ms ? 'selected' : ''}>${v} ms</option>`).join('')}</select></div>
    <div class="row"><span>keep history</span><select id="s-ret">${[1, 7, 30, 90, 365].map(v => `<option value="${v}" ${v === st.retention_days ? 'selected' : ''}>${v} days</option>`).join('')}</select></div>
    <div class="row"><span>Windows notifications</span><span><label class="tg" style="display:inline-flex"><input type="checkbox" id="s-notify" ${st.notify_os ? 'checked' : ''}><span>for rule alerts</span></label> <button class="btn" id="s-test">test</button></span></div>
    <div class="row"><span>start with Windows</span><select id="s-auto">
      <option value="off" ${auto === 'off' ? 'selected' : ''}>off</option>
      <option value="user" ${auto === 'user' ? 'selected' : ''}>at logon, in the tray</option>
      <option value="admin" ${auto === 'admin' ? 'selected' : ''}>at logon as admin (ETW)${i.admin ? '' : ' — needs admin'}</option>
    </select></div>
    <div class="row"><span>panel layout</span><span><button class="btn" id="s-layout">reset all layouts</button> <span class="dim2">drag titles to move · Shift = float</span></span></div>
    <div class="row"><span>hide own processes</span><label class="tg"><input type="checkbox" id="s-self" ${S.hideSelf ? 'checked' : ''}><span>logd powershell scanner</span></label></div>
    <div class="row"><span>mode</span><span>${i.admin ? '<span class="ok">administrator · ETW</span>' : `<span class="warn">user · polling</span> <button class="btn" id="s-admin">restart as admin</button>`}${i.etw_error && i.admin ? `<br><span class="err">${esc(i.etw_error)}</span>` : ''}</span></div>
    <div class="row"><span>history db</span><span class="dim" style="word-break:break-all">${esc(i.db_path || '')}</span></div>
    <div class="row"><span>version</span><span class="dim">logd ${esc(i.version || '')}</span></div>`, [
    { label: 'quit logd', cls: 'danger', onClick: () => api.invoke('quit_app') },
    { label: 'cancel' },
    {
      label: 'save', onClick: async () => {
        await api.invoke('set_settings', { settings: { interval_ms: +$('#s-int').value, retention_days: +$('#s-ret').value, notify_os: $('#s-notify').checked } });
        S.settings = await api.invoke('get_settings');
        const mode = $('#s-auto').value;
        if (mode !== auto) {
          try { await api.invoke('set_autostart', { mode }); toast(`start with Windows: ${mode}`); } catch (e) { toast('autostart: ' + esc(e), 'err'); }
        }
        S.hideSelf = $('#s-self').checked; store.set('hideSelf', S.hideSelf);
        rebuildFullLog();
      },
    },
  ]);
  $('#s-admin') && ($('#s-admin').onclick = () => api.invoke('restart_admin').catch(e => toast(esc(e), 'err')));
  $('#s-test').onclick = () => api.invoke('test_toast');
  // theme and opacity preview live; they are kept even if the dialog is cancelled
  const preview = () => {
    const a = +$('#s-alpha').value;
    $('#s-alpha-v').textContent = Math.round(a * 100) + '%';
    applyTheme($('#s-theme').value, a);
    store.set('theme', $('#s-theme').value); store.set('alpha', a);
    renderActive(true);
  };
  $('#s-theme').onchange = preview; $('#s-alpha').oninput = preview;
  $('#s-alpha-v').textContent = Math.round(+$('#s-alpha').value * 100) + '%';
  $('#s-layout').onclick = () => { Layout.resetAll(); toast('layouts reset'); };
}
$('#b-cfg').onclick = openSettings;

/* ───────────────────────── clicks & keys ───────────────────────── */
document.addEventListener('click', e => {
  if (e.target.closest('#drawer, #modal, #tree-q, .tools')) return;
  const el = e.target.closest('[data-pid]'); if (!el) return;
  openDetails({ pid: +el.dataset.pid, id: el.dataset.id ? +el.dataset.id : undefined });
});
document.addEventListener('keydown', e => {
  const typing = /INPUT|SELECT|TEXTAREA/.test(document.activeElement?.tagName);
  if (e.key === 'Escape') {
    if ($('#modal').classList.contains('on')) return closeModal();
    if (typing) return document.activeElement.blur();
    if ($('#drawer').classList.contains('on')) return closeDetails();
    const lay = Layout.get('ws-' + S.ws);
    if (lay?.max) return lay.toggleMax(lay.max);
    return;
  }
  if (typing || $('#modal').classList.contains('on')) return;
  const n = '12345678'.indexOf(e.key);
  if (n >= 0 && !e.ctrlKey && !e.altKey) return setWs(['dash', 'log', 'ps', 'tree', 'net', 'hist', 'sched', 'rules'][n]);
  if (e.key === '/') {
    e.preventDefault();
    const q = { log: '#log-q', ps: '#ps-q', tree: '#tree-q', net: '#net-q', hist: '#hist-q', sched: '#sch-q' }[S.ws];
    if (q) $(q).focus();
  }
  if (e.key === ' ') { e.preventDefault(); setPaused(!S.paused); }
  if (e.key === 'k' && S.sel && S.procs.has(S.sel.pid)) confirmKill(S.sel.pid, S.procs.get(S.sel.pid).name);
  if (e.key === 'r' && S.ws === 'hist') loadHistory();
});

/* window controls */
$('#b-min').onclick = () => api.win?.minimize();
$('#b-max').onclick = () => api.win?.toggleMaximize();
$('#b-close').onclick = () => { api.win?.hide(); };
$('#bar').addEventListener('dblclick', e => { if (e.target.closest('[data-tauri-drag-region]') === e.target) api.win?.toggleMaximize(); });

/* ───────────────────────── boot ───────────────────────── */
function onSnapshot(s) {
  S.snap = s;
  for (const p of s.procs) p.flags = allFlags(p.flags, p.sig, p.exe);
  S.procs = new Map(s.procs.map(p => [p.pid, p]));
  pushHist(s);
  renderBar();
  renderActive(false);
  if (S.sel && $('#drawer').classList.contains('on') && S.procs.has(S.sel.pid) && ++drawerTick % 2 === 0) {
    // light refresh of live numbers without refetching history
    const p = S.procs.get(S.sel.pid);
    const cpuEl = [...$$('#drawer .kvt .k')].find(k => k.textContent === 'cpu');
    if (cpuEl) cpuEl.nextElementSibling.innerHTML = `${cpuBar(p.cpu)}${p.cpu.toFixed(1)}%`;
  }
}
let drawerTick = 0;

/* ───────────────────────── rules & alerts ───────────────────────── */
const WHEN = { spawn: 'process starts', net: 'first contact with a host', sig: 'signature checked' };
function ruleSummary(r) {
  const parts = [];
  if (r.flag) parts.push(`flag <b>${esc(r.flag)}</b>`);
  if (r.proc) parts.push(`name ~ <b>${esc(r.proc)}</b>`);
  if (r.path) parts.push(`path ~ <b>${esc(r.path)}</b>`);
  if (r.parent) parts.push(`parent ~ <b>${esc(r.parent)}</b>`);
  if (r.remote) parts.push(`host ~ <b>${esc(r.remote)}</b>`);
  if (r.port) parts.push(`port <b>${esc(r.port)}</b>`);
  return parts.join(' · ') || '<span class="dim">anything</span>';
}
function renderRules() {
  $('#rules-meta').textContent = `${S.rules.filter(r => r.enabled).length} of ${S.rules.length} enabled`;
  $('#rules-body').innerHTML = S.rules.map((r, i) => `<tr class="${r.enabled ? '' : 'off'}" data-rule="${i}">` +
    `<td><input type="checkbox" data-toggle="${i}" ${r.enabled ? 'checked' : ''}></td><td class="nm">${esc(r.name)}</td>` +
    `<td class="dim">${WHEN[r.on] || r.on}</td><td>${ruleSummary(r)}</td><td><span class="act act-${r.action}">${r.action}</span></td>` +
    `<td class="r"><button class="btn" data-edit="${i}">edit</button> <button class="btn danger" data-del="${i}">✕</button></td></tr>`).join('')
    || '<tr><td colspan="6" class="empty">no rules</td></tr>';
}
async function saveRules() {
  try { await api.invoke('set_rules', { rules: S.rules }); } catch (e) { toast('could not save rules: ' + esc(e), 'err'); }
  renderRules();
}
$('#rules-body').addEventListener('click', e => {
  const t = e.target;
  if (t.dataset.toggle != null) { S.rules[+t.dataset.toggle].enabled = t.checked; saveRules(); }
  else if (t.dataset.edit != null) editRule(+t.dataset.edit);
  else if (t.dataset.del != null) {
    const r = S.rules[+t.dataset.del];
    modal('delete rule', `<div>Delete rule <b>${esc(r.name)}</b>?</div>`, [{ label: 'cancel' }, { label: 'delete', cls: 'danger', onClick: () => { S.rules.splice(+t.dataset.del, 1); saveRules(); } }]);
  }
});
function editRule(i) {
  const isNew = i == null;
  const r = isNew ? { id: 'r' + Date.now().toString(36), enabled: true, name: '', on: 'spawn', proc: '', path: '', parent: '', flag: '', remote: '', port: '', action: 'notify' } : { ...S.rules[i] };
  const sel = (id, opts, v) => `<select id="${id}">${Object.entries(opts).map(([k, l]) => `<option value="${k}" ${k === v ? 'selected' : ''}>${l}</option>`).join('')}</select>`;
  const inp = (id, v, ph) => `<input id="${id}" value="${esc(v)}" placeholder="${ph}" spellcheck="false">`;
  modal(isNew ? '+ new rule' : 'edit rule', `
    <div class="row"><span>name</span>${inp('r-name', r.name, 'e.g. Block crypto miner')}</div>
    <div class="row"><span>when</span>${sel('r-on', WHEN, r.on)}</div>
    <div class="row"><span>process name</span>${inp('r-proc', r.proc, 'any — e.g. chrome|firefox')}</div>
    <div class="row"><span>path</span>${inp('r-path', r.path, 'any — e.g. *\\appdata\\*')}</div>
    <div class="row"><span>parent</span>${inp('r-parent', r.parent, 'any — e.g. winword.exe')}</div>
    <div class="row"><span>flag</span>${inp('r-flag', r.flag, 'any | unsigned | bad-sig | temp …')}</div>
    <div class="row r-net"><span>host / ip</span>${inp('r-remote', r.remote, 'any — e.g. *.ru|45.*')}</div>
    <div class="row r-net"><span>port</span>${inp('r-port', r.port, 'any — e.g. 4444|6667')}</div>
    <div class="row"><span>then</span>${sel('r-action', { notify: 'notify me', log: 'only log an alert', kill: 'kill the process' }, r.action)}</div>
    <div class="dim2">Empty fields match anything. <code>chrome</code> = contains, <code>*</code> <code>?</code> wildcards, <code>a|b</code> either. Kill never touches core Windows processes.</div>`, [
    { label: 'cancel' },
    {
      label: 'save', onClick: () => {
        const v = id => $('#' + id).value.trim();
        Object.assign(r, { name: v('r-name') || 'Untitled rule', on: v('r-on'), proc: v('r-proc'), path: v('r-path'), parent: v('r-parent'), flag: v('r-flag'), remote: v('r-remote'), port: v('r-port'), action: v('r-action') });
        if (isNew) S.rules.push(r); else S.rules[i] = r;
        saveRules();
      },
    },
  ]);
  $('.mbox').classList.add('wide');
  const sync = () => $$('.r-net').forEach(x => x.classList.toggle('hide', $('#r-on').value !== 'net'));
  $('#r-on').onchange = sync; sync();
}
$('#rule-add').onclick = () => editRule(null);
$('#rule-defaults').onclick = () => modal('restore default rules', '<div>Replace all rules with the built-in set?</div>', [
  { label: 'cancel' }, { label: 'restore', cls: 'danger', onClick: async () => { S.rules = await api.invoke('default_rules'); saveRules(); } }]);

function alertHtml(a) {
  const pid = a.pid != null ? `<span class="pid">[${a.pid}]</span>` : '';
  return `<div class="ln ${a.action === 'kill' ? 'ln-stop' : 'ln-start'}" ${a.pid != null ? `data-pid="${a.pid}"` : ''} title="${esc(a.exe)}">` +
    `<span class="ts">${fmtDate(a.ts)}</span><span class="act act-${a.action}">${a.action}</span> <span class="acc">${esc(a.rule)}</span> ` +
    `<span class="nm">${esc(a.name)}</span>${pid} <span class="cmd">${esc(a.detail)}</span>${a.result ? ` <span class="${a.result === 'killed' ? 'err' : 'warn'}">${esc(a.result)}</span>` : ''}</div>`;
}
function renderAlerts() {
  const q = $('#alerts-q').value.trim().toLowerCase();
  const list = S.alerts.filter(a => !q || `${a.rule} ${a.name} ${a.exe} ${a.detail}`.toLowerCase().includes(q));
  $('#alerts-meta').textContent = `${S.alerts.length} total`;
  $('#alerts').innerHTML = list.map(alertHtml).join('') || '<div class="empty">no alerts — rules will report here</div>';
}
function setUnread(n) {
  S.unread = n;
  $('#alert-badge').textContent = n > 99 ? '99+' : n;
  $('#alert-badge').classList.toggle('hide', !n);
}
function onAlert(a) {
  S.alerts.unshift(a);
  if (S.alerts.length > 1000) S.alerts.length = 1000;
  if (S.ws === 'rules') renderAlerts(); else setUnread(S.unread + 1);
  // the backend sends a Windows toast when the window is not in front
  if (document.hasFocus()) {
    toast(`<span class="${a.action === 'kill' ? 'err' : 'warn'}">⚠ ${esc(a.rule)}</span>${a.result ? ` <span class="dim">— ${esc(a.result)}</span>` : ''}<br><b>${esc(a.name)}</b>${a.pid != null ? `[${a.pid}]` : ''}<br><span class="dim">${esc(a.detail)}</span>`,
      a.action === 'kill' ? 'err' : 'warn', () => a.pid != null && openDetails({ pid: a.pid }));
  }
}
$('#alerts-q').oninput = debounce(renderAlerts, 120);
$('#alerts-clear').onclick = () => modal('clear alerts', '<div>Delete all recorded alerts?</div>', [
  { label: 'cancel' }, { label: 'clear', cls: 'danger', onClick: async () => { await api.invoke('clear_alerts'); S.alerts = []; renderAlerts(); } }]);

/* ───────────────────────── autoruns ───────────────────────── */
const AR_KIND = { run: 'registry', folder: 'startup folder', task: 'logon task', service: 'service', winlogon: 'winlogon', ifeo: 'IFEO debugger', appinit: 'AppInit DLL', wmi: 'WMI' };
S.autoruns = null;
let arLoading = false;
async function loadAutoruns() {
  if (arLoading) return;
  arLoading = true; $('#ar-meta').textContent = 'scanning…';
  try { S.autoruns = await api.invoke('autoruns_list'); } catch (e) { toast('autoruns scan failed: ' + esc(e), 'err'); S.autoruns = S.autoruns || []; }
  arLoading = false; renderAutoruns();
}
const arId = a => `${a.kind}|${a.hive}|${a.key}|${a.value}|${a.backup_id ?? ''}`;
function renderAutoruns() {
  if (!S.autoruns) { if (S.ws === 'sched') loadAutoruns(); return; }
  const kind = $('#ar-kind').value, hideMs = $('#ar-ms').checked, q = $('#ar-q').value.trim().toLowerCase();
  const list = S.autoruns.filter(a =>
    (!hideMs || !a.ms) &&
    (!kind || (kind === 'startup' ? ['run', 'folder'].includes(a.kind) : kind === 'hidden' ? a.hidden : kind === 'off' ? !a.enabled : a.kind === kind)) &&
    (!q || `${a.name} ${a.command} ${a.location}`.toLowerCase().includes(q)))
    .sort((a, b) => (b.hidden - a.hidden) || (b.enabled - a.enabled) || a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name));
  const on = S.autoruns.filter(a => a.enabled && !a.ms).length, hid = S.autoruns.filter(a => a.hidden && a.enabled && !a.ms).length;
  $('#ar-meta').textContent = arLoading ? 'scanning…' : `${on} active · ${hid} hidden · ${list.length} shown`;
  $('#ar-body').innerHTML = list.map(a => {
    const risky = RISKY_DIR.test(a.command) && !/\\(appdata\\local\\microsoft|program files)/i.test(a.command);
    return `<tr class="${a.enabled ? '' : 'off'}" title="${esc(a.command)}"><td><span class="sw ${a.enabled ? 'on' : ''}" data-ar="${esc(arId(a))}"></span></td>` +
      `<td class="dim">${AR_KIND[a.kind] || a.kind}</td>` +
      `<td class="nm">${esc(a.name)}${a.hidden ? '<span class="tag hid">hidden</span>' : ''}${a.ms ? '<span class="tag">windows</span>' : ''}${a.kind === 'winlogon' || a.kind === 'ifeo' || a.kind === 'wmi' ? '<span class="tag risk">persistence</span>' : ''}${risky ? '<span class="tag risk">user folder</span>' : ''}</td>` +
      `<td class="path">${esc(a.command)}</td><td class="dim">${esc(a.hive ? a.hive + ' ' : '')}${esc(a.location)}</td></tr>`;
  }).join('') || `<tr><td colspan="5" class="empty">${arLoading ? 'scanning…' : 'nothing here'}</td></tr>`;
}
async function setAutorun(a, enable) {
  const go = async () => {
    try {
      await api.invoke('autorun_set', { item: a, enable });
      toast(`${enable ? 'enabled' : 'disabled'}: ${esc(a.name)}`);
      if (a.backup_id != null || ['service', 'winlogon', 'ifeo', 'appinit', 'wmi'].includes(a.kind) || (a.kind === 'run' && !a.approved)) loadAutoruns();
      else { a.enabled = enable; renderAutoruns(); }
    } catch (e) { toast(`could not ${enable ? 'enable' : 'disable'} ${esc(a.name)}: ${esc(e)}`, 'err'); renderAutoruns(); }
  };
  // entries that are changed by editing system state get a confirmation
  const warn = !enable && {
    service: 'The service will not start with Windows any more. Disabling a service a program relies on can break that program.',
    winlogon: 'This resets a Winlogon value to the Windows default. The current value is saved and can be restored.',
    ifeo: 'This removes the debugger hijack for this program. The value is saved and can be restored.',
    appinit: 'This clears AppInit_DLLs. The value is saved and can be restored.',
    wmi: 'This permanently deletes the WMI subscription. It cannot be restored.',
  }[a.kind];
  if (warn) modal(`disable ${esc(a.name)}`, `<div>${warn}</div><div class="dim">${esc(a.command)}</div>`, [{ label: 'cancel', onClick: renderAutoruns }, { label: 'disable', cls: 'danger', onClick: go }]);
  else go();
}
$('#ar-body').addEventListener('click', e => {
  const sw = e.target.closest('.sw[data-ar]'); if (!sw) return;
  const a = S.autoruns.find(x => arId(x) === sw.dataset.ar); if (!a) return;
  sw.classList.add('busy');
  setAutorun(a, !a.enabled);
});
$('#sch-tasks').addEventListener('click', async e => {
  const sw = e.target.closest('.sw[data-task]'); if (!sw) return;
  const u = S.upcoming.items.find(x => x.kind === 'task' && x.path + x.name === sw.dataset.task); if (!u) return;
  const enable = u.state === 'Disabled';
  sw.classList.add('busy');
  try { await api.invoke('autorun_set', { item: { kind: 'task', key: u.path + u.name, name: u.name }, enable }); u.state = enable ? 'Ready' : 'Disabled'; toast(`${enable ? 'enabled' : 'disabled'} task ${esc(u.name)}`); }
  catch (err) { toast('could not change task: ' + esc(err), 'err'); }
  renderSched();
});
['#ar-kind', '#ar-ms'].forEach(id => $(id).onchange = renderAutoruns);
$('#ar-q').oninput = debounce(renderAutoruns, 120);
$('#ar-scan').onclick = loadAutoruns;

/* ───────────────────────── right-click menu ───────────────────────── */
const CRITICAL = ['system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe', 'dwm.exe', 'fontdrvhost.exe', 'memory compression', 'logd.exe'];
function descendants(pid) {
  const out = [], seen = new Set([pid]), stack = [pid];
  while (stack.length) {
    const cur = stack.pop();
    for (const p of S.procs.values()) if (p.ppid === cur && !seen.has(p.pid) && p.start_ms >= (S.procs.get(cur)?.start_ms ?? 0) - 1000) { seen.add(p.pid); out.push(p); stack.push(p.pid); }
  }
  return out;
}
function closeCtx() { $('#ctx').classList.remove('on'); }
function openCtx(x, y, pid, rowId) {
  const p = S.procs.get(pid);
  const name = p?.name || S.events.find(e => e.row.pid === pid)?.row.name || `pid ${pid}`;
  const exe = p?.exe || '';
  const critical = pid <= 4 || CRITICAL.includes(name.toLowerCase());
  const kids = p ? descendants(pid) : [];
  const autos = exe && S.autoruns ? S.autoruns.filter(a => a.enabled && a.command.toLowerCase().includes(exe.toLowerCase())) : [];
  const items = [
    ['ⓘ', 'Details', () => openDetails({ pid, id: rowId })],
    'sep',
    p?.suspended
      ? ['▶', 'Resume process', () => suspendProc(pid, name, true)]
      : ['⏸', 'Suspend process (freeze)', () => suspendProc(pid, name, false), !p || critical],
    ['✕', 'Kill process', () => confirmKill(pid, name), !p || critical, 'danger'],
    ['⨯', `Kill process tree${kids.length ? ` (${kids.length + 1})` : ''}`, () => confirmKillTree(pid, name, kids), !p || critical || !kids.length, 'danger'],
    ['⛔', 'Block from starting (rule)', () => blockProc(name, exe), !exe || critical],
    autos.length ? ['⏻', `Disable autostart (${autos.length})`, () => autos.forEach(a => setAutorun(a, false))] : null,
    'sep',
    ['📂', 'Open file location', () => api.invoke('open_location', { path: exe }), !exe],
    ['⧉', 'Copy path', () => { navigator.clipboard.writeText(exe); toast('copied'); }, !exe],
    ['⧉', 'Copy command line', () => { navigator.clipboard.writeText(p?.cmd || exe); toast('copied'); }, !p?.cmd],
    ['⌕', 'Show in history', () => { $('#hist-q').value = name; setWs('hist'); }],
  ].filter(Boolean);
  const m = $('#ctx');
  m.innerHTML = `<div class="ch">${esc(name)} <span class="dim">[${pid}]</span>${p?.suspended ? '<span class="frozen">⏸ suspended</span>' : ''}${critical ? ' <span class="dim2">· system</span>' : ''}</div>` +
    items.map((it, i) => it === 'sep' ? '<div class="sep"></div>' : `<div class="ci ${it[3] ? 'off' : ''} ${it[4] || ''}" data-i="${i}"><i>${it[0]}</i>${it[1]}</div>`).join('');
  m.querySelectorAll('.ci').forEach(el => el.onclick = () => { closeCtx(); items[+el.dataset.i][2](); });
  m.classList.add('on');
  m.style.left = Math.min(x, innerWidth - m.offsetWidth - 6) + 'px';
  m.style.top = Math.min(y, innerHeight - m.offsetHeight - 6) + 'px';
}
async function suspendProc(pid, name, resume) {
  try { await api.invoke('suspend_process', { pid, resume }); toast(`${esc(name)}[${pid}] ${resume ? 'resumed' : 'suspended — it uses no CPU until resumed'}`); }
  catch (e) { toast(`could not ${resume ? 'resume' : 'suspend'}: ${esc(e)}`, 'err'); }
}
function confirmKillTree(pid, name, kids) {
  modal('kill tree', `<div>Terminate <b>${esc(name)}</b>[${pid}] and ${kids.length} child process${kids.length === 1 ? '' : 'es'}?</div><div class="dim">${kids.slice(0, 12).map(k => esc(k.name)).join(', ')}${kids.length > 12 ? '…' : ''}</div>`, [
    { label: 'cancel' },
    {
      label: 'kill all', cls: 'danger', onClick: async () => {
        let ok = 0;
        for (const k of [...kids].reverse().concat([{ pid }])) { try { await api.invoke('kill_process', { pid: k.pid }); ok++; } catch { } }
        toast(`terminated ${ok} of ${kids.length + 1}`);
      },
    },
  ]);
}
function blockProc(name, exe) {
  modal('block from starting', `<div>Add a rule that kills <b>${esc(name)}</b> every time it starts?</div><div class="dim">${esc(exe)}</div><div class="dim2">You can turn it off later on the rules tab.</div>`, [
    { label: 'cancel' },
    {
      label: 'block', cls: 'danger', onClick: () => {
        S.rules.push({ id: 'b' + Date.now().toString(36), enabled: true, name: `Block ${name}`, on: 'spawn', proc: '', path: exe, parent: '', flag: '', remote: '', port: '', action: 'kill' });
        saveRules(); toast(`${esc(name)} will be killed on start`);
      },
    },
  ]);
}
document.addEventListener('contextmenu', e => {
  if (e.target.closest('input, textarea')) return;
  e.preventDefault();
  const el = e.target.closest('[data-pid]');
  if (el && !e.target.closest('#modal')) openCtx(e.clientX, e.clientY, +el.dataset.pid, el.dataset.id ? +el.dataset.id : undefined);
  else closeCtx();
});
document.addEventListener('pointerdown', e => { if (!e.target.closest('#ctx')) closeCtx(); }, true);
addEventListener('blur', closeCtx);

/* ───────────────────────── layouts ───────────────────────── */
const DOCK = {
  dash: { d: 'col', s: [74, 26], c: [{ d: 'row', s: [25, 48, 27], c: [{ d: 'col', s: [38, 62], c: ['fetch', 'graphs'] }, 'log', { d: 'col', s: [60, 40], c: ['top', 'next'] }] }, 'tl'] },
  net: { d: 'row', s: [70, 30], c: ['conns', { d: 'col', s: [50, 50], c: ['listen', 'fresh'] }] },
  sched: { d: 'col', s: [46, 54], c: [{ d: 'row', s: [64, 36], c: ['tasks', 'svc'] }, 'autoruns'] },
  rules: { d: 'row', s: [52, 48], c: ['rules', 'alerts'] },
};
let relayoutRaf = 0;
const relayout = () => { if (!relayoutRaf) relayoutRaf = requestAnimationFrame(() => { relayoutRaf = 0; renderActive(true); }); };
for (const [ws, tree] of Object.entries(DOCK)) Layout.init($('#ws-' + ws), tree, relayout);

async function boot() {
  setWs(S.ws);
  S.info = await api.invoke('get_info');
  S.settings = await api.invoke('get_settings');
  if (S.info.db_note) toast(`⚠ ${esc(S.info.db_note)}`, 'warn');
  const snap = await api.invoke('get_snapshot');
  if (snap?.procs?.length) onSnapshot(snap);
  const evs = await api.invoke('recent_events', { sinceMs: now() - 30 * 60e3, limit: 1500 });
  addEvents(evs, false);
  const rec = await api.invoke('query_history', { fromMs: now() - 16 * 60e3, toMs: now(), search: '', limit: 800, hideLong: true });
  rec.forEach(r => S.recent.set(r.id, r));
  S.upcoming = await api.invoke('get_upcoming');
  await api.listen('snapshot', onSnapshot);
  await api.listen('proc-events', evs => addEvents(evs, true));
  await api.listen('upcoming', u => { S.upcoming = u; if (S.ws === 'sched') renderSched(); if (S.ws === 'dash') renderNext(); });
  S.rules = await api.invoke('get_rules');
  S.alerts = await api.invoke('get_alerts', { limit: 500 });
  renderRules(); renderAlerts();
  await api.listen('alert', onAlert);
  // the right-click menu needs it to offer "disable autostart"
  setTimeout(() => { if (!S.autoruns) loadAutoruns(); }, 5000);
  await api.listen('open-proc', pid => openDetails({ pid }));
  setInterval(() => { S.info && api.invoke('get_info').then(i => S.info = i); }, 30e3);
  addEventListener('resize', debounce(() => renderActive(true), 80));
}
boot().catch(e => { console.error(e); toast('startup error: ' + esc(e), 'err'); });
