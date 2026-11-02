// Fake backend so the UI can be previewed in a plain browser. Unused inside the app.
(() => {
  if (window.__TAURI__) return;
  const rnd = (a, b) => a + Math.random() * (b - a);
  const pick = a => a[Math.floor(Math.random() * a.length)];
  const T = () => Date.now();
  const W = 'C:\\Windows\\System32\\';
  const base = [
    ['System', '', 4, null], ['smss.exe', W, 412, 4], ['csrss.exe', W, 620, 600], ['wininit.exe', W, 700, 600],
    ['services.exe', W, 812, 700], ['lsass.exe', W, 830, 700], ['svchost.exe', W, 1004, 812], ['svchost.exe', W, 1180, 812],
    ['svchost.exe', W, 1320, 812], ['explorer.exe', 'C:\\Windows\\', 5120, 4980], ['dwm.exe', W, 1500, 700],
    ['chrome.exe', 'C:\\Program Files\\Google\\Chrome\\Application\\', 8812, 5120], ['chrome.exe', 'C:\\Program Files\\Google\\Chrome\\Application\\', 8840, 8812],
    ['chrome.exe', 'C:\\Program Files\\Google\\Chrome\\Application\\', 8866, 8812], ['Code.exe', 'C:\\Users\\me\\AppData\\Local\\Programs\\Microsoft VS Code\\', 9300, 5120],
    ['Discord.exe', 'C:\\Users\\me\\AppData\\Local\\Discord\\app-1.0\\', 7710, 5120], ['Telegram.exe', 'C:\\Users\\me\\AppData\\Roaming\\Telegram Desktop\\', 7020, 5120],
    ['WindowsTerminal.exe', 'C:\\Program Files\\WindowsApps\\Terminal\\', 6600, 5120], ['pwsh.exe', 'C:\\Program Files\\PowerShell\\7\\', 6610, 6600],
    ['MsMpEng.exe', 'C:\\ProgramData\\Microsoft\\Windows Defender\\', 3300, 812], ['spoolsv.exe', W, 2210, 812], ['SearchHost.exe', W, 5600, 1004],
    ['steam.exe', 'C:\\Program Files (x86)\\Steam\\', 4420, 5120], ['nvcontainer.exe', 'C:\\Program Files\\NVIDIA Corporation\\', 2800, 812],
  ];
  const boot = T() - 3.4 * 864e5;
  const procs = new Map(base.map(([name, dir, pid, ppid], i) => [pid, {
    pid, ppid, name, exe: dir ? dir + name : '', cmd: dir ? `"${dir}${name}"` : '', user: pid < 4000 ? 'SYSTEM' : 'me',
    cpu: 0, mem: rnd(5e6, 6e8), vmem: rnd(1e8, 2e9), dr: 0, dw: 0, start_ms: pid < 3000 ? boot : T() - rnd(1e6, 2e8), status: 'Run', flags: '', row_id: i + 1,
  }]));
  let id = 1000;
  const rows = [];
  const spawnables = [['conhost.exe', W], ['cmd.exe', W], ['git.exe', 'C:\\Program Files\\Git\\cmd\\'], ['node.exe', 'C:\\Program Files\\nodejs\\'],
    ['rg.exe', 'C:\\Users\\me\\.cargo\\bin\\'], ['SearchProtocolHost.exe', W], ['WmiPrvSE.exe', W + 'wbem\\'], ['setup_x64.exe', 'C:\\Users\\me\\AppData\\Local\\Temp\\is-3F2.tmp\\'],
    ['backgroundTaskHost.exe', W], ['RuntimeBroker.exe', W], ['python.exe', 'C:\\Python313\\']];
  const listeners = {};
  const emit = (ev, p) => (listeners[ev] || []).forEach(cb => cb(p));
  const mkRow = (p, start, end, code) => ({ id: ++id, pid: p.pid, ppid: p.ppid, parent: procs.get(p.ppid)?.name || 'explorer.exe', name: p.name, exe: p.exe, cmd: p.cmd, user: p.user,
    start_ms: start, end_ms: end, exit_code: code, source: 'etw', flags: p.flags, existing: false, peak_mem: Math.round(rnd(2e6, 9e7)), peak_cpu: rnd(0, 30) });
  const spawn = (t) => {
    const [name, dir] = pick(spawnables), ppid = pick([5120, 6610, 9300, 1004, 812]);
    const p = { pid: Math.floor(rnd(10000, 30000)) & ~3, ppid, name, exe: dir + name, cmd: `"${dir}${name}" ${pick(['--type=renderer', 'status --porcelain', '-Embedding', '/c echo ok', ''])}`, user: 'me',
      cpu: rnd(0, 20), mem: rnd(2e6, 8e7), vmem: 1e8, dr: 0, dw: 0, start_ms: t, status: 'Run', flags: dir.includes('Temp') ? 'temp' : '', row_id: 0 };
    const r = mkRow(p, t, null, null); p.row_id = r.id; rows.push(r);
    return { p, r };
  };
  // history backfill
  for (let t = T() - 40 * 60e3; t < T(); t += rnd(2e3, 25e3)) {
    const { p, r } = spawn(t); r.end_ms = t + rnd(80, 9e4); r.exit_code = Math.random() < .1 ? 1 : 0;
  }
  const events = () => rows.flatMap(r => [{ kind: 'start', ts: r.start_ms, lifetime_ms: null, row: r }, ...(r.end_ms ? [{ kind: 'stop', ts: r.end_ms, lifetime_ms: r.end_ms - r.start_ms, row: r }] : [])]).sort((a, b) => a.ts - b.ts);
  const cores = Array.from({ length: 16 }, () => rnd(0, 30));
  const tasks = [['GoogleUpdateTaskMachineUA', '\\', 'C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /ua', 3.5], ['OneDrive Reporting Task', '\\', '%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe', 11],
    ['Scheduled Scan', '\\Microsoft\\Windows\\Windows Defender\\', 'C:\\ProgramData\\Microsoft\\Windows Defender\\MpCmdRun.exe Scan', 24], ['MicrosoftEdgeUpdateTaskMachineCore', '\\', 'C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe /c', 0.6],
    ['Schedule Scan', '\\Microsoft\\Windows\\UpdateOrchestrator\\', 'C:\\Windows\\system32\\usoclient.exe StartScan', 47], ['ProactiveScan', '\\Microsoft\\Windows\\Chkdsk\\', 'COM {CF4270F5}', 140]];
  const upcoming = {
    items: [
      ...tasks.map(([name, path, exe, min]) => ({ kind: 'task', name, path, exe, next_ms: T() + min * 60e3, last_ms: T() - 36e5, last_result: 0, state: 'Ready', info: 'Time' })),
      { kind: 'task', name: 'Steam Logon', path: '\\', exe: 'steam.exe -silent', next_ms: null, last_ms: boot, last_result: 0, state: 'Ready', info: 'Logon' },
      { kind: 'service', name: 'wuauserv', path: 'Windows Update', exe: 'C:\\Windows\\system32\\svchost.exe -k netsvcs', state: 'StartPending', info: 'Manual' },
      { kind: 'service', name: 'gupdate', path: 'Google Update Service', exe: '"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /svc', state: 'Stopped', info: 'Auto delayed' },
      { kind: 'startup', name: 'Discord', path: 'HKU\\...\\Run', exe: '"C:\\Users\\me\\AppData\\Local\\Discord\\Update.exe" --processStart Discord.exe', info: 'me' },
      { kind: 'startup', name: 'SecurityHealth', path: 'HKLM\\...\\Run', exe: '%windir%\\system32\\SecurityHealthSystray.exe', info: 'Public' },
    ], scanned_ms: T(), scanning: false, error: null,
  };
  let hist = [];
  for (let t = T() - 6 * 36e5; t < T(); t += 6e4) hist.push({ ts: t, cpu: 10 + 8 * Math.sin(t / 9e5) + rnd(0, 12), mem: 9e9 + 1e9 * Math.sin(t / 4e6), procs: 300, rx: 0, tx: 0 });

  const snapshot = () => {
    for (const p of procs.values()) { p.cpu = Math.max(0, p.cpu * .6 + rnd(0, p.name === 'chrome.exe' ? 9 : 2)); p.mem *= rnd(.99, 1.01); p.dr = Math.random() < .2 ? rnd(0, 4e6) : 0; }
    cores.forEach((c, i) => cores[i] = Math.max(0, Math.min(100, c + rnd(-12, 12))));
    const cpu = cores.reduce((a, b) => a + b) / cores.length;
    return { ts: T(), cpu, cores: [...cores], mem_used: 11.2e9 + rnd(-2e8, 2e8), mem_total: 34.2e9, swap_used: 0, swap_total: 0, net_rx: rnd(0, 3e6), net_tx: rnd(0, 4e5),
      procs: [...procs.values()].map(p => ({ ...p, ...sigOf(p), net: conns.filter(c => c.pid === p.pid && c.state === 'ESTABLISHED').length, listen: 0 })),
      etw: true, db_rows: rows.length + 18234, ev_per_min: 23, conns };
  };
  const sigOf = p => !p.exe ? { sig: null } : p.exe.includes('Temp') || p.name === 'rg.exe' ? { sig: 'unsigned', signer: '' }
    : p.exe.startsWith('C:\\Windows') ? { sig: 'valid', signer: 'Microsoft Windows', sig_os: true }
    : { sig: 'valid', signer: { 'chrome.exe': 'Google LLC', 'Discord.exe': 'Discord Inc.', 'Telegram.exe': 'Telegram FZ-LLC', 'steam.exe': 'Valve Corp.' }[p.name] || 'Microsoft Corporation' };
  const mk = (proto, pid, la, lp, ra, rp, state, host, pub) => ({ proto, pid, laddr: la, lport: lp, raddr: ra, rport: rp, state, host, first_ms: T() - rnd(5e3, 9e5), public: pub });
  const conns = [
    mk('tcp', 8812, '192.168.1.20', 52114, '142.250.74.110', 443, 'ESTABLISHED', 'arn09s22-in-f14.1e100.net', true),
    mk('tcp', 8812, '192.168.1.20', 52120, '172.217.21.163', 443, 'ESTABLISHED', 'arn11s04-in-f3.1e100.net', true),
    mk('tcp', 8840, '192.168.1.20', 52190, '104.18.32.47', 443, 'ESTABLISHED', '', true),
    mk('tcp', 7710, '192.168.1.20', 50331, '162.159.135.234', 443, 'ESTABLISHED', '', true),
    mk('tcp', 7020, '192.168.1.20', 50412, '149.154.167.51', 443, 'ESTABLISHED', '', true),
    mk('tcp', 4420, '192.168.1.20', 50890, '155.133.248.39', 27017, 'ESTABLISHED', '', true),
    mk('tcp', 9300, '192.168.1.20', 51022, '13.107.42.18', 443, 'TIME_WAIT', '', true),
    mk('tcp', 3300, '192.168.1.20', 51210, '20.42.73.29', 443, 'SYN_SENT', '', true),
    mk('tcp', 830, '0.0.0.0', 49664, '0.0.0.0', 0, 'LISTEN', '', false), mk('tcp', 1004, '0.0.0.0', 135, '0.0.0.0', 0, 'LISTEN', '', false),
    mk('tcp', 4, '0.0.0.0', 445, '0.0.0.0', 0, 'LISTEN', '', false), mk('tcp', 9300, '127.0.0.1', 9229, '0.0.0.0', 0, 'LISTEN', '', false),
    mk('udp', 1180, '0.0.0.0', 5353, '*', 0, '', '', false), mk('udp', 1320, '0.0.0.0', 1900, '*', 0, '', '', false),
  ];
  setInterval(() => {
    const evs = [];
    if (Math.random() < .55) { const { p, r } = spawn(T()); procs.set(p.pid, p); evs.push({ kind: 'start', ts: r.start_ms, lifetime_ms: null, row: { ...r } }); }
    for (const p of [...procs.values()]) {
      if (p.row_id > 100 && Math.random() < .15) {
        procs.delete(p.pid); const r = rows.find(x => x.id === p.row_id); r.end_ms = T(); r.exit_code = Math.random() < .12 ? -1073741510 : 0;
        evs.push({ kind: 'stop', ts: r.end_ms, lifetime_ms: r.end_ms - r.start_ms, row: { ...r } });
      }
    }
    if (evs.length) emit('proc-events', evs);
    emit('snapshot', snapshot());
  }, 1000);

  let mockRules = null;
  const A = (kind, name, command, enabled, hidden, extra = {}) => ({ kind, name, command, enabled, hidden, ms: false, hive: 'HKCU', key: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', value: name, approved: 'Run', location: 'HKCU\\...\\Run', mode: '', backup_id: null, ...extra });
  const autoruns = [
    A('run', 'Discord', '"C:\\Users\\me\\AppData\\Local\\Discord\\Update.exe" --processStart Discord.exe', true, false),
    A('run', 'Steam', '"C:\\Program Files (x86)\\Steam\\steam.exe" -silent', false, false),
    A('run', 'svchostt', 'C:\\Users\\me\\AppData\\Roaming\\svchostt.exe -q', true, true, { key: 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run', approved: '', location: 'HKCU\\...\\Policies\\Explorer\\Run' }),
    A('folder', 'ShareX.lnk', 'C:\\Program Files\\ShareX\\ShareX.exe -silent', true, false, { approved: 'StartupFolder', location: 'Startup' }),
    A('task', 'GoogleUpdaterTaskUser', 'C:\\Users\\me\\AppData\\Local\\Google\\GoogleUpdater\\updater.exe --wake', true, true, { hive: '', key: '\\GoogleUpdaterTaskUser', location: '\\' }),
    A('ifeo', 'sethc.exe', 'C:\\Windows\\System32\\cmd.exe', true, true, { hive: 'HKLM', location: 'Image File Execution Options' }),
    A('service', 'Riot Vanguard', '"C:\\Program Files\\Riot Vanguard\\vgc.exe"', true, false, { hive: '', key: 'vgc', mode: 'auto', location: 'vgc' }),
    A('service', 'Windows Update', 'C:\\WINDOWS\\system32\\svchost.exe -k netsvcs', true, false, { hive: '', ms: true, key: 'wuauserv', location: 'wuauserv' }),
  ];
  const handlers = {
    get_info: () => ({ host: 'ARCH-PC', os: 'Windows 11 Pro (26200)', kernel: '10.0.26200', cpu_brand: 'AMD Ryzen 7 7800X3D 8-Core Processor', cores: 16, mem_total: 34.2e9,
      boot_ms: boot, user: 'me', admin: true, etw: true, etw_error: null, db_path: 'C:\\Users\\me\\AppData\\Roaming\\dev.logd.app\\history.db', version: '0.1.0', pid: 4242 }),
    get_settings: () => ({ interval_ms: 1000, retention_days: 30, notify_os: true }),
    get_rules: () => mockRules ||= handlers.default_rules(), set_rules: ({ rules }) => { mockRules = rules; },
    default_rules: () => [
      { id: 'd1', enabled: true, name: 'Suspicious launch', on: 'spawn', flag: 'any', action: 'notify' },
      { id: 'd2', enabled: true, name: 'Unsigned program in a user folder', on: 'sig', flag: 'unsigned', action: 'notify' },
      { id: 'd3', enabled: true, name: 'Broken or untrusted signature', on: 'sig', flag: 'bad-sig', action: 'notify' },
      { id: 'd4', enabled: true, name: 'Unsigned program reaches a new host', on: 'net', flag: 'unsigned|bad-sig', action: 'notify' },
      { id: 'd5', enabled: false, name: 'Block a program (example)', on: 'spawn', proc: 'example-blocked.exe', action: 'kill' }],
    get_alerts: () => [
      { id: 2, ts: T() - 4e5, rule: 'Unsigned program in a user folder', action: 'notify', pid: 21022, name: 'setup_x64.exe', exe: 'C:\\Users\\me\\AppData\\Local\\Temp\\is-3F2.tmp\\setup_x64.exe', detail: 'NotSigned', result: '' },
      { id: 1, ts: T() - 9e5, rule: 'Block a program (example)', action: 'kill', pid: 18800, name: 'miner.exe', exe: 'C:\\Users\\me\\Downloads\\miner.exe', detail: '← explorer.exe', result: 'killed' }],
    autoruns_list: () => new Promise(r => setTimeout(() => r(autoruns), 600)),
    autorun_set: () => null,
    suspend_process: ({ pid, resume }) => { const p = procs.get(pid); if (p) p.suspended = !resume; },
    clear_alerts: () => null, get_autostart: () => 'user', set_autostart: () => null, test_toast: () => null,
    set_settings: () => null,
    get_snapshot: snapshot,
    recent_events: ({ sinceMs }) => events().filter(e => e.ts >= sinceMs),
    query_history: ({ fromMs, toMs, search }) => rows.filter(r => r.start_ms <= toMs && (r.end_ms ?? T()) >= fromMs && (!search || (r.name + r.cmd).toLowerCase().includes(search.toLowerCase()))).sort((a, b) => b.start_ms - a.start_ms),
    get_samples: ({ fromMs, toMs }) => hist.filter(s => s.ts >= fromMs && s.ts <= toMs),
    exe_history: ({ exe, name }) => { const r = rows.filter(x => x.exe === exe || (!exe && x.name === name)); return { launches: r.length, avg_life_ms: 4200, first_ms: r[0]?.start_ms, rows: r.slice(-25).reverse() }; },
    get_row: ({ id }) => rows.find(r => r.id === id) || null,
    net_history: ({ name }) => conns.filter(c => procs.get(c.pid)?.name === name && c.public).map(c => ({ name, exe: '', pid: c.pid, proto: c.proto, raddr: c.raddr, rport: c.rport, host: c.host, first_ms: c.first_ms, last_ms: T(), novel: false, runs: 3 })),
    net_recent: () => conns.filter(c => c.public).map(c => ({ name: procs.get(c.pid)?.name || '?', exe: '', pid: c.pid, proto: c.proto, raddr: c.raddr, rport: c.rport, host: c.host, first_ms: c.first_ms, last_ms: T(), novel: true, runs: 1 })).sort((a, b) => b.first_ms - a.first_ms),
    get_upcoming: () => upcoming,
    refresh_upcoming: () => setTimeout(() => emit('upcoming', upcoming), 600),
    kill_process: ({ pid }) => { procs.delete(pid); },
    open_location: () => null, export_csv: () => 'C:\\Users\\me\\Downloads\\logd.csv', restart_admin: () => null, quit_app: () => null,
  };
  window.MOCK = {
    invoke: async (c, a) => handlers[c](a || {}),
    listen: async (ev, cb) => { (listeners[ev] ||= []).push(cb); },
    win: null,
  };
})();
