use crate::db::{self, ProcRow, Sample};
use crate::net::{self, Conn, Resolver};
use crate::rules::Engine;
use crate::sigs::Sigs;
use crate::util::{self, now_ms};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sysinfo::{Networks, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};
use tauri::{AppHandle, Emitter};

#[derive(Serialize, Clone)]
pub struct ProcEvent {
    pub kind: String, // "start" | "stop"
    pub ts: i64,
    pub lifetime_ms: Option<i64>,
    pub row: ProcRow,
}

#[derive(Serialize, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe: String,
    pub cmd: String,
    pub user: String,
    pub cpu: f32,
    pub mem: u64,
    pub vmem: u64,
    pub dr: u64,
    pub dw: u64,
    pub start_ms: i64,
    pub status: String,
    pub flags: String,
    pub row_id: i64,
    pub sig: Option<String>,
    pub signer: String,
    pub sig_os: bool,
    /// live remote TCP connections
    pub net: u32,
    /// listening sockets
    pub listen: u32,
    pub suspended: bool,
}

#[derive(Serialize, Clone, Default)]
pub struct Snapshot {
    pub ts: i64,
    pub cpu: f32,
    pub cores: Vec<f32>,
    pub mem_used: u64,
    pub mem_total: u64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub procs: Vec<ProcInfo>,
    pub etw: bool,
    pub db_rows: i64,
    pub ev_per_min: usize,
    pub conns: Vec<Conn>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Settings {
    pub interval_ms: u64,
    pub retention_days: u32,
    /// Windows toasts for rule alerts
    pub notify_os: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { interval_ms: 1000, retention_days: 30, notify_os: true }
    }
}

pub struct Shared {
    pub snap: Mutex<Snapshot>,
    pub etw: AtomicBool,
    pub etw_error: Mutex<Option<String>>,
    pub settings: Mutex<Settings>,
    /// pids frozen from the UI
    pub suspended: Mutex<HashSet<u32>>,
    /// set when the history had to be repaired at startup
    pub db_note: Mutex<Option<String>>,
}

struct Alive {
    row: ProcRow,
    peak_mem: u64,
    peak_cpu: f32,
    missing_since: Option<i64>,
}

/// Owns the writer connection and the set of processes believed alive.
/// Both the poller and the ETW callback feed it.
pub struct Tracker {
    pub db: Connection,
    alive: HashMap<u32, Alive>,
    ev_times: VecDeque<i64>,
    self_pid: u32,
    /// (row id, proto, remote addr, remote port) -> (netlog id, last written, host known)
    netseen: HashMap<(i64, &'static str, String, u16), (i64, i64, bool)>,
}

const SAME_START_MS: i64 = 2500;

impl Tracker {
    pub fn new(db: Connection) -> Self {
        Tracker { db, alive: HashMap::new(), ev_times: VecDeque::new(), self_pid: std::process::id(), netseen: HashMap::new() }
    }

    /// Running processes started from `exe` (compared case-insensitively).
    pub fn procs_with_exe(&self, exe: &str) -> Vec<ProcRow> {
        self.alive.values().filter(|a| a.row.exe.eq_ignore_ascii_case(exe)).map(|a| a.row.clone()).collect()
    }

    /// Writes remote endpoints to the netlog; `last_ms` is refreshed at most every 30 s.
    /// Returns the first-ever contacts, for the rules.
    pub fn log_conns(&mut self, conns: &[Conn], now: i64) -> Vec<(ProcRow, db::NetRow)> {
        let mut novel = Vec::new();
        let _ = self.db.execute_batch("BEGIN");
        for c in conns.iter().filter(|c| c.is_remote()) {
            let Some(a) = self.alive.get(&c.pid) else { continue };
            let key = (a.row.id, c.proto, c.raddr.clone(), c.rport);
            match self.netseen.get_mut(&key) {
                Some(e) => {
                    let host_new = !e.2 && !c.host.is_empty();
                    if now - e.1 > 30_000 || host_new {
                        let _ = db::net_touch(&self.db, e.0, &c.host, now);
                        e.1 = now;
                        e.2 |= host_new;
                    }
                }
                None => {
                    if let Ok((id, is_novel)) = db::net_seen(&self.db, &a.row, c.proto, &c.raddr, c.rport, &c.host, now) {
                        self.netseen.insert(key, (id, now, !c.host.is_empty()));
                        if is_novel {
                            novel.push((a.row.clone(), db::NetRow {
                                name: a.row.name.clone(),
                                exe: a.row.exe.clone(),
                                pid: c.pid,
                                proto: c.proto.into(),
                                raddr: c.raddr.clone(),
                                rport: c.rport,
                                host: c.host.clone(),
                                first_ms: now,
                                last_ms: now,
                                novel: true,
                                runs: 1,
                            }));
                        }
                    }
                }
            }
        }
        let _ = self.db.execute_batch("COMMIT");
        if self.netseen.len() > 20_000 {
            let live: HashSet<i64> = self.alive.values().map(|a| a.row.id).collect();
            self.netseen.retain(|k, _| live.contains(&k.0));
        }
        novel
    }

    pub fn is_alive(&self, pid: u32, start_ms: i64) -> bool {
        self.alive.get(&pid).is_some_and(|a| (a.row.start_ms - start_ms).abs() < SAME_START_MS)
    }

    /// ETW-born rows lack the user and sometimes the path; the poller has them.
    fn needs_fill(&self, pid: u32, exe: &str, user: &str) -> bool {
        self.alive
            .get(&pid)
            .is_some_and(|a| (a.row.exe.is_empty() && !exe.is_empty()) || (a.row.user.is_empty() && !user.is_empty()))
    }

    pub fn start(&mut self, mut row: ProcRow, out: &mut Vec<ProcEvent>) {
        if let Some(a) = self.alive.get_mut(&row.pid) {
            if (a.row.start_ms - row.start_ms).abs() < SAME_START_MS {
                // already known: fill whatever the first source could not see
                let mut changed = false;
                for (dst, src) in [(&mut a.row.exe, &row.exe), (&mut a.row.cmd, &row.cmd), (&mut a.row.user, &row.user)] {
                    if dst.is_empty() && !src.is_empty() {
                        *dst = src.clone();
                        changed = true;
                    }
                }
                if changed {
                    if !a.row.exe.is_empty() {
                        a.row.name = util::file_name(&a.row.exe);
                    }
                    a.row.flags = self_flags(&a.row, self.self_pid);
                    let _ = db::fill_proc(&self.db, &a.row);
                }
                return;
            }
            // pid reused: the previous owner is gone
            let pid = row.pid;
            self.stop(pid, None, row.start_ms, out);
        }
        if row.parent.is_empty() {
            if let Some(pp) = row.ppid.and_then(|pp| self.alive.get(&pp)) {
                row.parent = pp.row.name.clone();
            }
        }
        row.flags = self_flags(&row, self.self_pid);
        match db::insert_proc(&self.db, &row) {
            Ok(id) => row.id = id,
            Err(e) => {
                eprintln!("insert_proc: {e}");
                return;
            }
        }
        self.alive.insert(row.pid, Alive { row: row.clone(), peak_mem: 0, peak_cpu: 0.0, missing_since: None });
        if !row.existing {
            self.ev_times.push_back(now_ms());
            out.push(ProcEvent { kind: "start".into(), ts: row.start_ms, lifetime_ms: None, row });
        }
    }

    pub fn stop(&mut self, pid: u32, code: Option<i64>, ts: i64, out: &mut Vec<ProcEvent>) {
        let Some(a) = self.alive.remove(&pid) else { return };
        let ts = ts.max(a.row.start_ms);
        let _ = db::close_proc(&self.db, a.row.id, ts, code, a.peak_mem as i64, a.peak_cpu as f64);
        let mut row = a.row;
        row.end_ms = Some(ts);
        row.exit_code = code;
        row.peak_mem = row.peak_mem.max(a.peak_mem as i64);
        row.peak_cpu = row.peak_cpu.max(a.peak_cpu as f64);
        self.ev_times.push_back(now_ms());
        out.push(ProcEvent { kind: "stop".into(), ts, lifetime_ms: Some(ts - row.start_ms), row });
    }

    fn events_per_min(&mut self, now: i64) -> usize {
        while self.ev_times.front().is_some_and(|t| now - *t > 60_000) {
            self.ev_times.pop_front();
        }
        self.ev_times.len()
    }
}

fn self_flags(row: &ProcRow, self_pid: u32) -> String {
    let mut f = util::flags(&row.name, &row.exe, &row.cmd);
    if row.ppid == Some(self_pid) {
        if !f.is_empty() {
            f.push(',');
        }
        f.push_str("self");
    }
    f
}

fn clip(s: String, n: usize) -> String {
    if s.len() <= n {
        return s;
    }
    let mut end = n;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

pub fn run_poller(app: AppHandle, tracker: Arc<Mutex<Tracker>>, shared: Arc<Shared>, sigs: Arc<Sigs>, resolver: Arc<Resolver>, engine: Arc<Engine>) {
    let mut sys = System::new();
    sys.refresh_cpu_all();
    let mut nets = Networks::new_with_refreshed_list();
    let mut users = Users::new_with_refreshed_list();
    let ncpu = sys.cpus().len().max(1) as f32;
    let boot_ms = System::boot_time() as i64 * 1000;
    let kind = ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .with_disk_usage()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet)
        .with_user(UpdateKind::OnlyIfNotSet);

    let mut first = true;
    let mut prev_now = now_ms();
    let mut last_tick = Instant::now();
    let mut last_sample = 0i64;
    let mut last_hb = 0i64;
    let mut last_prune = 0i64;
    let mut last_users = now_ms();
    let mut db_rows = 0i64;
    let mut last_count = 0i64;
    let mut conns: Vec<Conn> = Vec::new();
    let mut conn_first: HashMap<(u32, &'static str, String, u16, String, u16), i64> = HashMap::new();
    let mut last_net = 0i64;

    loop {
        let interval = shared.settings.lock().unwrap().interval_ms.clamp(250, 10_000);
        let elapsed = last_tick.elapsed().as_secs_f64().max(0.001);
        last_tick = Instant::now();
        let now = now_ms();

        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        nets.refresh(true);
        if now - last_users > 60_000 {
            users.refresh();
            last_users = now;
        }
        let etw = shared.etw.load(Ordering::Relaxed);

        let net_due = now - last_net >= 2000;
        if net_due {
            let mut fresh_conns = net::snapshot();
            let mut keys = HashSet::new();
            for c in &mut fresh_conns {
                if c.public {
                    if let Ok(ip) = c.raddr.parse() {
                        c.host = resolver.name(ip);
                    }
                }
                let k = c.key();
                c.first_ms = *conn_first.entry(k.clone()).or_insert(now);
                keys.insert(k);
            }
            conn_first.retain(|k, _| keys.contains(k));
            conns = fresh_conns;
            last_net = now;
        }
        let mut per_pid: HashMap<u32, (u32, u32)> = HashMap::new();
        for c in &conns {
            let e = per_pid.entry(c.pid).or_default();
            if c.is_remote() && c.state == "ESTABLISHED" {
                e.0 += 1;
            } else if c.state == "LISTEN" {
                e.1 += 1;
            }
        }

        let frozen = shared.suspended.lock().unwrap().clone();
        let mut evs = Vec::new();
        let mut novel = Vec::new();
        let mut infos = Vec::with_capacity(sys.processes().len());
        let ev_per_min;
        {
            let mut t = tracker.lock().unwrap();
            let mut seen = HashSet::new();
            let mut fresh = Vec::new();
            let start_of = |p: &sysinfo::Process| {
                let st = p.start_time() as i64 * 1000;
                if st > 0 { st } else { boot_ms }
            };
            let user_of = |p: &sysinfo::Process| {
                p.user_id().and_then(|u| users.get_user_by_id(u)).map(|u| u.name().to_string()).unwrap_or_default()
            };
            let exe_of = |p: &sysinfo::Process| p.exe().map(|e| e.to_string_lossy().into_owned()).unwrap_or_default();
            let cmd_of = |p: &sysinfo::Process| p.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ");

            for (pid, p) in sys.processes() {
                let pid = pid.as_u32();
                if pid == 0 {
                    continue;
                }
                seen.insert(pid);
                let start_ms = start_of(p);
                let (exe, user) = (exe_of(p), user_of(p));
                if first || !t.is_alive(pid, start_ms) || t.needs_fill(pid, &exe, &user) {
                    fresh.push(ProcRow {
                        pid,
                        ppid: p.parent().map(|x| x.as_u32()),
                        name: p.name().to_string_lossy().into_owned(),
                        exe,
                        cmd: cmd_of(p),
                        user,
                        start_ms,
                        source: "poll".into(),
                        // a start time well before the previous poll is a bogus creation time, not a spawn
                        existing: first || start_ms < prev_now - 5000,
                        ..Default::default()
                    });
                }
            }
            // parents before children, so each child can resolve its parent's name
            // (start times are whole seconds, so also order by the parent links)
            fresh.sort_by_key(|r| r.start_ms);
            while !fresh.is_empty() {
                let pending: HashSet<u32> = fresh.iter().map(|r| r.pid).collect();
                let (ready, rest): (Vec<_>, Vec<_>) = fresh
                    .into_iter()
                    .partition(|r| !r.ppid.is_some_and(|pp| pp != r.pid && pending.contains(&pp)));
                if ready.is_empty() {
                    // pid-reuse cycle: no parent order exists
                    for row in rest {
                        t.start(row, &mut evs);
                    }
                    break;
                }
                for row in ready {
                    t.start(row, &mut evs);
                }
                fresh = rest;
            }

            for (pid, p) in sys.processes() {
                let pid = pid.as_u32();
                if pid == 0 {
                    continue;
                }
                let start_ms = start_of(p);
                let (exe, cmd, user) = (exe_of(p), cmd_of(p), user_of(p));
                let name = p.name().to_string_lossy().into_owned();
                let ppid = p.parent().map(|x| x.as_u32());
                let cpu = p.cpu_usage() / ncpu;
                let a = t.alive.get_mut(&pid);
                let (row_id, flags, known_cmd) = match a {
                    Some(a) => {
                        a.missing_since = None;
                        a.peak_mem = a.peak_mem.max(p.memory());
                        a.peak_cpu = a.peak_cpu.max(cpu);
                        (a.row.id, a.row.flags.clone(), a.row.cmd.clone())
                    }
                    None => (0, String::new(), String::new()),
                };
                let du = p.disk_usage();
                let sig = if exe.is_empty() { None } else { sigs.get(&exe) };
                let (net, listen) = per_pid.get(&pid).copied().unwrap_or_default();
                infos.push(ProcInfo {
                    sig: sig.as_ref().map(|s| s.status.clone()),
                    signer: sig.as_ref().map(|s| s.signer.clone()).unwrap_or_default(),
                    sig_os: sig.is_some_and(|s| s.os),
                    net,
                    listen,
                    suspended: frozen.contains(&pid),
                    pid,
                    ppid,
                    name,
                    exe,
                    cmd: clip(if cmd.is_empty() { known_cmd } else { cmd }, 600),
                    user,
                    cpu,
                    mem: p.memory(),
                    vmem: p.virtual_memory(),
                    dr: (du.read_bytes as f64 / elapsed) as u64,
                    dw: (du.written_bytes as f64 / elapsed) as u64,
                    start_ms,
                    status: p.status().to_string(),
                    flags,
                    row_id,
                });
            }
            let gone: Vec<u32> = t.alive.keys().filter(|p| !seen.contains(p)).copied().collect();
            for pid in gone {
                if etw {
                    // give ETW a moment to report the exact exit time and code
                    let a = t.alive.get_mut(&pid).unwrap();
                    let since = *a.missing_since.get_or_insert(now);
                    if now - since < 3000 {
                        continue;
                    }
                }
                t.stop(pid, None, now, &mut evs);
            }
            if net_due {
                novel = t.log_conns(&conns, now);
            }

            if now - last_count > 15_000 {
                db_rows = db::count(&t.db);
                last_count = now;
            }
            if now - last_hb > 10_000 {
                let _ = db::meta_set(&t.db, "heartbeat", &now.to_string());
                last_hb = now;
            }
            ev_per_min = t.events_per_min(now);
        }

        let (rx, tx) = nets.iter().fold((0u64, 0u64), |(r, x), (_, d)| (r + d.received(), x + d.transmitted()));
        let snap = Snapshot {
            ts: now,
            cpu: sys.global_cpu_usage(),
            cores: sys.cpus().iter().map(|c| c.cpu_usage()).collect(),
            mem_used: sys.used_memory(),
            mem_total: sys.total_memory(),
            swap_used: sys.used_swap(),
            swap_total: sys.total_swap(),
            net_rx: (rx as f64 / elapsed) as u64,
            net_tx: (tx as f64 / elapsed) as u64,
            procs: infos,
            etw,
            db_rows,
            ev_per_min,
            conns: conns.clone(),
        };

        if now - last_sample >= 5000 {
            let s = Sample {
                ts: now,
                cpu: snap.cpu as f64,
                mem: snap.mem_used as f64,
                procs: snap.procs.len() as f64,
                rx: snap.net_rx as i64 * 5,
                tx: snap.net_tx as i64 * 5,
            };
            let t = tracker.lock().unwrap();
            let _ = db::insert_sample(&t.db, &s);
            if now - last_prune > 3_600_000 {
                let days = shared.settings.lock().unwrap().retention_days.max(1) as i64;
                let _ = db::prune(&t.db, now - days * 86_400_000);
                last_prune = now;
            }
            last_sample = now;
        }

        if !evs.is_empty() {
            let _ = app.emit("proc-events", &evs);
            engine.on_proc_events(&evs);
        }
        if !novel.is_empty() {
            engine.on_net(&novel);
        }
        let _ = app.emit("snapshot", &snap);
        *shared.snap.lock().unwrap() = snap;
        first = false;
        prev_now = now;

        let spent = last_tick.elapsed();
        std::thread::sleep(Duration::from_millis(interval).saturating_sub(spent));
    }
}
