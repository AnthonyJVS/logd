use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use std::path::Path;

/// One process lifetime: from spawn to exit.
#[derive(Serialize, Clone, Debug, Default)]
pub struct ProcRow {
    pub id: i64,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub parent: String,
    pub name: String,
    pub exe: String,
    pub cmd: String,
    pub user: String,
    pub start_ms: i64,
    pub end_ms: Option<i64>,
    pub exit_code: Option<i64>,
    pub source: String,
    pub flags: String,
    /// Already running when we first saw it (spawn was not witnessed).
    pub existing: bool,
    pub peak_mem: i64,
    pub peak_cpu: f64,
    /// Authenticode verdict and signer, when the exe has been checked.
    pub sig: Option<String>,
    pub signer: Option<String>,
}

/// One remote endpoint a process talked to.
#[derive(Serialize, Clone, Debug)]
pub struct NetRow {
    pub name: String,
    pub exe: String,
    pub pid: u32,
    pub proto: String,
    pub raddr: String,
    pub rport: u16,
    pub host: String,
    pub first_ms: i64,
    pub last_ms: i64,
    /// first time ever this exe contacted this address
    pub novel: bool,
    /// number of process runs that used this endpoint
    pub runs: i64,
}

#[derive(Serialize, Clone, Debug)]
pub struct Sample {
    pub ts: i64,
    pub cpu: f64,
    pub mem: f64,
    pub procs: f64,
    pub rx: i64,
    pub tx: i64,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ExeHistory {
    pub launches: i64,
    pub avg_life_ms: Option<f64>,
    pub first_ms: Option<i64>,
    pub rows: Vec<ProcRow>,
}

const COLS: &str = "p.id,p.pid,p.ppid,p.parent,p.name,p.exe,p.cmd,p.user,p.start_ms,p.end_ms,p.exit_code,p.source,\
     p.flags,p.existing,p.peak_mem,p.peak_cpu,s.status,s.signer";
const FROM: &str = "procs p LEFT JOIN sigs s ON s.path = lower(p.exe)";

fn map_row(r: &Row) -> rusqlite::Result<ProcRow> {
    Ok(ProcRow {
        id: r.get(0)?,
        pid: r.get(1)?,
        ppid: r.get(2)?,
        parent: r.get(3)?,
        name: r.get(4)?,
        exe: r.get(5)?,
        cmd: r.get(6)?,
        user: r.get(7)?,
        start_ms: r.get(8)?,
        end_ms: r.get(9)?,
        exit_code: r.get(10)?,
        source: r.get(11)?,
        flags: r.get(12)?,
        existing: r.get::<_, i64>(13)? != 0,
        peak_mem: r.get(14)?,
        peak_cpu: r.get(15)?,
        sig: r.get(16)?,
        signer: r.get(17)?,
    })
}

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let c = Connection::open(path)?;
    c.execute_batch(
        r#"
PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS procs(
  id INTEGER PRIMARY KEY, pid INTEGER NOT NULL, ppid INTEGER, parent TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '', exe TEXT NOT NULL DEFAULT '', cmd TEXT NOT NULL DEFAULT '',
  user TEXT NOT NULL DEFAULT '', start_ms INTEGER NOT NULL, start_s INTEGER NOT NULL,
  end_ms INTEGER, exit_code INTEGER, source TEXT NOT NULL DEFAULT '', flags TEXT NOT NULL DEFAULT '',
  existing INTEGER NOT NULL DEFAULT 0, peak_mem INTEGER NOT NULL DEFAULT 0, peak_cpu REAL NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS ux_procs ON procs(pid, start_s);
CREATE INDEX IF NOT EXISTS ix_procs_start ON procs(start_ms);
CREATE INDEX IF NOT EXISTS ix_procs_end ON procs(end_ms);
CREATE INDEX IF NOT EXISTS ix_procs_exe ON procs(exe);
CREATE INDEX IF NOT EXISTS ix_procs_name ON procs(name);
CREATE TABLE IF NOT EXISTS samples(ts INTEGER PRIMARY KEY, cpu REAL, mem REAL, procs INTEGER, rx INTEGER, tx INTEGER);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sigs(path TEXT PRIMARY KEY, status TEXT NOT NULL, raw TEXT NOT NULL DEFAULT '',
  signer TEXT NOT NULL DEFAULT '', os INTEGER NOT NULL DEFAULT 0, mtime INTEGER NOT NULL DEFAULT 0, checked_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS netlog(id INTEGER PRIMARY KEY, row_id INTEGER NOT NULL, pid INTEGER, name TEXT NOT NULL DEFAULT '',
  exe TEXT NOT NULL DEFAULT '', proto TEXT NOT NULL, raddr TEXT NOT NULL, rport INTEGER NOT NULL, host TEXT NOT NULL DEFAULT '',
  first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL, novel INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS ux_netlog ON netlog(row_id, proto, raddr, rport);
CREATE INDEX IF NOT EXISTS ix_netlog_exe ON netlog(exe, raddr);
CREATE INDEX IF NOT EXISTS ix_netlog_first ON netlog(first_ms);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, rule_id TEXT, rule TEXT, kind TEXT,
  action TEXT, pid INTEGER, name TEXT, exe TEXT, detail TEXT, result TEXT);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS autorun_backup(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, name TEXT, location TEXT,
  command TEXT, hive TEXT, key TEXT, value TEXT, vtype INTEGER, data TEXT, mode TEXT, ts INTEGER);
"#,
    )?;
    Ok(c)
}

const TABLES: &[&str] = &["procs", "samples", "meta", "sigs", "netlog", "alerts", "autorun_backup"];

fn healthy(path: &Path) -> bool {
    Connection::open(path)
        .and_then(|c| c.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0)))
        .is_ok_and(|s| s == "ok")
}

/// Copies whatever rows are still readable from a damaged database, in small
/// rowid ranges so one bad page only loses its own rows. Returns rows saved.
fn salvage(from: &Path, to: &Connection) -> usize {
    if to.execute("ATTACH DATABASE ?1 AS bad", [from.to_string_lossy()]).is_err() {
        return 0;
    }
    let mut saved = 0;
    for t in TABLES {
        let max: i64 = to.query_row(&format!("SELECT MAX(rowid) FROM bad.{t}"), [], |r| r.get::<_, Option<i64>>(0)).ok().flatten().unwrap_or(0);
        let mut lo = 0;
        while lo <= max {
            if let Ok(n) = to.execute(&format!("INSERT OR IGNORE INTO main.{t} SELECT * FROM bad.{t} WHERE rowid BETWEEN ?1 AND ?2"), [lo, lo + 199]) {
                saved += n;
            }
            lo += 200;
        }
    }
    let _ = to.execute("DETACH DATABASE bad", []);
    saved
}

fn move_aside(path: &Path, suffix: &str) -> std::path::PathBuf {
    let dest = path.with_file_name(format!("history.{suffix}-{}.db", crate::util::now_ms()));
    let _ = std::fs::rename(path, &dest);
    for ext in ["-wal", "-shm"] {
        let side = std::path::PathBuf::from(format!("{}{ext}", path.display()));
        if side.exists() {
            let _ = std::fs::rename(&side, format!("{}{ext}", dest.display()));
        }
    }
    dest
}

/// Opens the history, first replacing a damaged file with a fresh one that
/// holds everything recoverable (the damaged file is kept next to it).
/// `legacy` is a database from an older install to import when `path` is new.
pub fn open_checked(path: &Path, legacy: Option<&Path>) -> rusqlite::Result<(Connection, Option<String>)> {
    let mut note = None;
    if path.exists() && !healthy(path) {
        let bad = move_aside(path, "corrupt");
        let c = open(path)?;
        let n = salvage(&bad, &c);
        note = Some(format!("history database was damaged; recovered {n} rows (damaged copy: {})", bad.display()));
    } else if !path.exists() {
        if let Some(old) = legacy.filter(|p| p.exists()) {
            if healthy(old) {
                // a consistent snapshot, unlike copying the db/-wal/-shm files
                Connection::open(old)?.execute("VACUUM INTO ?1", [path.to_string_lossy()])?;
            } else {
                let c = open(path)?;
                let n = salvage(old, &c);
                note = Some(format!("previous history was damaged; recovered {n} rows"));
            }
        }
    }
    Ok((open(path)?, note))
}

/// Rows left open by a previous run are closed at the last heartbeat; the
/// ones still alive get reopened by `insert_proc` on the first poll.
pub fn reconcile(c: &Connection) -> rusqlite::Result<()> {
    let hb: i64 = meta_get(c, "heartbeat")?.and_then(|v| v.parse().ok()).unwrap_or_else(crate::util::now_ms);
    c.execute("UPDATE procs SET end_ms=MAX(?1, start_ms) WHERE end_ms IS NULL", [hb])?;
    Ok(())
}

pub fn insert_proc(c: &Connection, p: &ProcRow) -> rusqlite::Result<i64> {
    let start_s = p.start_ms.div_euclid(1000);
    let n = c.execute(
        "INSERT OR IGNORE INTO procs(pid,ppid,parent,name,exe,cmd,user,start_ms,start_s,source,flags,existing)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![p.pid, p.ppid, p.parent, p.name, p.exe, p.cmd, p.user, p.start_ms, start_s, p.source, p.flags, p.existing as i64],
    )?;
    let id: i64 = c.query_row("SELECT id FROM procs WHERE pid=?1 AND start_s=?2", params![p.pid, start_s], |r| r.get(0))?;
    if n == 0 {
        // same (pid, start) seen before: it never actually exited
        c.execute("UPDATE procs SET end_ms=NULL, exit_code=NULL WHERE id=?1", [id])?;
    }
    Ok(id)
}

pub fn fill_proc(c: &Connection, p: &ProcRow) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE procs SET exe=?2, cmd=?3, user=?4, name=?5, flags=?6 WHERE id=?1",
        params![p.id, p.exe, p.cmd, p.user, p.name, p.flags],
    )?;
    Ok(())
}

pub fn close_proc(c: &Connection, id: i64, end_ms: i64, code: Option<i64>, peak_mem: i64, peak_cpu: f64) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE procs SET end_ms=?2, exit_code=?3, peak_mem=MAX(peak_mem,?4), peak_cpu=MAX(peak_cpu,?5) WHERE id=?1",
        params![id, end_ms, code, peak_mem, peak_cpu],
    )?;
    Ok(())
}

pub fn get_row(c: &Connection, id: i64) -> rusqlite::Result<Option<ProcRow>> {
    c.query_row(&format!("SELECT {COLS} FROM {FROM} WHERE id=?1"), [id], map_row).optional()
}

pub fn history(c: &Connection, from: i64, to: i64, search: &str, limit: u32, hide_long: bool) -> rusqlite::Result<Vec<ProcRow>> {
    let mut sql = format!("SELECT {COLS} FROM {FROM} WHERE start_ms <= ?1 AND (end_ms IS NULL OR end_ms >= ?2)");
    if hide_long {
        // drop processes that span the whole window
        sql += " AND NOT (start_ms < ?2 AND (end_ms IS NULL OR end_ms > ?1))";
    }
    if !search.is_empty() {
        sql += " AND (name LIKE ?3 OR exe LIKE ?3 OR cmd LIKE ?3 OR parent LIKE ?3 OR CAST(pid AS TEXT) = ?4)";
    }
    sql += " ORDER BY start_ms DESC LIMIT ?5";
    let like = format!("%{search}%");
    let mut st = c.prepare(&sql)?;
    let rows = st.query_map(params![to, from, like, search, limit], map_row)?;
    rows.collect()
}

/// Rows that spawned or exited since `since` (newest first).
pub fn recent(c: &Connection, since: i64, limit: u32) -> rusqlite::Result<Vec<ProcRow>> {
    let mut st = c.prepare(&format!(
        "SELECT {COLS} FROM {FROM} WHERE (existing=0 AND start_ms>=?1) OR end_ms>=?1
         ORDER BY COALESCE(end_ms,start_ms) DESC LIMIT ?2"
    ))?;
    let rows = st.query_map(params![since, limit], map_row)?;
    rows.collect()
}

pub fn exe_history(c: &Connection, exe: &str, name: &str, limit: u32) -> rusqlite::Result<ExeHistory> {
    let (col, key) = if exe.is_empty() { ("name", name) } else { ("exe", exe) };
    let (launches, avg, first): (i64, Option<f64>, Option<i64>) = c.query_row(
        &format!("SELECT COUNT(*), AVG(end_ms-start_ms), MIN(start_ms) FROM procs WHERE {col}=?1"),
        [key],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let mut st = c.prepare(&format!("SELECT {COLS} FROM {FROM} WHERE {col}=?1 ORDER BY start_ms DESC LIMIT ?2"))?;
    let rows = st.query_map(params![key, limit], map_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(ExeHistory { launches, avg_life_ms: avg, first_ms: first, rows })
}

pub fn insert_sample(c: &Connection, s: &Sample) -> rusqlite::Result<()> {
    c.execute(
        "INSERT OR REPLACE INTO samples(ts,cpu,mem,procs,rx,tx) VALUES(?1,?2,?3,?4,?5,?6)",
        params![s.ts, s.cpu, s.mem, s.procs as i64, s.rx, s.tx],
    )?;
    Ok(())
}

pub fn samples(c: &Connection, from: i64, to: i64, buckets: u32) -> rusqlite::Result<Vec<Sample>> {
    let b = ((to - from) / buckets.max(1) as i64).max(5000);
    let mut st = c.prepare(
        "SELECT (ts/?3)*?3 AS t, AVG(cpu), AVG(mem), AVG(procs), SUM(rx), SUM(tx)
         FROM samples WHERE ts BETWEEN ?1 AND ?2 GROUP BY t ORDER BY t",
    )?;
    let rows = st.query_map(params![from, to, b], |r| {
        Ok(Sample { ts: r.get(0)?, cpu: r.get(1)?, mem: r.get(2)?, procs: r.get(3)?, rx: r.get(4)?, tx: r.get(5)? })
    })?;
    rows.collect()
}

pub fn prune(c: &Connection, before: i64) -> rusqlite::Result<()> {
    c.execute("DELETE FROM procs WHERE end_ms IS NOT NULL AND end_ms < ?1", [before])?;
    c.execute("DELETE FROM samples WHERE ts < ?1", [before])?;
    c.execute("DELETE FROM netlog WHERE last_ms < ?1", [before])?;
    Ok(())
}

/// Records an endpoint for a process run; returns the netlog id and whether
/// this insert was the program's first ever contact with that address.
pub fn net_seen(c: &Connection, row: &ProcRow, proto: &str, raddr: &str, rport: u16, host: &str, now: i64) -> rusqlite::Result<(i64, bool)> {
    let inserted = c.execute(
        "INSERT OR IGNORE INTO netlog(row_id,pid,name,exe,proto,raddr,rport,host,first_ms,last_ms,novel)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9,
           NOT EXISTS(SELECT 1 FROM netlog WHERE exe=?4 AND name=?3 AND raddr=?6))",
        params![row.id, row.pid, row.name, row.exe, proto, raddr, rport, host, now],
    )?;
    let (id, novel): (i64, i64) = c.query_row(
        "SELECT id, novel FROM netlog WHERE row_id=?1 AND proto=?2 AND raddr=?3 AND rport=?4",
        params![row.id, proto, raddr, rport],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok((id, inserted > 0 && novel != 0))
}

pub fn net_touch(c: &Connection, id: i64, host: &str, now: i64) -> rusqlite::Result<()> {
    c.execute("UPDATE netlog SET last_ms=?2, host=CASE WHEN ?3 <> '' THEN ?3 ELSE host END WHERE id=?1", params![id, now, host])?;
    Ok(())
}

fn map_net(r: &Row) -> rusqlite::Result<NetRow> {
    Ok(NetRow {
        name: r.get(0)?,
        exe: r.get(1)?,
        pid: r.get(2)?,
        proto: r.get(3)?,
        raddr: r.get(4)?,
        rport: r.get(5)?,
        host: r.get(6)?,
        first_ms: r.get(7)?,
        last_ms: r.get(8)?,
        novel: r.get::<_, i64>(9)? != 0,
        runs: r.get(10)?,
    })
}

/// Every endpoint an executable has talked to, most recent first.
pub fn net_history(c: &Connection, exe: &str, name: &str, limit: u32) -> rusqlite::Result<Vec<NetRow>> {
    let (col, key) = if exe.is_empty() { ("name", name) } else { ("exe", exe) };
    let mut st = c.prepare(&format!(
        "SELECT MAX(name), MAX(exe), MAX(pid), proto, raddr, rport, MAX(host), MIN(first_ms), MAX(last_ms), MAX(novel), COUNT(DISTINCT row_id)
         FROM netlog WHERE {col}=?1 GROUP BY proto, raddr, rport ORDER BY MAX(last_ms) DESC LIMIT ?2"
    ))?;
    let rows = st.query_map(params![key, limit], map_net)?;
    rows.collect()
}

/// Newest endpoints across all processes.
pub fn net_recent(c: &Connection, only_novel: bool, limit: u32) -> rusqlite::Result<Vec<NetRow>> {
    let mut st = c.prepare(&format!(
        "SELECT name, exe, pid, proto, raddr, rport, host, first_ms, last_ms, novel, 1 FROM netlog
         {} ORDER BY first_ms DESC LIMIT ?1",
        if only_novel { "WHERE novel=1" } else { "" }
    ))?;
    let rows = st.query_map(params![limit], map_net)?;
    rows.collect()
}

pub fn count(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM procs", [], |r| r.get(0)).unwrap_or(0)
}

pub fn meta_get(c: &Connection, k: &str) -> rusqlite::Result<Option<String>> {
    c.query_row("SELECT v FROM meta WHERE k=?1", [k], |r| r.get(0)).optional()
}

pub fn meta_set(c: &Connection, k: &str, v: &str) -> rusqlite::Result<()> {
    c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?1,?2)", [k, v])?;
    Ok(())
}
