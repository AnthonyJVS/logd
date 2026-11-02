//! User rules evaluated in the backend (so they keep working while the window
//! is hidden): match spawns, first network contacts and signature verdicts,
//! then notify, kill or just log an alert.

use crate::db::{self, ProcRow};
use crate::monitor::{ProcEvent, Tracker};
use crate::sigs::{SigUpdate, Sigs};
use crate::util::{self, now_ms};
use crate::{db::NetRow, os};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tauri::{AppHandle, Emitter, Manager};

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(default)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub name: String,
    /// spawn | net | sig
    pub on: String,
    /// patterns: `*` and `?` wildcards, `|` separates alternatives, empty = any
    pub proc: String,
    pub path: String,
    pub parent: String,
    /// flag name(s), `any` = any warning flag, empty = don't care
    pub flag: String,
    pub remote: String,
    pub port: String,
    /// notify | kill | log
    pub action: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Alert {
    pub id: i64,
    pub ts: i64,
    pub rule_id: String,
    pub rule: String,
    pub kind: String,
    pub action: String,
    pub pid: Option<u32>,
    pub name: String,
    pub exe: String,
    pub detail: String,
    pub result: String,
}

/// What a rule is matched against.
struct Subject {
    kind: &'static str,
    pid: Option<u32>,
    name: String,
    exe: String,
    parent: String,
    flags: Vec<String>,
    remote: String,
    port: Option<u16>,
    detail: String,
}

pub fn default_rules() -> Vec<Rule> {
    let r = |id: &str, name: &str, on: &str, flag: &str, action: &str, enabled: bool| Rule {
        id: id.into(),
        enabled,
        name: name.into(),
        on: on.into(),
        flag: flag.into(),
        action: action.into(),
        ..Default::default()
    };
    vec![
        r("d1", "Suspicious launch", "spawn", "any", "notify", true),
        r("d2", "Unsigned program in a user folder", "sig", "unsigned", "notify", true),
        r("d3", "Broken or untrusted signature", "sig", "bad-sig", "notify", true),
        r("d4", "Unsigned program reaches a new host", "net", "unsigned|bad-sig", "notify", true),
        Rule { proc: "example-blocked.exe".into(), ..r("d5", "Block a program (example)", "spawn", "", "kill", false) },
    ]
}


static SELF_EXE: OnceLock<Option<String>> = OnceLock::new();

fn self_exe() -> Option<String> {
    std::env::current_exe().ok().map(|p| p.to_string_lossy().into_owned())
}

fn glob(pat: &str, text: &str) -> bool {
    fn m(p: &[char], t: &[char]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some('*'), _) => m(&p[1..], t) || (!t.is_empty() && m(p, &t[1..])),
            (Some('?'), Some(_)) => m(&p[1..], &t[1..]),
            (Some(a), Some(b)) => a == b && m(&p[1..], &t[1..]),
            _ => false,
        }
    }
    let t: Vec<char> = text.to_lowercase().chars().collect();
    pat.split('|').map(str::trim).filter(|s| !s.is_empty()).any(|alt| {
        let p: Vec<char> = alt.to_lowercase().chars().collect();
        // a bare word matches anywhere inside the text
        if !alt.contains(['*', '?']) {
            return text.to_lowercase().contains(&alt.to_lowercase());
        }
        m(&p, &t)
    })
}

fn field_ok(pat: &str, text: &str) -> bool {
    pat.trim().is_empty() || glob(pat, text)
}

impl Rule {
    fn matches(&self, s: &Subject) -> bool {
        if !self.enabled || self.on != s.kind || s.flags.iter().any(|f| f == "self") {
            return false;
        }
        let flag_ok = match self.flag.trim() {
            "" => true,
            "any" => !s.flags.is_empty(),
            f => f.split('|').map(str::trim).any(|x| s.flags.iter().any(|g| g == x)),
        };
        flag_ok
            && field_ok(&self.proc, &s.name)
            && field_ok(&self.path, &s.exe)
            && field_ok(&self.parent, &s.parent)
            && field_ok(&self.remote, &s.remote)
            && (self.port.trim().is_empty() || s.port.is_some_and(|p| self.port.split('|').any(|x| x.trim() == p.to_string())))
    }
}

pub struct Engine {
    app: AppHandle,
    db: Mutex<Connection>,
    pub rules: Mutex<Vec<Rule>>,
    pub notify_os: AtomicBool,
    tracker: OnceLock<Arc<Mutex<Tracker>>>,
    sigs: OnceLock<Arc<Sigs>>,
    /// (rule, process name) -> last toast, against notification floods
    last_toast: Mutex<HashMap<(String, String), i64>>,
}

impl Engine {
    pub fn new(app: AppHandle, db: Connection, rules: Vec<Rule>, notify_os: bool) -> Arc<Engine> {
        let _ = db.execute_batch(
            "CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, rule_id TEXT, rule TEXT, kind TEXT,
               action TEXT, pid INTEGER, name TEXT, exe TEXT, detail TEXT, result TEXT);
             CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);",
        );
        Arc::new(Engine {
            app,
            db: Mutex::new(db),
            rules: Mutex::new(rules),
            notify_os: AtomicBool::new(notify_os),
            tracker: OnceLock::new(),
            sigs: OnceLock::new(),
            last_toast: Mutex::default(),
        })
    }

    pub fn attach(&self, tracker: Arc<Mutex<Tracker>>, sigs: Arc<Sigs>) {
        let _ = self.tracker.set(tracker);
        let _ = self.sigs.set(sigs);
    }

    /// Process flags plus the ones derived from an already known signature.
    fn flags_for(&self, flags: &str, exe: &str) -> Vec<String> {
        let mut f: Vec<String> = flags.split(',').filter(|x| !x.is_empty()).map(String::from).collect();
        if let Some(sig) = self.sigs.get().and_then(|s| s.cached(exe)) {
            f.extend(util::sig_flags(&sig.status, exe).into_iter().map(String::from));
        }
        f
    }

    pub fn on_proc_events(&self, evs: &[ProcEvent]) {
        for ev in evs.iter().filter(|e| e.kind == "start") {
            let r = &ev.row;
            self.eval(Subject {
                kind: "spawn",
                pid: Some(r.pid),
                name: r.name.clone(),
                exe: r.exe.clone(),
                parent: r.parent.clone(),
                flags: self.flags_for(&r.flags, &r.exe),
                remote: String::new(),
                port: None,
                detail: format!("← {} {}", r.parent, clip(if r.cmd.is_empty() { &r.exe } else { &r.cmd }, 160)),
            });
        }
    }

    pub fn on_net(&self, items: &[(ProcRow, NetRow)]) {
        for (row, n) in items {
            let host = if n.host.is_empty() { n.raddr.clone() } else { format!("{} {}", n.host, n.raddr) };
            self.eval(Subject {
                kind: "net",
                pid: Some(row.pid),
                name: row.name.clone(),
                exe: row.exe.clone(),
                parent: row.parent.clone(),
                flags: self.flags_for(&row.flags, &row.exe),
                remote: host.clone(),
                port: Some(n.rport),
                detail: format!("→ {}:{} {}", n.raddr, n.rport, n.host),
            });
        }
    }

    pub fn on_sigs(&self, ups: &[SigUpdate]) {
        let Some(tracker) = self.tracker.get() else { return };
        for u in ups {
            let flags = util::sig_flags(&u.sig.status, &u.path);
            if flags.is_empty() {
                continue;
            }
            // report against the running instances of that file
            let procs = tracker.lock().unwrap().procs_with_exe(&u.path);
            let first = procs.first();
            self.eval(Subject {
                kind: "sig",
                pid: first.map(|r| r.pid),
                name: first.map(|r| r.name.clone()).unwrap_or_else(|| util::file_name(&u.path)),
                exe: first.map(|r| r.exe.clone()).unwrap_or_else(|| u.path.clone()),
                parent: first.map(|r| r.parent.clone()).unwrap_or_default(),
                flags: flags.into_iter().map(String::from).chain(first.map(|r| r.flags.clone()).into_iter()).collect(),
                remote: String::new(),
                port: None,
                detail: format!("{} {}", u.sig.raw, u.sig.signer).trim().to_string(),
            });
        }
    }

    fn eval(&self, s: Subject) {
        if s.pid == Some(std::process::id()) || SELF_EXE.get_or_init(self_exe).as_deref().is_some_and(|me| s.exe.eq_ignore_ascii_case(me)) {
            return;
        }
        let hits: Vec<Rule> = self.rules.lock().unwrap().iter().filter(|r| r.matches(&s)).cloned().collect();
        for rule in hits {
            let mut result = String::new();
            if rule.action == "kill" {
                result = match s.pid {
                    Some(pid) if !util::is_critical(pid, &s.name) => {
                        match util::kill(pid) {
                            Ok(()) => "killed".into(),
                            Err(e) => format!("kill failed: {e}"),
                        }
                    }
                    _ => "kill skipped (protected process)".into(),
                };
            }
            let alert = self.record(&rule, &s, &result);
            let _ = self.app.emit("alert", &alert);
            if rule.action != "log" {
                self.toast(&rule, &alert);
            }
        }
    }

    fn record(&self, rule: &Rule, s: &Subject, result: &str) -> Alert {
        let ts = now_ms();
        let db = self.db.lock().unwrap();
        let _ = db.execute(
            "INSERT INTO alerts(ts,rule_id,rule,kind,action,pid,name,exe,detail,result) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![ts, rule.id, rule.name, s.kind, rule.action, s.pid, s.name, s.exe, s.detail, result],
        );
        Alert {
            id: db.last_insert_rowid(),
            ts,
            rule_id: rule.id.clone(),
            rule: rule.name.clone(),
            kind: s.kind.into(),
            action: rule.action.clone(),
            pid: s.pid,
            name: s.name.clone(),
            exe: s.exe.clone(),
            detail: s.detail.clone(),
            result: result.into(),
        }
    }

    /// Windows toast, unless the window is in front (the page shows its own).
    fn toast(&self, rule: &Rule, a: &Alert) {
        if !self.notify_os.load(Ordering::Relaxed) {
            return;
        }
        if let Some(w) = self.app.get_webview_window("main") {
            if w.is_visible().unwrap_or(false) && w.is_focused().unwrap_or(false) && !w.is_minimized().unwrap_or(false) {
                return;
            }
        }
        let now = now_ms();
        {
            let mut last = self.last_toast.lock().unwrap();
            let key = (rule.id.clone(), a.name.to_lowercase());
            if last.get(&key).is_some_and(|t| now - t < 60_000) {
                return;
            }
            last.insert(key, now);
            if last.len() > 2000 {
                last.retain(|_, t| now - *t < 60_000);
            }
        }
        let pid = a.pid;
        let what = if a.result.is_empty() { String::new() } else { format!(" — {}", a.result) };
        os::toast(
            &self.app,
            &format!("{}{}", rule.name, what),
            &format!("{}{}", a.name, pid.map(|p| format!(" [{p}]")).unwrap_or_default()),
            &a.detail,
            pid,
        );
    }

    pub fn alerts(&self, limit: u32) -> rusqlite::Result<Vec<Alert>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare(
            "SELECT id,ts,rule_id,rule,kind,action,pid,name,exe,detail,result FROM alerts ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = st.query_map([limit], |r| {
            Ok(Alert {
                id: r.get(0)?,
                ts: r.get(1)?,
                rule_id: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                rule: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                kind: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                action: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                pid: r.get(6)?,
                name: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                exe: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
                detail: r.get::<_, Option<String>>(9)?.unwrap_or_default(),
                result: r.get::<_, Option<String>>(10)?.unwrap_or_default(),
            })
        })?;
        rows.collect()
    }

    pub fn clear_alerts(&self) -> rusqlite::Result<()> {
        self.db.lock().unwrap().execute("DELETE FROM alerts", [])?;
        Ok(())
    }

    pub fn save_rules(&self, rules: Vec<Rule>) -> rusqlite::Result<()> {
        db::meta_set(&self.db.lock().unwrap(), "rules", &serde_json::to_string(&rules).unwrap_or_default())?;
        *self.rules.lock().unwrap() = rules;
        Ok(())
    }
}

pub fn load_rules(c: &Connection) -> Vec<Rule> {
    db::meta_get(c, "rules").ok().flatten().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(default_rules)
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::glob;

    #[test]
    fn globs() {
        assert!(glob("chrome", "C:\\x\\chrome.exe"));
        assert!(glob("*.tmp\\*", "c:\\a\\b.tmp\\setup.exe"));
        assert!(glob("note*.exe|calc.exe", "calc.exe"));
        assert!(!glob("note?.exe", "notepad.exe"));
    }
}
