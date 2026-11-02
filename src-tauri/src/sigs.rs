//! Authenticode verdicts for executables, batched through Get-AuthenticodeSignature
//! (it also understands catalog-signed Windows binaries) and cached in the db.

use crate::db;
use crate::rules::Engine;
use crate::util::{self, now_ms};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tauri::{AppHandle, Emitter};

#[derive(Serialize, Clone, Debug)]
pub struct Sig {
    /// valid | unsigned | untrusted | invalid | error
    pub status: String,
    pub raw: String,
    pub signer: String,
    pub os: bool,
}

#[derive(Serialize, Clone)]
pub struct SigUpdate {
    pub path: String,
    pub sig: Sig,
}

pub struct Sigs {
    map: Mutex<HashMap<String, Sig>>,
    requested: Mutex<HashSet<String>>,
    tx: Mutex<Sender<String>>,
}

impl Sigs {
    /// Cached verdict without queueing a check.
    pub fn cached(&self, exe: &str) -> Option<Sig> {
        self.map.lock().unwrap().get(&exe.to_lowercase()).cloned()
    }

    /// Cached verdict, or None while the check is queued.
    pub fn get(&self, exe: &str) -> Option<Sig> {
        let key = exe.to_lowercase();
        if let Some(s) = self.map.lock().unwrap().get(&key) {
            return Some(s.clone());
        }
        if self.requested.lock().unwrap().insert(key) {
            let _ = self.tx.lock().unwrap().send(exe.to_string());
        }
        None
    }
}

const SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$paths = [Console]::In.ReadToEnd() -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$out = foreach ($p in $paths) {
  $s = Get-AuthenticodeSignature -LiteralPath $p
  [pscustomobject]@{ path = $p; status = [string]$s.Status; subject = [string]$s.SignerCertificate.Subject; os = [bool]$s.IsOSBinary }
}
ConvertTo-Json -InputObject @($out) -Compress
"#;

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawSig {
    path: String,
    status: String,
    subject: String,
    os: bool,
}

fn mtime(path: &str) -> i64 {
    std::fs::metadata(Path::new(path))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Organisation (O=) from a certificate subject, falling back to the common name.
fn signer(subject: &str) -> String {
    let mut parts = Vec::new();
    let (mut cur, mut quoted) = (String::new(), false);
    for c in subject.chars() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    let field = |k: &str| {
        parts.iter().find_map(|p| p.trim().strip_prefix(k).map(|v| v.trim().to_string())).filter(|v| !v.is_empty())
    };
    field("O=").or_else(|| field("CN=")).unwrap_or_default()
}

fn verdict(raw: &str) -> &'static str {
    match raw {
        "Valid" => "valid",
        "NotSigned" => "unsigned",
        "NotTrusted" | "UnknownError" => "untrusted",
        "" => "error",
        _ => "invalid",
    }
}

fn check(paths: &[String]) -> Result<Vec<SigUpdate>, String> {
    let utf16: Vec<u8> = SCRIPT.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, utf16);
    let mut child = util::hidden("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &b64])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    child.stdin.take().unwrap().write_all(paths.join("\n").as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim().trim_start_matches('\u{feff}');
    let raws: Vec<RawSig> = if text.is_empty() { vec![] } else { serde_json::from_str(text).map_err(|e| e.to_string())? };
    let mut by_path: HashMap<String, RawSig> = raws.into_iter().map(|r| (r.path.to_lowercase(), r)).collect();
    Ok(paths
        .iter()
        .map(|p| {
            let r = by_path.remove(&p.to_lowercase()).unwrap_or_default();
            SigUpdate {
                path: p.to_lowercase(),
                sig: Sig { status: verdict(&r.status).into(), raw: r.status, signer: signer(&r.subject), os: r.os },
            }
        })
        .collect())
}

pub fn start(app: AppHandle, db_path: &Path, engine: Arc<Engine>) -> rusqlite::Result<Arc<Sigs>> {
    let conn = db::open(db_path)?;
    let mut map = HashMap::new();
    {
        let mut st = conn.prepare("SELECT path, status, raw, signer, os, mtime FROM sigs")?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, Sig { status: r.get(1)?, raw: r.get(2)?, signer: r.get(3)?, os: r.get::<_, i64>(4)? != 0 }, r.get::<_, i64>(5)?))
        })?;
        for (path, sig, mt) in rows.flatten() {
            // a rewritten file gets checked again
            if mtime(&path) == mt {
                map.insert(path, sig);
            }
        }
    }
    let (tx, rx) = mpsc::channel();
    let sigs = Arc::new(Sigs { map: Mutex::new(map), requested: Mutex::default(), tx: Mutex::new(tx) });
    let me = sigs.clone();
    std::thread::spawn(move || worker(app, conn, me, rx, engine));
    Ok(sigs)
}

fn worker(app: AppHandle, conn: Connection, sigs: Arc<Sigs>, rx: Receiver<String>, engine: Arc<Engine>) {
    while let Ok(first) = rx.recv() {
        // collect a batch: one PowerShell start per burst of new executables
        let mut batch = vec![first];
        let deadline = Instant::now() + Duration::from_millis(1500);
        while batch.len() < 150 {
            match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(p) => batch.push(p),
                Err(_) => break,
            }
        }
        let updates = check(&batch).unwrap_or_else(|e| {
            batch
                .iter()
                .map(|p| SigUpdate { path: p.to_lowercase(), sig: Sig { status: "error".into(), raw: e.clone(), signer: String::new(), os: false } })
                .collect()
        });
        {
            let mut map = sigs.map.lock().unwrap();
            for u in &updates {
                map.insert(u.path.clone(), u.sig.clone());
                if u.sig.status != "error" {
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO sigs(path,status,raw,signer,os,mtime,checked_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                        params![u.path, u.sig.status, u.sig.raw, u.sig.signer, u.sig.os as i64, mtime(&u.path), now_ms()],
                    );
                }
            }
        }
        let _ = app.emit("sigs", &updates);
        engine.on_sigs(&updates);
    }
}
