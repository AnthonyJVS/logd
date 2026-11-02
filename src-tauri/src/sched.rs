//! "About to start": scheduled tasks with their next run time, services that
//! are pending or set to auto-start but not running, and logon startup items.

use crate::util::{self, now_ms};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct Upcoming {
    pub kind: String, // task | service | startup
    pub name: String,
    pub path: String,
    pub exe: String,
    pub next_ms: Option<i64>,
    pub last_ms: Option<i64>,
    pub last_result: Option<i64>,
    pub state: String,
    pub info: String,
}

#[derive(Serialize, Clone, Default)]
pub struct UpcomingState {
    pub items: Vec<Upcoming>,
    pub scanned_ms: i64,
    pub scanning: bool,
    pub error: Option<String>,
}

const SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function ms($d) { if ($d -and $d.Year -gt 2000) { [int64]([DateTimeOffset]$d).ToUnixTimeMilliseconds() } else { $null } }
$out = New-Object System.Collections.Generic.List[object]
foreach ($t in (Get-ScheduledTask)) {
  if ($t.State -eq 'Disabled') { continue }
  $i = $t | Get-ScheduledTaskInfo
  $exe = (@($t.Actions | ForEach-Object { if ($_.Execute) { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() } elseif ($_.ClassId) { 'COM ' + $_.ClassId } }) -join ' ; ')
  $trig = (@($t.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace '^MSFT_Task','' -replace 'Trigger$','' }) -join ',')
  $out.Add([pscustomobject]@{ kind='task'; name=[string]$t.TaskName; path=[string]$t.TaskPath; exe=$exe; next_ms=(ms $i.NextRunTime); last_ms=(ms $i.LastRunTime); last_result=[int64]$i.LastTaskResult; state=[string]$t.State; info=$trig })
}
foreach ($s in (Get-CimInstance Win32_Service)) {
  if ($s.State -like '*Pending*' -or ($s.StartMode -eq 'Auto' -and $s.State -ne 'Running')) {
    $d = if ($s.DelayedAutoStart) { ' delayed' } else { '' }
    $out.Add([pscustomobject]@{ kind='service'; name=[string]$s.Name; path=[string]$s.DisplayName; exe=[string]$s.PathName; next_ms=$null; last_ms=$null; last_result=[int64]$s.ExitCode; state=[string]$s.State; info=([string]$s.StartMode + $d) })
  }
}
foreach ($c in (Get-CimInstance Win32_StartupCommand)) {
  $out.Add([pscustomobject]@{ kind='startup'; name=[string]$c.Name; path=[string]$c.Location; exe=[string]$c.Command; next_ms=$null; last_ms=$null; last_result=$null; state='logon'; info=[string]$c.User })
}
ConvertTo-Json -InputObject ([object[]]$out.ToArray()) -Compress -Depth 3
"#;

pub fn scan() -> Result<Vec<Upcoming>, String> {
    let utf16: Vec<u8> = SCRIPT.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
    let out = util::hidden("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &b64])
        .output()
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim().trim_start_matches('\u{feff}');
    if text.is_empty() {
        return Err(String::from_utf8_lossy(&out.stderr).chars().take(300).collect());
    }
    serde_json::from_str(text).map_err(|e| format!("{e}"))
}

/// Rescans every 5 minutes, shortly after the earliest due task, or on demand.
pub fn run(app: AppHandle, state: Arc<Mutex<UpcomingState>>, wake: Receiver<()>) {
    loop {
        state.lock().unwrap().scanning = true;
        let _ = app.emit("upcoming", &*state.lock().unwrap());
        let res = scan();
        let next_due = {
            let mut s = state.lock().unwrap();
            s.scanning = false;
            s.scanned_ms = now_ms();
            match res {
                Ok(mut items) => {
                    items.sort_by_key(|u| u.next_ms.unwrap_or(i64::MAX));
                    s.items = items;
                    s.error = None;
                }
                Err(e) => s.error = Some(e),
            }
            let _ = app.emit("upcoming", &*s);
            s.items.iter().filter_map(|u| u.next_ms).filter(|t| *t > s.scanned_ms).min()
        };
        let mut wait = 300_000i64;
        if let Some(t) = next_due {
            wait = wait.min(t - now_ms() + 15_000);
        }
        let _ = wake.recv_timeout(Duration::from_millis(wait.max(20_000) as u64));
        while wake.try_recv().is_ok() {}
    }
}
