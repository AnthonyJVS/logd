//! Everything that starts automatically, including places Task Manager does
//! not show (RunOnce, policy Run keys, Winlogon, IFEO debuggers, AppInit DLLs,
//! WMI subscriptions), with reversible disable/enable.
//!
//! Run keys and startup-folder items are toggled the way Task Manager does it
//! (StartupApproved), tasks via schtasks. Everything else is backed up into the
//! `autorun_backup` table before it is changed, so it can be put back.

use crate::util::{self, now_ms};
use base64::Engine as _;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use winreg::enums::*;
use winreg::{RegKey, RegValue};

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(default)]
pub struct AutoItem {
    /// run | folder | task | service | winlogon | ifeo | appinit | wmi
    pub kind: String,
    pub location: String,
    pub name: String,
    pub command: String,
    pub enabled: bool,
    /// not visible in Task Manager's Startup page
    pub hidden: bool,
    /// shipped with Windows
    pub ms: bool,
    pub hive: String,
    pub key: String,
    pub value: String,
    /// StartupApproved subkey (Run, Run32, StartupFolder) when Windows tracks its state
    pub approved: String,
    /// start mode for services
    pub mode: String,
    /// set for entries Logd disabled by backing them up
    pub backup_id: Option<i64>,
}

const SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$out = New-Object System.Collections.Generic.List[object]
function Add($kind, $loc, $name, $cmd, $enabled, $hidden, $extra) {
  $o = [ordered]@{ kind = $kind; location = [string]$loc; name = [string]$name; command = [string]$cmd; enabled = [bool]$enabled; hidden = [bool]$hidden; ms = $false; hive = ''; key = ''; value = ''; approved = ''; mode = '' }
  if ($extra) { foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] } }
  $out.Add([pscustomobject]$o)
}
function Approved($hive, $sub, $name) {
  $v = (Get-ItemProperty -LiteralPath "${hive}:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$sub" -Name $name).$name
  if ($v -is [byte[]] -and $v.Length -gt 0) { return (($v[0] -band 1) -eq 0) }
  return $true
}
$runs = @(
  @('HKCU', 'Software\Microsoft\Windows\CurrentVersion\Run', 'Run', $false),
  @('HKLM', 'Software\Microsoft\Windows\CurrentVersion\Run', 'Run', $false),
  @('HKLM', 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'Run32', $false),
  @('HKCU', 'Software\Microsoft\Windows\CurrentVersion\RunOnce', '', $true),
  @('HKLM', 'Software\Microsoft\Windows\CurrentVersion\RunOnce', '', $true),
  @('HKLM', 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce', '', $true),
  @('HKCU', 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', '', $true),
  @('HKLM', 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', '', $true))
foreach ($r in $runs) {
  $k = Get-Item -LiteralPath "$($r[0]):\$($r[1])"
  if (-not $k) { continue }
  foreach ($n in $k.GetValueNames()) {
    if ($n -eq '') { continue }
    $en = if ($r[2]) { Approved $r[0] $r[2] $n } else { $true }
    Add 'run' "$($r[0])\$($r[1])" $n $k.GetValue($n) $en $r[3] @{ hive = $r[0]; key = $r[1]; value = $n; approved = $r[2] }
  }
}
$legacy = Get-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows'
foreach ($n in 'Load', 'Run') {
  $v = [string]$legacy.GetValue($n)
  if ($v.Trim()) { Add 'run' 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows' $n $v $true $true @{ hive = 'HKCU'; key = 'Software\Microsoft\Windows NT\CurrentVersion\Windows'; value = $n } }
}
$shell = New-Object -ComObject WScript.Shell
foreach ($f in @(@('HKCU', [Environment]::GetFolderPath('Startup')), @('HKLM', [Environment]::GetFolderPath('CommonStartup')))) {
  foreach ($file in (Get-ChildItem -LiteralPath $f[1] -File -Force)) {
    if ($file.Name -eq 'desktop.ini') { continue }
    $target = $file.FullName
    if ($file.Extension -eq '.lnk') { $l = $shell.CreateShortcut($file.FullName); if ($l.TargetPath) { $target = ($l.TargetPath + ' ' + $l.Arguments).Trim() } }
    $hid = ($file.Attributes -band [IO.FileAttributes]::Hidden) -ne 0
    Add 'folder' $f[1] $file.Name $target (Approved $f[0] 'StartupFolder' $file.Name) $hid @{ hive = $f[0]; key = $file.FullName; value = $file.Name; approved = 'StartupFolder' }
  }
}
foreach ($t in (Get-ScheduledTask)) {
  $tr = @($t.Triggers | ForEach-Object { $_.CimClass.CimClassName })
  if (-not ($tr -match 'Logon|Boot')) { continue }
  $cmd = (@($t.Actions | ForEach-Object { if ($_.Execute) { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() } elseif ($_.ClassId) { 'COM ' + $_.ClassId } }) -join ' ; ')
  Add 'task' $t.TaskPath $t.TaskName $cmd ($t.State -ne 'Disabled') ([bool]$t.Settings.Hidden) @{ key = ($t.TaskPath + $t.TaskName); ms = ($t.TaskPath -like '\Microsoft\*') }
}
foreach ($s in (Get-CimInstance Win32_Service)) {
  if ($s.StartMode -ne 'Auto') { continue }
  $p = [string]$s.PathName
  $mode = if ($s.DelayedAutoStart) { 'delayed-auto' } else { 'auto' }
  Add 'service' $s.Name $s.DisplayName $p $true $false @{ key = $s.Name; mode = $mode; ms = ($p -match '(?i)\\windows\\') }
}
$wl = Get-Item -LiteralPath 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
$shellV = [string]$wl.GetValue('Shell'); $ui = [string]$wl.GetValue('Userinit')
if ($shellV -and $shellV.Trim() -ne 'explorer.exe') { Add 'winlogon' 'HKLM\...\Winlogon' 'Shell' $shellV $true $true @{ hive = 'HKLM'; key = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'; value = 'Shell' } }
if ($ui -and $ui.Trim().TrimEnd(',') -notmatch '(?i)^c:\\windows\\system32\\userinit\.exe$') { Add 'winlogon' 'HKLM\...\Winlogon' 'Userinit' $ui $true $true @{ hive = 'HKLM'; key = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'; value = 'Userinit' } }
foreach ($k in (Get-ChildItem -LiteralPath 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
  $d = [string]$k.GetValue('Debugger')
  if ($d) { Add 'ifeo' 'Image File Execution Options' $k.PSChildName $d $true $true @{ hive = 'HKLM'; key = ('Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\' + $k.PSChildName); value = 'Debugger' } }
}
foreach ($base in 'Software\Microsoft\Windows NT\CurrentVersion\Windows', 'Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
  $k = Get-Item -LiteralPath "HKLM:\$base"
  $v = [string]$k.GetValue('AppInit_DLLs')
  if ($v.Trim()) { Add 'appinit' "HKLM\$base" 'AppInit_DLLs' $v ([int]$k.GetValue('LoadAppInit_DLLs') -eq 1) $true @{ hive = 'HKLM'; key = $base; value = 'AppInit_DLLs' } }
}
foreach ($c in @(Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer) + @(Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer)) {
  if (-not $c) { continue }
  $cmd = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } else { [string]$c.ScriptText }
  Add 'wmi' ('root\subscription ' + $c.CimClass.CimClassName) $c.Name $cmd $true $true @{ key = $c.Name; value = $c.CimClass.CimClassName }
}
ConvertTo-Json -InputObject ([object[]]$out.ToArray()) -Compress -Depth 3
"#;

pub fn init(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS autorun_backup(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, name TEXT, location TEXT,
           command TEXT, hive TEXT, key TEXT, value TEXT, vtype INTEGER, data TEXT, mode TEXT, ts INTEGER)",
    )
}

fn run_ps(script: &str) -> Result<String, String> {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
    let out = util::hidden("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &b64])
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().trim_start_matches('\u{feff}').to_string())
}

/// Live entries plus the ones Logd disabled by backing them up.
pub fn list(c: &Connection) -> Result<Vec<AutoItem>, String> {
    let text = run_ps(SCRIPT)?;
    let mut items: Vec<AutoItem> = if text.is_empty() { vec![] } else { serde_json::from_str(&text).map_err(|e| e.to_string())? };
    let mut st = c.prepare("SELECT id, kind, name, location, command, hive, key, value, mode FROM autorun_backup ORDER BY ts DESC").map_err(|e| e.to_string())?;
    let backups = st
        .query_map([], |r| {
            Ok(AutoItem {
                backup_id: Some(r.get(0)?),
                kind: r.get(1)?,
                name: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                location: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                command: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                hive: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                key: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                value: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                mode: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
                enabled: false,
                hidden: true,
                ..Default::default()
            })
        })
        .map_err(|e| e.to_string())?;
    for b in backups.flatten() {
        // a disabled service is still listed by Windows, just not as auto-start
        items.retain(|i| !(i.kind == b.kind && i.key == b.key && i.value == b.value));
        items.push(b);
    }
    Ok(items)
}

fn hive(name: &str) -> RegKey {
    RegKey::predef(if name == "HKLM" { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER })
}

fn reg_err(e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        "access denied — restart Logd as administrator for system-wide entries".into()
    } else {
        e.to_string()
    }
}

/// Task Manager's on/off switch for Run and startup-folder entries.
fn set_approved(item: &AutoItem, enable: bool) -> Result<(), String> {
    let path = format!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{}", item.approved);
    let (key, _) = hive(&item.hive).create_subkey(&path).map_err(reg_err)?;
    let mut bytes = vec![if enable { 2u8 } else { 3u8 }, 0, 0, 0];
    let ft = if enable {
        0u64
    } else {
        // disable time as FILETIME, like Task Manager records it
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64 / 100 + 116_444_736_000_000_000).unwrap_or(0)
    };
    bytes.extend_from_slice(&ft.to_le_bytes());
    key.set_raw_value(&item.value, &RegValue { bytes, vtype: REG_BINARY }).map_err(reg_err)
}

/// Saves a registry value into the backup table, then deletes it or writes the Windows default.
fn backup_registry(c: &Connection, item: &AutoItem) -> Result<(), String> {
    let key = hive(&item.hive).open_subkey_with_flags(&item.key, KEY_READ | KEY_WRITE).map_err(reg_err)?;
    let raw = key.get_raw_value(&item.value).map_err(reg_err)?;
    c.execute(
        "INSERT INTO autorun_backup(kind,name,location,command,hive,key,value,vtype,data,mode,ts) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'',?10)",
        params![item.kind, item.name, item.location, item.command, item.hive, item.key, item.value, raw.vtype.clone() as u32,
            base64::engine::general_purpose::STANDARD.encode(&raw.bytes), now_ms()],
    )
    .map_err(|e| e.to_string())?;
    let neutral = match (item.kind.as_str(), item.value.as_str()) {
        ("winlogon", "Shell") => Some("explorer.exe"),
        ("winlogon", "Userinit") => Some(r"C:\Windows\system32\userinit.exe,"),
        ("appinit", _) => Some(""),
        _ => None,
    };
    let res = match neutral {
        Some(v) => key.set_value(&item.value, &v.to_string()),
        None => key.delete_value(&item.value),
    };
    if let Err(e) = res {
        // nothing changed, so the backup row must not pretend otherwise
        let _ = c.execute("DELETE FROM autorun_backup WHERE id=?1", [c.last_insert_rowid()]);
        return Err(reg_err(e));
    }
    Ok(())
}

fn restore_registry(c: &Connection, id: i64) -> Result<(), String> {
    let (h, k, v, vtype, data): (String, String, String, u32, String) = c
        .query_row("SELECT hive, key, value, vtype, data FROM autorun_backup WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .map_err(|e| e.to_string())?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(data).map_err(|e| e.to_string())?;
    let vtype = match vtype {
        2 => REG_EXPAND_SZ,
        7 => REG_MULTI_SZ,
        3 => REG_BINARY,
        4 => REG_DWORD,
        _ => REG_SZ,
    };
    let (key, _) = hive(&h).create_subkey(&k).map_err(reg_err)?;
    key.set_raw_value(&v, &RegValue { bytes, vtype }).map_err(reg_err)?;
    c.execute("DELETE FROM autorun_backup WHERE id=?1", [id]).map_err(|e| e.to_string())?;
    Ok(())
}

fn cmd_ok(program: &str, args: &[&str]) -> Result<(), String> {
    let out = util::hidden(program).args(args).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    let msg = String::from_utf8_lossy(&out.stderr).trim().to_string() + String::from_utf8_lossy(&out.stdout).trim();
    let msg = if msg.is_empty() { format!("{program} failed") } else { msg };
    Err(if util::is_admin() { msg } else { format!("{msg} (system entries need Logd running as administrator)") })
}

pub fn set(c: &Connection, item: &AutoItem, enable: bool) -> Result<(), String> {
    match item.kind.as_str() {
        "run" | "folder" if !item.approved.is_empty() => set_approved(item, enable),
        "task" => cmd_ok("schtasks.exe", &["/Change", "/TN", &item.key, if enable { "/ENABLE" } else { "/DISABLE" }]),
        "service" => {
            if enable {
                let id = item.backup_id.ok_or("no saved start mode for this service")?;
                let mode: String = c.query_row("SELECT mode FROM autorun_backup WHERE id=?1", [id], |r| r.get(0)).map_err(|e| e.to_string())?;
                cmd_ok("sc.exe", &["config", &item.key, "start=", if mode.is_empty() { "auto" } else { &mode }])?;
                c.execute("DELETE FROM autorun_backup WHERE id=?1", [id]).map_err(|e| e.to_string())?;
                Ok(())
            } else {
                cmd_ok("sc.exe", &["config", &item.key, "start=", "disabled"])?;
                c.execute(
                    "INSERT INTO autorun_backup(kind,name,location,command,hive,key,value,vtype,data,mode,ts) VALUES('service',?1,?2,?3,'',?4,'',0,'',?5,?6)",
                    params![item.name, item.location, item.command, item.key, item.mode, now_ms()],
                )
                .map_err(|e| e.to_string())?;
                Ok(())
            }
        }
        "wmi" => {
            if enable {
                return Err("a removed WMI subscription cannot be restored".into());
            }
            let name = item.key.replace('\'', "''");
            let script = format!(
                "$ErrorActionPreference='Stop'; Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding | \
                 Where-Object {{ $_.Consumer.Name -eq '{name}' }} | Remove-CimInstance; \
                 Get-CimInstance -Namespace root\\subscription -ClassName {} | Where-Object {{ $_.Name -eq '{name}' }} | Remove-CimInstance; 'ok'",
                item.value
            );
            if run_ps(&script)?.ends_with("ok") { Ok(()) } else { Err("could not remove — administrator rights required".into()) }
        }
        // RunOnce, policy Run keys, legacy Load/Run, Winlogon, IFEO, AppInit
        _ => {
            if enable {
                restore_registry(c, item.backup_id.ok_or("nothing to restore")?)
            } else {
                backup_registry(c, item)
            }
        }
    }
}
