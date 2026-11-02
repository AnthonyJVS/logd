//! Windows integration: toast notifications and start-with-Windows.

use crate::util;
use std::path::Path;
use tauri::{AppHandle, Emitter, Manager};
use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

pub const AUMID: &str = "dev.logd.app";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const TASK: &str = "logd";
/// Name the app shipped under before it became Logd.
pub const LEGACY: &str = "archmon";

/// History database of the install under the previous name.
pub fn legacy_db(new_dir: &Path) -> Option<std::path::PathBuf> {
    new_dir.parent().map(|p| p.join(format!("dev.{LEGACY}.app")).join("history.db"))
}


/// An unpackaged app needs its AppUserModelID registered before Windows shows its toasts.
pub fn register_aumid(data_dir: &Path) -> std::io::Result<()> {
    let icon = data_dir.join("icon.png");
    std::fs::write(&icon, include_bytes!("../icons/128x128.png"))?;
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(format!(r"Software\Classes\AppUserModelId\{AUMID}"))?;
    key.set_value("DisplayName", &"Logd")?;
    key.set_value("IconUri", &icon.to_string_lossy().into_owned())?;
    key.set_value("IconBackgroundColor", &"FF23262B")?;
    Ok(())
}

/// Shows a toast; clicking it brings the window up on that process.
pub fn toast(app: &AppHandle, title: &str, line1: &str, line2: &str, pid: Option<u32>) {
    use tauri_winrt_notification::{Duration, Sound, Toast};
    let app = app.clone();
    let res = Toast::new(AUMID)
        .title(title)
        .text1(line1)
        .text2(line2)
        .sound(Some(Sound::Default))
        .duration(Duration::Short)
        .on_activated(move |_| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
            if let Some(pid) = pid {
                let _ = app.emit("open-proc", pid);
            }
            Ok(())
        })
        .show();
    if let Err(e) = res {
        eprintln!("toast: {e:?}");
    }
}

/// off | user (HKCU Run key) | admin (logon task with highest privileges, enables ETW)
pub fn autostart_get() -> String {
    let task = util::hidden("schtasks.exe").args(["/Query", "/TN", TASK]).output().is_ok_and(|o| o.status.success());
    if task {
        return "admin".into();
    }
    let run = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(RUN_KEY)
        .and_then(|k| k.get_value::<String, _>(TASK))
        .is_ok();
    if run { "user".into() } else { "off".into() }
}

pub fn autostart_set(mode: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let cmd = format!("\"{}\" --tray", exe.display());
    let run = RegKey::predef(HKEY_CURRENT_USER).create_subkey(RUN_KEY).map_err(|e| e.to_string())?.0;
    // also drop entries made under the app's previous name
    for name in [TASK, LEGACY] {
        let _ = run.delete_value(name);
        let _ = util::hidden("schtasks.exe").args(["/Delete", "/TN", name, "/F"]).output();
    }
    match mode {
        "off" => Ok(()),
        "user" => run.set_value(TASK, &cmd).map_err(|e| e.to_string()),
        "admin" => {
            if !util::is_admin() {
                return Err("run logd as administrator first to create an elevated logon task".into());
            }
            let out = util::hidden("schtasks.exe")
                .args(["/Create", "/TN", TASK, "/TR", &cmd, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"])
                .output()
                .map_err(|e| e.to_string())?;
            if out.status.success() {
                Ok(())
            } else {
                Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
            }
        }
        _ => Err(format!("unknown mode {mode}")),
    }
}
