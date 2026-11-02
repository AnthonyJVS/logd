use std::os::windows::process::CommandExt;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Command that never flashes a console window.
pub fn hidden(program: &str) -> Command {
    let mut c = Command::new(program);
    c.creation_flags(CREATE_NO_WINDOW);
    c
}

pub fn is_admin() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

/// Full image path of a live process (works for most processes without admin).
pub fn exe_path(pid: u32) -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::*;
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let r = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(h);
        r.ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

pub fn kill(pid: u32) -> Result<(), String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::*;
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|e| e.message().to_string())?;
        let r = TerminateProcess(h, 1);
        let _ = CloseHandle(h);
        r.map_err(|e| e.message().to_string())
    }
}

/// Core Windows processes: freezing or killing them hangs or crashes the session.
pub const CRITICAL: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "explorer.exe", "dwm.exe", "fontdrvhost.exe", "memory compression", "logd.exe",
];

pub fn is_critical(pid: u32, name: &str) -> bool {
    pid <= 4 || pid == std::process::id() || CRITICAL.contains(&name.to_lowercase().as_str())
}

#[link(name = "ntdll")]
extern "system" {
    fn NtSuspendProcess(process: *mut std::ffi::c_void) -> i32;
    fn NtResumeProcess(process: *mut std::ffi::c_void) -> i32;
}

/// Freezes (or thaws) every thread of a process at once.
pub fn suspend(pid: u32, resume: bool) -> Result<(), String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::*;
    unsafe {
        let h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid).map_err(|e| e.message().to_string())?;
        let status = if resume { NtResumeProcess(h.0) } else { NtSuspendProcess(h.0) };
        let _ = CloseHandle(h);
        if status < 0 {
            Err(format!("NTSTATUS 0x{:08x}", status as u32))
        } else {
            Ok(())
        }
    }
}

pub fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// Name from the first token of a command line: `"C:\x\a.exe" -y` -> `a.exe`.
pub fn name_from_cmd(cmd: &str) -> String {
    let c = cmd.trim();
    let first = if let Some(rest) = c.strip_prefix('"') {
        rest.split('"').next().unwrap_or("")
    } else {
        c.split(' ').next().unwrap_or("")
    };
    file_name(first)
}

/// Folders a normal user can write to, where unsigned binaries are worth a look.
pub fn risky_dir(exe: &str) -> bool {
    let e = exe.to_lowercase();
    ["\\appdata\\", "\\temp\\", "\\downloads\\", "\\programdata\\", "\\users\\public\\", "\\desktop\\"].iter().any(|d| e.contains(d))
}

/// Warning flags implied by a signature verdict (mirrors the UI).
pub fn sig_flags(status: &str, exe: &str) -> Vec<&'static str> {
    match status {
        "unsigned" if risky_dir(exe) => vec!["unsigned"],
        "invalid" | "untrusted" => vec!["bad-sig"],
        _ => vec![],
    }
}

const SYSTEM_NAMES: &[&str] = &[
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
    "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "rundll32.exe",
    "lsm.exe", "explorer.exe",
];
const DOC_EXTS: &[&str] = &[".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".zip", ".mp4"];

/// Heuristic markers for processes worth a second look. Comma separated.
pub fn flags(name: &str, exe: &str, cmd: &str) -> String {
    let n = name.to_lowercase();
    let e = exe.to_lowercase();
    let c = cmd.to_lowercase();
    let mut f: Vec<&str> = Vec::new();
    if e.contains("\\appdata\\local\\temp\\") || e.contains("\\windows\\temp\\") {
        f.push("temp");
    }
    if e.contains("\\downloads\\") {
        f.push("downloads");
    }
    if e.contains("\\$recycle.bin\\") || e.contains("\\users\\public\\") {
        f.push("odd-path");
    }
    if SYSTEM_NAMES.contains(&n.as_str()) && !e.is_empty() && !e.starts_with("c:\\windows\\") {
        f.push("masquerade");
    }
    let is_ps = n.starts_with("powershell") || n == "pwsh.exe";
    if is_ps && (c.contains(" -enc") || c.contains(" -e ") || c.contains("encodedcommand")) {
        f.push("encoded");
    }
    if is_ps && (c.contains("-windowstyle hidden") || c.contains("-w hidden")) {
        f.push("hidden");
    }
    if n.ends_with(".exe") && DOC_EXTS.iter().any(|x| n[..n.len() - 4].ends_with(x)) {
        f.push("double-ext");
    }
    f.join(",")
}
