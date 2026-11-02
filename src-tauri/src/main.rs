#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod autoruns;
mod db;
mod etw;
mod monitor;
mod net;
mod os;
mod rules;
mod sched;
mod sigs;
mod util;

use monitor::{ProcEvent, Settings, Shared, Snapshot, Tracker};
use rusqlite::Connection;
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, RunEvent, State, WindowEvent};

struct AppState {
    tracker: Arc<Mutex<Tracker>>,
    reader: Mutex<Connection>,
    shared: Arc<Shared>,
    upcoming: Arc<Mutex<sched::UpcomingState>>,
    rescan: Mutex<Sender<()>>,
    info: SysInfo,
    engine: Arc<rules::Engine>,
}

#[derive(Serialize, Clone)]
struct SysInfo {
    host: String,
    os: String,
    kernel: String,
    cpu_brand: String,
    cores: usize,
    mem_total: u64,
    boot_ms: i64,
    user: String,
    admin: bool,
    db_path: String,
    version: String,
    pid: u32,
}

type R<T> = Result<T, String>;
fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

#[tauri::command]
fn get_info(st: State<AppState>) -> serde_json::Value {
    let mut v = serde_json::to_value(&st.info).unwrap();
    v["etw"] = st.shared.etw.load(Ordering::Relaxed).into();
    v["etw_error"] = st.shared.etw_error.lock().unwrap().clone().into();
    v["db_note"] = st.shared.db_note.lock().unwrap().clone().into();
    v
}

#[tauri::command]
fn get_snapshot(st: State<AppState>) -> Snapshot {
    st.shared.snap.lock().unwrap().clone()
}

#[tauri::command]
fn recent_events(st: State<AppState>, since_ms: i64, limit: u32) -> R<Vec<ProcEvent>> {
    let rows = db::recent(&st.reader.lock().unwrap(), since_ms, limit).map_err(e)?;
    let mut evs = Vec::new();
    for r in rows {
        if !r.existing && r.start_ms >= since_ms {
            evs.push(ProcEvent { kind: "start".into(), ts: r.start_ms, lifetime_ms: None, row: r.clone() });
        }
        if let Some(end) = r.end_ms.filter(|x| *x >= since_ms) {
            evs.push(ProcEvent { kind: "stop".into(), ts: end, lifetime_ms: Some(end - r.start_ms), row: r });
        }
    }
    evs.sort_by_key(|x| x.ts);
    Ok(evs)
}

#[tauri::command]
fn query_history(st: State<AppState>, from_ms: i64, to_ms: i64, search: String, limit: u32, hide_long: bool) -> R<Vec<db::ProcRow>> {
    db::history(&st.reader.lock().unwrap(), from_ms, to_ms, search.trim(), limit, hide_long).map_err(e)
}

#[tauri::command]
fn get_samples(st: State<AppState>, from_ms: i64, to_ms: i64, buckets: u32) -> R<Vec<db::Sample>> {
    db::samples(&st.reader.lock().unwrap(), from_ms, to_ms, buckets).map_err(e)
}

#[tauri::command]
fn exe_history(st: State<AppState>, exe: String, name: String, limit: u32) -> R<db::ExeHistory> {
    db::exe_history(&st.reader.lock().unwrap(), &exe, &name, limit).map_err(e)
}

#[tauri::command]
fn get_row(st: State<AppState>, id: i64) -> R<Option<db::ProcRow>> {
    db::get_row(&st.reader.lock().unwrap(), id).map_err(e)
}

#[tauri::command]
fn net_history(st: State<AppState>, exe: String, name: String, limit: u32) -> R<Vec<db::NetRow>> {
    db::net_history(&st.reader.lock().unwrap(), &exe, &name, limit).map_err(e)
}

#[tauri::command]
fn net_recent(st: State<AppState>, only_novel: bool, limit: u32) -> R<Vec<db::NetRow>> {
    db::net_recent(&st.reader.lock().unwrap(), only_novel, limit).map_err(e)
}

#[tauri::command]
fn get_upcoming(st: State<AppState>) -> sched::UpcomingState {
    st.upcoming.lock().unwrap().clone()
}

#[tauri::command]
fn refresh_upcoming(st: State<AppState>) {
    let _ = st.rescan.lock().unwrap().send(());
}

#[tauri::command]
fn kill_process(pid: u32) -> R<()> {
    util::kill(pid)
}

#[tauri::command]
fn open_location(path: String) -> R<()> {
    use std::os::windows::process::CommandExt;
    util::hidden("explorer.exe").raw_arg(format!("/select,\"{path}\"")).spawn().map(|_| ()).map_err(e)
}

#[tauri::command]
fn get_settings(st: State<AppState>) -> Settings {
    st.shared.settings.lock().unwrap().clone()
}

#[tauri::command]
fn set_settings(st: State<AppState>, settings: Settings) -> R<()> {
    let json = serde_json::to_string(&settings).map_err(e)?;
    db::meta_set(&st.tracker.lock().unwrap().db, "settings", &json).map_err(e)?;
    st.engine.notify_os.store(settings.notify_os, Ordering::Relaxed);
    *st.shared.settings.lock().unwrap() = settings;
    Ok(())
}

#[tauri::command]
fn export_csv(app: AppHandle, st: State<AppState>, from_ms: i64, to_ms: i64, search: String) -> R<String> {
    let rows = db::history(&st.reader.lock().unwrap(), from_ms, to_ms, search.trim(), 1_000_000, false).map_err(e)?;
    let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    let mut out = String::from("\u{feff}id,pid,ppid,parent,name,exe,cmd,user,start,end,lifetime_ms,exit_code,source,flags,peak_mem\n");
    for r in rows {
        out += &format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            r.id,
            r.pid,
            r.ppid.map(|x| x.to_string()).unwrap_or_default(),
            q(&r.parent),
            q(&r.name),
            q(&r.exe),
            q(&r.cmd),
            q(&r.user),
            r.start_ms,
            r.end_ms.map(|x| x.to_string()).unwrap_or_default(),
            r.end_ms.map(|x| (x - r.start_ms).to_string()).unwrap_or_default(),
            r.exit_code.map(|x| x.to_string()).unwrap_or_default(),
            r.source,
            q(&r.flags),
            r.peak_mem
        );
    }
    let dir = app.path().download_dir().map_err(e)?;
    let path = dir.join(format!("logd-{}.csv", util::now_ms()));
    std::fs::write(&path, out).map_err(e)?;
    Ok(path.to_string_lossy().into_owned())
}

#[tauri::command]
fn restart_admin(app: AppHandle) -> R<()> {
    let exe = std::env::current_exe().map_err(e)?;
    let status = util::hidden("powershell.exe")
        .args(["-NoProfile", "-Command", &format!("Start-Process -FilePath '{}' -Verb RunAs", exe.display())])
        .status()
        .map_err(e)?;
    if !status.success() {
        return Err("UAC prompt was declined".into());
    }
    app.exit(0);
    Ok(())
}

#[tauri::command]
fn get_rules(st: State<AppState>) -> Vec<rules::Rule> {
    st.engine.rules.lock().unwrap().clone()
}

#[tauri::command]
fn set_rules(st: State<AppState>, rules: Vec<rules::Rule>) -> R<()> {
    st.engine.save_rules(rules).map_err(e)
}

#[tauri::command]
fn default_rules() -> Vec<rules::Rule> {
    rules::default_rules()
}

#[tauri::command]
fn get_alerts(st: State<AppState>, limit: u32) -> R<Vec<rules::Alert>> {
    st.engine.alerts(limit).map_err(e)
}

#[tauri::command]
fn clear_alerts(st: State<AppState>) -> R<()> {
    st.engine.clear_alerts().map_err(e)
}

#[tauri::command]
fn get_autostart() -> String {
    os::autostart_get()
}

#[tauri::command]
fn set_autostart(mode: String) -> R<()> {
    os::autostart_set(&mode)
}

#[tauri::command]
fn test_toast(app: AppHandle) {
    os::toast(&app, "logd", "Notifications work", "Rule alerts will show up like this.", None);
}

#[tauri::command(async)]
fn autoruns_list(st: State<AppState>) -> R<Vec<autoruns::AutoItem>> {
    let c = db::open(std::path::Path::new(&st.info.db_path)).map_err(e)?;
    autoruns::list(&c)
}

#[tauri::command(async)]
fn autorun_set(st: State<AppState>, item: autoruns::AutoItem, enable: bool) -> R<()> {
    let c = db::open(std::path::Path::new(&st.info.db_path)).map_err(e)?;
    autoruns::set(&c, &item, enable)
}

#[tauri::command]
fn suspend_process(st: State<AppState>, pid: u32, resume: bool) -> R<()> {
    let name = st.shared.snap.lock().unwrap().procs.iter().find(|p| p.pid == pid).map(|p| p.name.clone()).unwrap_or_default();
    if util::is_critical(pid, &name) {
        return Err(format!("{name} is a core Windows process; freezing it would hang the system"));
    }
    util::suspend(pid, resume)?;
    let mut set = st.shared.suspended.lock().unwrap();
    if resume { set.remove(&pid); } else { set.insert(pid); }
    Ok(())
}

#[tauri::command]
fn quit_app(app: AppHandle) {
    app.exit(0);
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn main() {
    tauri::Builder::default()
        // a second launch just brings the running window forward
        .plugin(tauri_plugin_single_instance::init(|app, _, _| show_main(app)))
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let db_path = dir.join("history.db");
            let (writer, db_note) = db::open_checked(&db_path, os::legacy_db(&dir).as_deref())?;
            let reader = db::open(&db_path)?;
            if let Err(err) = os::register_aumid(&dir) {
                eprintln!("aumid: {err}");
            }
            db::reconcile(&writer)?;
            autoruns::init(&writer)?;
            let settings: Settings = db::meta_get(&writer, "settings")?
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

            let mut sys = sysinfo::System::new();
            sys.refresh_cpu_all();
            sys.refresh_memory();
            let admin = util::is_admin();
            let info = SysInfo {
                host: sysinfo::System::host_name().unwrap_or_default(),
                os: sysinfo::System::long_os_version().unwrap_or_default(),
                kernel: sysinfo::System::kernel_version().unwrap_or_default(),
                cpu_brand: sys.cpus().first().map(|c| c.brand().trim().to_string()).unwrap_or_default(),
                cores: sys.cpus().len(),
                mem_total: sys.total_memory(),
                boot_ms: sysinfo::System::boot_time() as i64 * 1000,
                user: std::env::var("USERNAME").unwrap_or_default(),
                admin,
                db_path: db_path.to_string_lossy().into_owned(),
                version: env!("CARGO_PKG_VERSION").into(),
                pid: std::process::id(),
            };

            let engine = rules::Engine::new(app.handle().clone(), db::open(&db_path)?, rules::load_rules(&writer), settings.notify_os);
            let tracker = Arc::new(Mutex::new(Tracker::new(writer)));
            let shared = Arc::new(Shared {
                snap: Mutex::new(Snapshot::default()),
                etw: Default::default(),
                etw_error: Mutex::new(None),
                settings: Mutex::new(settings),
                suspended: Mutex::default(),
                db_note: Mutex::new(None),
            });
            let upcoming = Arc::new(Mutex::new(sched::UpcomingState::default()));
            let (tx, rx) = mpsc::channel();
            app.manage(AppState {
                tracker: tracker.clone(),
                reader: Mutex::new(reader),
                shared: shared.clone(),
                upcoming: upcoming.clone(),
                rescan: Mutex::new(tx),
                info,
                engine: engine.clone(),
            });

            if let Some(note) = db_note {
                eprintln!("{note}");
                *shared.db_note.lock().unwrap() = Some(note);
            }
            if admin {
                match etw::start(app.handle().clone(), tracker.clone(), engine.clone()) {
                    Ok(()) => shared.etw.store(true, Ordering::Relaxed),
                    Err(err) => *shared.etw_error.lock().unwrap() = Some(err),
                }
            } else {
                *shared.etw_error.lock().unwrap() = Some("administrator rights required".into());
            }
            let sigs = sigs::start(app.handle().clone(), &db_path, engine.clone())?;
            engine.attach(tracker.clone(), sigs.clone());
            let resolver = net::Resolver::start();
            {
                let (h, t, s) = (app.handle().clone(), tracker, shared);
                let eng = engine.clone();
                std::thread::spawn(move || monitor::run_poller(h, t, s, sigs, resolver, eng));
            }
            {
                let h = app.handle().clone();
                std::thread::spawn(move || sched::run(h, upcoming, rx));
            }

            let show = MenuItem::with_id(app, "show", "Show logd", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::with_id("tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("logd — process monitor")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, ev| match ev.id.as_ref() {
                    "show" => show_main(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, ev| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;

            // started by autostart: stay in the tray
            if !std::env::args().any(|a| a == "--tray") {
                show_main(app.handle());
            }
            Ok(())
        })
        .on_window_event(|w, ev| {
            // closing hides to tray so history keeps recording
            if let WindowEvent::CloseRequested { api, .. } = ev {
                api.prevent_close();
                let _ = w.hide();
                let _ = w.emit("hidden-to-tray", ());
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_info,
            get_snapshot,
            recent_events,
            query_history,
            get_samples,
            exe_history,
            get_row,
            net_history,
            net_recent,
            get_upcoming,
            refresh_upcoming,
            kill_process,
            open_location,
            get_settings,
            set_settings,
            export_csv,
            restart_admin,
            get_rules,
            set_rules,
            default_rules,
            get_alerts,
            clear_alerts,
            get_autostart,
            set_autostart,
            test_toast,
            autoruns_list,
            autorun_set,
            suspend_process,
            quit_app
        ])
        .build(tauri::generate_context!())
        .expect("failed to build logd")
        .run(|_, ev| {
            if let RunEvent::Exit = ev {
                etw::shutdown();
            }
        });
}
