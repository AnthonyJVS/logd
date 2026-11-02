//! Kernel process events via ETW: exact spawn/exit times, exit codes and
//! processes that live only a few milliseconds. Requires administrator rights.

use crate::db::ProcRow;
use crate::monitor::Tracker;
use crate::rules::Engine;
use crate::util::{self, now_ms};
use ferrisetw::parser::Parser;
use ferrisetw::provider::{kernel_providers, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{stop_trace_by_name, KernelTrace};
use ferrisetw::EventRecord;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};

const SESSION: &str = "logd-kernel-process";
const FILETIME_UNIX_DIFF: i64 = 116_444_736_000_000_000;

fn filetime_ms(ft: i64) -> Option<i64> {
    // anything outside 2000..2100 means the clock isn't a FILETIME
    let ms = (ft - FILETIME_UNIX_DIFF) / 10_000;
    (946_684_800_000..4_102_444_800_000).contains(&ms).then_some(ms)
}

pub fn start(app: AppHandle, tracker: Arc<Mutex<Tracker>>, engine: Arc<Engine>) -> Result<(), String> {
    let _ = stop_trace_by_name(SESSION);
    let _ = stop_trace_by_name("archmon-kernel-process");
    let provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
            let op = rec.opcode();
            if op != 1 && op != 2 {
                return;
            }
            let Ok(schema) = loc.event_schema(rec) else { return };
            let p = Parser::create(rec, &schema);
            let pid: u32 = p.try_parse("ProcessId").unwrap_or(0);
            if pid == 0 {
                return;
            }
            let ts = filetime_ms(rec.raw_timestamp()).unwrap_or_else(now_ms);
            let mut evs = Vec::new();
            if op == 1 {
                let ppid: u32 = p.try_parse("ParentId").unwrap_or(0);
                let image: String = p.try_parse("ImageFileName").unwrap_or_default();
                let cmd: String = p.try_parse("CommandLine").unwrap_or_default();
                let exe = util::exe_path(pid).unwrap_or_default();
                let name = if !exe.is_empty() {
                    util::file_name(&exe)
                } else {
                    let from_cmd = util::name_from_cmd(&cmd);
                    if from_cmd.len() > image.len() { from_cmd } else { image }
                };
                let row = ProcRow {
                    pid,
                    ppid: (ppid != 0).then_some(ppid),
                    name,
                    exe,
                    cmd,
                    start_ms: ts,
                    source: "etw".into(),
                    ..Default::default()
                };
                tracker.lock().unwrap().start(row, &mut evs);
            } else {
                let code: Option<i64> = p.try_parse::<u32>("ExitStatus").ok().map(|c| c as i32 as i64);
                tracker.lock().unwrap().stop(pid, code, ts, &mut evs);
            }
            if !evs.is_empty() {
                let _ = app.emit("proc-events", &evs);
                engine.on_proc_events(&evs);
            }
        })
        .build();

    let trace = KernelTrace::new()
        .named(SESSION.to_string())
        .enable(provider)
        .start_and_process()
        .map_err(|e| format!("{e:?}"))?;
    // lives for the whole run; the session is stopped by name on exit
    Box::leak(Box::new(trace));
    Ok(())
}

pub fn shutdown() {
    let _ = stop_trace_by_name(SESSION);
}
