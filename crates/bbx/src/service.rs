//! Windows service plumbing (SCM). The service is `bbx.exe service`.

use crate::agent::{self, RunOptions};
use anyhow::Result;
use bbx_collect::Stop;
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "BlackBox";
pub const DISPLAY_NAME: &str = "BlackBox Flight Recorder";
pub const DESCRIPTION: &str =
    "Continuously records system activity with a fixed disk budget so freezes, crashes and slowdowns can be investigated after the fact.";

define_windows_service!(ffi_service_main, service_main);

/// Write an error to the Application event log (source "BlackBox") so it is
/// visible without admin rights (the BlackBox log file is admin-only).
pub fn report_to_event_log(msg: &str) {
    use windows_sys::Win32::System::EventLog::{DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE};
    let src: Vec<u16> = "BlackBox".encode_utf16().chain(Some(0)).collect();
    let text: Vec<u16> = msg.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let h = RegisterEventSourceW(std::ptr::null(), src.as_ptr());
        if h.is_null() {
            return;
        }
        let strings = [text.as_ptr()];
        ReportEventW(h, EVENTLOG_ERROR_TYPE, 0, 1, std::ptr::null_mut(), 1, 0, strings.as_ptr(), std::ptr::null());
        DeregisterEventSource(h);
    }
}

/// The newest startup error the service reported, if any.
pub fn last_reported_error() -> Option<(i64, String)> {
    let ev = bbx_collect::eventlog::query("Application", "*[System[Provider[@Name='BlackBox'] and Level=2]]", 500).ok()?;
    let e = ev.last()?;
    let text = e.message.clone().or_else(|| e.data.values().next().and_then(|v| v.as_str()).map(String::from))?;
    Some((e.event_ft, text))
}

pub fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        log::error!("service failed: {e:#}");
    }
}

fn run_service() -> Result<()> {
    let stop = Stop::new();
    let shutdown = Arc::new(AtomicBool::new(false));
    let (s2, sd2) = (stop.clone(), shutdown.clone());
    let handler = move |ev| match ev {
        ServiceControl::Stop => {
            s2.signal();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Shutdown => {
            sd2.store(true, Ordering::SeqCst);
            s2.signal();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let h = service_control_handler::register(SERVICE_NAME, handler)?;
    let status = |state, accept, wait: u64| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(wait),
        process_id: None,
    };
    h.set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0))?;

    let result = agent::run(stop, shutdown, RunOptions { console: false, verbose: false });

    let mut st = status(ServiceState::Stopped, ServiceControlAccept::empty(), 0);
    if let Err(e) = &result {
        log::error!("agent exited with error: {e:#}");
        report_to_event_log(&format!("BlackBox could not start recording: {e:#}"));
        // A non-zero exit makes SCM apply the recovery (restart) actions.
        st.exit_code = ServiceExitCode::ServiceSpecific(1);
    }
    h.set_service_status(st)?;
    // Everything is saved by now. Make sure the process really goes away:
    // a stuck worker thread once kept it alive after reporting STOPPED,
    // which locked bbx.exe and blocked the next install.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(3));
        log::warn!("process still alive 3 s after stopping; terminating");
        log::logger().flush();
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(windows_sys::Win32::System::Threading::GetCurrentProcess(), 0);
        }
    });
    result
}
