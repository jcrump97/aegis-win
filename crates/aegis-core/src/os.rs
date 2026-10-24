//! Thin, safe wrappers over the Windows primitives the plugins share.
//!
//! Rules (PLUGIN_SPEC §4): call Win32 directly where an API exists; when a
//! system binary is unavoidable, run it from System32 by absolute path with an
//! argument vector, never through a shell or a PATH lookup.

use std::io::{self, Read};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Globalization::{GetOEMCP, MultiByteToWideChar, MULTI_BYTE_TO_WIDE_CHAR_FLAGS};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, CREATE_NO_WINDOW};
use windows::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId, SW_SHOWNORMAL};

/// True when this process runs with an elevated (administrator) token.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// `C:\Windows\System32` as reported by the OS (not assumed from `%SystemRoot%`).
pub fn system32() -> PathBuf {
    let mut buf = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if len == 0 || len > buf.len() {
        return PathBuf::from(r"C:\Windows\System32");
    }
    PathBuf::from(String::from_utf16_lossy(&buf[..len]))
}

/// Used only to scrub Off-LAN LLM payloads; never sent anywhere itself.
pub fn username() -> Option<String> {
    std::env::var("USERNAME").ok().filter(|s| !s.is_empty())
}

pub fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandOutput {
    pub command: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }

    /// Windows tools print this (in English) when they need an elevated token.
    pub fn mentions_elevation(&self) -> bool {
        let text = format!("{}\n{}", self.stdout, self.stderr).to_ascii_lowercase();
        text.contains("requires elevation") || text.contains("administrator") || text.contains("access is denied")
    }
}

/// Runs `System32\<exe>` with `args`, hidden, and waits up to `timeout`.
pub fn run_system_binary(exe: &str, args: &[&str], timeout: Duration) -> io::Result<CommandOutput> {
    let valid_name = exe.to_ascii_lowercase().ends_with(".exe")
        && !exe.contains(['/', '\\', ':'])
        && !exe.starts_with('.');
    if !valid_name {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected a bare System32 executable name"));
    }
    let path = system32().join(exe);
    let mut child = Command::new(&path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW.0)
        .spawn()?;

    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });

    let started = Instant::now();
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait()? {
            break (Some(status), false);
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            break (child.wait().ok(), true);
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    Ok(CommandOutput {
        command: std::iter::once(exe).chain(args.iter().copied()).collect::<Vec<_>>().join(" "),
        exit_code: if timed_out { None } else { status.and_then(|s| s.code()) },
        stdout: decode_console_output(&out_reader.join().unwrap_or_default()),
        stderr: decode_console_output(&err_reader.join().unwrap_or_default()),
        timed_out,
    })
}

/// Console tools disagree on encoding: `sfc` writes UTF-16LE, `ipconfig` and
/// `netsh` write the OEM code page. Progress lines are redrawn with bare `\r`,
/// so only the last redraw of each line is kept.
pub fn decode_console_output(bytes: &[u8]) -> String {
    let text = if looks_utf16le(bytes) {
        let start = if bytes.starts_with(&[0xFF, 0xFE]) { 2 } else { 0 };
        let units: Vec<u16> = bytes[start..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else if let Ok(s) = std::str::from_utf8(bytes) {
        s.to_owned()
    } else {
        decode_oem(bytes)
    };
    text.replace("\r\n", "\n")
        .split('\n')
        .map(|line| line.rsplit('\r').find(|seg| !seg.trim().is_empty()).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        .replace('\0', "")
        .trim()
        .to_owned()
}

fn looks_utf16le(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return true;
    }
    if bytes.len() < 4 {
        return false;
    }
    let odd_zeros = bytes.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
    odd_zeros * 2 > bytes.len() / 2
}

fn decode_oem(bytes: &[u8]) -> String {
    unsafe {
        let cp = GetOEMCP();
        let len = MultiByteToWideChar(cp, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, None);
        if len <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut wide = vec![0u16; len as usize];
        MultiByteToWideChar(cp, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, Some(&mut wide));
        String::from_utf16_lossy(&wide)
    }
}

/// Process id owning the foreground window, if any.
pub fn foreground_process_id() -> Option<u32> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.is_invalid() {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        (pid != 0).then_some(pid)
    }
}

/// Starts a second copy of this exe through the UAC "runas" verb. The caller
/// should exit once this returns `Ok`. `ErrorKind::Interrupted` means the user
/// declined the UAC prompt.
pub fn relaunch_elevated() -> io::Result<()> {
    let exe = HSTRING::from(std::env::current_exe()?.as_os_str());
    let verb = HSTRING::from("runas");
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(exe.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut info) }.map_err(|e| {
        // ERROR_CANCELLED: the user clicked "No" on the UAC prompt.
        if e.code().0 as u32 == 0x800704C7 {
            io::Error::new(io::ErrorKind::Interrupted, "the administrator prompt was declined")
        } else {
            io::Error::other(e.message())
        }
    })
}

/// The private IPv4 address this PC uses to reach other networks, if any.
/// `connect` on a UDP socket only picks a route; no packet is sent.
pub fn primary_lan_ipv4() -> Option<std::net::Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if ip.is_private() => Some(ip),
        _ => None,
    }
}

pub mod eventlog {
    //! Read-only access to Windows event channels through `wevtapi`.

    use std::collections::HashMap;

    use serde::Serialize;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS};
    use windows::Win32::System::EventLog::*;

    /// Channels users may query. Anything else is rejected before it reaches XPath.
    pub const CHANNELS: [&str; 4] = ["Application", "System", "Security", "Setup"];
    const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15007;
    const MAX_MESSAGE_CHARS: usize = 4000;

    #[derive(Debug, thiserror::Error)]
    pub enum EventLogError {
        #[error("unknown channel '{0}'")]
        UnknownChannel(String),
        #[error("invalid filter: {0}")]
        InvalidFilter(String),
        #[error("reading the {0} log requires administrator rights")]
        AccessDenied(String),
        #[error("event log query failed: {0}")]
        Failed(String),
    }

    #[derive(Debug, Clone, Default)]
    pub struct EventQuery {
        pub channel: String,
        /// Empty = all levels. 1 Critical, 2 Error, 3 Warning, 4 Information.
        pub levels: Vec<u8>,
        pub event_ids: Vec<u32>,
        pub provider: Option<String>,
        pub lookback_hours: Option<u32>,
        pub limit: usize,
    }

    #[derive(Debug, Clone, Serialize, PartialEq)]
    #[serde(rename_all = "camelCase")]
    pub struct EventRecord {
        pub record_id: u64,
        pub time_created: String,
        pub provider: String,
        pub event_id: u32,
        pub level: u8,
        pub level_name: &'static str,
        pub message: Option<String>,
    }

    pub fn level_name(level: u8) -> &'static str {
        match level {
            1 => "Critical",
            2 => "Error",
            3 => "Warning",
            0 | 4 => "Information",
            5 => "Verbose",
            _ => "Unknown",
        }
    }

    fn valid_provider(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 128
            && name.chars().all(|c| c.is_ascii_alphanumeric() || " ._-()/".contains(c))
    }

    /// Builds the XPath filter from validated, typed values only.
    pub fn build_xpath(q: &EventQuery) -> Result<String, EventLogError> {
        let mut clauses = Vec::new();
        if !q.levels.is_empty() {
            let mut levels: Vec<u8> = q.levels.clone();
            if levels.contains(&4) && !levels.contains(&0) {
                levels.push(0); // "LogAlways" events render as Information.
            }
            if levels.iter().any(|l| *l > 5) {
                return Err(EventLogError::InvalidFilter("level must be 0-5".into()));
            }
            clauses.push(format!("({})", levels.iter().map(|l| format!("Level={l}")).collect::<Vec<_>>().join(" or ")));
        }
        if !q.event_ids.is_empty() {
            if q.event_ids.iter().any(|id| *id > 65535) {
                return Err(EventLogError::InvalidFilter("event IDs are 0-65535".into()));
            }
            clauses.push(format!("({})", q.event_ids.iter().map(|id| format!("EventID={id}")).collect::<Vec<_>>().join(" or ")));
        }
        if let Some(provider) = &q.provider {
            if !valid_provider(provider) {
                return Err(EventLogError::InvalidFilter("source may contain letters, digits, spaces and . _ - ( ) / only".into()));
            }
            clauses.push(format!("Provider[@Name='{provider}']"));
        }
        if let Some(hours) = q.lookback_hours {
            let ms = u64::from(hours.clamp(1, 24 * 90)) * 3_600_000;
            clauses.push(format!("TimeCreated[timediff(@SystemTime) <= {ms}]"));
        }
        Ok(if clauses.is_empty() { "*".into() } else { format!("*[System[{}]]", clauses.join(" and ")) })
    }

    struct Handle(EVT_HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = EvtClose(self.0);
                }
            }
        }
    }

    pub fn query(q: &EventQuery) -> Result<Vec<EventRecord>, EventLogError> {
        let channel = CHANNELS
            .iter()
            .find(|c| c.eq_ignore_ascii_case(&q.channel))
            .ok_or_else(|| EventLogError::UnknownChannel(q.channel.clone()))?;
        let xpath = build_xpath(q)?;
        let limit = q.limit.clamp(1, 500);

        let results = unsafe {
            EvtQuery(None, &HSTRING::from(*channel), &HSTRING::from(xpath), EvtQueryChannelPath.0 | EvtQueryReverseDirection.0)
        }
        .map_err(|e| {
            let code = (e.code().0 as u32) & 0xFFFF;
            if code == ERROR_ACCESS_DENIED.0 {
                EventLogError::AccessDenied((*channel).to_owned())
            } else if code == ERROR_EVT_CHANNEL_NOT_FOUND {
                EventLogError::UnknownChannel((*channel).to_owned())
            } else {
                EventLogError::Failed(e.message())
            }
        })?;
        let results = Handle(results);
        let context = Handle(
            unsafe { EvtCreateRenderContext(None, EvtRenderContextSystem.0) }.map_err(|e| EventLogError::Failed(e.message()))?,
        );
        let mut publishers: HashMap<String, Option<Handle>> = HashMap::new();
        let mut records = Vec::new();

        while records.len() < limit {
            let mut batch = [0isize; 32];
            let want = (limit - records.len()).min(batch.len());
            let mut returned = 0u32;
            if let Err(e) = unsafe { EvtNext(results.0, &mut batch[..want], 5000, 0, &mut returned) } {
                if (e.code().0 as u32) & 0xFFFF == ERROR_NO_MORE_ITEMS.0 {
                    break;
                }
                return Err(EventLogError::Failed(e.message()));
            }
            for raw in &batch[..returned as usize] {
                let event = Handle(EVT_HANDLE(*raw));
                if let Some(mut record) = render_system(&context, &event) {
                    let publisher = publishers
                        .entry(record.provider.clone())
                        .or_insert_with(|| open_publisher(&record.provider));
                    record.message = publisher.as_ref().and_then(|p| format_message(p, &event));
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    fn render_system(context: &Handle, event: &Handle) -> Option<EventRecord> {
        let mut used = 0u32;
        let mut count = 0u32;
        let first = unsafe { EvtRender(Some(context.0), event.0, EvtRenderEventValues.0, 0, None, &mut used, &mut count) };
        if let Err(e) = first {
            if (e.code().0 as u32) & 0xFFFF != ERROR_INSUFFICIENT_BUFFER.0 {
                return None;
            }
        }
        // u64 storage keeps the EVT_VARIANT array 8-byte aligned.
        let mut buf = vec![0u64; (used as usize).div_ceil(8)];
        unsafe {
            EvtRender(Some(context.0), event.0, EvtRenderEventValues.0, used, Some(buf.as_mut_ptr().cast()), &mut used, &mut count).ok()?;
            let values = std::slice::from_raw_parts(buf.as_ptr() as *const EVT_VARIANT, count as usize);
            let get = |id: EVT_SYSTEM_PROPERTY_ID| values.get(id.0 as usize);
            let provider = get(EvtSystemProviderName)
                .filter(|v| v.Type == EvtVarTypeString.0 as u32 && !v.Anonymous.StringVal.is_null())
                .map(|v| v.Anonymous.StringVal.to_string().unwrap_or_default())
                .unwrap_or_default();
            let event_id = get(EvtSystemEventID).filter(|v| v.Type == EvtVarTypeUInt16.0 as u32).map(|v| v.Anonymous.UInt16Val as u32)?;
            let level = get(EvtSystemLevel).filter(|v| v.Type == EvtVarTypeByte.0 as u32).map(|v| v.Anonymous.ByteVal).unwrap_or(4);
            let filetime = get(EvtSystemTimeCreated).filter(|v| v.Type == EvtVarTypeFileTime.0 as u32).map(|v| v.Anonymous.FileTimeVal)?;
            let record_id = get(EvtSystemEventRecordId).filter(|v| v.Type == EvtVarTypeUInt64.0 as u32).map(|v| v.Anonymous.UInt64Val).unwrap_or(0);
            Some(EventRecord {
                record_id,
                time_created: filetime_to_rfc3339(filetime),
                provider,
                event_id,
                level,
                level_name: level_name(level),
                message: None,
            })
        }
    }

    fn open_publisher(provider: &str) -> Option<Handle> {
        if provider.is_empty() {
            return None;
        }
        unsafe { EvtOpenPublisherMetadata(None, &HSTRING::from(provider), PCWSTR::null(), 0, 0) }.ok().map(Handle)
    }

    fn format_message(publisher: &Handle, event: &Handle) -> Option<String> {
        let mut used = 0u32;
        let _ = unsafe { EvtFormatMessage(Some(publisher.0), Some(event.0), 0, None, EvtFormatMessageEvent.0, None, &mut used) };
        if used == 0 {
            return None;
        }
        let mut buf = vec![0u16; used as usize];
        // Unresolved inserts still produce useful text, so the result code is
        // ignored as long as something was written.
        let _ = unsafe { EvtFormatMessage(Some(publisher.0), Some(event.0), 0, None, EvtFormatMessageEvent.0, Some(&mut buf), &mut used) };
        let text = String::from_utf16_lossy(&buf[..(used as usize).min(buf.len())]);
        let text = text.trim_end_matches('\0').trim();
        if text.is_empty() {
            return None;
        }
        Some(text.chars().take(MAX_MESSAGE_CHARS).collect())
    }

    /// FILETIME (100 ns ticks since 1601) to an RFC 3339 UTC timestamp.
    pub fn filetime_to_rfc3339(ft: u64) -> String {
        const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
        let secs = (ft / 10_000_000) as i64 - EPOCH_DIFF_SECS;
        chrono::DateTime::from_timestamp(secs, ((ft % 10_000_000) * 100) as u32)
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_default()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn xpath_is_built_from_typed_values_only() {
            let q = EventQuery {
                channel: "Application".into(),
                levels: vec![1, 2],
                event_ids: vec![1000, 1002],
                provider: Some("Application Error".into()),
                lookback_hours: Some(24),
                limit: 10,
            };
            assert_eq!(
                build_xpath(&q).unwrap(),
                "*[System[(Level=1 or Level=2) and (EventID=1000 or EventID=1002) and Provider[@Name='Application Error'] and TimeCreated[timediff(@SystemTime) <= 86400000]]]"
            );
            assert_eq!(build_xpath(&EventQuery::default()).unwrap(), "*");
            let info = EventQuery { levels: vec![4], ..Default::default() };
            assert_eq!(build_xpath(&info).unwrap(), "*[System[(Level=4 or Level=0)]]");
        }

        #[test]
        fn xpath_injection_through_the_source_is_rejected() {
            let q = EventQuery { provider: Some("x'] or [1=1".into()), ..Default::default() };
            assert!(matches!(build_xpath(&q), Err(EventLogError::InvalidFilter(_))));
        }

        #[test]
        fn unknown_channels_are_rejected_before_querying() {
            let q = EventQuery { channel: "Microsoft-Windows-Sysmon/Operational".into(), limit: 1, ..Default::default() };
            assert!(matches!(query(&q), Err(EventLogError::UnknownChannel(_))));
        }

        #[test]
        fn reads_real_events_from_the_application_log() {
            // Every Windows install (including CI runners) has Application events.
            let q = EventQuery { channel: "Application".into(), limit: 5, ..Default::default() };
            let events = query(&q).expect("Application log is readable by standard users");
            assert!(!events.is_empty());
            for e in &events {
                assert!(e.time_created.ends_with('Z'), "{}", e.time_created);
                assert!(!e.provider.is_empty());
            }
            // Newest first.
            assert!(events.windows(2).all(|w| w[0].time_created >= w[1].time_created));
        }

        #[test]
        fn filetime_conversion() {
            // 2024-01-01T00:00:00Z
            assert_eq!(filetime_to_rfc3339(133_485_408_000_000_000), "2024-01-01T00:00:00Z");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_utf16_and_collapses_progress_redraws() {
        let text = "Verification 5% complete.\rVerification 100% complete.\r\nDone.\r\n";
        let utf16: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(decode_console_output(&utf16), "Verification 100% complete.\nDone.");
        assert_eq!(decode_console_output(b"Windows IP Configuration\r\n\r\nOK\r\n"), "Windows IP Configuration\n\nOK");
    }

    #[test]
    fn runs_a_harmless_system_binary_hidden_with_argv() {
        let out = run_system_binary("whoami.exe", &[], Duration::from_secs(20)).unwrap();
        assert!(out.success(), "{out:?}");
        assert!(!out.stdout.is_empty());
        assert_eq!(out.command, "whoami.exe");
    }

    #[test]
    fn refuses_paths_and_non_exe_names() {
        for bad in [r"..\cmd.exe", "C:/Windows/System32/cmd.exe", "cmd", "x/y.exe"] {
            assert!(run_system_binary(bad, &[], Duration::from_secs(1)).is_err(), "{bad}");
        }
    }

    #[test]
    fn system32_exists_and_elevation_check_does_not_panic() {
        assert!(system32().join("ipconfig.exe").is_file());
        let _ = is_elevated();
    }
}
