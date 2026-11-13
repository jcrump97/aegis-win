//! Diagnose checks (ADR 0005 §4). [`read_all`] reads the providers and event
//! IDs below and nothing else; every check is a pure function over what was
//! read and the time window, so the tests feed it recorded events.

use std::collections::{BTreeMap, BTreeSet};

use aegis_core::diagnose::{CheckContext, CheckResult, Evidence, Finding, Next, Severity, MAX_EVENTS_PER_QUERY};
use aegis_core::os::eventlog::{EventLogError, EventQuery, EventRecord};
use chrono::{DateTime, Duration, Utc};

/// Events of one incident are logged within this many minutes of each other
/// (a restart logs Kernel-Power 41 and EventLog 6008, a blue screen also 1001).
pub const INCIDENT_GAP_MINUTES: i64 = 10;
/// A service that could not start this soon after Windows started.
pub const BOOT_WINDOW_MINUTES: i64 = 2;

/// One query: a single provider in one channel. Levels empty means all.
pub struct Read {
    pub key: &'static str,
    pub channel: &'static str,
    pub provider: &'static str,
    pub ids: &'static [u32],
    pub levels: &'static [u8],
}

const PROBLEMS: &[u8] = &[1, 2, 3];

pub const READS: &[Read] = &[
    Read { key: "kernel_power", channel: "System", provider: "Microsoft-Windows-Kernel-Power", ids: &[41], levels: &[] },
    Read { key: "unexpected", channel: "System", provider: "EventLog", ids: &[6008], levels: &[] },
    // 6005 "The Event log service was started": Windows started.
    Read { key: "boot", channel: "System", provider: "EventLog", ids: &[6005], levels: &[] },
    // The BugCheck source belongs to this provider on current Windows; the old name is read too.
    Read { key: "bugcheck", channel: "System", provider: "Microsoft-Windows-WER-SystemErrorReporting", ids: &[1001], levels: &[] },
    Read { key: "bugcheck", channel: "System", provider: "BugCheck", ids: &[1001], levels: &[] },
    Read { key: "app_crash", channel: "Application", provider: "Application Error", ids: &[1000], levels: &[] },
    Read { key: "app_crash", channel: "Application", provider: "Application Hang", ids: &[1002], levels: &[] },
    Read { key: "scm", channel: "System", provider: "Service Control Manager", ids: &[7031, 7034, 7000, 7009], levels: &[] },
    Read { key: "disk", channel: "System", provider: "disk", ids: &[7, 51, 153], levels: PROBLEMS },
    Read { key: "disk", channel: "System", provider: "storahci", ids: &[129], levels: PROBLEMS },
    Read { key: "disk", channel: "System", provider: "stornvme", ids: &[129], levels: PROBLEMS },
    // Ntfs 98 is also logged, as Information, when a volume is healthy: problems only.
    Read { key: "disk", channel: "System", provider: "Ntfs", ids: &[55, 98], levels: PROBLEMS },
    Read { key: "disk", channel: "System", provider: "Microsoft-Windows-Ntfs", ids: &[55, 98], levels: PROBLEMS },
    Read { key: "whea", channel: "System", provider: "Microsoft-Windows-WHEA-Logger", ids: &[17, 18, 19, 47], levels: &[] },
    Read { key: "display", channel: "System", provider: "Display", ids: &[4101], levels: &[] },
    Read { key: "update", channel: "System", provider: "Microsoft-Windows-WindowsUpdateClient", ids: &[20], levels: &[] },
    Read { key: "dns", channel: "System", provider: "Microsoft-Windows-DNS-Client", ids: &[1014], levels: &[] },
];

/// The reads each check needs.
pub const CHECKS: &[(&str, &[&str])] = &[
    ("unexpected_shutdown", &["kernel_power", "unexpected", "bugcheck"]),
    ("blue_screen", &["bugcheck"]),
    ("app_crashes", &["app_crash"]),
    ("service_failures", &["scm", "boot"]),
    ("disk_errors", &["disk"]),
    ("hardware_errors", &["whea"]),
    ("display_driver_resets", &["display"]),
    ("update_failures", &["update"]),
    ("dns_timeouts", &["dns"]),
];

#[derive(Debug, Clone, PartialEq)]
pub enum ReadFailure {
    NeedsAdmin(String),
    Failed(String),
}

/// What was read, by key.
#[derive(Debug, Default, Clone)]
pub struct Reads {
    events: BTreeMap<&'static str, Vec<EventRecord>>,
    capped: BTreeSet<&'static str>,
    failed: BTreeMap<&'static str, ReadFailure>,
}

impl Reads {
    pub fn add(&mut self, key: &'static str, records: Vec<EventRecord>) {
        if records.len() >= MAX_EVENTS_PER_QUERY {
            self.capped.insert(key);
        }
        self.events.entry(key).or_default().extend(records);
    }

    pub fn fail(&mut self, key: &'static str, failure: ReadFailure) {
        self.failed.entry(key).or_insert(failure);
    }

    /// For tests: records under `key`.
    pub fn with(mut self, key: &'static str, records: Vec<EventRecord>) -> Self {
        self.add(key, records);
        self
    }

    fn events(&self, key: &str, w: &Window) -> Vec<Ev<'_>> {
        let channel = READS.iter().find(|r| r.key == key).map_or("", |r| r.channel);
        self.events
            .get(key)
            .into_iter()
            .flatten()
            .filter_map(|rec| {
                let time = DateTime::parse_from_rfc3339(&rec.time_created).ok()?.with_timezone(&Utc);
                (time >= w.since && time <= w.now).then_some(Ev { time, channel, rec })
            })
            .collect()
    }
}

/// Reads everything the checks need, newest first, at most
/// [`MAX_EVENTS_PER_QUERY`] per query. Blocking: run off the async runtime.
pub fn read_all(lookback_days: u32) -> Reads {
    let mut reads = Reads::default();
    for r in READS {
        let query = EventQuery {
            channel: r.channel.into(),
            levels: r.levels.to_vec(),
            event_ids: r.ids.to_vec(),
            provider: Some(r.provider.into()),
            lookback_hours: Some(lookback_days * 24),
            limit: MAX_EVENTS_PER_QUERY,
        };
        match aegis_core::os::eventlog::query(&query) {
            Ok(records) => reads.add(r.key, records),
            Err(EventLogError::AccessDenied(ch)) => reads.fail(r.key, ReadFailure::NeedsAdmin(format!("Reading the {ch} log needs administrator rights."))),
            Err(e) => reads.fail(r.key, ReadFailure::Failed(format!("Could not read the {} log: {e}", r.channel))),
        }
    }
    reads
}

#[derive(Debug, Clone, Copy)]
pub struct Window {
    pub since: DateTime<Utc>,
    pub now: DateTime<Utc>,
    pub days: u32,
}

impl Window {
    pub fn of(ctx: &CheckContext) -> Self {
        Self { since: ctx.since(), now: ctx.now, days: ctx.lookback_days }
    }

    fn phrase(&self) -> String {
        if self.days == 1 {
            "in the last day".into()
        } else {
            format!("in the last {} days", self.days)
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Ev<'a> {
    time: DateTime<Utc>,
    channel: &'static str,
    rec: &'a EventRecord,
}

impl Ev<'_> {
    fn msg(&self) -> &str {
        self.rec.message.as_deref().unwrap_or("")
    }
}

/// Every check, in manifest order.
pub fn evaluate_all(reads: &Reads, w: &Window) -> Vec<CheckResult> {
    CHECKS.iter().map(|(id, keys)| evaluate(id, keys, reads, w)).collect()
}

fn evaluate(id: &str, keys: &[&str], reads: &Reads, w: &Window) -> CheckResult {
    if let Some(failure) = keys.iter().find_map(|k| reads.failed.get(k)) {
        return match failure {
            ReadFailure::NeedsAdmin(reason) => CheckResult::skipped(id, reason.clone()),
            ReadFailure::Failed(reason) => CheckResult::failed(id, reason.clone()),
        };
    }
    let mut findings = match id {
        "unexpected_shutdown" => unexpected_shutdown(reads, w),
        "blue_screen" => blue_screen(reads, w),
        "app_crashes" => app_crashes(reads, w),
        "service_failures" => service_failures(reads, w),
        "disk_errors" => disk_errors(reads, w),
        "hardware_errors" => hardware_errors(reads, w),
        "display_driver_resets" => display_driver_resets(reads, w),
        "update_failures" => update_failures(reads, w),
        "dns_timeouts" => dns_timeouts(reads, w),
        _ => return CheckResult::failed(id, "Unknown check."),
    };
    if keys.iter().any(|k| reads.capped.contains(k)) {
        for f in &mut findings {
            f.count_is_minimum = true;
        }
    }
    CheckResult::ran(id, findings)
}

// ---- helpers ---------------------------------------------------------------

/// Groups events into incidents: each event within [`INCIDENT_GAP_MINUTES`]
/// of the one before it belongs to the same incident. Oldest first.
fn incidents(mut evs: Vec<Ev<'_>>) -> Vec<Vec<Ev<'_>>> {
    evs.sort_by_key(|e| (e.time, e.rec.record_id));
    let mut out: Vec<Vec<Ev>> = Vec::new();
    for e in evs {
        match out.last_mut() {
            Some(last) if e.time - last.last().expect("never empty").time <= Duration::minutes(INCIDENT_GAP_MINUTES) => last.push(e),
            _ => out.push(vec![e]),
        }
    }
    out
}

fn near(a: DateTime<Utc>, b: DateTime<Utc>) -> bool {
    (a - b).abs() <= Duration::minutes(INCIDENT_GAP_MINUTES)
}

fn times(n: usize) -> String {
    if n == 1 {
        "once".into()
    } else {
        format!("{n} times")
    }
}

struct Draft {
    key: Option<String>,
    severity: Severity,
    title: String,
    detail: String,
    next: Vec<Next>,
}

/// A finding counting `groups` (incidents, or single events), with the newest events as evidence.
fn finding(d: Draft, groups: &[Vec<Ev<'_>>]) -> Finding {
    let mut all: Vec<&Ev> = groups.iter().flatten().collect();
    all.sort_by_key(|e| std::cmp::Reverse(e.time));
    Finding {
        key: d.key,
        severity: d.severity,
        title: d.title,
        detail: d.detail,
        count: groups.len() as u64,
        count_is_minimum: false,
        first_seen: groups.iter().flatten().map(|e| e.time).min(),
        last_seen: groups.iter().flatten().map(|e| e.time).max(),
        evidence: all
            .iter()
            .take(aegis_core::diagnose::MAX_EVIDENCE)
            .map(|e| Evidence {
                source: e.channel.into(),
                provider: Some(e.rec.provider.clone()),
                event_id: Some(e.rec.event_id),
                record_id: Some(e.rec.record_id),
                time: Some(e.time),
                message: e.msg().to_owned(),
            })
            .collect(),
        next: d.next,
    }
}

fn manual(text: &str) -> Next {
    Next::Manual { text: text.into() }
}

fn tool(tool: &str, why: &str) -> Next {
    Next::Tool { tool: tool.into(), args: serde_json::json!({}), why: why.into() }
}

const SFC: &str = "windows-health:sfc_scan";
const FLUSH_DNS: &str = "windows-health:flush_dns";

/// The text between `start` and the next `end` (ASCII case ignored).
fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let lower = text.to_ascii_lowercase();
    let from = lower.find(&start.to_ascii_lowercase())? + start.len();
    let to = from + lower[from..].find(&end.to_ascii_lowercase())?;
    let found = text[from..to].trim();
    (!found.is_empty()).then_some(found)
}

// ---- the checks --------------------------------------------------------------

fn unexpected_shutdown(r: &Reads, w: &Window) -> Vec<Finding> {
    let crashes = r.events("bugcheck", w);
    let mut evs = r.events("kernel_power", w);
    evs.extend(r.events("unexpected", w));
    // A restart that belongs to a blue screen is counted under blue_screen.
    let found: Vec<_> = incidents(evs).into_iter().filter(|i| !i.iter().any(|e| crashes.iter().any(|c| near(c.time, e.time)))).collect();
    if found.is_empty() {
        return vec![];
    }
    let n = found.len();
    vec![finding(
        Draft {
            key: None,
            severity: if n >= 3 { Severity::Critical } else { Severity::Warning },
            title: format!("Windows shut down unexpectedly {} {}", times(n), w.phrase()),
            detail: "Windows restarted without shutting down cleanly (Kernel-Power 41 or EventLog 6008): a freeze, a power loss, or a held power button.".into(),
            next: vec![
                tool(SFC, "Checks the Windows system files an unexpected shutdown can damage."),
                manual("If it happened during a power cut or after holding the power button, it may not be a fault."),
                manual("If it keeps happening, check that the power cable is firmly connected, and that the PC is not overheating."),
            ],
        },
        &found,
    )]
}

/// `0x0000009f` from "The bugcheck was: 0x0000009f (0x..., ...)", as `0x9F`.
pub fn stop_code(message: &str) -> Option<String> {
    let lower = message.to_ascii_lowercase();
    let from = lower.find("bugcheck was:")? + "bugcheck was:".len();
    let token: String = lower[from..].trim_start().chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
    let value = u32::from_str_radix(token.strip_prefix("0x")?, 16).ok()?;
    Some(format!("0x{value:X}"))
}

fn blue_screen(r: &Reads, w: &Window) -> Vec<Finding> {
    let found = incidents(r.events("bugcheck", w));
    if found.is_empty() {
        return vec![];
    }
    let n = found.len();
    let codes: BTreeSet<String> = found.iter().flatten().filter_map(|e| stop_code(e.msg())).collect();
    let codes = if codes.is_empty() { String::new() } else { format!(" (stop code {})", codes.into_iter().collect::<Vec<_>>().join(", ")) };
    vec![finding(
        Draft {
            key: None,
            severity: if n >= 2 { Severity::Critical } else { Severity::Warning },
            title: format!("Windows stopped with a blue screen {} {}{codes}", times(n), w.phrase()),
            detail: "Windows stopped to protect itself from an error (BugCheck 1001). The stop code points at the cause; drivers and failing hardware are the most common.".into(),
            next: vec![
                tool(SFC, "Checks the Windows system files a blue screen can damage."),
                manual("Install the latest Windows updates and drivers, especially graphics, chipset and storage drivers."),
                manual("If it started after new hardware or a new driver, remove or roll back that change."),
            ],
        },
        &found,
    )]
}

/// Program names from Application Error 1000 and Application Hang 1002 (English messages).
pub fn program(e: &EventRecord) -> Option<String> {
    let msg = e.message.as_deref()?;
    let name = match e.event_id {
        1000 => between(msg, "Faulting application name:", ","),
        1002 => between(msg, "The program ", " version"),
        _ => None,
    }?;
    Some(name.to_ascii_lowercase())
}

/// One program crashing or hanging this often is worth a look.
pub const APP_CRASH_FINDING_AT: usize = 3;
pub const APP_CRASH_WARNING_AT: usize = 10;

fn app_crashes(r: &Reads, w: &Window) -> Vec<Finding> {
    let mut by_program: BTreeMap<String, Vec<Ev>> = BTreeMap::new();
    for e in r.events("app_crash", w) {
        by_program.entry(program(e.rec).unwrap_or_default()).or_default().push(e);
    }
    let mut out = Vec::new();
    for (name, evs) in by_program {
        let found = incidents(evs);
        let n = found.len();
        if n < APP_CRASH_FINDING_AT {
            continue;
        }
        let (key, label) = if name.is_empty() { ("unknown".to_owned(), "A program AegisWin could not name".to_owned()) } else { (name.clone(), name.clone()) };
        out.push(finding(
            Draft {
                key: Some(key),
                severity: if n >= APP_CRASH_WARNING_AT { Severity::Warning } else { Severity::Info },
                title: format!("{label} crashed or stopped responding {} {}", times(n), w.phrase()),
                detail: "Windows recorded this program crashing (Application Error 1000) or hanging (Application Hang 1002). Repeated crashes of one program usually point at that program, not Windows.".into(),
                next: vec![manual("Update the program, or repair or reinstall it."), manual("If several programs crash, look at the other findings first.")],
            },
            &found,
        ));
    }
    out
}

/// The service a Service Control Manager event names (English messages).
pub fn service(e: &EventRecord) -> Option<String> {
    let msg = e.message.as_deref()?;
    match e.event_id {
        7031 | 7034 => between(msg, "The ", " service terminated"),
        7000 => between(msg, "The ", " service failed to start"),
        7009 => between(msg, "waiting for the ", " service to connect"),
        _ => None,
    }
    .map(str::to_owned)
}

fn crashed(e: &Ev) -> bool {
    matches!(e.rec.event_id, 7031 | 7034)
}

fn service_failures(r: &Reads, w: &Window) -> Vec<Finding> {
    let boots = r.events("boot", w);
    let at_boot = |e: &Ev| boots.iter().position(|b| e.time >= b.time && e.time - b.time <= Duration::minutes(BOOT_WINDOW_MINUTES));
    let mut by_service: BTreeMap<String, Vec<Ev>> = BTreeMap::new();
    for e in r.events("scm", w) {
        by_service.entry(service(e.rec).unwrap_or_default()).or_default().push(e);
    }
    let mut out = Vec::new();
    for (name, evs) in by_service {
        // Noise: a service that could not start during one Windows start, and
        // never failed otherwise, is a common timing problem that sorts itself out.
        let boot_starts: BTreeSet<usize> = evs.iter().filter(|e| !crashed(e)).filter_map(at_boot).collect();
        if evs.iter().all(|e| !crashed(e) && at_boot(e).is_some()) && boot_starts.len() < 2 {
            continue;
        }
        let crashes = evs.iter().filter(|e| crashed(e)).count();
        let starts = evs.len() - crashes;
        let found = incidents(evs);
        let n = found.len();
        let label = if name.is_empty() { "A service AegisWin could not name".to_owned() } else { format!("The {name} service") };
        let what = match (crashes, starts) {
            (0, s) => format!("failed to start {}", times(s)),
            (c, 0) => format!("stopped unexpectedly {}", times(c)),
            (c, s) => format!("stopped unexpectedly {} and failed to start {}", times(c), times(s)),
        };
        out.push(finding(
            Draft {
                key: Some(if name.is_empty() { "unknown".into() } else { name.clone() }),
                severity: if n >= 3 { Severity::Warning } else { Severity::Info },
                title: format!("{label} {what} {}", w.phrase()),
                detail: "Windows recorded this service stopping unexpectedly (7031, 7034) or failing to start (7000, 7009). Features that depend on it may not work.".into(),
                next: vec![manual("Restart the PC and see if it happens again."), manual("If the service belongs to a program, update or reinstall that program.")],
            },
            &found,
        ));
    }
    out
}

fn disk_errors(r: &Reads, w: &Window) -> Vec<Finding> {
    let found = incidents(r.events("disk", w));
    if found.is_empty() {
        return vec![];
    }
    let n = found.len();
    // A bad block (disk 7) or a damaged file system (Ntfs 55) is serious on its own.
    let serious = found.iter().flatten().any(|e| (e.rec.event_id == 7 && e.rec.provider.eq_ignore_ascii_case("disk")) || e.rec.event_id == 55);
    vec![finding(
        Draft {
            key: None,
            severity: if serious || n >= 5 { Severity::Critical } else { Severity::Warning },
            title: format!("Windows logged disk or file system errors {} {}", times(n), w.phrase()),
            detail: "Bad blocks (disk 7), paging errors (51), commands the disk did not answer (153, 129), or file system damage (Ntfs 55, 98). A disk can fail soon after errors like these.".into(),
            next: vec![
                manual("Back up your important files now."),
                manual("Then run chkdsk /scan from a Command Prompt opened as administrator."),
                manual("Check that the disk's cable is firmly connected (desktops)."),
            ],
        },
        &found,
    )]
}

fn hardware_errors(r: &Reads, w: &Window) -> Vec<Finding> {
    let found = incidents(r.events("whea", w));
    if found.is_empty() {
        return vec![];
    }
    let fatal = found.iter().flatten().any(|e| e.rec.event_id == 18);
    vec![finding(
        Draft {
            key: None,
            severity: if fatal { Severity::Critical } else { Severity::Warning },
            title: format!("The hardware reported errors {} {}", times(found.len()), w.phrase()),
            detail: "WHEA-Logger records errors the processor, memory or PCIe devices report (17, 19, 47 corrected; 18 fatal). Corrected errors that repeat often come before failures.".into(),
            next: vec![
                manual("Update the BIOS or UEFI firmware and chipset drivers from the PC or motherboard maker."),
                manual("Turn off any overclocking or memory profile (XMP/EXPO) and see if the errors stop."),
                manual("Run Windows Memory Diagnostic (mdsched.exe)."),
            ],
        },
        &found,
    )]
}

fn display_driver_resets(r: &Reads, w: &Window) -> Vec<Finding> {
    let found = incidents(r.events("display", w));
    if found.is_empty() {
        return vec![];
    }
    let n = found.len();
    vec![finding(
        Draft {
            key: None,
            severity: if n >= 3 { Severity::Warning } else { Severity::Info },
            title: format!("The display driver stopped responding and recovered {} {}", times(n), w.phrase()),
            detail: "Display 4101: the graphics driver hung and Windows restarted it. The screen goes black for a moment, and games or video may crash.".into(),
            next: vec![
                manual("Install the latest graphics driver from the graphics card maker (NVIDIA, AMD or Intel)."),
                manual("If it happens under load, check that the graphics card is not overheating."),
            ],
        },
        &found,
    )]
}

fn update_failures(r: &Reads, w: &Window) -> Vec<Finding> {
    let found = incidents(r.events("update", w));
    if found.is_empty() {
        return vec![];
    }
    let n = found.len();
    vec![finding(
        Draft {
            key: None,
            severity: if n >= 3 { Severity::Warning } else { Severity::Info },
            title: format!("Windows Update failed to install updates {} {}", times(n), w.phrase()),
            detail: "WindowsUpdateClient 20: an update did not install. The evidence names the update and the error code.".into(),
            next: vec![
                tool(SFC, "Damaged system files are a common reason updates fail."),
                manual("Restart the PC, then try again in Settings > Windows Update."),
                manual("Make sure the system drive has at least 10 GB free."),
            ],
        },
        &found,
    )]
}

/// DNS timeouts are common on healthy PCs; this many is worth a look.
pub const DNS_FINDING_AT: usize = 10;
pub const DNS_WARNING_AT: usize = 50;

fn dns_timeouts(r: &Reads, w: &Window) -> Vec<Finding> {
    // Counted one by one: each timeout is a name that did not resolve.
    let evs = r.events("dns", w);
    let n = evs.len();
    if n < DNS_FINDING_AT {
        return vec![];
    }
    let each: Vec<Vec<Ev>> = evs.into_iter().map(|e| vec![e]).collect();
    vec![finding(
        Draft {
            key: None,
            severity: if n >= DNS_WARNING_AT { Severity::Warning } else { Severity::Info },
            title: format!("Name lookups timed out {} {}", times(n), w.phrase()),
            detail: "DNS Client 1014: Windows asked for a website's address and got no answer in time. Pages then load slowly or not at all.".into(),
            next: vec![
                tool(FLUSH_DNS, "Clears saved lookups, in case some are stale."),
                manual("Restart your router."),
                manual("If it keeps happening, try another DNS server in your network settings."),
            ],
        },
        &each,
    )]
}
