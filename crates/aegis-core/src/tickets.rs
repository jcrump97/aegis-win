//! Approval tickets for `pin_required` tools called over MCP.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::AegisError;
use crate::plan::PlanOrigin;
use crate::registry::CallReview;

pub const TICKET_TTL: Duration = Duration::from_secs(30 * 60);
/// Plans wait for a decision for less time than single requests (ADR 0003 §3).
pub const PLAN_TTL: Duration = Duration::from_secs(10 * 60);
pub const STRIKES_PER_TICKET: u8 = 3;
/// A device code works for 5 minutes, and never past its ticket (ADR 0004 §1.2).
pub const DEVICE_CODE_TTL: Duration = Duration::from_secs(5 * 60);
/// Crockford base32: no `I`, `L`, `O` or `U`.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const MAX_TICKETS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    PendingApproval,
    /// Approved, waiting for the one state-changing slot (ADR 0003 §5.1).
    Queued,
    Running,
    Approved,
    Declined,
    ExecutionFailed,
    LockedOut,
    Expired,
    /// Withdrawn before it ran, or a plan stopped before its next step.
    Cancelled,
}

impl TicketStatus {
    pub fn is_final(self) -> bool {
        !matches!(self, Self::PendingApproval | Self::Queued | Self::Running)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    /// Not run because an earlier step failed.
    Skipped,
    /// Not run because the plan was cancelled or AegisWin was locking.
    Cancelled,
}

/// One step of a plan, as approved: its arguments never change.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanStep {
    /// 1-based.
    pub index: usize,
    /// The MCP tool name, `<plugin>__<tool>`.
    pub tool: String,
    pub plugin_id: String,
    pub tool_id: String,
    pub tool_name: String,
    pub tool_description: String,
    pub requires_admin: bool,
    /// Validated, with defaults filled in.
    pub args: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    /// The commands the step's dry run said it would run.
    pub commands: Vec<String>,
    pub status: StepStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AegisError>,
}

/// What a plan ticket adds; the per-step details are in `steps`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    pub origin: PlanOrigin,
    /// "Supplied by the requesting agent" or "Written by you".
    pub supplied_label: &'static str,
    /// SHA-256 of the canonical plan; an approval must name it.
    pub hash: String,
    pub short_hash: String,
    /// Written by AegisWin from the steps.
    pub summary: String,
    /// Tools the supplied text names that are not steps.
    pub flags: Vec<String>,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Ticket {
    pub id: String,
    pub csrf: String,
    pub plugin_id: String,
    pub tool_id: String,
    pub tool_name: String,
    pub tool_description: String,
    pub requires_admin: bool,
    pub args: Value,
    pub review: Option<CallReview>,
    pub created: Instant,
    pub created_at: String,
    pub status: TicketStatus,
    pub strikes: u8,
    pub comment: Option<String>,
    pub decided_via: Option<&'static str>,
    pub result: Option<Value>,
    pub error: Option<AegisError>,
    pub ttl: Duration,
    pub plan: Option<PlanMeta>,
    pub steps: Vec<PlanStep>,
    /// A running plan stops before its next step.
    pub cancel_requested: bool,
    /// The one-time code for approving on another device, while one is shown.
    pub device_code: Option<DeviceCode>,
}

/// Only the code's hash is kept; the code itself is shown once, in the app.
#[derive(Debug, Clone)]
pub struct DeviceCode {
    hash: [u8; 32],
    pub expires: Instant,
}

impl DeviceCode {
    /// A fresh 40-bit code for a ticket, shown as `K7QM-4XRT`, valid until
    /// `expires`.
    pub fn generate(expires: Instant) -> (String, Self) {
        let mut bytes = [0u8; 5];
        getrandom::fill(&mut bytes).expect("the OS random number generator is unavailable");
        let bits = bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        let code: String = (0..8).rev().map(|i| char::from(CROCKFORD[((bits >> (i * 5)) & 31) as usize])).collect();
        let hash = Sha256::digest(code.as_bytes()).into();
        (format!("{}-{}", &code[..4], &code[4..]), Self { hash, expires })
    }

    /// Whether `input` is this code, still valid at `now`. Ignores case,
    /// spaces and dashes, and reads `I`/`L` as `1` and `O` as `0`.
    pub fn matches(&self, input: &str, now: Instant) -> bool {
        let Some(code) = normalize_code(input) else { return false };
        let hash: [u8; 32] = Sha256::digest(code.as_bytes()).into();
        now < self.expires && bool::from(hash.ct_eq(&self.hash))
    }
}

/// The canonical form of a typed code, or `None` when it cannot be one.
pub fn normalize_code(input: &str) -> Option<String> {
    let code: String = input
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t'))
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        })
        .collect();
    (code.len() == 8 && code.bytes().all(|b| CROCKFORD.contains(&b))).then_some(code)
}

/// What agents and the UI may see about a ticket (never the CSRF token).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TicketView {
    pub ticket_id: String,
    pub plugin_id: String,
    pub tool_id: String,
    pub tool_name: String,
    pub tool_description: String,
    pub requires_admin: bool,
    pub args: Value,
    /// The plugin's code-generated description of the call, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review: Option<CallReview>,
    pub created_at: String,
    pub status: TicketStatus,
    /// While `queued`: 1 means it runs next. Other items are never described.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_position: Option<usize>,
    pub attempts_remaining: u8,
    pub comment: Option<String>,
    pub decided_via: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AegisError>,
    /// Present for action plans only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanMeta>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<PlanStep>,
}

impl Ticket {
    pub fn view(&self) -> TicketView {
        TicketView {
            ticket_id: self.id.clone(),
            plugin_id: self.plugin_id.clone(),
            tool_id: self.tool_id.clone(),
            tool_name: self.tool_name.clone(),
            tool_description: self.tool_description.clone(),
            requires_admin: self.requires_admin,
            args: self.args.clone(),
            review: self.review.clone(),
            created_at: self.created_at.clone(),
            status: self.status,
            queue_position: None,
            attempts_remaining: STRIKES_PER_TICKET.saturating_sub(self.strikes),
            comment: self.comment.clone(),
            decided_via: self.decided_via,
            result: self.result.clone(),
            error: self.error.clone(),
            plan: self.plan.clone(),
            steps: self.steps.clone(),
        }
    }
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("the OS random number generator is unavailable");
    hex::encode(buf)
}

#[derive(Default)]
pub struct TicketStore {
    tickets: HashMap<String, Ticket>,
}

pub struct NewTicket {
    pub plugin_id: String,
    pub tool_id: String,
    pub tool_name: String,
    pub tool_description: String,
    pub requires_admin: bool,
    pub args: Value,
    pub review: Option<CallReview>,
    pub plan: Option<PlanMeta>,
    pub steps: Vec<PlanStep>,
}

impl TicketStore {
    pub fn create(&mut self, t: NewTicket, now: Instant) -> TicketView {
        self.expire(now);
        if self.tickets.len() >= MAX_TICKETS {
            // Drop the oldest finished ticket; pending ones are never dropped silently.
            if let Some(oldest) = self.tickets.values().filter(|t| t.status.is_final()).min_by_key(|t| t.created).map(|t| t.id.clone()) {
                self.tickets.remove(&oldest);
            }
        }
        let ttl = if t.plan.is_some() { PLAN_TTL } else { TICKET_TTL };
        let mut plan = t.plan;
        if let Some(p) = &mut plan {
            let expires = Utc::now() + chrono::Duration::from_std(ttl).unwrap_or_default();
            p.expires_at = expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        }
        let ticket = Ticket {
            id: random_hex(16),
            csrf: random_hex(16),
            plugin_id: t.plugin_id,
            tool_id: t.tool_id,
            tool_name: t.tool_name,
            tool_description: t.tool_description,
            requires_admin: t.requires_admin,
            args: t.args,
            review: t.review,
            created: now,
            created_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            status: TicketStatus::PendingApproval,
            strikes: 0,
            comment: None,
            decided_via: None,
            result: None,
            error: None,
            ttl,
            plan,
            steps: t.steps,
            cancel_requested: false,
            device_code: None,
        };
        let view = ticket.view();
        self.tickets.insert(ticket.id.clone(), ticket);
        view
    }

    /// Marks pending tickets older than the TTL as expired. A ticket that is
    /// no longer pending keeps no device code.
    pub fn expire(&mut self, now: Instant) {
        for t in self.tickets.values_mut() {
            if t.status == TicketStatus::PendingApproval && now.duration_since(t.created) >= t.ttl {
                t.status = TicketStatus::Expired;
            }
            if t.status != TicketStatus::PendingApproval {
                t.device_code = None;
            }
        }
    }

    /// Forgets every device code (the setting was turned off).
    pub fn clear_device_codes(&mut self) {
        for t in self.tickets.values_mut() {
            t.device_code = None;
        }
    }

    pub fn get(&mut self, id: &str, now: Instant) -> Option<&Ticket> {
        self.expire(now);
        self.tickets.get(id)
    }

    pub fn get_mut(&mut self, id: &str, now: Instant) -> Option<&mut Ticket> {
        self.expire(now);
        self.tickets.get_mut(id)
    }

    /// Newest first.
    pub fn list(&mut self, now: Instant) -> Vec<TicketView> {
        self.expire(now);
        let mut all: Vec<&Ticket> = self.tickets.values().collect();
        all.sort_by_key(|t| std::cmp::Reverse(t.created));
        all.into_iter().map(Ticket::view).collect()
    }

    pub fn pending_plans(&mut self, now: Instant) -> usize {
        self.expire(now);
        self.tickets.values().filter(|t| t.plan.is_some() && t.status == TicketStatus::PendingApproval).count()
    }

    /// Requests from agents still waiting for the owner (the owner's own
    /// plans are not counted).
    pub fn pending_from_agents(&mut self, now: Instant) -> usize {
        self.expire(now);
        self.tickets
            .values()
            .filter(|t| t.status == TicketStatus::PendingApproval && t.plan.as_ref().is_none_or(|p| p.origin == crate::plan::PlanOrigin::Agent))
            .count()
    }

    pub fn clear(&mut self) {
        self.tickets.clear();
    }

    /// Forgets a request that was never recorded (ADR 0004 §4.6).
    pub fn remove(&mut self, id: &str) {
        self.tickets.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn new_ticket() -> NewTicket {
        NewTicket {
            plugin_id: "windows-health".into(),
            tool_id: "flush_dns".into(),
            tool_name: "Flush DNS".into(),
            tool_description: "d".into(),
            requires_admin: false,
            args: json!({}),
            review: None,
            plan: None,
            steps: Vec::new(),
        }
    }

    #[test]
    fn ids_are_128_bit_and_views_hide_the_csrf_token() {
        let mut store = TicketStore::default();
        let now = Instant::now();
        let view = store.create(new_ticket(), now);
        assert_eq!(view.ticket_id.len(), 32);
        let csrf = store.get(&view.ticket_id, now).unwrap().csrf.clone();
        assert_eq!(csrf.len(), 32);
        assert!(!serde_json::to_string(&view).unwrap().contains(&csrf));
        assert_eq!(view.attempts_remaining, STRIKES_PER_TICKET);
    }

    #[test]
    fn device_codes_are_crockford_single_form_and_expire() {
        let now = Instant::now();
        let (shown, code) = DeviceCode::generate(now + DEVICE_CODE_TTL);
        assert_eq!(shown.len(), 9);
        assert_eq!(shown.as_bytes()[4], b'-');
        assert!(shown.bytes().filter(|&b| b != b'-').all(|b| CROCKFORD.contains(&b)), "{shown}");
        assert!(code.matches(&shown, now));
        assert!(code.matches(&shown.to_lowercase().replace('-', " "), now), "case and separators are ignored");
        assert!(!code.matches(&shown, now + DEVICE_CODE_TTL), "expired");
        assert!(!code.matches("0000-0000", now) || shown == "0000-0000");
        assert_eq!(normalize_code("k7qm-4xrt").as_deref(), Some("K7QM4XRT"));
        assert_eq!(normalize_code("IL0O-abcd").as_deref(), Some("1100ABCD"), "I and L read as 1, O as 0");
        assert_eq!(normalize_code("U000-0000"), None, "U is not in the alphabet");
        assert_eq!(normalize_code("123"), None);
        // Codes differ from one another.
        let (other, _) = DeviceCode::generate(now);
        assert_ne!(shown, other);
    }

    #[test]
    fn a_decided_ticket_keeps_no_device_code() {
        let mut store = TicketStore::default();
        let now = Instant::now();
        let id = store.create(new_ticket(), now).ticket_id;
        store.get_mut(&id, now).unwrap().device_code = Some(DeviceCode::generate(now + DEVICE_CODE_TTL).1);
        store.get_mut(&id, now).unwrap().status = TicketStatus::Declined;
        assert!(store.get(&id, now).unwrap().device_code.is_none());
    }

    #[test]
    fn pending_tickets_expire() {
        let mut store = TicketStore::default();
        let now = Instant::now();
        let id = store.create(new_ticket(), now).ticket_id;
        assert_eq!(store.get(&id, now + TICKET_TTL - Duration::from_secs(1)).unwrap().status, TicketStatus::PendingApproval);
        assert_eq!(store.get(&id, now + TICKET_TTL).unwrap().status, TicketStatus::Expired);
    }
}
