//! Approval tickets for `pin_required` tools called over MCP.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;

use crate::error::AegisError;

pub const TICKET_TTL: Duration = Duration::from_secs(30 * 60);
pub const STRIKES_PER_TICKET: u8 = 3;
const MAX_TICKETS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    PendingApproval,
    Running,
    Approved,
    Declined,
    ExecutionFailed,
    LockedOut,
    Expired,
}

impl TicketStatus {
    pub fn is_final(self) -> bool {
        !matches!(self, Self::PendingApproval | Self::Running)
    }
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
    pub created: Instant,
    pub created_at: String,
    pub status: TicketStatus,
    pub strikes: u8,
    pub comment: Option<String>,
    pub decided_via: Option<&'static str>,
    pub result: Option<Value>,
    pub error: Option<AegisError>,
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
    pub created_at: String,
    pub status: TicketStatus,
    pub attempts_remaining: u8,
    pub comment: Option<String>,
    pub decided_via: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AegisError>,
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
            created_at: self.created_at.clone(),
            status: self.status,
            attempts_remaining: STRIKES_PER_TICKET.saturating_sub(self.strikes),
            comment: self.comment.clone(),
            decided_via: self.decided_via,
            result: self.result.clone(),
            error: self.error.clone(),
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
        let ticket = Ticket {
            id: random_hex(16),
            csrf: random_hex(16),
            plugin_id: t.plugin_id,
            tool_id: t.tool_id,
            tool_name: t.tool_name,
            tool_description: t.tool_description,
            requires_admin: t.requires_admin,
            args: t.args,
            created: now,
            created_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            status: TicketStatus::PendingApproval,
            strikes: 0,
            comment: None,
            decided_via: None,
            result: None,
            error: None,
        };
        let view = ticket.view();
        self.tickets.insert(ticket.id.clone(), ticket);
        view
    }

    /// Marks pending tickets older than the TTL as expired.
    pub fn expire(&mut self, now: Instant) {
        for t in self.tickets.values_mut() {
            if t.status == TicketStatus::PendingApproval && now.duration_since(t.created) >= TICKET_TTL {
                t.status = TicketStatus::Expired;
            }
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

    pub fn clear(&mut self) {
        self.tickets.clear();
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
    fn pending_tickets_expire() {
        let mut store = TicketStore::default();
        let now = Instant::now();
        let id = store.create(new_ticket(), now).ticket_id;
        assert_eq!(store.get(&id, now + TICKET_TTL - Duration::from_secs(1)).unwrap().status, TicketStatus::PendingApproval);
        assert_eq!(store.get(&id, now + TICKET_TTL).unwrap().status, TicketStatus::Expired);
    }
}
