//! `event-logs`: read-only Windows event log queries plus LLM explanations.

use aegis_core::os::eventlog::{self, EventLogError, EventQuery};
use aegis_core::registry::{Plugin, PluginManifest, ToolContext};
use aegis_core::{AegisError, AegisResult, ErrorCode};
use async_trait::async_trait;
use serde_json::{json, Value};

const SYSTEM_PROMPT: &str = "You are a Windows diagnostics assistant. The user message contains Windows event log \
entries as JSON. Identify the most likely root cause, explain it in plain language, and list safe next steps in order, \
starting with the least invasive. Say when the evidence is not enough to be sure. Never ask for passwords or PINs.";

pub struct EventLogsPlugin {
    manifest: PluginManifest,
}

impl Default for EventLogsPlugin {
    fn default() -> Self {
        Self { manifest: PluginManifest::from_json(include_str!("../manifest.json")).expect("event-logs manifest.json is valid") }
    }
}

/// Maps a minimum severity to the event levels it includes.
pub fn levels_for(severity: &str) -> Vec<u8> {
    match severity {
        "Critical" => vec![1],
        "Error" => vec![1, 2],
        "Warning" => vec![1, 2, 3],
        "Information" => vec![1, 2, 3, 4],
        _ => vec![],
    }
}

fn int(args: &Value, key: &str) -> Option<u64> {
    args.get(key).and_then(Value::as_u64)
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

async fn run_query(query: EventQuery, elevated: bool) -> AegisResult<Value> {
    let channel = query.channel.clone();
    let events = tokio::task::spawn_blocking(move || eventlog::query(&query))
        .await
        .map_err(|e| AegisError::failed(e.to_string()))?
        .map_err(|e| match e {
            EventLogError::AccessDenied(ch) if !elevated => AegisError::requires_admin(&format!("Reading the {ch} log")),
            EventLogError::AccessDenied(ch) => AegisError::new(ErrorCode::AccessDenied, format!("Windows denied access to the {ch} log")),
            EventLogError::UnknownChannel(_) | EventLogError::InvalidFilter(_) => AegisError::invalid(e.to_string()),
            EventLogError::Failed(msg) => AegisError::failed(msg),
        })?;
    Ok(json!({ "channel": channel, "count": events.len(), "events": events }))
}

#[async_trait]
impl Plugin for EventLogsPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn call(&self, tool: &str, args: Value, ctx: ToolContext) -> AegisResult<Value> {
        let base = |args: &Value| EventQuery {
            channel: str_arg(args, "channel").unwrap_or("Application").to_owned(),
            limit: int(args, "limit").unwrap_or(25) as usize,
            lookback_hours: int(args, "lookbackHours").map(|h| h as u32),
            ..Default::default()
        };
        match tool {
            "query_logs" => {
                let query = EventQuery { levels: levels_for(str_arg(&args, "severity").unwrap_or("Error")), ..base(&args) };
                run_query(query, ctx.elevated).await
            }
            "filter_by_event_id" => {
                let event_id = int(&args, "eventId").ok_or_else(|| AegisError::invalid("eventId is required"))? as u32;
                let provider = str_arg(&args, "source").map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned);
                let query = EventQuery { event_ids: vec![event_id], provider, ..base(&args) };
                run_query(query, ctx.elevated).await
            }
            "analyze_logs_with_llm" => {
                let events = args.get("events").cloned().unwrap_or(Value::Array(vec![]));
                if events.as_array().is_none_or(|e| e.is_empty()) {
                    return Err(AegisError::invalid("select at least one event to analyze"));
                }
                let focus = str_arg(&args, "focusQuestion").unwrap_or("What is going wrong, and what should I do about it?");
                let answer = ctx.llm()?.complete(SYSTEM_PROMPT, json!({ "question": focus, "events": events })).await?;
                Ok(json!({ "analysis": answer }))
            }
            other => Err(AegisError::new(ErrorCode::UnknownTool, format!("event-logs has no tool '{other}'"))),
        }
    }
}
