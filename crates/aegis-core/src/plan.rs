//! Action plans ([ADR 0003](../../../documentation/adr/0003-action-plans.md)):
//! the request shape, its limits, the hash that binds an approval to what was
//! shown, and the text AegisWin writes about a plan. The engine does the
//! checks that need the registry and the vault.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::registry::CommandLine;
use crate::schema::is_hidden_char;

pub const MAX_STEPS: usize = 5;
pub const MAX_TITLE_CHARS: usize = 80;
pub const MAX_PLAN_REASONING_CHARS: usize = 600;
pub const MAX_STEP_REASONING_CHARS: usize = 200;
/// At most this many plans wait for a decision at once.
pub const MAX_PENDING_PLANS: usize = 5;

/// What an agent (or the owner) asks for.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub reasoning: Option<String>,
    pub steps: Vec<StepRequest>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepRequest {
    /// The MCP tool name, `<plugin>__<tool>`.
    pub tool: String,
    #[serde(default = "empty_object")]
    pub args: Value,
    #[serde(default)]
    pub reasoning: Option<String>,
}

fn empty_object() -> Value {
    json!({})
}

/// Who wrote the plan's title and reasoning, shown next to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanOrigin {
    Agent,
    Owner,
}

impl PlanOrigin {
    pub fn label(self) -> &'static str {
        match self {
            Self::Agent => "Supplied by the requesting agent",
            Self::Owner => "Written by you",
        }
    }
}

impl PlanRequest {
    pub fn parse(value: Value) -> Result<Self, String> {
        let request: Self = serde_json::from_value(value).map_err(|e| format!("not a valid plan: {e}"))?;
        if request.steps.is_empty() || request.steps.len() > MAX_STEPS {
            return Err(format!("a plan has 1 to {MAX_STEPS} steps"));
        }
        let title = clean("title", request.title, MAX_TITLE_CHARS, false)?;
        let reasoning = clean("reasoning", request.reasoning, MAX_PLAN_REASONING_CHARS, true)?;
        let mut steps = Vec::with_capacity(request.steps.len());
        for (i, step) in request.steps.into_iter().enumerate() {
            let reasoning = clean(&format!("step {} reasoning", i + 1), step.reasoning, MAX_STEP_REASONING_CHARS, true)?;
            if step.args.get("dryRun") == Some(&Value::Bool(true)) {
                return Err(format!("step {} is a dry run; call the tool directly instead, dry runs need no approval", i + 1));
            }
            steps.push(StepRequest { reasoning, ..step });
        }
        Ok(Self { title, reasoning, steps })
    }
}

/// Trims, treats empty as absent, and refuses text over the limit or with
/// characters that could make it read differently from what it says.
fn clean(what: &str, text: Option<String>, max: usize, newlines: bool) -> Result<Option<String>, String> {
    let Some(text) = text.map(|t| t.trim().to_owned()).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    if text.chars().count() > max {
        return Err(format!("{what} is longer than {max} characters"));
    }
    if text.chars().any(|c| is_hidden_char(c) && !(newlines && c == '\n')) {
        return Err(format!("{what} contains control or invisible characters"));
    }
    Ok(Some(text))
}

/// One step as the hash sees it: the tool, its filled-in arguments, its
/// reasoning, and the commands it runs.
pub type HashedStep = (String, Value, Option<String>, Vec<CommandLine>);

/// SHA-256 of the plan in canonical JSON (sorted keys, no spaces): the title,
/// the reasoning, and each step's tool, filled-in arguments, reasoning and
/// commands (ADR 0004 §5). Everything the review screen shows is covered.
pub fn plan_hash(title: Option<&str>, reasoning: Option<&str>, steps: &[HashedStep]) -> String {
    let steps: Vec<Value> =
        steps.iter().map(|(tool, args, why, commands)| json!({ "tool": tool, "args": args, "reasoning": why, "commands": commands })).collect();
    let mut canonical = String::new();
    write_canonical(&json!({ "title": title, "reasoning": reasoning, "steps": steps }), &mut canonical);
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// The first 8 hex characters, for the owner to match what an agent said.
pub fn short_hash(hash: &str) -> &str {
    &hash[..8.min(hash.len())]
}

/// The one-line summary AegisWin writes from the steps.
pub fn summary(steps: usize, admin_steps: usize) -> String {
    let mut parts = vec![if steps == 1 { "1 step".to_owned() } else { format!("{steps} steps") }];
    if admin_steps > 0 {
        parts.push(format!("{admin_steps} need{} administrator", if admin_steps == 1 { "s" } else { "" }));
    }
    parts.push("changes Windows settings".into());
    parts.push("stops if a step fails, earlier changes stay".into());
    parts.join(" · ")
}

/// Tools the supplied text names that are not steps of the plan, so the
/// owner sees when the reasoning describes a different plan. `known` is every
/// tool as (MCP name, tool id, display name).
pub fn consistency_flags(texts: &[&str], known: &[(String, String, String)], in_plan: &[String]) -> Vec<String> {
    let text = texts.join("\n").to_lowercase();
    let mut flags = Vec::new();
    for (mcp_name, id, name) in known {
        if in_plan.contains(mcp_name) {
            continue;
        }
        let named = [mcp_name.as_str(), id.as_str(), name.as_str()].iter().any(|n| !n.is_empty() && contains_word(&text, &n.to_lowercase()));
        if named {
            flags.push(format!("The supplied text mentions \"{name}\", which is not a step of this plan."));
        }
    }
    flags
}

fn contains_word(text: &str, needle: &str) -> bool {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    text.match_indices(needle).any(|(i, _)| {
        let before = text[..i].chars().next_back().is_none_or(|c| !word(c));
        let after = text[i + needle.len()..].chars().next().is_none_or(|c| !word(c));
        before && after
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn steps(n: usize) -> Value {
        Value::Array((0..n).map(|i| json!({ "tool": format!("windows-health__t{i}") })).collect())
    }

    #[test]
    fn requests_are_bounded() {
        assert!(PlanRequest::parse(json!({ "steps": steps(1) })).is_ok());
        assert!(PlanRequest::parse(json!({ "steps": steps(5) })).is_ok());
        assert!(PlanRequest::parse(json!({ "steps": steps(0) })).unwrap_err().contains("1 to 5"));
        assert!(PlanRequest::parse(json!({ "steps": steps(6) })).unwrap_err().contains("1 to 5"));
        assert!(PlanRequest::parse(json!({ "steps": steps(1), "extra": 1 })).is_err(), "unknown fields");
        assert!(PlanRequest::parse(json!({ "steps": [{ "tool": "a__b", "run": true }] })).is_err());
        let long = "x".repeat(MAX_TITLE_CHARS + 1);
        assert!(PlanRequest::parse(json!({ "title": long, "steps": steps(1) })).unwrap_err().contains("title"));
        let long = "x".repeat(MAX_STEP_REASONING_CHARS + 1);
        assert!(PlanRequest::parse(json!({ "steps": [{ "tool": "a__b", "reasoning": long }] })).unwrap_err().contains("step 1"));
        assert!(PlanRequest::parse(json!({ "steps": [{ "tool": "a__b", "args": { "dryRun": true } }] })).unwrap_err().contains("dry run"));
    }

    #[test]
    fn hidden_characters_are_refused_and_blank_text_is_dropped() {
        let bidi = PlanRequest::parse(json!({ "title": "Reset \u{202E}tesrof", "steps": steps(1) }));
        assert!(bidi.unwrap_err().contains("invisible"));
        assert!(PlanRequest::parse(json!({ "title": "a\nb", "steps": steps(1) })).is_err(), "no newline in a title");
        let ok = PlanRequest::parse(json!({ "title": "  ", "reasoning": " line one\nline two ", "steps": steps(1) })).unwrap();
        assert_eq!((ok.title, ok.reasoning.as_deref()), (None, Some("line one\nline two")));
    }

    #[test]
    fn the_hash_covers_every_shown_field_and_ignores_key_order() {
        let flush = || vec![CommandLine::new(r"C:\Windows\System32\ipconfig.exe", &["/flushdns"])];
        let base = || vec![("windows-health__flush_dns".to_owned(), json!({ "dryRun": false }), None, flush())];
        let h = plan_hash(Some("t"), Some("r"), &base());
        assert_eq!(h.len(), 64);
        assert_eq!(short_hash(&h).len(), 8);
        let reordered = vec![("windows-health__flush_dns".to_owned(), serde_json::from_str(r#"{"dryRun":false}"#).unwrap(), None, flush())];
        assert_eq!(plan_hash(Some("t"), Some("r"), &reordered), h);
        let a = json!({ "a": 1, "b": 2 });
        let b: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        let one = |args: Value| plan_hash(None, None, &[("x__y".to_owned(), args, None, Vec::new())]);
        assert_eq!(one(a), one(b), "key order does not matter");
        assert_ne!(plan_hash(Some("T"), Some("r"), &base()), h, "title");
        assert_ne!(plan_hash(Some("t"), None, &base()), h, "reasoning");
        let mut s = base();
        s[0].2 = Some("why".into());
        assert_ne!(plan_hash(Some("t"), Some("r"), &s), h, "step reasoning");
        let mut s = base();
        s[0].1 = json!({ "dryRun": false, "adapterFilter": "x" });
        assert_ne!(plan_hash(Some("t"), Some("r"), &s), h, "arguments");
        let mut s = base();
        s[0].3[0].args.push("/x".into());
        assert_ne!(plan_hash(Some("t"), Some("r"), &s), h, "commands");
        let mut s = base();
        s[0].3[0].exe = r"C:\Temp\ipconfig.exe".into();
        assert_ne!(plan_hash(Some("t"), Some("r"), &s), h, "the program run");
        let mut s = base();
        s.push(s[0].clone());
        assert_ne!(plan_hash(Some("t"), Some("r"), &s), h, "steps");
    }

    #[test]
    fn summary_line() {
        assert_eq!(summary(3, 2), "3 steps · 2 need administrator · changes Windows settings · stops if a step fails, earlier changes stay");
        assert_eq!(summary(1, 1), "1 step · 1 needs administrator · changes Windows settings · stops if a step fails, earlier changes stay");
        assert!(!summary(2, 0).contains("administrator"));
    }

    #[test]
    fn reasoning_that_names_other_tools_is_flagged() {
        let known = vec![
            ("windows-health__flush_dns".to_owned(), "flush_dns".to_owned(), "Flush DNS Resolver Cache".to_owned()),
            ("windows-health__winsock_reset".to_owned(), "winsock_reset".to_owned(), "Reset Winsock Catalog".to_owned()),
            ("windows-health__sfc_scan".to_owned(), "sfc_scan".to_owned(), "System File Checker".to_owned()),
        ];
        let plan = vec!["windows-health__flush_dns".to_owned()];
        let flags = consistency_flags(&["Flush the DNS cache, then winsock_reset.", "Clears stale entries."], &known, &plan);
        assert_eq!(flags.len(), 1);
        assert!(flags[0].contains("Reset Winsock Catalog"), "{flags:?}");
        // Whole words only, and steps of the plan are never flagged.
        assert!(consistency_flags(&["flush_dns_extra and mysfc_scan"], &known, &plan).is_empty());
        assert!(consistency_flags(&["run flush_dns"], &known, &plan).is_empty());
    }
}
