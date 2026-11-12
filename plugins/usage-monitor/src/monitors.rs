//! Saved monitors (ADR 0002 §1): the owner-approved rules, kept in the
//! plugin's vault store under one record, plus their runtime state.
//!
//! Every change here runs only from a `pin_required` tool, so an agent can
//! propose a monitor but never switch one on, off, or away by itself.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::rules::{self, describe, privacy_flags, Evaluator, Hit, Rule, MAX_MONITORS};

/// The plugin data key holding the [`MonitorBook`].
pub const STORE_KEY: &str = "monitors";
const MAX_ID_CHARS: usize = 20;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredMonitor {
    pub id: String,
    /// The validated, normalized rule. Kept as JSON so a rule that a later
    /// version cannot read is reported instead of breaking every monitor.
    pub rule: Value,
    pub paused: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorBook {
    pub next_id: u64,
    pub monitors: Vec<StoredMonitor>,
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Ids are `m1`, `m2`, …; anything else is refused before a lookup.
pub fn check_id(id: &str) -> Result<(), String> {
    let ok = id.len() <= MAX_ID_CHARS && id.strip_prefix('m').is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
    if ok {
        Ok(())
    } else {
        Err("monitor ids look like m1, m2, ...".into())
    }
}

impl MonitorBook {
    /// Reads the stored record. A record that does not parse is an error,
    /// never an empty book, so a damaged record is not silently overwritten.
    pub fn from_store(value: Option<Value>) -> Result<Self, String> {
        match value {
            None => Ok(Self::default()),
            Some(v) => serde_json::from_value(v).map_err(|e| format!("the saved monitors could not be read ({e}); nothing was changed")),
        }
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("a monitor book always serializes")
    }

    pub fn get(&self, id: &str) -> Option<&StoredMonitor> {
        self.monitors.iter().find(|m| m.id == id)
    }

    fn get_mut(&mut self, id: &str) -> Result<&mut StoredMonitor, String> {
        check_id(id)?;
        self.monitors.iter_mut().find(|m| m.id == id).ok_or_else(|| format!("no monitor with id {id}"))
    }

    /// Adds a validated rule, or replaces the rule of `replace_id` (which keeps
    /// its id and is un-paused). Returns the monitor's id.
    pub fn activate(&mut self, rule: &Rule, replace_id: Option<&str>) -> Result<String, String> {
        let rule = serde_json::to_value(rule).map_err(|e| e.to_string())?;
        if let Some(id) = replace_id {
            let m = self.get_mut(id)?;
            m.rule = rule;
            m.paused = false;
            m.updated_at = now();
            return Ok(m.id.clone());
        }
        if self.monitors.len() >= MAX_MONITORS {
            return Err(format!("there are already {MAX_MONITORS} monitors; delete or replace one first"));
        }
        self.next_id += 1;
        let id = format!("m{}", self.next_id);
        let stamp = now();
        self.monitors.push(StoredMonitor { id: id.clone(), rule, paused: false, created_at: stamp.clone(), updated_at: stamp });
        Ok(id)
    }

    pub fn set_paused(&mut self, id: &str, paused: bool) -> Result<(), String> {
        let m = self.get_mut(id)?;
        if m.paused != paused {
            m.paused = paused;
            m.updated_at = now();
        }
        Ok(())
    }

    pub fn delete(&mut self, id: &str) -> Result<StoredMonitor, String> {
        check_id(id)?;
        let at = self.monitors.iter().position(|m| m.id == id).ok_or_else(|| format!("no monitor with id {id}"))?;
        Ok(self.monitors.remove(at))
    }
}

/// A monitor the sampler is evaluating.
pub struct ActiveMonitor {
    pub id: String,
    pub evaluator: Evaluator,
}

/// Runtime view of the book: which monitors run, and why the others do not.
#[derive(Default)]
pub struct MonitorRuntime {
    pub active: Vec<ActiveMonitor>,
    /// Monitor id → reasons it is not running (besides being paused).
    pub problems: Vec<(String, Vec<String>)>,
    /// Set when the saved record could not be read; nothing runs then.
    pub load_error: Option<String>,
    /// How many monitors are saved, running or paused. `None` when built
    /// from a runtime section (locked) or when the record could not be read.
    pub saved: Option<usize>,
}

impl MonitorRuntime {
    /// Re-validates every saved rule against the components enabled now. A
    /// rule whose component was turned off stops, with the reason, and runs
    /// again when the component is back.
    pub fn build(book: &MonitorBook, enabled_components: &[String]) -> Self {
        let mut rt = Self { saved: Some(book.monitors.len()), ..Self::default() };
        for m in &book.monitors {
            match rules::validate(&m.rule, enabled_components) {
                Ok(rule) if !m.paused => rt.active.push(ActiveMonitor { id: m.id.clone(), evaluator: Evaluator::new(rule) }),
                Ok(_) => {}
                Err(errors) => rt.problems.push((m.id.clone(), errors)),
            }
        }
        rt
    }

    pub fn failed(error: String) -> Self {
        Self { load_error: Some(error), ..Self::default() }
    }

    /// Rebuilds the running monitors from a runtime section
    /// (`{"monitors": [{"id", "rule"}], "components": [...]}`), checking
    /// every rule again. Returns the components the section names too.
    pub fn from_runtime(section: &Value) -> (Self, Vec<String>) {
        let components: Vec<String> = section["components"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default();
        let mut rt = Self::default();
        for m in section["monitors"].as_array().into_iter().flatten().take(MAX_MONITORS) {
            let id = m["id"].as_str().unwrap_or_default().chars().take(MAX_ID_CHARS).collect::<String>();
            match rules::validate(&m["rule"], &components) {
                Ok(rule) => rt.active.push(ActiveMonitor { id, evaluator: Evaluator::new(rule) }),
                Err(errors) => rt.problems.push((id, errors)),
            }
        }
        (rt, components)
    }

    pub fn problems_for(&self, id: &str) -> &[String] {
        self.problems.iter().find(|(m, _)| m == id).map_or(&[], |(_, p)| p.as_slice())
    }

    pub fn is_active(&self, id: &str) -> bool {
        self.active.iter().any(|a| a.id == id)
    }
}

/// The code-generated review of a rule: description and privacy flags.
pub fn review(rule: &Rule) -> Value {
    json!({
        "name": rule.name,
        "description": describe(rule),
        "privacyFlags": privacy_flags(rule).into_iter().map(|f| json!({ "flag": f, "explanation": f.explain() })).collect::<Vec<_>>(),
    })
}

/// One stored monitor as `list_monitors` shows it.
pub fn view(m: &StoredMonitor, rt: &MonitorRuntime, hits: &[MonitorHit]) -> Value {
    // Described from the stored rule even when it cannot run right now.
    let rule = serde_json::from_value::<Rule>(m.rule.clone()).ok();
    let mine: Vec<&MonitorHit> = hits.iter().filter(|h| h.monitor_id == m.id).collect();
    json!({
        "id": m.id,
        "name": rule.as_ref().map(|r| r.name.clone()),
        "paused": m.paused,
        "running": rt.is_active(&m.id),
        "problems": rt.problems_for(&m.id),
        "review": rule.as_ref().map(review),
        // As stored, so the owner can adjust it and activate it with `replaceId`.
        "rule": m.rule,
        "createdAt": m.created_at,
        "updatedAt": m.updated_at,
        "hitsSinceUnlock": mine.len(),
        "lastHit": mine.last().map(|h| h.time.clone()),
    })
}

/// A recorded hit (in memory; cleared on lock and by purge).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorHit {
    pub monitor_id: String,
    pub name: String,
    pub time: String,
    pub matched: Vec<String>,
}

impl MonitorHit {
    pub fn new(monitor_id: &str, name: &str, hit: Hit) -> Self {
        Self { monitor_id: monitor_id.to_owned(), name: name.to_owned(), time: hit.time, matched: hit.matched }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{COMPONENT_CRASHES, COMPONENT_FOREGROUND, COMPONENT_SPIKES};

    fn all() -> Vec<String> {
        vec![COMPONENT_SPIKES.into(), COMPONENT_CRASHES.into(), COMPONENT_FOREGROUND.into()]
    }

    fn rule(name: &str) -> Rule {
        let v = json!({
            "version": 1, "name": name,
            "schedule": { "startTime": "00:00", "endTime": "00:00" },
            "trigger": { "any": [{ "type": "process_cpu", "process": "game.exe", "atLeastPercent": 50, "forSeconds": 10 }] },
            "cooldownSeconds": 60, "notify": "none"
        });
        rules::validate(&v, &all()).unwrap()
    }

    #[test]
    fn ids_are_sequential_and_never_reused() {
        let mut book = MonitorBook::default();
        assert_eq!(book.activate(&rule("a"), None).unwrap(), "m1");
        assert_eq!(book.activate(&rule("b"), None).unwrap(), "m2");
        book.delete("m2").unwrap();
        assert_eq!(book.activate(&rule("c"), None).unwrap(), "m3", "a deleted id is not handed out again");
    }

    #[test]
    fn replacing_keeps_the_id_and_resumes() {
        let mut book = MonitorBook::default();
        book.activate(&rule("a"), None).unwrap();
        book.set_paused("m1", true).unwrap();
        assert_eq!(book.activate(&rule("a2"), Some("m1")).unwrap(), "m1");
        assert_eq!(book.monitors.len(), 1);
        assert!(!book.monitors[0].paused);
        assert_eq!(book.monitors[0].rule["name"], "a2");
        assert!(book.activate(&rule("x"), Some("m9")).unwrap_err().contains("no monitor"));
        assert!(book.activate(&rule("x"), Some("../m1")).unwrap_err().contains("look like"));
    }

    #[test]
    fn the_cap_counts_saved_monitors() {
        let mut book = MonitorBook::default();
        for i in 0..MAX_MONITORS {
            book.activate(&rule(&format!("r{i}")), None).unwrap();
        }
        assert!(book.activate(&rule("one more"), None).unwrap_err().contains("already 20"));
        assert!(book.activate(&rule("replace is fine"), Some("m3")).is_ok());
    }

    #[test]
    fn a_damaged_record_is_an_error_not_an_empty_book() {
        assert_eq!(MonitorBook::from_store(None).unwrap(), MonitorBook::default());
        assert!(MonitorBook::from_store(Some(json!({ "monitors": "nope" }))).is_err());
        let mut book = MonitorBook::default();
        book.activate(&rule("a"), None).unwrap();
        assert_eq!(MonitorBook::from_store(Some(book.to_value())).unwrap(), book);
    }

    #[test]
    fn runtime_skips_paused_and_reports_missing_components() {
        let mut book = MonitorBook::default();
        book.activate(&rule("a"), None).unwrap();
        book.activate(&rule("b"), None).unwrap();
        book.set_paused("m2", true).unwrap();
        let rt = MonitorRuntime::build(&book, &all());
        assert!(rt.is_active("m1") && !rt.is_active("m2"));
        assert!(rt.problems.is_empty());
        let off = MonitorRuntime::build(&book, &[COMPONENT_CRASHES.to_owned()]);
        assert!(!off.is_active("m1"));
        assert!(off.problems_for("m1")[0].contains("resource-spikes"));
    }
}
