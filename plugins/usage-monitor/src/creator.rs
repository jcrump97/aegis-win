//! The AI monitor creator's checks (ADR 0002 §2-3): the reply format the
//! model must use, its limits, the question filter, and the consistency check
//! between the AI's reasoning and the rule.
//!
//! The model never acts: a proposal still goes through [`rules::validate`],
//! the owner's review, and the PIN. These checks keep its questions on topic
//! and its explanation honest.

use serde_json::{Map, Value};

use crate::rules::{self, clean_text, Condition, Rule};

pub const MAX_ROUNDS: usize = 3;
pub const MAX_QUESTIONS: usize = 3;
pub const MAX_QUESTION_CHARS: usize = 200;
pub const MAX_CHOICES: usize = 4;
pub const MAX_CHOICE_CHARS: usize = 80;
pub const MAX_REASONING_BULLETS: usize = 3;
pub const MAX_REASONING_CHARS: usize = 600;
const MAX_REASON_CHARS: usize = 300;

pub const INCONSISTENT: &str = "The AI's explanation mentions things this monitor does not watch.";

#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    pub text: String,
    pub choices: Vec<String>,
}

/// One AI turn. Exactly one of these, or the turn is rejected.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    Questions(Vec<Question>),
    /// `rule` is unchecked here; it goes through [`rules::validate`] next.
    Proposal { rule: Value, reasoning: Vec<String> },
    Unsupported { reason: String },
    /// Asks the owner to share running process names, once per conversation.
    RequestRunningApps { reason: String },
}

/// The text the model was asked to reply with, as a JSON object. Fenced
/// code blocks and text around the object are tolerated.
fn json_object(text: &str) -> Result<Map<String, Value>, String> {
    let (start, end) = (text.find('{'), text.rfind('}'));
    let (Some(start), Some(end)) = (start, end) else { return Err("the reply is not a JSON object".into()) };
    if end < start {
        return Err("the reply is not a JSON object".into());
    }
    match serde_json::from_str::<Value>(&text[start..=end]) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err("the reply is not a JSON object".into()),
        Err(e) => Err(format!("the reply is not valid JSON ({e})")),
    }
}

fn only_keys(map: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), String> {
    match map.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(format!("{what} has an unknown field '{}'", rules::echo(k, 40))),
        None => Ok(()),
    }
}

fn text_field(map: &Map<String, Value>, key: &str, max: usize, what: &str) -> Result<String, String> {
    let raw = map.get(key).and_then(Value::as_str).ok_or_else(|| format!("{what} needs a '{key}' string"))?;
    let text = clean_text(raw);
    if text.is_empty() {
        return Err(format!("{what} '{key}' is empty"));
    }
    if text.chars().count() > max {
        return Err(format!("{what} '{key}' is longer than {max} characters"));
    }
    Ok(text)
}

fn object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object().ok_or_else(|| format!("{what} must be an object"))
}

/// Parses and checks one AI turn. Errors are short and safe to show the
/// model on its one retry.
pub fn parse_reply(text: &str) -> Result<Reply, String> {
    let map = json_object(text)?;
    if map.len() != 1 {
        return Err("the reply must have exactly one of: questions, proposal, unsupported, requestRunningApps".into());
    }
    let (kind, body) = map.iter().next().expect("one entry");
    match kind.as_str() {
        "questions" => {
            let list = body.as_array().ok_or("questions must be a list")?;
            if list.is_empty() || list.len() > MAX_QUESTIONS {
                return Err(format!("ask 1-{MAX_QUESTIONS} questions"));
            }
            let mut out = Vec::new();
            for (i, q) in list.iter().enumerate() {
                let what = format!("question {}", i + 1);
                let q = object(q, &what)?;
                only_keys(q, &["text", "choices"], &what)?;
                let text = text_field(q, "text", MAX_QUESTION_CHARS, &what)?;
                let choices = match q.get("choices") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(c)) if c.len() <= MAX_CHOICES => c
                        .iter()
                        .map(|c| {
                            let c = clean_text(c.as_str().ok_or_else(|| format!("{what}: choices must be strings"))?);
                            if c.is_empty() || c.chars().count() > MAX_CHOICE_CHARS {
                                return Err(format!("{what}: each choice must be 1-{MAX_CHOICE_CHARS} characters"));
                            }
                            Ok(c)
                        })
                        .collect::<Result<_, String>>()?,
                    Some(_) => return Err(format!("{what}: at most {MAX_CHOICES} choices")),
                };
                out.push(Question { text, choices });
            }
            Ok(Reply::Questions(out))
        }
        "proposal" => {
            let p = object(body, "proposal")?;
            only_keys(p, &["rule", "reasoning"], "proposal")?;
            let rule = p.get("rule").filter(|r| r.is_object()).cloned().ok_or("proposal needs a 'rule' object")?;
            let bullets: Vec<&str> = match p.get("reasoning") {
                Some(Value::String(s)) => vec![s.as_str()],
                Some(Value::Array(a)) if !a.is_empty() && a.len() <= MAX_REASONING_BULLETS => {
                    a.iter().map(|b| b.as_str().ok_or("reasoning bullets must be strings")).collect::<Result<_, _>>()?
                }
                _ => return Err(format!("proposal needs 'reasoning': a string or 1-{MAX_REASONING_BULLETS} strings")),
            };
            // 600 characters in total; whatever is past that is cut.
            let mut left = MAX_REASONING_CHARS;
            let mut reasoning = Vec::new();
            for b in bullets {
                let b: String = clean_text(b).chars().take(left).collect();
                left -= b.chars().count();
                if !b.is_empty() {
                    reasoning.push(b);
                }
            }
            Ok(Reply::Proposal { rule, reasoning })
        }
        "unsupported" | "requestRunningApps" => {
            let what = kind.as_str();
            let b = object(body, what)?;
            only_keys(b, &["reason"], what)?;
            let reason = text_field(b, "reason", MAX_REASON_CHARS, what)?;
            Ok(if what == "unsupported" { Reply::Unsupported { reason } } else { Reply::RequestRunningApps { reason } })
        }
        other => Err(format!("unknown reply type '{}'", rules::echo(other, 40))),
    }
}

/// Lower-cased words, splitting on anything but letters, digits, `.`, `_`, `-`.
fn words(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !(c.is_alphanumeric() || matches!(c, '.' | '_' | '-')))
        .map(|w| w.trim_matches(|c| c == '.' || c == '-').to_owned())
        .filter(|w| !w.is_empty())
        .collect()
}

const SECRET_WORDS: &[&str] = &[
    "password", "passwords", "passphrase", "passcode", "pin", "pins", "token", "tokens", "secret", "secrets", "credential", "credentials",
    "apikey", "otp", "2fa", "mfa",
];
const SECRET_PHRASES: &[&str] = &["api key", "private key", "recovery code", "security code", "one-time code", "seed phrase"];
const CODE_MARKS: &[&str] = &[
    "`", "$(", "&&", "||", "<script", "#!", "powershell", "pwsh", "cmd.exe", "cmd /", "iex", "invoke-", "bash", "curl ", "wget ", "regedit", "reg add",
    "reg delete", "netsh", "sudo",
];
// Narrow on purpose: "does it freeze when you click play?" is a fair question.
const ACTION_WORDS: &[&str] = &["install", "uninstall", "reinstall", "download", "execute", "paste"];
const ACTION_PHRASES: &[&str] = &[
    "run this", "run the following", "please run", "can you run", "could you run", "try running", "click here", "click this", "click the link",
    "change your", "change the setting", "turn off your", "open this", "please visit", "please disable", "disable your", "please delete", "delete your",
];
const TLDS: &[&str] = &["com", "net", "org", "io", "co", "ru", "cn", "xyz", "info", "biz", "app", "dev", "ly", "me", "gg", "top", "site", "link"];

/// Why a question or choice must not be shown, if it must not. A backstop:
/// the AI cannot act, so this only keeps it from steering the owner.
pub fn question_problem(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    let collapsed = lower.split_whitespace().collect::<Vec<_>>().join(" ");
    let ws = words(&lower);
    let has_word = |list: &[&str]| ws.iter().any(|w| list.contains(&w.as_str()));
    let has_phrase = |list: &[&str]| list.iter().any(|p| collapsed.contains(p));
    let link = collapsed.contains("://") || collapsed.contains("www.") || ws.iter().any(|w| w.rsplit_once('.').is_some_and(|(_, tld)| TLDS.contains(&tld)));
    if link {
        Some("it contained a link")
    } else if has_word(SECRET_WORDS) || has_phrase(SECRET_PHRASES) {
        Some("it asked for a password, PIN, key, or other secret")
    } else if CODE_MARKS.iter().any(|m| collapsed.contains(m)) {
        Some("it contained code or a command")
    } else if has_word(ACTION_WORDS) || has_phrase(ACTION_PHRASES) {
        Some("it asked you to run, install, download, or change something")
    } else {
        None
    }
}

/// A question that was dropped, with the reason the owner sees.
#[derive(Debug, Clone, PartialEq)]
pub struct Dropped {
    pub reason: &'static str,
}

/// Keeps the questions that pass [`question_problem`]; a bad choice drops
/// only that choice.
pub fn filter_questions(questions: Vec<Question>) -> (Vec<Question>, Vec<Dropped>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for mut q in questions {
        if let Some(reason) = question_problem(&q.text) {
            dropped.push(Dropped { reason });
            continue;
        }
        let before = q.choices.len();
        q.choices.retain(|c| question_problem(c).is_none());
        if q.choices.len() < before {
            dropped.push(Dropped { reason: "a suggested answer was removed by the same checks" });
        }
        kept.push(q);
    }
    (kept, dropped)
}

/// True when `reasoning` names a process or event id the rule does not use.
pub fn mentions_unwatched(reasoning: &str, rule: &Rule) -> bool {
    let mut processes = Vec::new();
    let mut any_process = false;
    let mut events = Vec::new();
    for c in rule.trigger.conditions() {
        match c {
            Condition::ProcessCpu { process, .. } | Condition::ProcessMemory { process, .. } | Condition::Crash { process } | Condition::Foreground { process } => {
                if process == "*" {
                    any_process = true;
                } else {
                    processes.push(process.to_lowercase());
                }
            }
            Condition::Event { event_id, .. } => events.push(*event_id),
            Condition::SystemCpu { .. } | Condition::SystemMemory { .. } => {}
        }
        if matches!(c, Condition::Crash { .. }) {
            events.extend([1000, 1002]);
        }
    }
    let ws = words(reasoning);
    let unknown_process = !any_process && ws.iter().any(|w| w.ends_with(".exe") && w.len() > 4 && !processes.contains(w));
    // An event id is a number right after "event", "id", or "event id".
    let unknown_event = ws.windows(2).any(|w| {
        matches!(w[0].as_str(), "event" | "events" | "id" | "eventid" | "event-id") && w[1].parse::<u32>().is_ok_and(|id| !events.contains(&id))
    });
    unknown_process || unknown_event
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{COMPONENT_CRASHES, COMPONENT_FOREGROUND, COMPONENT_SPIKES};
    use serde_json::json;

    fn rule(trigger: Value) -> Rule {
        let components = [COMPONENT_SPIKES, COMPONENT_CRASHES, COMPONENT_FOREGROUND].map(String::from);
        let v = json!({ "version": 1, "name": "R", "schedule": { "startTime": "00:00", "endTime": "00:00" }, "trigger": trigger, "cooldownSeconds": 60, "notify": "none" });
        rules::validate(&v, &components).unwrap()
    }

    #[test]
    fn each_reply_type_parses_from_fenced_or_chatty_text() {
        let q = parse_reply("Sure!\n```json\n{\"questions\":[{\"text\":\"Which game?\",\"choices\":[\"game.exe\",\"other\"]}]}\n```").unwrap();
        assert_eq!(q, Reply::Questions(vec![Question { text: "Which game?".into(), choices: vec!["game.exe".into(), "other".into()] }]));
        assert!(matches!(parse_reply(r#"{"proposal":{"rule":{"version":1},"reasoning":"Because."}}"#).unwrap(), Reply::Proposal { reasoning, .. } if reasoning == ["Because."]));
        assert_eq!(parse_reply(r#"{"unsupported":{"reason":"GPU temperature is not something AegisWin can watch."}}"#).unwrap(), Reply::Unsupported { reason: "GPU temperature is not something AegisWin can watch.".into() });
        assert!(matches!(parse_reply(r#"{"requestRunningApps":{"reason":"To find the game's process name."}}"#).unwrap(), Reply::RequestRunningApps { .. }));
    }

    #[test]
    fn replies_outside_the_format_or_limits_are_rejected() {
        let long = "x".repeat(MAX_QUESTION_CHARS + 1);
        for bad in [
            "no json here".to_owned(),
            "[1,2]".into(),
            r#"{"questions":[],"proposal":{}}"#.into(),
            r#"{"questions":[]}"#.into(),
            r#"{"questions":[{"text":"a"},{"text":"b"},{"text":"c"},{"text":"d"}]}"#.into(),
            format!(r#"{{"questions":[{{"text":"{long}"}}]}}"#),
            r#"{"questions":[{"text":"a","choices":["1","2","3","4","5"]}]}"#.into(),
            r#"{"questions":[{"text":"a","run":"x"}]}"#.into(),
            r#"{"proposal":{"rule":"not an object","reasoning":"r"}}"#.into(),
            r#"{"proposal":{"rule":{},"reasoning":["1","2","3","4"]}}"#.into(),
            r#"{"execute":{"command":"x"}}"#.into(),
            json!({ "questions": [{ "text": "\u{200b}\u{202e}" }] }).to_string(),
        ] {
            assert!(parse_reply(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reasoning_is_cleaned_and_capped_in_total() {
        let b = "y".repeat(400);
        let Reply::Proposal { reasoning, .. } = parse_reply(&format!(r#"{{"proposal":{{"rule":{{}},"reasoning":["{b}","{b}","{b}"]}}}}"#)).unwrap() else { panic!() };
        assert_eq!(reasoning.iter().map(|r| r.chars().count()).sum::<usize>(), MAX_REASONING_CHARS);
        assert_eq!(reasoning.len(), 2, "the third bullet had nothing left");
        let Reply::Proposal { reasoning, .. } = parse_reply("{\"proposal\":{\"rule\":{},\"reasoning\":\"ok\\u202e then\"}}").unwrap() else { panic!() };
        assert!(!reasoning[0].contains('\u{202E}'));
    }

    #[test]
    fn off_topic_questions_are_caught() {
        for (text, why) in [
            ("Can you open https://example.com/fix?", "link"),
            ("Check example.ru for a patch?", "link"),
            ("What is your Windows password?", "secret"),
            ("Please share your PIN so I can test", "secret"),
            ("What is your OpenAI API key?", "secret"),
            ("Paste the output of `Get-Process`", "code"),
            ("Run powershell -c iex(...) and tell me", "code"),
            ("Could you install the latest driver first?", "run, install"),
            ("Please run this and tell me what happens", "run, install"),
            ("Download the tool from the vendor?", "run, install"),
        ] {
            let p = question_problem(text).unwrap_or_else(|| panic!("not caught: {text}"));
            assert!(p.contains(why), "{text}: {p}");
        }
        for ok in [
            "Which app freezes: is it game.exe?",
            "Does it happen when the game is running, or at startup?",
            "How long does the freeze last?",
            "Is it worse on weekday evenings?",
            "Do you see an error message before it closes?",
            "Does it freeze at login, or when you click play?",
            "Did it start after a Windows update?",
        ] {
            assert_eq!(question_problem(ok), None, "{ok}");
        }
    }

    #[test]
    fn filtering_drops_bad_questions_and_choices_with_a_reason() {
        let qs = vec![
            Question { text: "Which app?".into(), choices: vec!["game.exe".into(), "see www.x.com".into()] },
            Question { text: "What's your password?".into(), choices: vec![] },
        ];
        let (kept, dropped) = filter_questions(qs);
        assert_eq!(kept, vec![Question { text: "Which app?".into(), choices: vec!["game.exe".into()] }]);
        assert_eq!(dropped.len(), 2);
    }

    #[test]
    fn the_consistency_check_flags_processes_and_event_ids_the_rule_does_not_watch() {
        let r = rule(json!({ "all": [
            { "type": "process_cpu", "process": "game.exe", "atLeastPercent": 80, "forSeconds": 30 },
            { "type": "event", "channel": "System", "eventId": 41 }
        ] }));
        assert!(!mentions_unwatched("game.exe pegs the CPU right before event 41 (Kernel-Power).", &r));
        assert!(!mentions_unwatched("Your GAME.EXE gets slow; Event ID 41 follows.", &r), "case does not matter");
        assert!(mentions_unwatched("game.exe and launcher.exe both spike.", &r));
        assert!(mentions_unwatched("This also catches event ID 1001.", &r));
        assert!(!mentions_unwatched("It needs 30 seconds above 80% CPU.", &r), "plain numbers are not event ids");

        let crash = rule(json!({ "any": [{ "type": "crash", "process": "*" }] }));
        assert!(!mentions_unwatched("Any app crash (event 1000) or hang (event 1002), like game.exe.", &crash), "crash covers 1000/1002 and * covers any app");
    }
}
