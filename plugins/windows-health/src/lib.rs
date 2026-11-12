//! `windows-health`: PIN-gated Windows repair commands. `describe` lists the
//! exact commands from the same `plan` that runs them, so AegisWin answers
//! dry runs and binds approvals to what was shown (ADR 0004 §5).

use std::time::Duration;

use aegis_core::os::{self, CommandOutput};
use aegis_core::registry::{CallReview, CommandLine, Plugin, PluginManifest, ToolContext};
use aegis_core::{AegisError, AegisResult, ErrorCode};
use async_trait::async_trait;
use serde_json::{json, Value};

const SYSTEM_PROMPT: &str = "You are a Windows repair assistant. The user message contains output from a Windows \
maintenance command (sfc, ipconfig, or netsh). Explain what the output means in plain language, whether anything \
still needs fixing, and the safest next steps (for example DISM /RestoreHealth after unrepaired SFC results). \
Never ask for passwords or PINs.";

/// One planned system command: executable in System32 plus its argument vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub exe: &'static str,
    pub args: Vec<String>,
    pub timeout: Duration,
}

impl Step {
    fn new(exe: &'static str, args: &[&str], timeout_secs: u64) -> Self {
        Self { exe, args: args.iter().map(|a| a.to_string()).collect(), timeout: Duration::from_secs(timeout_secs) }
    }
    /// The command as AegisWin shows and checks it: System32's absolute path
    /// (the folder `os::run_system_binary` runs it from) and the argv.
    pub fn command_line(&self) -> CommandLine {
        CommandLine { exe: os::system32().join(self.exe).to_string_lossy().into_owned(), args: self.args.clone() }
    }
}

pub struct Plan {
    pub steps: Vec<Step>,
    pub impact: &'static str,
}

/// The repairs: every tool except the read-only interpreter.
const REPAIRS: [&str; 4] = ["sfc_scan", "flush_dns", "ip_release_renew", "winsock_reset"];

/// Adapter names are passed as one argv element, but are still limited to
/// characters real adapter names and ipconfig wildcards use.
pub fn valid_adapter_filter(filter: &str) -> bool {
    filter.chars().all(|c| c.is_alphanumeric() || " *-_.()#".contains(c))
}

pub fn plan(tool: &str, args: &Value) -> AegisResult<Plan> {
    Ok(match tool {
        "sfc_scan" => Plan {
            steps: vec![Step::new("sfc.exe", &["/scannow"], 45 * 60)],
            impact: "Scans every protected system file and replaces corrupted ones from the component store. Takes 5-20 minutes and uses a lot of disk I/O. Nothing is changed when no violations are found.",
        },
        "flush_dns" => Plan {
            steps: vec![Step::new("ipconfig.exe", &["/flushdns"], 60)],
            impact: "Clears cached DNS answers. The next lookup of each name takes slightly longer. No connections are dropped.",
        },
        "ip_release_renew" => {
            let filter = args.get("adapterFilter").and_then(Value::as_str).unwrap_or("").trim();
            if !valid_adapter_filter(filter) {
                return Err(AegisError::invalid("adapterFilter may contain letters, digits, spaces and * - _ . ( ) # only"));
            }
            let (release, renew) =
                if filter.is_empty() { (vec!["/release"], vec!["/renew"]) } else { (vec!["/release", filter], vec!["/renew", filter]) };
            Plan {
                steps: vec![Step::new("ipconfig.exe", &release, 120), Step::new("ipconfig.exe", &renew, 180)],
                impact: "Gives up the current DHCP IPv4 address and requests a new one. Network connections (downloads, calls, remote sessions) drop for a few seconds. Adapters with static IPs are not affected.",
            }
        }
        "winsock_reset" => Plan {
            steps: vec![Step::new("netsh.exe", &["winsock", "reset"], 120)],
            impact: "Restores the Winsock catalog to defaults and removes third-party layered providers (some VPN, proxy, or security software). Windows must be restarted to finish; affected software may need reinstalling.",
        },
        other => return Err(AegisError::new(ErrorCode::UnknownTool, format!("windows-health has no repair '{other}'"))),
    })
}

/// Classifies `sfc /scannow` output (English Windows).
pub fn summarize_sfc(output: &str) -> &'static str {
    let text = output.to_ascii_lowercase();
    if text.contains("did not find any integrity violations") {
        "no_violations"
    } else if text.contains("successfully repaired") {
        "repaired"
    } else if text.contains("unable to fix") {
        "unrepaired"
    } else if text.contains("could not perform the requested operation") || text.contains("pending repair") {
        "could_not_run"
    } else {
        "unknown"
    }
}

async fn run_step(step: Step) -> AegisResult<CommandOutput> {
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = step.args.iter().map(String::as_str).collect();
        os::run_system_binary(step.exe, &args, step.timeout)
    })
    .await
    .map_err(|e| AegisError::failed(e.to_string()))?
    .map_err(|e| AegisError::failed(format!("could not start the command: {e}")))
}

pub struct WindowsHealthPlugin {
    manifest: PluginManifest,
}

impl Default for WindowsHealthPlugin {
    fn default() -> Self {
        Self { manifest: PluginManifest::from_json(include_str!("../manifest.json")).expect("windows-health manifest.json is valid") }
    }
}

#[async_trait]
impl Plugin for WindowsHealthPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn call(&self, tool: &str, args: Value, ctx: ToolContext) -> AegisResult<Value> {
        if tool == "interpret_health_output" {
            let output = args.get("commandOutput").and_then(Value::as_str).unwrap_or_default();
            let focus = args.get("focusQuestion").and_then(Value::as_str).unwrap_or("What does this mean and what should I do next?");
            let answer = ctx.llm()?.complete(SYSTEM_PROMPT, json!({ "question": focus, "commandOutput": output })).await?;
            return Ok(json!({ "analysis": answer }));
        }

        // AegisWin answers dry runs from `describe` and never calls this for one.
        // Refused rather than run, should that ever change.
        if args.get("dryRun") == Some(&Value::Bool(true)) {
            return Err(AegisError::invalid("windows-health does not run dry runs; AegisWin answers them"));
        }
        let plan = plan(tool, &args)?;
        let commands: Vec<String> = plan.steps.iter().map(|s| s.command_line().display()).collect();

        let mut outputs = Vec::new();
        for step in plan.steps {
            let out = run_step(step).await?;
            let failed = !out.success();
            if failed && !ctx.elevated && out.mentions_elevation() {
                return Err(AegisError::requires_admin(&out.command));
            }
            outputs.push(out);
            if failed {
                break;
            }
        }
        let ok = outputs.iter().all(CommandOutput::success);
        let combined = outputs.iter().map(|o| o.stdout.as_str()).collect::<Vec<_>>().join("\n\n");
        let mut result = json!({
            "executed": true,
            "success": ok,
            "commands": commands,
            "outputs": outputs,
        });
        match tool {
            "sfc_scan" => result["sfcResult"] = json!(summarize_sfc(&combined)),
            "winsock_reset" if ok => result["rebootRequired"] = json!(true),
            _ => {}
        }
        Ok(result)
    }

    fn describe(&self, tool: &str, args: &Value) -> Option<AegisResult<Vec<CommandLine>>> {
        REPAIRS.contains(&tool).then(|| plan(tool, args).map(|p| p.steps.iter().map(Step::command_line).collect()))
    }

    fn review_call(&self, tool: &str, args: &Value, _enabled_components: &[String]) -> Option<CallReview> {
        let plan = plan(tool, args).ok()?;
        let mut lines = vec![plan.impact.to_owned()];
        lines.extend(plan.steps.iter().map(|s| format!("Runs {}", s.command_line().display())));
        if plan.steps.len() > 1 {
            lines.push("Stops at the first command that fails.".into());
        }
        let mut warnings = Vec::new();
        match tool {
            "ip_release_renew" => warnings.push("Network connections drop for a few seconds, including any remote session to this PC.".to_owned()),
            "winsock_reset" => warnings.push("Windows must be restarted to finish, and some VPN or security software may need reinstalling.".to_owned()),
            _ => {}
        }
        Some(CallReview { lines, warnings })
    }
}
