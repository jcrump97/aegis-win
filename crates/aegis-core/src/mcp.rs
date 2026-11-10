//! MCP server (Streamable HTTP, JSON responses only) and the device page for
//! approving on another device.
//!
//! - `POST /mcp`: JSON-RPC 2.0, bearer token required.
//! - `GET|POST /approve/{ticketId}`: a no-script HTML page that exists only
//!   while the owner has turned on Approve from another device. Approving
//!   needs the one-time code the app showed for that request; declining
//!   needs nothing. The page never asks for the PIN (ADR 0004 §1.1).
//!   Protected by a per-ticket CSRF token.
//!
//! Every request must carry a `Host` header naming the address it arrived on
//! (DNS rebinding defense), and a cross-site `Origin` is rejected.
//!
//! A LAN bind also listens on `127.0.0.1` at the same port, so clients on this
//! PC keep one fixed URL whatever the bind address. Device page links always
//! use the bind address, so other devices on the network can open them.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::engine::{Engine, Origin, RunOutcome};
use crate::error::{AegisError, AegisResult, ErrorCode};
use crate::plan::{PlanOrigin, MAX_PLAN_REASONING_CHARS, MAX_STEPS, MAX_STEP_REASONING_CHARS, MAX_TITLE_CHARS};
use crate::registry::{self, GatePolicy};
use crate::tickets::{PlanMeta, StepStatus, TicketStatus, TicketView};

/// Newest first. The first entry is offered when a client asks for a version we do not know.
pub const PROTOCOL_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
pub const CHECK_TICKET_TOOL: &str = "aegis__check_ticket";
pub const PROPOSE_PLAN_TOOL: &str = "aegis__propose_plan";
pub const CANCEL_TICKET_TOOL: &str = "aegis__cancel_ticket";
const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpStatus {
    pub running: bool,
    /// The bind address URL. For a LAN bind, what other devices on the network use.
    pub url: Option<String>,
    /// Set only for a LAN bind: the `127.0.0.1` URL that clients on this PC use.
    pub local_url: Option<String>,
    pub firewall_rule: bool,
    /// Something the owner should know (e.g. the firewall rule could not be added).
    pub note: Option<String>,
}

impl McpStatus {
    pub fn stopped() -> Self {
        Self { running: false, url: None, local_url: None, firewall_rule: false, note: None }
    }
}

pub struct McpHandle {
    /// `true` once stopping: listeners stop accepting and refuse every request.
    stopped: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    status: McpStatus,
    firewall_rule: Option<String>,
}

impl McpHandle {
    pub fn status(&self) -> McpStatus {
        self.status.clone()
    }

    pub async fn stop(self) {
        self.stopped.send_replace(true);
        // Connections still open after this run on as their own tasks, but
        // host_guard refuses anything they send.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        for task in self.tasks {
            let _ = tokio::time::timeout_at(deadline, task).await;
        }
        if let Some(rule) = self.firewall_rule {
            let _ = tokio::task::spawn_blocking(move || delete_firewall_rule(&rule)).await;
        }
    }
}

#[derive(Clone)]
struct AppState {
    engine: Arc<Engine>,
    allowed_hosts: Arc<Vec<String>>,
    stopped: watch::Receiver<bool>,
}

/// The `Host` values a listener on `host:port` accepts: only its own address.
fn allowed_hosts(host: Ipv4Addr, port: u16) -> Vec<String> {
    let mut hosts = vec![format!("{host}:{port}")];
    if host == Ipv4Addr::LOCALHOST {
        hosts.push(format!("localhost:{port}"));
    }
    hosts
}

pub async fn start(engine: Arc<Engine>, host: Ipv4Addr, port: u16, open_firewall: bool, elevated: bool) -> AegisResult<McpHandle> {
    let listener = TcpListener::bind(SocketAddr::from((host, port))).await.map_err(|e| {
        AegisError::new(ErrorCode::Conflict, format!("Could not start the MCP server on {host}:{port} (port in use, or not an address of this PC): {e}"))
    })?;
    let port = listener.local_addr().map_err(|e| AegisError::failed(e.to_string()))?.port();
    let base_url = format!("http://{host}:{port}");

    // Any other bind keeps 127.0.0.1 too, so this PC's clients never need the
    // LAN address. That port must be ours: if another program held it, local
    // clients would hand it their bearer token, so refuse to start instead.
    let loopback = if host == Ipv4Addr::LOCALHOST {
        None
    } else {
        Some(TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await.map_err(|e| {
            AegisError::new(
                ErrorCode::Conflict,
                format!("Could not also listen on 127.0.0.1:{port}, which clients on this PC use. Another program may be using that port; pick a different one: {e}"),
            )
        })?)
    };
    let local_url = loopback.is_some().then(|| format!("http://{}:{port}/mcp", Ipv4Addr::LOCALHOST));

    let mut status = McpStatus { running: true, url: Some(format!("{base_url}/mcp")), local_url, firewall_rule: false, note: None };
    let mut firewall_rule = None;
    if !host.is_loopback() && open_firewall {
        if elevated {
            let rule = format!("AegisWin-MCP-{port}");
            let (rule_for_task, host_s) = (rule.clone(), host.to_string());
            let added = tokio::task::spawn_blocking(move || add_firewall_rule(&rule_for_task, &host_s, port)).await.map_err(|e| e.to_string()).and_then(|r| r);
            match added {
                Ok(()) => {
                    status.firewall_rule = true;
                    firewall_rule = Some(rule);
                }
                Err(e) => status.note = Some(format!("The Windows Firewall rule could not be added: {e}")),
            }
        } else {
            status.note = Some(
                "Windows Firewall may block other PCs. Restart AegisWin as administrator to add a rule for this port automatically.".into(),
            );
        }
    }

    let (stopped, rx) = watch::channel(false);
    let mut tasks = vec![serve(listener, router(engine.clone(), allowed_hosts(host, port), rx.clone()), rx.clone())];
    if let Some(l) = loopback {
        tasks.push(serve(l, router(engine, allowed_hosts(Ipv4Addr::LOCALHOST, port), rx.clone()), rx));
    }
    Ok(McpHandle { stopped, tasks, status, firewall_rule })
}

fn router(engine: Arc<Engine>, allowed_hosts: Vec<String>, stopped: watch::Receiver<bool>) -> Router {
    let state = AppState { engine, allowed_hosts: Arc::new(allowed_hosts), stopped };
    Router::new()
        .route("/mcp", post(mcp_post).get(method_not_allowed).delete(method_not_allowed))
        .route("/approve/{id}", get(portal_get).post(portal_post))
        .layer(middleware::from_fn_with_state(state.clone(), host_guard))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

fn serve(listener: TcpListener, app: Router, mut stopped: watch::Receiver<bool>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = stopped.wait_for(|s| *s).await;
            })
            .await;
    })
}

// ---- request guards -----------------------------------------------------

async fn host_guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if *state.stopped.borrow() {
        let mut response = (StatusCode::SERVICE_UNAVAILABLE, "The MCP server has stopped.").into_response();
        response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
        return response;
    }
    let headers = request.headers();
    let host_ok = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| state.allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(h)));
    if !host_ok {
        return (StatusCode::FORBIDDEN, "Host not allowed").into_response();
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let ok = origin
            .to_str()
            .ok()
            .and_then(|o| o.strip_prefix("http://"))
            .is_some_and(|o| state.allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(o)));
        if !ok {
            return (StatusCode::FORBIDDEN, "Origin not allowed").into_response();
        }
    }
    next.run(request).await
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token.trim())
}

async fn method_not_allowed() -> Response {
    let mut response = (StatusCode::METHOD_NOT_ALLOWED, "This server only accepts POST /mcp (no SSE stream or sessions).").into_response();
    response.headers_mut().insert(header::ALLOW, HeaderValue::from_static("POST"));
    response
}

// ---- JSON-RPC -----------------------------------------------------------

fn rpc_result(id: &Value, result: Value) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

fn rpc_error(status: StatusCode, id: &Value, code: i64, message: &str) -> Response {
    (status, Json(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }))).into_response()
}

async fn mcp_post(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !bearer(&headers).is_some_and(|t| state.engine.mcp_token_matches(t)) {
        let mut response = (StatusCode::UNAUTHORIZED, Json(json!({ "error": "missing or wrong bearer token" }))).into_response();
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return response;
    }
    if let Some(version) = headers.get("mcp-protocol-version").and_then(|v| v.to_str().ok()) {
        if !PROTOCOL_VERSIONS.contains(&version) {
            return rpc_error(StatusCode::BAD_REQUEST, &Value::Null, -32600, &format!("unsupported MCP-Protocol-Version {version}"));
        }
    }
    let message: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return rpc_error(StatusCode::BAD_REQUEST, &Value::Null, -32700, &format!("parse error: {e}")),
    };
    if message.is_array() {
        return rpc_error(StatusCode::BAD_REQUEST, &Value::Null, -32600, "JSON-RPC batches are not supported");
    }
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        // A response or something else from the client: acknowledge and ignore.
        return StatusCode::ACCEPTED.into_response();
    };
    let Some(id) = message.get("id").filter(|id| id.is_string() || id.is_number()) else {
        // Notifications (e.g. notifications/initialized) get no response body.
        return StatusCode::ACCEPTED.into_response();
    };
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    match method {
        "initialize" => rpc_result(id, initialize(&params)),
        "ping" => rpc_result(id, json!({})),
        "tools/list" => match tools_list(&state) {
            Ok(result) => rpc_result(id, result),
            Err(e) => rpc_error(StatusCode::OK, id, -32603, &e.message),
        },
        "tools/call" => tools_call(&state, id, &params).await,
        _ => rpc_error(StatusCode::OK, id, -32601, &format!("method not found: {method}")),
    }
}

fn initialize(params: &Value) -> Value {
    let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or_default();
    let version = PROTOCOL_VERSIONS.iter().find(|v| **v == requested).copied().unwrap_or(PROTOCOL_VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "aegis-win", "title": "AegisWin", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "AegisWin diagnoses and repairs this Windows PC. Read-only tools run immediately. \
Tools marked as needing approval return status 'pending_approval': tell the user to approve the request in the AegisWin app, \
then call aegis__check_ticket with the ticketId until the status is final. AegisWin never asks anyone to type its PIN outside the app. \
To run several repairs in order under one approval, use aegis__propose_plan. \
Tools that need administrator rights fail unless AegisWin runs elevated.",
    })
}

fn tools_list(state: &AppState) -> AegisResult<Value> {
    let exposed = state.engine.exposed_tools()?;
    let eligible: Vec<String> = exposed.iter().filter(|t| t.tool.plan_eligible).map(|t| registry::mcp_tool_name(&t.plugin_id, &t.tool.id)).collect();
    let mut tools: Vec<Value> = exposed
        .into_iter()
        .map(|t| {
            let mut description = t.tool.description.clone();
            if t.tool.requires_admin {
                description.push_str(" Needs AegisWin running as administrator.");
            }
            if t.policy == GatePolicy::PinRequired {
                description.push_str(" Needs the owner's approval in the AegisWin app: returns a ticketId; poll aegis__check_ticket.");
            }
            if t.tool.input_schema.pointer("/properties/dryRun").is_some() {
                description.push_str(if t.described {
                    " dryRun: true shows the exact commands without running them or needing approval."
                } else {
                    " dryRun: true still needs the owner's approval, since this tool cannot list its commands."
                });
            }
            json!({
                "name": registry::mcp_tool_name(&t.plugin_id, &t.tool.id),
                "title": t.tool.name,
                "description": description,
                "inputSchema": t.tool.input_schema,
                "annotations": {
                    "title": t.tool.name,
                    "readOnlyHint": t.tool.read_only,
                    "destructiveHint": !t.tool.read_only,
                    "openWorldHint": false,
                },
            })
        })
        .collect();
    tools.push(json!({
        "name": CHECK_TICKET_TOOL,
        "title": "Check approval request",
        "description": "Returns the status of an approval request (pending_approval, queued, running, approved, declined, execution_failed, locked_out, expired or cancelled) and, once approved, the tool's result. For a plan, steps shows each step's status, result, or error.",
        "inputSchema": {
            "type": "object",
            "properties": { "ticketId": { "type": "string", "description": "ticketId returned by a tool that needs approval" } },
            "required": ["ticketId"],
            "additionalProperties": false,
        },
        "annotations": { "title": "Check approval request", "readOnlyHint": true, "destructiveHint": false, "openWorldHint": false },
    }));
    if !eligible.is_empty() {
        tools.push(json!({
            "name": PROPOSE_PLAN_TOOL,
            "title": "Propose an action plan",
            "description": format!(
                "Proposes up to {MAX_STEPS} repairs to run in order under one approval. Nothing runs until the owner approves it in the AegisWin app. \
Each step is checked and dry-run now; the owner sees every argument and the exact commands. Steps run one at a time and the plan \
stops at the first failure; earlier changes stay. Returns a ticketId and a plan fingerprint (plan.shortHash) to \
tell the owner; poll aegis__check_ticket, whose steps array shows each step. Pending plans expire after 10 minutes. \
Steps can use: {}.",
                eligible.join(", ")
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": { "type": "string", "maxLength": MAX_TITLE_CHARS, "description": "Shown to the owner, labelled as supplied by you." },
                    "reasoning": { "type": "string", "maxLength": MAX_PLAN_REASONING_CHARS, "description": "Why this plan; shown to the owner, labelled as supplied by you." },
                    "steps": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_STEPS,
                        "items": {
                            "type": "object",
                            "properties": {
                                "tool": { "type": "string", "enum": eligible },
                                "args": { "type": "object", "description": "The tool's arguments, as for a direct call; dryRun: true is not allowed." },
                                "reasoning": { "type": "string", "maxLength": MAX_STEP_REASONING_CHARS },
                            },
                            "required": ["tool"],
                            "additionalProperties": false,
                        },
                    },
                },
                "required": ["steps"],
                "additionalProperties": false,
            },
            "annotations": { "title": "Propose an action plan", "readOnlyHint": false, "destructiveHint": false, "openWorldHint": false },
        }));
    }
    tools.push(json!({
        "name": CANCEL_TICKET_TOOL,
        "title": "Cancel approval request",
        "description": "Withdraws an approval request that has not started, or stops a running plan before its next step (the running step finishes). Needs no approval, since it only does less.",
        "inputSchema": {
            "type": "object",
            "properties": { "ticketId": { "type": "string" } },
            "required": ["ticketId"],
            "additionalProperties": false,
        },
        "annotations": { "title": "Cancel approval request", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false },
    }));
    Ok(json!({ "tools": tools }))
}

fn tool_text(value: &Value, is_error: bool) -> Value {
    let structured = if value.is_object() { value.clone() } else { json!({ "result": value }) };
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(value).unwrap_or_default() }],
        "structuredContent": structured,
        "isError": is_error,
    })
}

fn tool_error(e: &AegisError) -> Value {
    json!({
        "content": [{ "type": "text", "text": format!("{:?}: {}", e.code, e.message) }],
        "structuredContent": { "error": e },
        "isError": true,
    })
}

fn ticket_payload(ticket: &TicketView) -> Value {
    let mut value = serde_json::to_value(ticket).unwrap_or_default();
    match (ticket.status, &ticket.plan) {
        (TicketStatus::PendingApproval, plan) => {
            value["message"] = json!(match plan {
                Some(p) => format!(
                    "Waiting for the owner to approve in the AegisWin app. Tell them the plan fingerprint {}, then call aegis__check_ticket to see the outcome.",
                    p.short_hash
                ),
                None => "Waiting for the owner to approve in the AegisWin app. Call aegis__check_ticket to see the outcome.".into(),
            });
        }
        (TicketStatus::Queued, _) => {
            value["message"] = json!("Approved. Another change is running first; this one starts when its turn comes. Keep calling aegis__check_ticket.");
        }
        (TicketStatus::Running, Some(_)) => {
            let at = ticket.steps.iter().position(|s| s.status == StepStatus::Running).map_or(1, |i| i + 1);
            value["message"] = json!(format!(
                "Approved. Running step {at} of {}. Keep calling aegis__check_ticket; aegis__cancel_ticket stops the plan before its next step.",
                ticket.steps.len()
            ));
        }
        _ => {}
    }
    value
}

async fn tools_call(state: &AppState, id: &Value, params: &Value) -> Response {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return rpc_error(StatusCode::OK, id, -32602, "tools/call needs a tool name");
    };
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

    let not_found = || AegisError::new(ErrorCode::NotFound, "No such approval request (they are forgotten when AegisWin locks).");
    if name == CHECK_TICKET_TOOL {
        let ticket_id = args.get("ticketId").and_then(Value::as_str).unwrap_or_default();
        return match state.engine.ticket(ticket_id) {
            Some(ticket) => rpc_result(id, tool_text(&ticket_payload(&ticket), false)),
            None => rpc_result(id, tool_error(&not_found())),
        };
    }
    if name == CANCEL_TICKET_TOOL {
        let ticket_id = args.get("ticketId").and_then(Value::as_str).unwrap_or_default();
        return match state.engine.cancel_ticket(ticket_id) {
            Ok(ticket) => rpc_result(id, tool_text(&ticket_payload(&ticket), false)),
            Err(e) if e.code == ErrorCode::NotFound => rpc_result(id, tool_error(&not_found())),
            Err(e) => rpc_result(id, tool_error(&e)),
        };
    }
    if name == PROPOSE_PLAN_TOOL {
        return match state.engine.propose_plan(PlanOrigin::Agent, args).await {
            Ok(ticket) => rpc_result(id, tool_text(&ticket_payload(&ticket), false)),
            Err(e) => rpc_result(id, tool_error(&e)),
        };
    }
    let Some((plugin_id, tool_id)) = registry::parse_mcp_tool_name(name) else {
        return rpc_error(StatusCode::OK, id, -32602, &format!("unknown tool: {name}"));
    };
    match state.engine.run_tool(Origin::Mcp, plugin_id, tool_id, args).await {
        Ok(RunOutcome::Completed { result }) => rpc_result(id, tool_text(&result, false)),
        Ok(RunOutcome::PendingApproval { ticket }) => rpc_result(id, tool_text(&ticket_payload(&ticket), false)),
        Err(e) if e.code == ErrorCode::UnknownTool => rpc_error(StatusCode::OK, id, -32602, &format!("unknown tool: {name}")),
        Err(e) => rpc_result(id, tool_error(&e)),
    }
}

// ---- approval portal ----------------------------------------------------

fn valid_ticket_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Shows a core RFC 3339 timestamp in this PC's local time zone (the page runs
/// no script, so the browser cannot convert it).
fn local_time(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| t.with_timezone(&chrono::Local).format("%a %-d %b %Y, %-I:%M:%S %p").to_string())
        .unwrap_or_else(|_| rfc3339.to_owned())
}

pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn page(status: StatusCode, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>AegisWin approval</title><style>{CSS}</style></head><body><main>{body}</main></body></html>"
    );
    let mut response = (status, Html(html)).into_response();
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // Not `no-referrer`: under that policy browsers send `Origin: null` on the
    // form post, which the Origin guard rightly rejects. `same-origin` still
    // sends nothing to other sites.
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

const CSS: &str = "body{font-family:'Segoe UI',system-ui,sans-serif;background:#f4f5f7;color:#1b1f24;margin:0}\
main{max-width:640px;margin:32px auto;padding:24px;background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08)}\
h1{font-size:1.3rem;margin-top:0}dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px}dt{color:#5a6270}\
dd{margin:0}pre{background:#f0f1f3;padding:12px;border-radius:8px;overflow:auto;white-space:pre-wrap;word-break:break-word}\
label{display:block;margin-top:14px;font-weight:600}input,textarea{width:100%;box-sizing:border-box;padding:8px;font:inherit;\
border:1px solid #c5cad3;border-radius:6px}.row{display:flex;gap:12px;margin-top:18px}button{flex:1;padding:10px;font:inherit;\
border:0;border-radius:6px;cursor:pointer}.approve{background:#1f6feb;color:#fff}.decline{background:#e5e7eb}\
.msg{padding:10px 12px;border-radius:6px;background:#fff4e5;margin-bottom:12px}.ok{background:#e6f4ea}\
.supplied{border-left:4px solid #c5cad3;padding:2px 12px;margin:12px 0}.label{font-size:.85rem;color:#5a6270;margin:4px 0}\
.steps>li{margin-bottom:16px}.pre-line{white-space:pre-wrap}.stop{background:#e5e7eb}\
@media (prefers-color-scheme:dark){body{background:#111317;color:#e6e8eb}main{background:#1b1e24;box-shadow:none}\
pre{background:#262a31}dt{color:#9aa3af}input,textarea{background:#262a31;color:inherit;border-color:#3a3f48}\
.decline{background:#30353d;color:inherit}.msg{background:#3a2e1a}.ok{background:#1d3324}.supplied{border-color:#3a3f48}\
.label{color:#9aa3af}.stop{background:#30353d;color:inherit}}";

/// The one-time code field. Not `required`: declining needs no code.
const CODE_FIELD: &str = "<label for=\"code\">Code shown in the AegisWin app (needed to approve)</label>\
<input id=\"code\" name=\"code\" type=\"text\" inputmode=\"text\" autocapitalize=\"characters\" spellcheck=\"false\" \
maxlength=\"16\" placeholder=\"XXXX-XXXX\" autofocus>\
<p class=\"label\">AegisWin never asks for your PIN on a web page. If a page asks for it, it is not AegisWin.</p>";

fn render_ticket(ticket: &TicketView, csrf: Option<&str>, message: Option<(&str, bool)>) -> String {
    if let Some(plan) = &ticket.plan {
        return render_plan(ticket, plan, csrf, message);
    }
    let mut body = String::from("<h1>Approve a request from an AI agent?</h1>");
    if let Some((text, ok)) = message {
        body.push_str(&format!("<div class=\"msg{}\">{}</div>", if ok { " ok" } else { "" }, escape_html(text)));
    }
    let args = serde_json::to_string_pretty(&ticket.args).unwrap_or_default();
    body.push_str(&format!(
        "<dl><dt>Action</dt><dd><strong>{}</strong></dd><dt>Plugin</dt><dd>{}</dd><dt>What it does</dt><dd>{}</dd>\
<dt>Requested</dt><dd>{}</dd><dt>Status</dt><dd>{}</dd></dl><p>Arguments:</p><pre>{}</pre>",
        escape_html(&ticket.tool_name),
        escape_html(&ticket.plugin_id),
        escape_html(&ticket.tool_description),
        escape_html(&local_time(&ticket.created_at)),
        escape_html(&status_label(ticket.status)),
        escape_html(&args),
    ));
    if let Some(review) = &ticket.review {
        body.push_str("<p><strong>What this does</strong> (written by AegisWin from the arguments):</p><ul>");
        for line in &review.lines {
            body.push_str(&format!("<li>{}</li>", escape_html(line)));
        }
        body.push_str("</ul>");
        for warning in &review.warnings {
            body.push_str(&format!("<div class=\"msg\">{}</div>", escape_html(warning)));
        }
    }
    if !ticket.commands.is_empty() {
        body.push_str(&format!("<p>Commands it will run (checked again just before they run):</p><pre>{}</pre>", escape_html(&ticket.commands.join("\n"))));
    }
    if ticket.requires_admin {
        body.push_str("<p>This action changes system settings and runs with administrator rights.</p>");
    }
    match (ticket.status, csrf) {
        (TicketStatus::PendingApproval, Some(csrf)) => body.push_str(&format!(
            "<form method=\"post\" autocomplete=\"off\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
{CODE_FIELD}\
<label for=\"comment\">Note for the agent (optional)</label><textarea id=\"comment\" name=\"comment\" rows=\"2\" maxlength=\"500\"></textarea>\
<p>{} attempt(s) left for this request.</p><div class=\"row\"><button class=\"approve\" name=\"decision\" value=\"approve\">Approve and run</button>\
<button class=\"decline\" name=\"decision\" value=\"decline\">Decline</button></div></form>",
            escape_html(csrf),
            ticket.attempts_remaining
        )),
        (TicketStatus::Queued, csrf) => {
            body.push_str("<p>Approved. Another change is running first; this one starts when it finishes. You can close this page.</p>");
            body.push_str(&cancel_form(csrf, "Cancel before it starts"));
        }
        (TicketStatus::Running, _) => body.push_str("<p>Approved. The action is running; you can close this page.</p>"),
        _ => body.push_str("<p>This request is closed. You can close this page.</p>"),
    }
    body
}

/// A PIN-free form that only withdraws or stops (it can never make more happen).
fn cancel_form(csrf: Option<&str>, label: &str) -> String {
    csrf.map(|csrf| {
        format!(
            "<form method=\"post\" autocomplete=\"off\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
<div class=\"row\"><button class=\"stop\" name=\"decision\" value=\"cancel\">{}</button></div></form>",
            escape_html(csrf),
            escape_html(label)
        )
    })
    .unwrap_or_default()
}

/// The plan review (ADR 0003 §2): AegisWin's own summary and steps first,
/// then the supplied text under its label, then the decision.
fn render_plan(ticket: &TicketView, plan: &PlanMeta, csrf: Option<&str>, message: Option<(&str, bool)>) -> String {
    let pending = ticket.status == TicketStatus::PendingApproval;
    let mut body = String::from(match (plan.origin, pending) {
        (PlanOrigin::Agent, true) => "<h1>Approve an action plan from an AI agent?</h1>",
        (PlanOrigin::Agent, false) => "<h1>Action plan from an AI agent</h1>",
        (PlanOrigin::Owner, true) => "<h1>Approve your action plan?</h1>",
        (PlanOrigin::Owner, false) => "<h1>Your action plan</h1>",
    });
    if let Some((text, ok)) = message {
        body.push_str(&format!("<div class=\"msg{}\">{}</div>", if ok { " ok" } else { "" }, escape_html(text)));
    }
    body.push_str(&format!(
        "<p><strong>{}</strong></p><dl><dt>Plan fingerprint</dt><dd><code>{}</code></dd><dt>Requested</dt><dd>{}</dd>{}<dt>Status</dt><dd>{}</dd></dl>",
        escape_html(&plan.summary),
        escape_html(&plan.short_hash),
        escape_html(&local_time(&ticket.created_at)),
        if pending { format!("<dt>Expires</dt><dd>{}</dd>", escape_html(&local_time(&plan.expires_at))) } else { String::new() },
        escape_html(&status_label(ticket.status)),
    ));
    body.push_str("<p>The steps run one at a time, in this order. The plan stops at the first failure, and changes made by earlier steps stay: Windows repairs cannot be undone.</p><ol class=\"steps\">");
    for step in &ticket.steps {
        let args = serde_json::to_string_pretty(&step.args).unwrap_or_default();
        let commands = if step.commands.is_empty() { "(none)".to_owned() } else { step.commands.join("\n") };
        body.push_str(&format!(
            "<li><strong>{}</strong> ({}){}{}<br>{}<p>Arguments:</p><pre>{}</pre><p>Commands it will run:</p><pre>{}</pre>",
            escape_html(&step.tool_name),
            escape_html(&step.plugin_id),
            if step.requires_admin { " · needs administrator" } else { "" },
            if pending { String::new() } else { format!(" · <em>{}</em>", escape_html(&step_label(step.status))) },
            escape_html(&step.tool_description),
            escape_html(&args),
            escape_html(&commands),
        ));
        if let Some(why) = &step.reasoning {
            body.push_str(&format!("<div class=\"supplied\"><p class=\"label\">{}</p><p class=\"pre-line\">{}</p></div>", escape_html(plan.supplied_label), escape_html(why)));
        }
        if let Some(e) = &step.error {
            body.push_str(&format!("<div class=\"msg\">{}</div>", escape_html(&e.message)));
        }
        body.push_str("</li>");
    }
    body.push_str("</ol>");
    if plan.title.is_some() || plan.reasoning.is_some() {
        body.push_str(&format!("<div class=\"supplied\"><p class=\"label\">{}</p>", escape_html(plan.supplied_label)));
        if let Some(title) = &plan.title {
            body.push_str(&format!("<p><strong>{}</strong></p>", escape_html(title)));
        }
        if let Some(why) = &plan.reasoning {
            body.push_str(&format!("<p class=\"pre-line\">{}</p>", escape_html(why)));
        }
        body.push_str("</div>");
    }
    for flag in &plan.flags {
        body.push_str(&format!("<div class=\"msg\">{}</div>", escape_html(flag)));
    }
    if let Some(reason) = &plan.stop_reason {
        body.push_str(&format!("<div class=\"msg\">{}</div>", escape_html(reason)));
    }
    match (ticket.status, csrf) {
        (TicketStatus::PendingApproval, Some(csrf)) => body.push_str(&format!(
            "<form method=\"post\" autocomplete=\"off\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
<input type=\"hidden\" name=\"plan_hash\" value=\"{}\">\
{CODE_FIELD}\
<label for=\"comment\">Note for the agent (optional)</label><textarea id=\"comment\" name=\"comment\" rows=\"2\" maxlength=\"500\"></textarea>\
<p>{} attempt(s) left for this request.</p><div class=\"row\"><button class=\"approve\" name=\"decision\" value=\"approve\">Approve and run {} step{}</button>\
<button class=\"decline\" name=\"decision\" value=\"decline\">Decline</button></div></form>",
            escape_html(csrf),
            escape_html(&plan.hash),
            ticket.attempts_remaining,
            ticket.steps.len(),
            if ticket.steps.len() == 1 { "" } else { "s" },
        )),
        (TicketStatus::Queued, csrf) => {
            body.push_str("<p>Approved. Another change is running first; the plan starts when it finishes.</p>");
            body.push_str(&cancel_form(csrf, "Cancel before it starts"));
        }
        (TicketStatus::Running, csrf) => {
            body.push_str("<p>Approved and running. You can close this page; reload it to see each step.</p>");
            body.push_str(&cancel_form(csrf, "Stop after this step"));
        }
        _ => body.push_str("<p>This plan is closed. You can close this page.</p>"),
    }
    body
}

fn step_label(status: StepStatus) -> String {
    serde_json::to_value(status).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()
}

fn status_label(status: TicketStatus) -> String {
    serde_json::to_value(status).ok().and_then(|v| v.as_str().map(|s| s.replace('_', " "))).unwrap_or_default()
}

/// The device page exists only while the owner has it turned on.
fn device_page_off(state: &AppState) -> Option<Response> {
    (!state.engine.device_approval_on()).then(|| page(StatusCode::NOT_FOUND, "<h1>Not found</h1>"))
}

async fn portal_get(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if let Some(off) = device_page_off(&state) {
        return off;
    }
    if !valid_ticket_id(&id) {
        return page(StatusCode::NOT_FOUND, "<h1>Not found</h1>");
    }
    match state.engine.ticket(&id) {
        Some(ticket) => {
            let csrf = state.engine.ticket_csrf(&id);
            page(StatusCode::OK, &render_ticket(&ticket, csrf.as_deref(), None))
        }
        None => page(StatusCode::NOT_FOUND, "<h1>No such request</h1><p>It may have expired, or AegisWin was locked.</p>"),
    }
}

#[derive(Deserialize)]
struct PortalForm {
    csrf: String,
    /// The one-time device code; not sent by the cancel form.
    #[serde(default)]
    code: String,
    decision: String,
    #[serde(default)]
    comment: Option<String>,
    /// Sent by a plan's form; the engine checks it in constant time.
    #[serde(default)]
    plan_hash: Option<String>,
}

async fn portal_post(State(state): State<AppState>, Path(id): Path<String>, Form(form): Form<PortalForm>) -> Response {
    if let Some(off) = device_page_off(&state) {
        return off;
    }
    if !valid_ticket_id(&id) || state.engine.ticket(&id).is_none() {
        return page(StatusCode::NOT_FOUND, "<h1>No such request</h1>");
    }
    if !state.engine.ticket_csrf_matches(&id, &form.csrf) {
        return page(StatusCode::FORBIDDEN, "<h1>Request blocked</h1><p>The form token did not match. Reload the approval link and try again.</p>");
    }
    let approve = match form.decision.as_str() {
        "approve" => true,
        "decline" => false,
        "cancel" => return portal_cancel(&state, &id),
        _ => return page(StatusCode::BAD_REQUEST, "<h1>Choose approve or decline</h1>"),
    };
    let result = state.engine.decide_on_device(&id, approve, &form.code, form.comment, form.plan_hash.as_deref());
    let ticket = state.engine.ticket(&id);
    let csrf = state.engine.ticket_csrf(&id);
    match (result, ticket) {
        (Ok(view), _) => {
            let text = match view.status {
                TicketStatus::Declined => "Declined. The agent has been told.",
                TicketStatus::ExecutionFailed => "Approved, but the action could not start. The agent can see the error.",
                TicketStatus::Queued => "Approved. It runs after the change ahead of it finishes.",
                _ if view.plan.is_some() => "Approved. The plan is running.",
                _ => "Approved. The action is running.",
            };
            let csrf = state.engine.ticket_csrf(&id);
            page(StatusCode::OK, &render_ticket(&view, csrf.as_deref(), Some((text, true))))
        }
        (Err(e), Some(ticket)) => {
            let status = match e.code {
                ErrorCode::CodeInvalid if ticket.status == TicketStatus::LockedOut => StatusCode::LOCKED,
                ErrorCode::CodeInvalid => StatusCode::FORBIDDEN,
                ErrorCode::Conflict => StatusCode::CONFLICT,
                ErrorCode::VaultLocked => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            page(status, &render_ticket(&ticket, csrf.as_deref(), Some((&e.message, false))))
        }
        (Err(e), None) => page(StatusCode::NOT_FOUND, &format!("<h1>No such request</h1><p>{}</p>", escape_html(&e.message))),
    }
}

/// The cancel button: the CSRF token has already been checked.
fn portal_cancel(state: &AppState, id: &str) -> Response {
    let csrf = state.engine.ticket_csrf(id);
    match state.engine.cancel_ticket(id) {
        Ok(view) => {
            let text = if view.status == TicketStatus::Cancelled { "Cancelled. Nothing more will run." } else { "Stopping after the step that is running now." };
            page(StatusCode::OK, &render_ticket(&view, csrf.as_deref(), Some((text, true))))
        }
        Err(e) => match state.engine.ticket(id) {
            Some(ticket) => page(StatusCode::CONFLICT, &render_ticket(&ticket, csrf.as_deref(), Some((&e.message, false)))),
            None => page(StatusCode::NOT_FOUND, "<h1>No such request</h1>"),
        },
    }
}

// ---- Windows Firewall ---------------------------------------------------

fn add_firewall_rule(rule: &str, host: &str, port: u16) -> Result<(), String> {
    delete_firewall_rule(rule);
    let name = format!("name={rule}");
    let localport = format!("localport={port}");
    let localip = format!("localip={host}");
    let out = crate::os::run_system_binary(
        "netsh.exe",
        &[
            "advfirewall", "firewall", "add", "rule", &name, "dir=in", "action=allow", "protocol=TCP", &localport, &localip,
            "remoteip=localsubnet", "profile=private",
        ],
        Duration::from_secs(20),
    )
    .map_err(|e| e.to_string())?;
    if out.success() {
        Ok(())
    } else {
        Err(out.stdout.trim().to_owned())
    }
}

fn delete_firewall_rule(rule: &str) {
    let name = format!("name={rule}");
    let _ = crate::os::run_system_binary("netsh.exe", &["advfirewall", "firewall", "delete", "rule", &name], Duration::from_secs(20));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html() {
        assert_eq!(escape_html("<script>alert('x')</script>&\""), "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&quot;");
    }

    #[test]
    fn negotiates_protocol_versions() {
        assert_eq!(initialize(&json!({ "protocolVersion": "2025-03-26" }))["protocolVersion"], "2025-03-26");
        assert_eq!(initialize(&json!({ "protocolVersion": "1999-01-01" }))["protocolVersion"], PROTOCOL_VERSIONS[0]);
    }

    #[test]
    fn approval_page_shows_local_time() {
        let utc = "2026-10-24T19:14:05Z";
        let expected = chrono::DateTime::parse_from_rfc3339(utc).unwrap().with_timezone(&chrono::Local);
        let shown = local_time(utc);
        assert!(shown.contains(&expected.format("%-I:%M:%S").to_string()), "{shown}");
        assert!(!shown.contains(utc), "{shown}");
        assert_eq!(local_time("not a time"), "not a time");
    }

    #[test]
    fn a_queued_request_offers_only_cancel_and_says_it_waits() {
        let ticket = TicketView {
            ticket_id: "0".repeat(32),
            plugin_id: "windows-health".into(),
            tool_id: "flush_dns".into(),
            tool_name: "Flush DNS".into(),
            tool_description: "d".into(),
            requires_admin: false,
            args: json!({}),
            review: None,
            commands: Vec::new(),
            created_at: "2026-11-07T10:00:00Z".into(),
            status: TicketStatus::Queued,
            queue_position: Some(2),
            attempts_remaining: 3,
            comment: None,
            decided_via: Some("app"),
            result: None,
            error: None,
            plan: None,
            steps: Vec::new(),
        };
        let html = render_ticket(&ticket, Some("csrf-token"), None);
        assert!(html.contains("Another change is running first"), "{html}");
        assert!(!html.contains("name=\"code\"") && !html.contains("value=\"approve\""), "a decided request cannot be decided again");
        assert!(!html.contains("name=\"pin\""), "the page never asks for the PIN");
        assert!(html.contains("value=\"cancel\"") && html.contains("Cancel before it starts"), "{html}");
        let closed = render_ticket(&TicketView { status: TicketStatus::Approved, ..ticket }, Some("csrf-token"), None);
        assert!(!closed.contains("<form") && !closed.contains("csrf-token"), "a finished request offers no form");
    }

    #[test]
    fn ticket_ids_must_be_hex() {
        assert!(valid_ticket_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_ticket_id("../../etc/passwd"));
        assert!(!valid_ticket_id("0123456789abcdef0123456789abcdeg"));
    }
}
