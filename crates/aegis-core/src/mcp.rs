//! MCP server (Streamable HTTP, JSON responses only) and the browser
//! approval portal for `pin_required` tools.
//!
//! - `POST /mcp`: JSON-RPC 2.0, bearer token required.
//! - `GET|POST /approve/{ticketId}`: a no-script HTML page where the owner
//!   approves or declines with their PIN. Protected by a per-ticket CSRF token.
//!
//! Every request must carry a `Host` header naming the bound address (DNS
//! rebinding defense), and a cross-site `Origin` is rejected.

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
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::engine::{Engine, Origin, RunOutcome};
use crate::error::{AegisError, AegisResult, ErrorCode};
use crate::registry::{self, GatePolicy};
use crate::tickets::{TicketStatus, TicketView};

/// Newest first. The first entry is offered when a client asks for a version we do not know.
pub const PROTOCOL_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
pub const CHECK_TICKET_TOOL: &str = "aegis__check_ticket";
const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpStatus {
    pub running: bool,
    pub url: Option<String>,
    pub firewall_rule: bool,
    /// Something the owner should know (e.g. the firewall rule could not be added).
    pub note: Option<String>,
}

impl McpStatus {
    pub fn stopped() -> Self {
        Self { running: false, url: None, firewall_rule: false, note: None }
    }
}

pub struct McpHandle {
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
    status: McpStatus,
    firewall_rule: Option<String>,
}

impl McpHandle {
    pub fn status(&self) -> McpStatus {
        self.status.clone()
    }

    pub async fn stop(self) {
        let _ = self.shutdown.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
        if let Some(rule) = self.firewall_rule {
            let _ = tokio::task::spawn_blocking(move || delete_firewall_rule(&rule)).await;
        }
    }
}

#[derive(Clone)]
struct AppState {
    engine: Arc<Engine>,
    allowed_hosts: Arc<Vec<String>>,
    base_url: Arc<String>,
}

pub async fn start(engine: Arc<Engine>, host: Ipv4Addr, port: u16, open_firewall: bool, elevated: bool) -> AegisResult<McpHandle> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((host, port))).await.map_err(|e| {
        AegisError::new(ErrorCode::Conflict, format!("Could not start the MCP server on {host}:{port} (port in use, or not an address of this PC): {e}"))
    })?;
    let port = listener.local_addr().map_err(|e| AegisError::failed(e.to_string()))?.port();
    let base_url = format!("http://{host}:{port}");
    let mut allowed_hosts = vec![format!("{host}:{port}")];
    if host.is_loopback() {
        allowed_hosts.push(format!("localhost:{port}"));
    }

    let mut status = McpStatus { running: true, url: Some(format!("{base_url}/mcp")), firewall_rule: false, note: None };
    let mut firewall_rule = None;
    if !host.is_loopback() && open_firewall {
        if elevated {
            let rule = format!("AegisWin-MCP-{port}");
            let (rule_for_task, host_s) = (rule.clone(), host.to_string());
            match tokio::task::spawn_blocking(move || add_firewall_rule(&rule_for_task, &host_s, port)).await {
                Ok(Ok(())) => {
                    status.firewall_rule = true;
                    firewall_rule = Some(rule);
                }
                Ok(Err(e)) => status.note = Some(format!("The Windows Firewall rule could not be added: {e}")),
                Err(e) => status.note = Some(format!("The Windows Firewall rule could not be added: {e}")),
            }
        } else {
            status.note = Some(
                "Windows Firewall may block other PCs. Restart AegisWin as administrator to add a rule for this port automatically.".into(),
            );
        }
    }

    let state = AppState { engine, allowed_hosts: Arc::new(allowed_hosts), base_url: Arc::new(base_url) };
    let app = Router::new()
        .route("/mcp", post(mcp_post).get(method_not_allowed).delete(method_not_allowed))
        .route("/approve/{id}", get(portal_get).post(portal_post))
        .layer(middleware::from_fn_with_state(state.clone(), host_guard))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state);

    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });
    Ok(McpHandle { shutdown: tx, task, status, firewall_rule })
}

// ---- request guards -----------------------------------------------------

async fn host_guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
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
Tools marked as needing approval return status 'pending_approval' with an approvalUrl: give that link to the user, \
who approves with their PIN, then call aegis__check_ticket with the ticketId until the status is final. \
Tools that need administrator rights fail unless AegisWin runs elevated.",
    })
}

fn tools_list(state: &AppState) -> AegisResult<Value> {
    let mut tools: Vec<Value> = state
        .engine
        .exposed_tools()?
        .into_iter()
        .map(|t| {
            let mut description = t.tool.description.clone();
            if t.tool.requires_admin {
                description.push_str(" Needs AegisWin running as administrator.");
            }
            if t.policy == GatePolicy::PinRequired {
                description.push_str(" Needs the owner's PIN approval: returns a ticketId and approvalUrl; poll aegis__check_ticket.");
            }
            if t.tool.input_schema.pointer("/properties/dryRun").is_some() {
                description.push_str(" dryRun: true shows the exact commands without running them or needing approval.");
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
        "description": "Returns the status of an approval request (pending_approval, running, approved, declined, execution_failed, locked_out or expired) and, once approved, the tool's result.",
        "inputSchema": {
            "type": "object",
            "properties": { "ticketId": { "type": "string", "description": "ticketId returned by a tool that needs approval" } },
            "required": ["ticketId"],
            "additionalProperties": false,
        },
        "annotations": { "title": "Check approval request", "readOnlyHint": true, "destructiveHint": false, "openWorldHint": false },
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

fn ticket_payload(state: &AppState, ticket: &TicketView) -> Value {
    let mut value = serde_json::to_value(ticket).unwrap_or_default();
    if ticket.status == TicketStatus::PendingApproval {
        value["approvalUrl"] = json!(format!("{}/approve/{}", state.base_url, ticket.ticket_id));
        value["message"] = json!("Waiting for the owner. Show them the approvalUrl (or they can approve in the AegisWin app), then call aegis__check_ticket.");
    }
    value
}

async fn tools_call(state: &AppState, id: &Value, params: &Value) -> Response {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return rpc_error(StatusCode::OK, id, -32602, "tools/call needs a tool name");
    };
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

    if name == CHECK_TICKET_TOOL {
        let ticket_id = args.get("ticketId").and_then(Value::as_str).unwrap_or_default();
        return match state.engine.ticket(ticket_id) {
            Some(ticket) => rpc_result(id, tool_text(&ticket_payload(state, &ticket), false)),
            None => rpc_result(id, tool_error(&AegisError::new(ErrorCode::NotFound, "No such approval request (they are forgotten when AegisWin locks)."))),
        };
    }
    let Some((plugin_id, tool_id)) = registry::parse_mcp_tool_name(name) else {
        return rpc_error(StatusCode::OK, id, -32602, &format!("unknown tool: {name}"));
    };
    match state.engine.run_tool(Origin::Mcp, plugin_id, tool_id, args).await {
        Ok(RunOutcome::Completed { result }) => rpc_result(id, tool_text(&result, false)),
        Ok(RunOutcome::PendingApproval { ticket }) => rpc_result(id, tool_text(&ticket_payload(state, &ticket), false)),
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
@media (prefers-color-scheme:dark){body{background:#111317;color:#e6e8eb}main{background:#1b1e24;box-shadow:none}\
pre{background:#262a31}dt{color:#9aa3af}input,textarea{background:#262a31;color:inherit;border-color:#3a3f48}\
.decline{background:#30353d;color:inherit}.msg{background:#3a2e1a}.ok{background:#1d3324}}";

fn render_ticket(ticket: &TicketView, csrf: Option<&str>, message: Option<(&str, bool)>) -> String {
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
    if ticket.requires_admin {
        body.push_str("<p>This action changes system settings and runs with administrator rights.</p>");
    }
    match (ticket.status, csrf) {
        (TicketStatus::PendingApproval, Some(csrf)) => body.push_str(&format!(
            "<form method=\"post\" autocomplete=\"off\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
<label for=\"pin\">Your AegisWin PIN</label><input id=\"pin\" name=\"pin\" type=\"password\" required autofocus>\
<label for=\"comment\">Note for the agent (optional)</label><textarea id=\"comment\" name=\"comment\" rows=\"2\" maxlength=\"500\"></textarea>\
<p>{} attempt(s) left for this request.</p><div class=\"row\"><button class=\"approve\" name=\"decision\" value=\"approve\">Approve and run</button>\
<button class=\"decline\" name=\"decision\" value=\"decline\">Decline</button></div></form>",
            escape_html(csrf),
            ticket.attempts_remaining
        )),
        (TicketStatus::Running, _) => body.push_str("<p>Approved. The action is running; you can close this page.</p>"),
        _ => body.push_str("<p>This request is closed. You can close this page.</p>"),
    }
    body
}

fn status_label(status: TicketStatus) -> String {
    serde_json::to_value(status).ok().and_then(|v| v.as_str().map(|s| s.replace('_', " "))).unwrap_or_default()
}

async fn portal_get(State(state): State<AppState>, Path(id): Path<String>) -> Response {
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
    pin: String,
    decision: String,
    #[serde(default)]
    comment: Option<String>,
}

async fn portal_post(State(state): State<AppState>, Path(id): Path<String>, Form(form): Form<PortalForm>) -> Response {
    let pin = zeroize::Zeroizing::new(form.pin);
    if !valid_ticket_id(&id) || state.engine.ticket(&id).is_none() {
        return page(StatusCode::NOT_FOUND, "<h1>No such request</h1>");
    }
    if !state.engine.ticket_csrf_matches(&id, &form.csrf) {
        return page(StatusCode::FORBIDDEN, "<h1>Request blocked</h1><p>The form token did not match. Reload the approval link and try again.</p>");
    }
    let approve = match form.decision.as_str() {
        "approve" => true,
        "decline" => false,
        _ => return page(StatusCode::BAD_REQUEST, "<h1>Choose approve or decline</h1>"),
    };
    let result = state.engine.decide_ticket(&id, approve, pin.to_string(), form.comment, "browser").await;
    let ticket = state.engine.ticket(&id);
    let csrf = state.engine.ticket_csrf(&id);
    match (result, ticket) {
        (Ok(view), _) => {
            let text = match view.status {
                TicketStatus::Declined => "Declined. The agent has been told.",
                TicketStatus::ExecutionFailed => "Approved, but the action could not start. The agent can see the error.",
                _ => "Approved. The action is running.",
            };
            page(StatusCode::OK, &render_ticket(&view, None, Some((text, true))))
        }
        (Err(e), Some(ticket)) => {
            let status = match e.code {
                ErrorCode::PinInvalid => StatusCode::FORBIDDEN,
                ErrorCode::PinLockedOut if ticket.status == TicketStatus::LockedOut => StatusCode::LOCKED,
                ErrorCode::PinLockedOut => StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::Conflict => StatusCode::CONFLICT,
                ErrorCode::VaultLocked => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            page(status, &render_ticket(&ticket, csrf.as_deref(), Some((&e.message, false))))
        }
        (Err(e), None) => page(StatusCode::NOT_FOUND, &format!("<h1>No such request</h1><p>{}</p>", escape_html(&e.message))),
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
    fn ticket_ids_must_be_hex() {
        assert!(valid_ticket_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_ticket_id("../../etc/passwd"));
        assert!(!valid_ticket_id("0123456789abcdef0123456789abcdeg"));
    }
}
