//! Drives the real MCP server and approval portal over loopback HTTP.

mod common;

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use aegis_core::engine::SettingsUpdate;
use common::{ready, Fixture, PIN};
use serde_json::{json, Value};

struct Server {
    f: Fixture,
    url: String,
    base: String,
    token: String,
    http: reqwest::Client,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn server() -> Server {
    server_on(None).await
}

async fn server_on(host: Option<String>) -> Server {
    let f = ready().await;
    let view = f
        .engine
        .update_settings(SettingsUpdate { mcp_enabled: Some(true), mcp_host: host, mcp_port: Some(free_port()), ..Default::default() })
        .await
        .unwrap();
    assert!(view.mcp.status.running, "{:?}", view.mcp.status);
    let url = view.mcp.status.url.clone().unwrap();
    let base = url.trim_end_matches("/mcp").to_owned();
    let token = f.engine.reveal_mcp_token(PIN.into()).await.unwrap();
    Server { f, url, base, token, http: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap() }
}

impl Server {
    async fn rpc(&self, method: &str, params: Value) -> Value {
        let response = self
            .http
            .post(&self.url)
            .bearer_auth(&self.token)
            .header("accept", "application/json, text/event-stream")
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        response.json().await.unwrap()
    }

    async fn call(&self, name: &str, arguments: Value) -> Value {
        self.rpc("tools/call", json!({ "name": name, "arguments": arguments })).await["result"].clone()
    }
}

#[tokio::test]
async fn handshake_and_tool_listing() {
    let s = server().await;
    let init = s.rpc("initialize", json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "1" } })).await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["result"]["serverInfo"]["name"], "aegis-win");
    assert_eq!(init["result"]["capabilities"]["tools"]["listChanged"], false);

    let note = s
        .http
        .post(&s.url)
        .bearer_auth(&s.token)
        .json(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .send()
        .await
        .unwrap();
    assert_eq!(note.status(), 202);

    let list = s.rpc("tools/list", json!({})).await;
    let tools = list["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"demo__echo") && names.contains(&"demo__fix") && names.contains(&"aegis__check_ticket"));
    assert!(names.iter().all(|n| n.len() <= 64 && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')));
    let fix = tools.iter().find(|t| t["name"] == "demo__fix").unwrap();
    assert_eq!(fix["annotations"]["readOnlyHint"], false);
    assert!(fix["description"].as_str().unwrap().contains("PIN approval"));

    assert_eq!(s.rpc("ping", json!({})).await["result"], json!({}));
    assert_eq!(s.rpc("resources/list", json!({})).await["error"]["code"], -32601);
}

#[tokio::test]
async fn requests_need_the_token_and_the_right_host() {
    let s = server().await;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let r = s.http.post(&s.url).json(&body).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = s.http.post(&s.url).bearer_auth("wrong").json(&body).send().await.unwrap();
    assert_eq!(r.status(), 401);
    // DNS rebinding: a page on evil.example resolving to 127.0.0.1.
    let r = s.http.post(&s.url).bearer_auth(&s.token).header("host", "evil.example").json(&body).send().await.unwrap();
    assert_eq!(r.status(), 403);
    let r = s.http.post(&s.url).bearer_auth(&s.token).header("origin", "http://evil.example").json(&body).send().await.unwrap();
    assert_eq!(r.status(), 403);
    let r = s.http.get(&s.url).bearer_auth(&s.token).send().await.unwrap();
    assert_eq!(r.status(), 405);
    let r = s.http.post(&s.url).bearer_auth(&s.token).json(&json!([body])).send().await.unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn auto_tools_return_structured_content_and_errors_are_tool_results() {
    let s = server().await;
    let out = s.call("demo__echo", json!({ "text": "hello" })).await;
    assert_eq!(out["isError"], false);
    assert_eq!(out["structuredContent"]["echo"]["text"], "hello");
    assert_eq!(out["content"][0]["type"], "text");

    let out = s.call("demo__admin_fix", json!({})).await;
    assert_eq!(out["isError"], true);
    assert_eq!(out["structuredContent"]["error"]["code"], "REQUIRES_ADMIN");

    let unknown = s.rpc("tools/call", json!({ "name": "demo__nope", "arguments": {} })).await;
    assert_eq!(unknown["error"]["code"], -32602);
}

fn extract_csrf(html: &str) -> String {
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker).unwrap() + marker.len();
    html[start..start + 32].to_owned()
}

#[tokio::test]
async fn pin_gated_tools_are_approved_in_the_browser_portal() {
    let s = server().await;
    let pending = s.call("demo__fix", json!({ "note": "<script>alert(1)</script>" })).await;
    let content = &pending["structuredContent"];
    assert_eq!(content["status"], "pending_approval");
    assert!(content.get("csrf").is_none());
    let ticket_id = content["ticketId"].as_str().unwrap().to_owned();
    let approval_url = content["approvalUrl"].as_str().unwrap().to_owned();
    assert_eq!(approval_url, format!("{}/approve/{ticket_id}", s.base));

    let page = s.http.get(&approval_url).send().await.unwrap();
    assert_eq!(page.status(), 200);
    let csp = page.headers()["content-security-policy"].to_str().unwrap().to_owned();
    assert!(csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(page.headers()["x-frame-options"], "DENY");
    // Browsers send `Origin: null` on a form post from a `no-referrer` page, and
    // the guard rejects that, so the page must keep its real origin.
    assert_eq!(page.headers()["referrer-policy"], "same-origin");
    let html = page.text().await.unwrap();
    assert!(html.contains("Fix &lt;it&gt;"), "tool name is escaped");
    assert!(!html.contains("<script>"), "arguments are escaped");
    // The plugin's own description of the call is shown, escaped.
    assert!(html.contains("<li>Fixes &lt;script&gt;alert(1)&lt;/script&gt;.</li>"), "{html}");
    assert!(html.contains("Fixing &lt;b&gt;cannot&lt;/b&gt; be undone."));
    assert_eq!(content["review"]["warnings"][0], "Fixing <b>cannot</b> be undone.", "agents see the same review");
    let csrf = extract_csrf(&html);

    let post = |origin: &str, csrf: &str, pin: &str, decision: &str| {
        s.http
            .post(&approval_url)
            .header("origin", origin)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([("csrf", csrf), ("pin", pin), ("decision", decision), ("comment", "ok from test")])
                    .finish(),
            )
    };
    let form = |csrf: &str, pin: &str, decision: &str| post(&s.base, csrf, pin, decision);
    assert_eq!(form("0".repeat(32).as_str(), PIN, "approve").send().await.unwrap().status(), 403, "bad CSRF");
    let null_origin = post("null", &csrf, PIN, "approve").send().await.unwrap();
    assert_eq!(null_origin.status(), 403, "an opaque origin is still refused");
    assert_eq!(form(&csrf, "000000", "approve").send().await.unwrap().status(), 403, "wrong PIN");
    let approved = form(&csrf, PIN, "approve").send().await.unwrap();
    assert_eq!(approved.status(), 200);
    assert!(approved.text().await.unwrap().contains("Approved"));

    let mut status = Value::Null;
    for _ in 0..100 {
        let out = s.call("aegis__check_ticket", json!({ "ticketId": ticket_id })).await;
        status = out["structuredContent"].clone();
        if status["status"] != "running" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(status["status"], "approved", "{status}");
    assert_eq!(status["result"]["done"], "fix");
    assert_eq!(status["decidedVia"], "browser");
    assert_eq!(status["comment"], "ok from test");

    assert_eq!(form(&csrf, PIN, "approve").send().await.unwrap().status(), 409, "no double approval");
    assert_eq!(s.http.get(format!("{}/approve/../../x", s.base)).send().await.unwrap().status(), 404);
}

#[tokio::test]
async fn locking_stops_the_server() {
    let s = server().await;
    s.f.engine.lock().await;
    assert!(s.http.post(&s.url).bearer_auth(&s.token).json(&json!({})).send().await.is_err());
}

#[tokio::test]
async fn stop_drops_connections_that_outlive_the_grace_period() {
    let f = ready().await;
    let handle = aegis_core::mcp::start(f.engine.clone(), Ipv4Addr::LOCALHOST, 0, false, false).await.unwrap();
    let addr = handle.status().url.unwrap().trim_start_matches("http://").trim_end_matches("/mcp").to_owned();
    // Headers never finish, so graceful shutdown would wait on this connection forever.
    let mut slow = tokio::net::TcpStream::connect(&addr).await.unwrap();
    slow.write_all(b"GET /approve/x HTTP/1.1\r\nHost: ").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    handle.stop().await;
    assert!(tokio::net::TcpStream::connect(&addr).await.is_err(), "the listener outlived stop()");

    // Finishing the request must not reach the stopped server's handlers.
    let _ = slow.write_all(format!("{addr}\r\nConnection: close\r\n\r\n").as_bytes()).await;
    let mut reply = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), slow.read_to_end(&mut reply)).await;
    let reply = String::from_utf8_lossy(&reply);
    assert!(reply.is_empty() || reply.starts_with("HTTP/1.1 503"), "a stopped server answered: {reply}");
}

#[tokio::test]
async fn loopback_bind_has_no_separate_local_url() {
    let s = server().await;
    assert!(s.url.starts_with("http://127.0.0.1:"));
    assert_eq!(s.f.engine.mcp_status().await.local_url, None);
}

/// Checks a running non-loopback bind on `host` and its 127.0.0.1 companion, then stops it.
async fn assert_dual_listener(s: &Server, host: Ipv4Addr, local: &str) {
    let port = s.url.trim_end_matches("/mcp").rsplit(':').next().unwrap().to_owned();
    assert_eq!(s.url, format!("http://{host}:{port}/mcp"));
    assert_eq!(local, format!("http://127.0.0.1:{port}/mcp"));

    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    for url in [s.url.as_str(), local] {
        let r = s.http.post(url).bearer_auth(&s.token).json(&ping).send().await.unwrap();
        assert_eq!(r.status(), 200, "{url}");
    }
    // Each listener accepts only its own address in Host.
    let r = s.http.post(local).bearer_auth(&s.token).header("host", format!("{host}:{port}")).json(&ping).send().await.unwrap();
    assert_eq!(r.status(), 403);
    let r = s.http.post(&s.url).bearer_auth(&s.token).header("host", format!("127.0.0.1:{port}")).json(&ping).send().await.unwrap();
    assert_eq!(r.status(), 403);

    // A ticket asked for over loopback still links to the bind address, so a phone can approve it.
    let out: Value = s
        .http
        .post(local)
        .bearer_auth(&s.token)
        .json(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "demo__fix", "arguments": { "note": "from loopback" } } }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let approval_url = out["result"]["structuredContent"]["approvalUrl"].as_str().unwrap_or_default();
    assert!(approval_url.starts_with(&format!("http://{host}:{port}/approve/")), "{out}");
}

/// Runs everywhere: 127.0.0.2 is not 127.0.0.1, so it gets the same companion listener as a LAN bind.
#[tokio::test]
async fn non_loopback_bind_also_serves_127_0_0_1() {
    let f = ready().await;
    let host = Ipv4Addr::new(127, 0, 0, 2);
    let handle = aegis_core::mcp::start(f.engine.clone(), host, 0, false, false).await.unwrap();
    let status = handle.status();
    let local = status.local_url.clone().expect("companion listener");
    let token = f.engine.reveal_mcp_token(PIN.into()).await.unwrap();
    let s = Server { f, url: status.url.unwrap(), base: String::new(), token, http: reqwest::Client::new() };
    assert_dual_listener(&s, host, &local).await;

    handle.stop().await;
    for url in [s.url.as_str(), local.as_str()] {
        assert!(s.http.post(url).bearer_auth(&s.token).json(&json!({})).send().await.is_err(), "{url} still answers after stop");
    }
}

#[tokio::test]
async fn non_loopback_bind_refuses_to_start_when_127_0_0_1_is_taken() {
    let f = ready().await;
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = squatter.local_addr().unwrap().port();
    let err = aegis_core::mcp::start(f.engine.clone(), Ipv4Addr::new(127, 0, 0, 2), port, false, false).await.err().expect("must not start");
    assert_eq!(err.code, aegis_core::ErrorCode::Conflict);
    assert!(err.message.contains("127.0.0.1"), "{}", err.message);
}

/// Through the settings path with this PC's real LAN address. Skipped (with a
/// message) without one; `non_loopback_bind_also_serves_127_0_0_1` covers the logic.
#[tokio::test]
async fn lan_bind_from_settings_also_serves_loopback() {
    let Some(lan) = aegis_core::os::primary_lan_ipv4() else {
        eprintln!("skipped: this PC has no private IPv4 address");
        return;
    };
    let s = server_on(Some(lan.to_string())).await;
    let local = s.f.engine.mcp_status().await.local_url.expect("companion listener");
    assert_dual_listener(&s, lan, &local).await;

    s.f.engine.lock().await;
    for url in [s.url.as_str(), local.as_str()] {
        assert!(s.http.post(url).bearer_auth(&s.token).json(&json!({})).send().await.is_err(), "{url} still answers after lock");
    }
}

async fn poll_until_final(s: &Server, ticket_id: &str) -> Value {
    for _ in 0..250 {
        let out = s.call("aegis__check_ticket", json!({ "ticketId": ticket_id })).await["structuredContent"].clone();
        if !matches!(out["status"].as_str(), Some("running" | "queued" | "pending_approval")) {
            return out;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("ticket {ticket_id} did not finish");
}

fn step_statuses(ticket: &Value) -> Vec<&str> {
    ticket["steps"].as_array().unwrap().iter().map(|s| s["status"].as_str().unwrap()).collect()
}

#[tokio::test]
async fn plans_are_proposed_over_mcp_and_approved_with_their_fingerprint() {
    let s = server().await;
    let list = s.rpc("tools/list", json!({})).await;
    let tools = list["result"]["tools"].as_array().unwrap();
    let propose = tools.iter().find(|t| t["name"] == "aegis__propose_plan").expect("listed");
    assert_eq!(propose["inputSchema"]["properties"]["steps"]["items"]["properties"]["tool"]["enum"], json!(["demo__fix"]), "only eligible tools");
    assert!(tools.iter().any(|t| t["name"] == "aegis__cancel_ticket"));

    let refused = s.call("aegis__propose_plan", json!({ "steps": [{ "tool": "demo__echo" }] })).await;
    assert_eq!(refused["isError"], true);
    assert!(refused["structuredContent"]["error"]["message"].as_str().unwrap().contains("cannot be a plan step"));

    let plan = json!({
        "title": "Fix <both>",
        "reasoning": "First a, then <b>b</b>.",
        "steps": [{ "tool": "demo__fix", "args": { "note": "a" }, "reasoning": "<i>a</i> first" }, { "tool": "demo__fix", "args": { "note": "b" } }],
    });
    let pending = s.call("aegis__propose_plan", plan).await["structuredContent"].clone();
    assert_eq!(pending["status"], "pending_approval", "{pending}");
    assert!(pending.get("csrf").is_none());
    let (hash, short) = (pending["plan"]["hash"].as_str().unwrap().to_owned(), pending["plan"]["shortHash"].as_str().unwrap().to_owned());
    assert!(pending["message"].as_str().unwrap().contains(&short), "the agent is told the fingerprint to share");
    assert_eq!(pending["steps"][0]["commands"], json!(["fix.exe a"]));
    let id = pending["ticketId"].as_str().unwrap().to_owned();
    let url = pending["approvalUrl"].as_str().unwrap().to_owned();

    let html = s.http.get(&url).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("Supplied by the requesting agent"));
    assert!(html.contains("Fix &lt;both&gt;") && html.contains("First a, then &lt;b&gt;b&lt;/b&gt;.") && html.contains("&lt;i&gt;a&lt;/i&gt; first"), "{html}");
    assert!(!html.contains("<b>b</b>") && !html.contains("<i>a</i>"));
    assert!(html.contains("<code>") && html.contains(&short));
    assert!(html.contains("fix.exe a") && html.contains("fix.exe b"));
    assert!(html.contains("Approve and run 2 steps"));
    assert!(html.contains(&format!("name=\"plan_hash\" value=\"{hash}\"")));
    let csrf = extract_csrf(&html);

    let post = |pairs: Vec<(&str, &str)>| {
        s.http
            .post(&url)
            .header("origin", &s.base)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish())
    };
    let stale = "0".repeat(64);
    for pairs in [vec![("csrf", csrf.as_str()), ("pin", PIN), ("decision", "approve")], vec![("csrf", &csrf), ("pin", PIN), ("decision", "approve"), ("plan_hash", &stale)]] {
        let r = post(pairs).send().await.unwrap();
        assert_eq!(r.status(), 409);
        assert!(r.text().await.unwrap().contains("3 attempt(s) left"), "a stale page costs no PIN attempt");
    }
    let approved = post(vec![("csrf", &csrf), ("pin", PIN), ("decision", "approve"), ("plan_hash", &hash)]).send().await.unwrap();
    assert_eq!(approved.status(), 200);
    let done = poll_until_final(&s, &id).await;
    assert_eq!(done["status"], "approved", "{done}");
    assert_eq!(step_statuses(&done), ["succeeded", "succeeded"]);
    assert_eq!(done["decidedVia"], "browser");
    assert_eq!(*s.f.plugin.fixed.lock().unwrap(), ["a", "b"]);
}

#[tokio::test]
async fn plans_can_be_cancelled_over_mcp_and_stopped_from_the_page() {
    let s = server().await;
    let missing = s.call("aegis__cancel_ticket", json!({ "ticketId": "0".repeat(32) })).await;
    assert_eq!(missing["structuredContent"]["error"]["code"], "NOT_FOUND");

    let pending = s.call("aegis__propose_plan", json!({ "steps": [{ "tool": "demo__fix", "args": { "note": "never" } }] })).await["structuredContent"].clone();
    let withdrawn = s.call("aegis__cancel_ticket", json!({ "ticketId": pending["ticketId"] })).await["structuredContent"].clone();
    assert_eq!(withdrawn["status"], "cancelled");
    assert_eq!(step_statuses(&withdrawn), ["cancelled"]);

    let pending = s.call("aegis__propose_plan", json!({ "steps": [{ "tool": "demo__fix", "args": { "note": "wait-a" } }, { "tool": "demo__fix", "args": { "note": "b" } }] })).await["structuredContent"].clone();
    let (id, url, hash) = (pending["ticketId"].as_str().unwrap().to_owned(), pending["approvalUrl"].as_str().unwrap().to_owned(), pending["plan"]["hash"].as_str().unwrap().to_owned());
    let csrf = extract_csrf(&s.http.get(&url).send().await.unwrap().text().await.unwrap());
    let post = |pairs: Vec<(&str, &str)>| {
        s.http
            .post(&url)
            .header("origin", &s.base)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish())
    };
    let approved = post(vec![("csrf", &csrf), ("pin", PIN), ("decision", "approve"), ("plan_hash", &hash)]).send().await.unwrap();
    assert!(approved.text().await.unwrap().contains("Stop after this step"), "the running plan offers a stop button");
    for _ in 0..250 {
        if !s.f.plugin.started.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let running = s.call("aegis__check_ticket", json!({ "ticketId": id })).await["structuredContent"].clone();
    assert!(running["message"].as_str().unwrap().contains("Running step 1 of 2"), "{running}");

    assert_eq!(post(vec![("csrf", &"0".repeat(32)), ("decision", "cancel")]).send().await.unwrap().status(), 403, "cancel still needs the form token");
    let stopped = post(vec![("csrf", &csrf), ("decision", "cancel")]).send().await.unwrap();
    assert_eq!(stopped.status(), 200);
    assert!(stopped.text().await.unwrap().contains("Stopping after the step"));
    s.f.plugin.release.add_permits(1);
    let done = poll_until_final(&s, &id).await;
    assert_eq!(done["status"], "cancelled", "{done}");
    assert_eq!(step_statuses(&done), ["succeeded", "cancelled"]);
    assert_eq!(*s.f.plugin.fixed.lock().unwrap(), ["wait-a"]);
}
