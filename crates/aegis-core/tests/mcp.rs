//! Drives the real MCP server and approval portal over loopback HTTP.

mod common;

use std::time::Duration;

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
    let f = ready().await;
    let view = f
        .engine
        .update_settings(SettingsUpdate { mcp_enabled: Some(true), mcp_port: Some(free_port()), ..Default::default() })
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
