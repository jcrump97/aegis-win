//! Central LLM service: one OpenAI-compatible client shared by every plugin,
//! with the Off-LAN trust gate and PII scrubbing in front of it.
//!
//! Plugins never pick their own identity: the engine builds an [`LlmHandle`]
//! bound to the calling plugin's id and its trust grant, and the plugin can
//! only call [`LlmHandle::complete`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{AegisError, AegisResult, ErrorCode};
use crate::secret::Secret;

const MAX_PROMPT_CHARS: usize = 48_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmConfig {
    pub base_url: String,
    pub model: String,
    #[serde(default)]
    pub api_key: Option<Secret>,
}

impl Default for LlmConfig {
    fn default() -> Self {
        // Ollama's OpenAI-compatible endpoint.
        Self { base_url: "http://127.0.0.1:11434/v1".into(), model: "llama3.2:latest".into(), api_key: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub host: String,
    pub is_lan: bool,
    pub https: bool,
}

/// Parses an endpoint and decides whether it is on the local network.
pub fn classify_endpoint(base_url: &str) -> AegisResult<Endpoint> {
    let url = Url::parse(base_url.trim()).map_err(|e| AegisError::invalid(format!("LLM base URL is not a valid URL: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AegisError::invalid("LLM base URL must start with http:// or https://"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AegisError::invalid("put credentials in the API key field, not in the URL"));
    }
    let (host, is_lan) = match url.host() {
        Some(url::Host::Ipv4(ip)) => (ip.to_string(), is_lan_ip(IpAddr::V4(ip))),
        Some(url::Host::Ipv6(ip)) => (ip.to_string(), is_lan_ip(IpAddr::V6(ip))),
        Some(url::Host::Domain(d)) => (d.to_ascii_lowercase(), is_lan_domain(d)),
        None => return Err(AegisError::invalid("LLM base URL has no host")),
    };
    let https = url.scheme() == "https";
    Ok(Endpoint { host, is_lan, https })
}

pub fn is_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_lan_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_lan_v4(v4);
            }
            let first = v6.segments()[0];
            v6 == Ipv6Addr::LOCALHOST || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

fn is_lan_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local()
}

/// Names that only resolve inside a local network. Matching is by suffix on
/// whole labels, so `fcbarcelona.com` or `evil-local.com` are not LAN.
fn is_lan_domain(domain: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    d == "localhost"
        || [".localhost", ".local", ".lan", ".home", ".internal", ".home.arpa"].iter().any(|s| d.ends_with(s))
}

/// Replaces the Windows user name, computer name, profile paths and UNC
/// server names in every string inside `value`.
pub fn scrub_value(value: &mut Value, username: Option<&str>, hostname: Option<&str>) {
    match value {
        Value::String(s) => *s = scrub_text(s, username, hostname),
        Value::Array(items) => items.iter_mut().for_each(|v| scrub_value(v, username, hostname)),
        Value::Object(map) => map.values_mut().for_each(|v| scrub_value(v, username, hostname)),
        _ => {}
    }
}

pub fn scrub_text(text: &str, username: Option<&str>, hostname: Option<&str>) -> String {
    let mut out = mask_after(text, "\\users\\", "<user>");
    out = mask_after(&out, "/users/", "<user>");
    out = mask_unc_servers(&out);
    if let Some(u) = username.filter(|u| u.chars().count() >= 3) {
        out = replace_word_ci(&out, u, "<user>");
    }
    if let Some(h) = hostname.filter(|h| h.chars().count() >= 3) {
        out = replace_word_ci(&out, h, "<host>");
    }
    out
}

fn is_segment_end(c: char) -> bool {
    matches!(c, '\\' | '/' | '"' | '\'' | '<' | '>' | '|') || c.is_whitespace()
}

/// Replaces the path segment that follows each (case-insensitive) `marker`.
fn mask_after(text: &str, marker: &str, replacement: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(pos) = lower[i..].find(marker) {
        let seg_start = i + pos + marker.len();
        out.push_str(&text[i..seg_start]);
        let seg_len = text[seg_start..].find(is_segment_end).unwrap_or(text.len() - seg_start);
        let segment = &text[seg_start..seg_start + seg_len];
        if segment.is_empty() || segment.eq_ignore_ascii_case("public") || segment.eq_ignore_ascii_case("default") {
            out.push_str(segment);
        } else {
            out.push_str(replacement);
        }
        i = seg_start + seg_len;
    }
    out.push_str(&text[i..]);
    out
}

fn mask_unc_servers(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(pos) = text[i..].find("\\\\") {
        let start = i + pos;
        let at_boundary = start == 0 || text[..start].ends_with(|c: char| c.is_whitespace() || "\"'(=:".contains(c));
        let server_start = start + 2;
        out.push_str(&text[i..server_start]);
        let len = text[server_start..].find(is_segment_end).unwrap_or(text.len() - server_start);
        if at_boundary && len > 0 && text[server_start + len..].starts_with('\\') {
            out.push_str("<host>");
        } else {
            out.push_str(&text[server_start..server_start + len]);
        }
        i = server_start + len;
    }
    out.push_str(&text[i..]);
    out
}

fn replace_word_ci(text: &str, word: &str, replacement: &str) -> String {
    let lower = text.to_lowercase();
    let needle = word.to_lowercase();
    if lower.len() != text.len() {
        // Lowercasing changed byte offsets (rare non-ASCII case); fall back to exact matching.
        return text.replace(word, replacement);
    }
    let is_word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(pos) = lower[i..].find(&needle) {
        let start = i + pos;
        let end = start + needle.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        out.push_str(&text[i..start]);
        out.push_str(if is_word(before) || is_word(after) { &text[start..end] } else { replacement });
        i = end;
    }
    out.push_str(&text[i..]);
    out
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmAnswer {
    pub text: String,
    pub model: String,
    pub endpoint_host: String,
    pub off_lan: bool,
    pub scrubbed: bool,
}

/// The only way a plugin reaches an LLM. Bound to one plugin per call.
#[derive(Clone)]
pub struct LlmHandle {
    client: reqwest::Client,
    config: LlmConfig,
    plugin_id: String,
    trusted_off_lan: bool,
}

pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(180))
        // A LAN endpoint must not be able to bounce data to an off-LAN host.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client configuration is valid")
}

fn api_url(base: &str, path: &str) -> String {
    format!("{}/{}", base.trim().trim_end_matches('/'), path)
}

impl LlmHandle {
    pub fn new(client: reqwest::Client, config: LlmConfig, plugin_id: &str, trusted_off_lan: bool) -> Self {
        Self { client, config, plugin_id: plugin_id.to_owned(), trusted_off_lan }
    }

    /// Checks the endpoint and trust grant without sending anything.
    pub fn preflight(&self) -> AegisResult<Endpoint> {
        if self.config.base_url.trim().is_empty() || self.config.model.trim().is_empty() {
            return Err(AegisError::new(ErrorCode::LlmNotConfigured, "Set an LLM endpoint and model in the LLM tab first."));
        }
        let endpoint = classify_endpoint(&self.config.base_url)?;
        if !endpoint.is_lan && !endpoint.https {
            return Err(AegisError::invalid("Off-LAN LLM endpoints must use https:// so diagnostics are not sent in clear text."));
        }
        if !endpoint.is_lan && !self.trusted_off_lan {
            return Err(AegisError::new(
                ErrorCode::OffLanTrustRequired,
                format!("Plugin '{}' needs your permission before it sends diagnostics to {}, which is outside your LAN.", self.plugin_id, endpoint.host),
            ));
        }
        Ok(endpoint)
    }

    pub async fn complete(&self, system_prompt: &str, mut payload: Value) -> AegisResult<LlmAnswer> {
        let endpoint = self.preflight()?;
        let off_lan = !endpoint.is_lan;
        if off_lan {
            scrub_value(&mut payload, crate::os::username().as_deref(), crate::os::hostname().as_deref());
        }
        let mut user = match payload {
            Value::String(s) => s,
            other => serde_json::to_string_pretty(&other).unwrap_or_default(),
        };
        if user.chars().count() > MAX_PROMPT_CHARS {
            user = user.chars().take(MAX_PROMPT_CHARS).collect::<String>() + "\n…(truncated)";
        }
        let body = json!({
            "model": self.config.model,
            "temperature": 0.2,
            "stream": false,
            "messages": [
                { "role": "system", "content": system_prompt },
                { "role": "user", "content": user },
            ],
        });
        let mut request = self.client.post(api_url(&self.config.base_url, "chat/completions")).json(&body);
        if let Some(key) = self.config.api_key.as_ref().filter(|k| !k.is_empty()) {
            request = request.bearer_auth(key.expose());
        }
        let response = request.send().await.map_err(|e| llm_failed(&endpoint, &e.to_string()))?;
        let status = response.status();
        let value: Value = response.json().await.map_err(|e| llm_failed(&endpoint, &format!("HTTP {status}: {e}")))?;
        if !status.is_success() {
            let detail = value.pointer("/error/message").and_then(Value::as_str).unwrap_or("request rejected");
            return Err(llm_failed(&endpoint, &format!("HTTP {status}: {}", truncate(detail, 300))));
        }
        let text = value
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .ok_or_else(|| llm_failed(&endpoint, "response has no choices[0].message.content"))?;
        Ok(LlmAnswer {
            text: text.trim().to_owned(),
            model: self.config.model.clone(),
            endpoint_host: endpoint.host,
            off_lan,
            scrubbed: off_lan,
        })
    }
}

/// Lists model ids at the endpoint (`GET /models`). Sends no diagnostic data.
pub async fn list_models(client: &reqwest::Client, config: &LlmConfig) -> AegisResult<Vec<String>> {
    let endpoint = classify_endpoint(&config.base_url)?;
    let mut request = client.get(api_url(&config.base_url, "models"));
    if let Some(key) = config.api_key.as_ref().filter(|k| !k.is_empty()) {
        request = request.bearer_auth(key.expose());
    }
    let response = request.send().await.map_err(|e| llm_failed(&endpoint, &e.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(llm_failed(&endpoint, &format!("HTTP {status}")));
    }
    let value: Value = response.json().await.map_err(|e| llm_failed(&endpoint, &e.to_string()))?;
    Ok(value
        .get("data")
        .and_then(Value::as_array)
        .map(|models| models.iter().filter_map(|m| m.get("id").and_then(Value::as_str).map(str::to_owned)).collect())
        .unwrap_or_default())
}

fn llm_failed(endpoint: &Endpoint, detail: &str) -> AegisError {
    AegisError::new(ErrorCode::LlmFailed, format!("LLM request to {} failed: {}", endpoint.host, truncate(detail, 300)))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_lan_and_off_lan_endpoints() {
        for lan in [
            "http://127.0.0.1:11434/v1",
            "http://localhost:1234/v1",
            "http://192.168.1.20:11434/v1",
            "http://10.0.0.5/v1",
            "http://172.20.1.1/v1",
            "http://169.254.10.10/v1",
            "http://[::1]:8080/v1",
            "http://[fd12:3456::1]/v1",
            "http://[fe80::1]/v1",
            "http://ollama.lan/v1",
            "http://gpu-box.local:11434/v1",
            "http://llm.home.arpa/v1",
        ] {
            assert!(classify_endpoint(lan).unwrap().is_lan, "{lan}");
        }
        for wan in [
            "https://api.openai.com/v1",
            "https://fcbarcelona.com/v1",
            "https://fd.example.com/v1",
            "https://evil-local.com/v1",
            "https://local.example.com/v1",
            "http://8.8.8.8/v1",
            "http://172.32.0.1/v1",
            "http://[2001:db8::1]/v1",
        ] {
            assert!(!classify_endpoint(wan).unwrap().is_lan, "{wan}");
        }
    }

    #[test]
    fn rejects_unusable_urls() {
        for bad in ["ftp://127.0.0.1/v1", "not a url", "http://user:pw@127.0.0.1/v1"] {
            assert!(classify_endpoint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn scrubs_profile_paths_unc_user_and_host() {
        let text = r#"Faulting module C:\Users\JonCrump\AppData\app.dll on DESKTOP-ABC12 by joncrump; share \\FILESRV01\docs; C:/Users/JonCrump/x; C:\Users\Public\y; jonCrumpster"#;
        let out = scrub_text(text, Some("joncrump"), Some("DESKTOP-ABC12"));
        assert_eq!(
            out,
            r#"Faulting module C:\Users\<user>\AppData\app.dll on <host> by <user>; share \\<host>\docs; C:/Users/<user>/x; C:\Users\Public\y; jonCrumpster"#
        );
    }

    #[test]
    fn scrubs_nested_json_strings() {
        let mut v = json!({ "events": [{ "message": "user bob1 at C:\\Users\\bob1\\x" }], "n": 3 });
        scrub_value(&mut v, Some("bob1"), None);
        assert_eq!(v, json!({ "events": [{ "message": "user <user> at C:\\Users\\<user>\\x" }], "n": 3 }));
    }

    fn handle(base: &str, trusted: bool) -> LlmHandle {
        LlmHandle::new(http_client(), LlmConfig { base_url: base.into(), model: "m".into(), api_key: None }, "event-logs", trusted)
    }

    #[test]
    fn off_lan_requires_trust_and_https() {
        let err = handle("https://api.example.com/v1", false).preflight().unwrap_err();
        assert_eq!(err.code, ErrorCode::OffLanTrustRequired);
        assert!(err.message.contains("event-logs"));
        assert!(handle("https://api.example.com/v1", true).preflight().is_ok());
        assert_eq!(handle("http://api.example.com/v1", true).preflight().unwrap_err().code, ErrorCode::InvalidArguments);
        assert!(handle("http://127.0.0.1:11434/v1", false).preflight().is_ok());
    }

    #[tokio::test]
    async fn completes_against_an_openai_compatible_server() {
        let (base, server) = crate::testing::mock_llm("  Disk is full.  ").await;
        let answer = handle(&format!("{base}/"), false).complete("sys", json!({ "q": 1 })).await.unwrap();
        assert_eq!(answer.text, "Disk is full.");
        assert!(!answer.off_lan);
        let request = server.await.unwrap();
        assert!(request.starts_with("POST /v1/chat/completions "), "{request}");
        assert!(request.contains("\"model\":\"m\""));
    }
}
