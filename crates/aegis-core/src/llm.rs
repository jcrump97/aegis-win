//! Central LLM service: one OpenAI-compatible client shared by every plugin,
//! with the Off-LAN trust gate and PII scrubbing in front of it.
//!
//! Plugins never pick their own identity: the engine builds an [`LlmHandle`]
//! bound to the calling plugin's id and its trust grant, and the plugin can
//! only call [`LlmHandle::complete`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{AegisError, AegisResult, ErrorCode};
use crate::secret::Secret;

const MAX_PROMPT_CHARS: usize = 48_000;

/// The context window assumed until the owner changes it. Ollama's own
/// default (2048-4096) is too small for the monitor creator.
pub const DEFAULT_CONTEXT_TOKENS: u32 = 8192;
pub const MIN_CONTEXT_TOKENS: u32 = 2048;
pub const MAX_CONTEXT_TOKENS: u32 = 131_072;

fn default_context_tokens() -> u32 {
    DEFAULT_CONTEXT_TOKENS
}

/// How long to wait for the first sign of an answer. A local model may first
/// have to load from disk.
pub const DEFAULT_FIRST_TOKEN_SECS: u32 = 180;
pub const MIN_FIRST_TOKEN_SECS: u32 = 30;
pub const MAX_FIRST_TOKEN_SECS: u32 = 900;
/// Once the model is answering, the longest silence allowed between pieces.
const IDLE_LIMIT: Duration = Duration::from_secs(60);
/// The longest any one answer may take.
const ANSWER_LIMIT: Duration = Duration::from_secs(600);
/// A streamed answer larger than this is not an answer.
const MAX_STREAM_BYTES: usize = 4 << 20;

fn default_first_token_secs() -> u32 {
    DEFAULT_FIRST_TOKEN_SECS
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmConfig {
    pub base_url: String,
    pub model: String,
    #[serde(default)]
    pub api_key: Option<Secret>,
    /// How many tokens the model reads at once. AegisWin sets it on Ollama and
    /// keeps every request inside it.
    #[serde(default = "default_context_tokens")]
    pub context_tokens: u32,
    /// Seconds to wait for the model to start answering.
    #[serde(default = "default_first_token_secs")]
    pub first_token_secs: u32,
}

impl Default for LlmConfig {
    fn default() -> Self {
        // Ollama's OpenAI-compatible endpoint.
        Self { base_url: "http://127.0.0.1:11434/v1".into(), model: "llama3.2:latest".into(), api_key: None, context_tokens: DEFAULT_CONTEXT_TOKENS, first_token_secs: DEFAULT_FIRST_TOKEN_SECS }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub host: String,
    pub is_lan: bool,
    pub https: bool,
    /// The host is on the LAN, but the model runs elsewhere (Ollama cloud
    /// models), so prompts still leave this network.
    pub relayed: bool,
}

impl Endpoint {
    /// True only when both the host and the model are local.
    pub fn stays_on_lan(&self) -> bool {
        self.is_lan && !self.relayed
    }
}

/// Ollama serves its cloud models (`glm-4.6:cloud`, `gpt-oss:120b-cloud`) at
/// the local endpoint and forwards every prompt to ollama.com.
pub fn model_runs_remotely(model: &str) -> bool {
    let tag = model.trim().rsplit_once(':').map(|(_, tag)| tag.to_ascii_lowercase()).unwrap_or_default();
    tag == "cloud" || tag.ends_with("-cloud")
}

/// Classifies the endpoint together with the model it will run.
pub fn classify(base_url: &str, model: &str) -> AegisResult<Endpoint> {
    let mut endpoint = classify_endpoint(base_url)?;
    endpoint.relayed = endpoint.is_lan && model_runs_remotely(model);
    Ok(endpoint)
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
    Ok(Endpoint { host, is_lan, https, relayed: false })
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
    /// Prompt tokens as the server counted them, when it says.
    pub prompt_tokens: Option<u64>,
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
        // No overall timeout: answers stream, and `LlmHandle` times the wait
        // for the first piece, the gaps between pieces, and the whole answer.
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
        let endpoint = classify(&self.config.base_url, &self.config.model)?;
        if !endpoint.is_lan && !endpoint.https {
            return Err(AegisError::invalid("Off-LAN LLM endpoints must use https:// so diagnostics are not sent in clear text."));
        }
        if !endpoint.stays_on_lan() && !self.trusted_off_lan {
            let destination = if endpoint.relayed {
                format!("model '{}', which runs on Ollama's cloud servers outside your LAN", self.config.model.trim())
            } else {
                format!("{}, which is outside your LAN", endpoint.host)
            };
            return Err(AegisError::new(
                ErrorCode::OffLanTrustRequired,
                format!("Plugin '{}' needs your permission before it sends diagnostics to {destination}.", self.plugin_id),
            ));
        }
        Ok(endpoint)
    }

    pub async fn complete(&self, system_prompt: &str, payload: Value) -> AegisResult<LlmAnswer> {
        self.complete_with(system_prompt, payload, LlmOptions::default()).await
    }

    /// Like [`complete`](Self::complete), with per-call options.
    pub async fn complete_with(&self, system_prompt: &str, payload: Value, options: LlmOptions) -> AegisResult<LlmAnswer> {
        self.complete_watched(system_prompt, payload, options, &LlmProgress::default()).await
    }

    /// Like [`complete_with`](Self::complete_with), reporting how the answer
    /// is coming along to `progress` while it streams in.
    pub async fn complete_watched(&self, system_prompt: &str, mut payload: Value, options: LlmOptions, progress: &LlmProgress) -> AegisResult<LlmAnswer> {
        let endpoint = self.preflight()?;
        let off_lan = !endpoint.stays_on_lan();
        if off_lan {
            scrub_value(&mut payload, crate::os::username().as_deref(), crate::os::hostname().as_deref());
        }
        // Compact JSON: indentation costs tokens a small local model can't spare.
        let user = match payload {
            Value::String(s) => s,
            other => serde_json::to_string(&other).unwrap_or_default(),
        };
        let user = self.fit(system_prompt, user, options)?;
        let ollama = match ollama_root(&self.config.base_url).filter(|_| endpoint.is_lan) {
            Some(root) if is_ollama(&self.client, &root).await => Some(root),
            _ => None,
        };
        let messages = json!([
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": user },
        ]);
        let reply = match &ollama {
            // Ollama's OpenAI endpoint ignores the context size, so a long
            // prompt would be cut silently. Its own API takes it.
            Some(root) => {
                let mut body = json!({
                    "model": self.config.model,
                    "stream": true,
                    "messages": messages,
                    "options": { "temperature": 0.2, "num_ctx": self.config.context_tokens, "num_predict": options.max_tokens },
                });
                if options.json {
                    body["format"] = json!("json");
                }
                self.stream(&endpoint, format!("{root}/api/chat"), &body, Wire::Ndjson, progress).await?
            }
            None => {
                let body = json!({
                    "model": self.config.model,
                    "temperature": 0.2,
                    "max_tokens": options.max_tokens,
                    "stream": true,
                    "messages": messages,
                });
                self.stream(&endpoint, api_url(&self.config.base_url, "chat/completions"), &body, Wire::Sse, progress).await?
            }
        };
        let text = reply.text.ok_or_else(|| llm_failed(&endpoint, "the response has no answer text"))?;
        let text = strip_thinking(&text).filter(|_| !reply.cut_off).ok_or_else(|| {
            llm_failed(
                &endpoint,
                &format!(
                    "the model's answer was cut off at its {}-token limit. Try a model that answers more briefly, or one without a long thinking phase.",
                    options.max_tokens
                ),
            )
        })?;
        // A prompt that filled the whole window was most likely cut at the
        // start, which is where the instructions are.
        if options.must_fit && reply.prompt_tokens.is_some_and(|n| n + 16 >= u64::from(self.config.context_tokens)) {
            return Err(llm_failed(
                &endpoint,
                &format!(
                    "the prompt filled the model's whole {}-token context window, so the model probably did not see all of it. Raise Context window on the LLM tab, or start a new conversation.",
                    self.config.context_tokens
                ),
            ));
        }
        Ok(LlmAnswer {
            text,
            model: self.config.model.clone(),
            endpoint_host: endpoint.host,
            off_lan,
            scrubbed: off_lan,
            prompt_tokens: reply.prompt_tokens,
        })
    }

    /// Keeps the request inside the context window: the system prompt, the
    /// user message and room for the answer, with a 10% margin. Shortens the
    /// user message, or refuses when it must be sent whole.
    fn fit(&self, system_prompt: &str, user: String, options: LlmOptions) -> AegisResult<String> {
        let context = self.config.context_tokens;
        let usable = u64::from(context) * 9 / 10;
        let fixed = estimate_tokens(system_prompt) + u64::from(options.max_tokens);
        let room = usable.saturating_sub(fixed);
        let needed = estimate_tokens(&user);
        if needed <= room && user.chars().count() <= MAX_PROMPT_CHARS {
            return Ok(user);
        }
        if options.must_fit || room < 256 {
            return Err(AegisError::new(
                ErrorCode::LlmFailed,
                format!(
                    "This request needs about {} tokens, more than the {context}-token context window set on the LLM tab. Raise it there if your model supports more, or start a new conversation.",
                    needed + fixed
                ),
            ));
        }
        let keep = usize::try_from(room * CHARS_PER_TOKEN).unwrap_or(usize::MAX).min(MAX_PROMPT_CHARS);
        Ok(user.chars().take(keep).collect::<String>() + "\n…(truncated)")
    }

    /// Sends a streaming request and reads the answer as it arrives. Waits
    /// up to the owner's first-answer setting for the first piece (thinking
    /// counts), then at most [`IDLE_LIMIT`] between pieces and
    /// [`ANSWER_LIMIT`] in all. A server that ignores `stream` and answers in
    /// one piece is read the same way.
    async fn stream(&self, endpoint: &Endpoint, url: String, body: &Value, wire: Wire, progress: &LlmProgress) -> AegisResult<Reply> {
        let first_wait = Duration::from_secs(u64::from(self.config.first_token_secs));
        let started = Instant::now();
        let first_deadline = started + first_wait.min(ANSWER_LIMIT);
        let all_deadline = started + ANSWER_LIMIT;
        progress.begin(self.config.first_token_secs);
        let _done = ProgressDone(progress);

        let mut request = self.client.post(url).json(body);
        if let Some(key) = self.config.api_key.as_ref().filter(|k| !k.is_empty()) {
            request = request.bearer_auth(key.expose());
        }
        let first_wait_error = || {
            llm_failed(
                endpoint,
                &format!(
                    "the model did not start answering within {} seconds. It may still be loading, or be too large for this PC. Try again, raise First answer wait on the LLM tab, or pick a smaller model.",
                    self.config.first_token_secs
                ),
            )
        };
        let mut response = match tokio::time::timeout_at(first_deadline.into(), request.send()).await {
            Err(_) => return Err(first_wait_error()),
            Ok(Err(e)) => return Err(send_failed(endpoint, &e)),
            Ok(Ok(r)) => r,
        };
        let status = response.status();
        if !status.is_success() {
            let raw = tokio::time::timeout(Duration::from_secs(30), response.text()).await.ok().and_then(Result::ok).unwrap_or_default();
            let value: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            let detail = value
                .pointer("/error/message")
                .or_else(|| value.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("request rejected");
            return Err(self.rejected(endpoint, status, detail));
        }

        let mut parser = StreamParser::new(wire);
        loop {
            let deadline = if parser.active { (Instant::now() + IDLE_LIMIT).min(all_deadline) } else { first_deadline };
            let chunk = match tokio::time::timeout_at(deadline.into(), response.chunk()).await {
                Err(_) if Instant::now() >= all_deadline => {
                    return Err(llm_failed(endpoint, &format!("the answer took longer than {} minutes, so AegisWin stopped waiting.", ANSWER_LIMIT.as_secs() / 60)));
                }
                Err(_) if parser.active => {
                    return Err(llm_failed(endpoint, &format!("the model stopped answering for {} seconds partway through.", IDLE_LIMIT.as_secs())));
                }
                Err(_) => return Err(first_wait_error()),
                Ok(Err(e)) => return Err(llm_failed(endpoint, &format!("the connection broke while the answer was arriving ({e})."))),
                Ok(Ok(None)) => break,
                Ok(Ok(Some(bytes))) => bytes,
            };
            parser.push(&chunk).map_err(|detail| llm_failed(endpoint, &detail))?;
            progress.update(parser.active, parser.answering(), parser.answer_chars());
            if parser.done {
                break;
            }
        }
        parser.finish().map_err(|detail| llm_failed(endpoint, &detail))
    }
}

struct Reply {
    text: Option<String>,
    cut_off: bool,
    prompt_tokens: Option<u64>,
}

/// How a server streams its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    /// OpenAI server-sent events: `data: {...}` lines, then `data: [DONE]`.
    Sse,
    /// Ollama: one JSON object per line, the last with `"done": true`.
    Ndjson,
}

/// Collects a streamed answer line by line.
struct StreamParser {
    wire: Wire,
    pending: Vec<u8>,
    /// Everything received, kept only while it is small, for a server that
    /// ignored `stream` and sent one ordinary JSON answer.
    whole: Vec<u8>,
    received: usize,
    saw_stream: bool,
    text: String,
    /// The model has sent something: thinking or answer text.
    active: bool,
    cut_off: bool,
    prompt_tokens: Option<u64>,
    done: bool,
}

impl StreamParser {
    fn new(wire: Wire) -> Self {
        Self {
            wire,
            pending: Vec::new(),
            whole: Vec::new(),
            received: 0,
            saw_stream: false,
            text: String::new(),
            active: false,
            cut_off: false,
            prompt_tokens: None,
            done: false,
        }
    }

    fn answering(&self) -> bool {
        !self.text.trim().is_empty()
    }

    fn answer_chars(&self) -> u64 {
        self.text.chars().count() as u64
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.received += bytes.len();
        if self.received > MAX_STREAM_BYTES {
            return Err("the answer was far larger than expected, so AegisWin stopped reading it.".into());
        }
        if !self.saw_stream {
            self.whole.extend_from_slice(bytes);
        }
        self.pending.extend_from_slice(bytes);
        while let Some(end) = self.pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            self.line(&String::from_utf8_lossy(&line))?;
            if self.done {
                break;
            }
        }
        Ok(())
    }

    fn line(&mut self, line: &str) -> Result<(), String> {
        let line = line.trim();
        let data = match self.wire {
            Wire::Sse => match line.strip_prefix("data:") {
                Some(d) => d.trim(),
                None => return Ok(()),
            },
            Wire::Ndjson => line,
        };
        if data.is_empty() {
            return Ok(());
        }
        if data == "[DONE]" {
            self.saw_stream = true;
            self.done = true;
            return Ok(());
        }
        let Ok(v) = serde_json::from_str::<Value>(data) else {
            return Ok(());
        };
        if let Some(e) = v.pointer("/error/message").or_else(|| v.get("error")).and_then(Value::as_str) {
            return Err(format!("the server reported an error: {}", truncate(e, 300)));
        }
        let (piece, thinking, finish, prompt_tokens) = match self.wire {
            Wire::Sse => {
                let delta = v.pointer("/choices/0/delta");
                if delta.is_none() && v.pointer("/choices/0/message").is_some() {
                    // An ordinary answer on one line; read at the end.
                    return Ok(());
                }
                self.saw_stream = true;
                let piece = delta.and_then(|d| d.get("content")).and_then(Value::as_str);
                let thinking = delta.and_then(|d| d.get("reasoning_content").or_else(|| d.get("reasoning"))).and_then(Value::as_str);
                let finish = v.pointer("/choices/0/finish_reason").and_then(Value::as_str);
                (piece, thinking, finish, v.pointer("/usage/prompt_tokens").and_then(Value::as_u64))
            }
            Wire::Ndjson => {
                self.saw_stream = true;
                let piece = v.pointer("/message/content").and_then(Value::as_str);
                let thinking = v.pointer("/message/thinking").and_then(Value::as_str);
                let done = v.get("done").and_then(Value::as_bool) == Some(true);
                if done {
                    self.done = true;
                }
                let finish = if done { v.get("done_reason").and_then(Value::as_str) } else { None };
                (piece, thinking, finish, v.get("prompt_eval_count").and_then(Value::as_u64))
            }
        };
        if let Some(piece) = piece {
            self.text.push_str(piece);
        }
        if piece.is_some_and(|p| !p.is_empty()) || thinking.is_some_and(|t| !t.is_empty()) {
            self.active = true;
        }
        if finish == Some("length") {
            self.cut_off = true;
        }
        if prompt_tokens.is_some() {
            self.prompt_tokens = prompt_tokens;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Reply, String> {
        if !self.pending.is_empty() && !self.done {
            let rest = std::mem::take(&mut self.pending);
            self.line(&String::from_utf8_lossy(&rest))?;
        }
        if !self.saw_stream {
            // The server ignored `stream` and answered in one piece.
            let v: Value = serde_json::from_slice(&self.whole).unwrap_or(Value::Null);
            return Ok(Reply {
                text: v.pointer("/choices/0/message/content").or_else(|| v.pointer("/message/content")).and_then(Value::as_str).map(str::to_owned),
                cut_off: v.pointer("/choices/0/finish_reason").or_else(|| v.get("done_reason")).and_then(Value::as_str) == Some("length"),
                prompt_tokens: v.pointer("/usage/prompt_tokens").or_else(|| v.get("prompt_eval_count")).and_then(Value::as_u64),
            });
        }
        Ok(Reply { text: Some(self.text), cut_off: self.cut_off, prompt_tokens: self.prompt_tokens })
    }
}

/// How one LLM request is coming along, for a progress line in the app. A
/// plugin keeps one and passes it to [`LlmHandle::complete_watched`].
#[derive(Debug, Default)]
pub struct LlmProgress {
    /// 0 idle, 1 waiting for the model, 2 thinking, 3 answering.
    phase: AtomicU8,
    chars: AtomicU64,
    first_token_secs: AtomicU64,
    started: Mutex<Option<Instant>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProgressView {
    /// `idle`, `waiting` (no answer yet), `thinking`, or `answering`.
    pub phase: &'static str,
    pub elapsed_secs: u64,
    /// Answer characters received so far.
    pub chars: u64,
    pub first_token_secs: u64,
}

impl LlmProgress {
    fn begin(&self, first_token_secs: u32) {
        self.chars.store(0, Ordering::SeqCst);
        self.first_token_secs.store(u64::from(first_token_secs), Ordering::SeqCst);
        *self.started.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Instant::now());
        self.phase.store(1, Ordering::SeqCst);
    }

    fn update(&self, active: bool, answering: bool, chars: u64) {
        self.chars.store(chars, Ordering::SeqCst);
        self.phase.store(if answering { 3 } else if active { 2 } else { 1 }, Ordering::SeqCst);
    }

    fn end(&self) {
        self.phase.store(0, Ordering::SeqCst);
        *self.started.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub fn view(&self) -> ProgressView {
        let phase = match self.phase.load(Ordering::SeqCst) {
            1 => "waiting",
            2 => "thinking",
            3 => "answering",
            _ => "idle",
        };
        let started = *self.started.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        ProgressView {
            phase,
            elapsed_secs: started.map_or(0, |s| s.elapsed().as_secs()),
            chars: self.chars.load(Ordering::SeqCst),
            first_token_secs: self.first_token_secs.load(Ordering::SeqCst),
        }
    }
}

/// Marks the progress idle however the request ends.
struct ProgressDone<'a>(&'a LlmProgress);

impl Drop for ProgressDone<'_> {
    fn drop(&mut self) {
        self.0.end();
    }
}

/// Explains a request that never got an answer.
fn send_failed(endpoint: &Endpoint, e: &reqwest::Error) -> AegisError {
    if e.is_connect() {
        return llm_failed(
            endpoint,
            "could not connect. Check that the LLM server is running (Ollama: open it from the Start menu) and that the base URL on the LLM tab is right.",
        );
    }
    if e.is_timeout() {
        return llm_failed(endpoint, "connecting took longer than 10 seconds. Check that the server is reachable from this PC.");
    }
    llm_failed(endpoint, &e.to_string())
}

/// A deliberately low estimate of characters per token, so requests err on
/// the side of fitting: English runs about 4, JSON and names nearer 3.
const CHARS_PER_TOKEN: u64 = 3;

fn estimate_tokens(text: &str) -> u64 {
    (text.chars().count() as u64).div_ceil(CHARS_PER_TOKEN)
}

/// Ollama's server root for a base URL ending in `/v1`.
fn ollama_root(base_url: &str) -> Option<String> {
    base_url.trim().trim_end_matches('/').strip_suffix("/v1").map(str::to_owned)
}

/// Whether the server is Ollama (`GET /api/version`). Sends no prompt data.
async fn is_ollama(client: &reqwest::Client, root: &str) -> bool {
    let Ok(response) = client.get(format!("{root}/api/version")).timeout(Duration::from_secs(5)).send().await else {
        return false;
    };
    response.status().is_success() && response.json::<Value>().await.is_ok_and(|v| v.get("version").is_some_and(Value::is_string))
}

/// What Test connection learns beyond the model list.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub ollama: bool,
    /// The model's largest context window, when the server says (Ollama).
    pub model_context_limit: Option<u32>,
    /// Advice about the context window setting.
    pub warnings: Vec<String>,
}

/// Checks the context window setting against the server. Sends only the
/// model name, and only to a LAN endpoint.
pub async fn server_info(client: &reqwest::Client, config: &LlmConfig) -> ServerInfo {
    let mut info = ServerInfo::default();
    let lan = classify_endpoint(&config.base_url).is_ok_and(|e| e.is_lan);
    if let Some(root) = ollama_root(&config.base_url).filter(|_| lan) {
        if is_ollama(client, &root).await {
            info.ollama = true;
            let show = client.post(format!("{root}/api/show")).timeout(Duration::from_secs(10)).json(&json!({ "model": config.model.trim() })).send().await;
            if let Ok(response) = show.and_then(reqwest::Response::error_for_status) {
                info.model_context_limit = response.json::<Value>().await.ok().as_ref().and_then(context_limit);
            }
        }
    }
    let wanted = config.context_tokens;
    match (info.ollama, info.model_context_limit) {
        (true, Some(limit)) if limit < wanted => {
            info.warnings.push(format!("{} reads at most {limit} tokens at once. Set Context window to {limit} or less.", config.model.trim()));
        }
        (true, _) => {}
        (false, _) => info.warnings.push(format!(
            "AegisWin can set the context window only on Ollama. On this server, load the model with at least {wanted} tokens (LM Studio: Context Length), or set Context window to what it uses."
        )),
    }
    info
}

/// `model_info["<architecture>.context_length"]` from Ollama's `/api/show`.
fn context_limit(show: &Value) -> Option<u32> {
    show.get("model_info")?
        .as_object()?
        .iter()
        .find(|(k, _)| k.ends_with(".context_length"))
        .and_then(|(_, v)| v.as_u64())
        .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
}

/// Per-call request options.
#[derive(Debug, Clone, Copy)]
pub struct LlmOptions {
    /// The most tokens the model may write. Without a cap a looping model runs
    /// until the request times out.
    pub max_tokens: u32,
    /// Ask for a JSON object (Ollama's `format: "json"`).
    pub json: bool,
    /// Refuse rather than shorten a request that does not fit the context
    /// window: a cut conversation is worse than a clear error.
    pub must_fit: bool,
}

impl Default for LlmOptions {
    fn default() -> Self {
        Self { max_tokens: 2048, json: false, must_fit: false }
    }
}

/// Drops `<think>…</think>` blocks that reasoning models put before their
/// answer, and trims. `None` when a block is never closed: the answer was cut
/// off while the model was still thinking.
fn strip_thinking(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("<think>") {
        out.push_str(&rest[..start]);
        let after = &rest[start + "<think>".len()..];
        let end = after.find("</think>")?;
        rest = &after[end + "</think>".len()..];
    }
    out.push_str(rest);
    Some(out.trim().to_owned())
}

impl LlmHandle {
    /// Turns a rejected request into advice: a missing model and a wrong base
    /// URL are the usual first-run problems.
    fn rejected(&self, endpoint: &Endpoint, status: reqwest::StatusCode, detail: &str) -> AegisError {
        if status == reqwest::StatusCode::NOT_FOUND {
            let model = &self.config.model;
            if detail.to_ascii_lowercase().contains("model") {
                return llm_failed(
                    endpoint,
                    &format!("the model '{model}' isn't installed there. On the LLM tab, click Test connection and pick a listed model, or install it (Ollama: ollama pull {model})."),
                );
            }
            return llm_failed(endpoint, "nothing answered at this base URL (HTTP 404). Check it on the LLM tab; Ollama's is http://127.0.0.1:11434/v1.");
        }
        llm_failed(endpoint, &format!("HTTP {status}: {}", truncate(detail, 300)))
    }
}

/// Lists model ids at the endpoint (`GET /models`). Sends no diagnostic data.
pub async fn list_models(client: &reqwest::Client, config: &LlmConfig) -> AegisResult<Vec<String>> {
    let endpoint = classify_endpoint(&config.base_url)?;
    let mut request = client.get(api_url(&config.base_url, "models")).timeout(Duration::from_secs(30));
    if let Some(key) = config.api_key.as_ref().filter(|k| !k.is_empty()) {
        request = request.bearer_auth(key.expose());
    }
    let response = request.send().await.map_err(|e| send_failed(&endpoint, &e))?;
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
    fn ollama_cloud_models_leave_the_lan() {
        for remote in ["glm-4.6:cloud", "gpt-oss:120b-cloud", "qwen3-coder:480b-cloud", " Kimi-K2.6:CLOUD "] {
            assert!(model_runs_remotely(remote), "{remote}");
            let e = classify("http://127.0.0.1:11434/v1", remote).unwrap();
            assert!(e.is_lan && e.relayed && !e.stays_on_lan(), "{remote}");
        }
        for local in ["llama3.2:latest", "mistral:7b-instruct", "cloud-tools:latest", "mycloud", "qwen3:14b"] {
            assert!(!model_runs_remotely(local), "{local}");
            assert!(classify("http://127.0.0.1:11434/v1", local).unwrap().stays_on_lan(), "{local}");
        }
        // A remote host is off-LAN whatever the model; "relayed" only qualifies a LAN host.
        assert!(!classify("https://api.openai.com/v1", "gpt-oss:120b-cloud").unwrap().relayed);
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
        LlmHandle::new(http_client(), LlmConfig { base_url: base.into(), model: "m".into(), ..LlmConfig::default() }, "event-logs", trusted)
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
    async fn explains_a_missing_model_and_a_wrong_url() {
        let ollama = json!({ "error": { "message": "model \"m\" not found, try pulling it first" } }).to_string();
        let (base, _) = crate::testing::mock_http("404 Not Found", ollama).await;
        let err = handle(&base, false).complete("sys", json!({})).await.unwrap_err();
        assert!(err.message.contains("model 'm' isn't installed") && err.message.contains("ollama pull m"), "{}", err.message);

        let (base, _) = crate::testing::mock_http("404 Not Found", "404 page not found".into()).await;
        let err = handle(&base, false).complete("sys", json!({})).await.unwrap_err();
        assert!(err.message.contains("Check it on the LLM tab"), "{}", err.message);

        let (base, _) = crate::testing::mock_http("500 Internal Server Error", json!({ "error": "out of memory" }).to_string()).await;
        let err = handle(&base, false).complete("sys", json!({})).await.unwrap_err();
        assert!(err.message.contains("HTTP 500 Internal Server Error: out of memory"), "{}", err.message);
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
        assert!(request.contains("\"max_tokens\":2048"), "{request}");
        // The payload is sent as compact JSON.
        assert!(request.contains(r#"{\"q\":1}"#), "{request}");
    }

    #[tokio::test]
    async fn complete_with_caps_the_reply_and_strips_thinking() {
        let (base, server) = crate::testing::mock_llm("<think>hmm
long</think>
{\"ok\":true}").await;
        let answer = handle(&base, false).complete_with("sys", json!({}), LlmOptions { max_tokens: 1024, ..LlmOptions::default() }).await.unwrap();
        assert_eq!(answer.text, "{\"ok\":true}");
        assert!(server.await.unwrap().contains("\"max_tokens\":1024"));
    }

    #[tokio::test]
    async fn a_cut_off_answer_is_reported_as_such() {
        let body = json!({ "choices": [{ "message": { "content": "{\"a\":" }, "finish_reason": "length" }] }).to_string();
        let (base, _server) = crate::testing::mock_http("200 OK", body).await;
        let err = handle(&base, false).complete("sys", json!({})).await.unwrap_err();
        assert!(err.message.contains("cut off at its 2048-token limit"), "{}", err.message);
    }

    #[test]
    fn strip_thinking_handles_blocks_and_unclosed_tags() {
        assert_eq!(strip_thinking("  plain  ").as_deref(), Some("plain"));
        assert_eq!(strip_thinking("<think>a</think>x<think>b</think> y").as_deref(), Some("x y"));
        assert_eq!(strip_thinking("<think>still going"), None);
    }

    fn sized(base: &str, context_tokens: u32) -> LlmHandle {
        LlmHandle::new(http_client(), LlmConfig { base_url: base.into(), model: "m".into(), api_key: None, context_tokens, ..LlmConfig::default() }, "event-logs", false)
    }

    #[tokio::test]
    async fn ollama_gets_its_native_api_with_the_context_size() {
        let (base, server) = crate::testing::mock_ollama(&["{\"ok\":1}"], 32768).await;
        let options = LlmOptions { max_tokens: 1024, json: true, must_fit: true };
        let answer = sized(&base, 16384).complete_with("sys", json!({ "q": 1 }), options).await.unwrap();
        assert_eq!(answer.text, "{\"ok\":1}");
        assert_eq!(answer.prompt_tokens, Some(100));
        let request = server.await.unwrap().remove(0);
        assert!(request.starts_with("POST /api/chat "), "{request}");
        let body: Value = serde_json::from_str(&request[request.find("\r\n\r\n").unwrap() + 4..]).unwrap();
        assert_eq!(body["options"], json!({ "temperature": 0.2, "num_ctx": 16384, "num_predict": 1024 }));
        assert_eq!(body["format"], "json");
        assert_eq!(body["stream"], true);
    }

    #[tokio::test]
    async fn a_request_that_must_fit_is_refused_and_others_are_shortened() {
        let long = "x".repeat(30_000); // about 10k tokens
        let options = LlmOptions { max_tokens: 1024, json: false, must_fit: true };
        let err = sized("http://127.0.0.1:9/v1", 8192).complete_with("sys", json!(long), options).await.unwrap_err();
        assert!(err.message.contains("more than the 8192-token context window"), "{}", err.message);

        let (base, server) = crate::testing::mock_llm("fine").await;
        sized(&base, 8192).complete_with("sys", json!(long), LlmOptions { must_fit: false, ..options }).await.unwrap();
        let request = server.await.unwrap();
        let body: Value = serde_json::from_str(&request[request.find("\r\n\r\n").unwrap() + 4..]).unwrap();
        let sent = body["messages"][1]["content"].as_str().unwrap();
        // 90% of 8192, less the system prompt and the reply, at 3 characters a token.
        assert_eq!(sent.chars().count(), (8192 * 9 / 10 - 1 - 1024) * 3 + "\n…(truncated)".chars().count());
    }

    #[tokio::test]
    async fn a_prompt_that_filled_the_window_is_reported() {
        let body = json!({ "choices": [{ "message": { "content": "ok" } }], "usage": { "prompt_tokens": 4090 } }).to_string();
        let (base, _server) = crate::testing::mock_http("200 OK", body).await;
        let options = LlmOptions { max_tokens: 256, json: false, must_fit: true };
        let err = sized(&base, 4096).complete_with("sys", json!({}), options).await.unwrap_err();
        assert!(err.message.contains("filled the model's whole 4096-token context window"), "{}", err.message);
    }

    fn timed(base: &str, first_token_secs: u32) -> LlmHandle {
        LlmHandle::new(http_client(), LlmConfig { base_url: base.into(), model: "m".into(), first_token_secs, ..LlmConfig::default() }, "event-logs", false)
    }

    fn at(ms: u64, text: &str) -> (Duration, String) {
        (Duration::from_millis(ms), text.to_owned())
    }

    #[tokio::test]
    async fn reads_an_openai_stream_and_reports_progress() {
        let sse = |content: &str| format!("data: {}\n\n", json!({ "choices": [{ "delta": { "content": content } }] }));
        let (base, server) = crate::testing::mock_stream(
            false,
            vec![
                at(0, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"hmm\"}}]}\n\n"),
                at(10, &sse("Disk ")),
                // A line split across two writes.
                at(10, &sse("is full.")[..12]),
                at(10, &sse("is full.")[12..]),
                at(10, "data: [DONE]\n\n"),
            ],
        )
        .await;
        let progress = LlmProgress::default();
        let answer = timed(&base, 30).complete_watched("sys", json!({}), LlmOptions::default(), &progress).await.unwrap();
        assert_eq!(answer.text, "Disk is full.");
        assert_eq!(progress.view().phase, "idle", "finished");
        let request = server.await.unwrap();
        assert!(request.contains("\"stream\":true"), "{request}");
    }

    #[tokio::test]
    async fn reads_an_ollama_stream_with_thinking() {
        let line = |v: Value| format!("{v}\n");
        let (base, _server) = crate::testing::mock_stream(
            true,
            vec![
                at(0, &line(json!({ "message": { "content": "", "thinking": "let me see" }, "done": false }))),
                at(10, &line(json!({ "message": { "content": "{\"a\":1}" }, "done": false }))),
                at(10, &line(json!({ "message": { "content": "" }, "done": true, "done_reason": "length", "prompt_eval_count": 50 }))),
            ],
        )
        .await;
        let err = timed(&base, 30).complete("sys", json!({})).await.unwrap_err();
        assert!(err.message.contains("cut off at its 2048-token limit"), "{}", err.message);
    }

    #[tokio::test]
    async fn waits_for_the_first_piece_then_for_gaps() {
        // Nothing arrives in time.
        let (base, _server) = crate::testing::mock_stream(false, vec![at(3_000, "data: [DONE]\n\n")]).await;
        let mut slow = timed(&base, 30);
        slow.config.first_token_secs = 1;
        let err = slow.complete("sys", json!({})).await.unwrap_err();
        assert!(err.message.contains("did not start answering within 1 seconds"), "{}", err.message);

        // Thinking counts as a start, so the first-answer wait no longer applies.
        let (base, _server) = crate::testing::mock_stream(
            false,
            vec![at(0, "data: {\"choices\":[{\"delta\":{\"reasoning\":\"x\"}}]}\n\n"), at(1_500, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n")],
        )
        .await;
        let mut thinking = timed(&base, 30);
        thinking.config.first_token_secs = 1;
        assert_eq!(thinking.complete("sys", json!({})).await.unwrap().text, "ok");
    }

    #[tokio::test]
    async fn a_server_that_is_not_running_gets_a_clear_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = timed(&format!("http://127.0.0.1:{port}/v1"), 30).complete("sys", json!({})).await.unwrap_err();
        assert!(err.message.contains("could not connect. Check that the LLM server is running"), "{}", err.message);
    }

    #[test]
    fn progress_reports_each_phase() {
        let p = LlmProgress::default();
        assert_eq!(p.view().phase, "idle");
        p.begin(180);
        assert_eq!((p.view().phase, p.view().first_token_secs), ("waiting", 180));
        p.update(true, false, 0);
        assert_eq!(p.view().phase, "thinking");
        p.update(true, true, 42);
        assert_eq!((p.view().phase, p.view().chars), ("answering", 42));
        p.end();
        assert_eq!(p.view().phase, "idle");
    }

    #[tokio::test]
    async fn test_connection_checks_the_context_window() {
        let config = |base: &str, context_tokens| LlmConfig { base_url: base.into(), model: "m".into(), api_key: None, context_tokens, ..LlmConfig::default() };
        let (base, _server) = crate::testing::mock_ollama(&["unused"], 8192).await;
        let info = server_info(&http_client(), &config(&base, 16384)).await;
        assert!(info.ollama);
        assert_eq!(info.model_context_limit, Some(8192));
        assert_eq!(info.warnings, ["m reads at most 8192 tokens at once. Set Context window to 8192 or less."]);
        let info = server_info(&http_client(), &config(&base, 8192)).await;
        assert!(info.warnings.is_empty(), "{:?}", info.warnings);

        let (base, _server) = crate::testing::mock_llm_replies(&["unused"]).await;
        let info = server_info(&http_client(), &config(&base, 8192)).await;
        assert!(!info.ollama);
        assert!(info.warnings[0].starts_with("AegisWin can set the context window only on Ollama."));
    }
}
