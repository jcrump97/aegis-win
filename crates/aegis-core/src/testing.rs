//! Test helpers shared by the core and plugin crates (`features = ["test-util"]`).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::llm::{http_client, LlmConfig, LlmHandle};

fn completion(answer: &str) -> String {
    serde_json::json!({ "choices": [{ "message": { "content": answer } }] }).to_string()
}

/// Starts a one-shot OpenAI-compatible server on loopback that answers
/// `/chat/completions` with `answer`. The join handle yields the raw request.
pub async fn mock_llm(answer: &str) -> (String, JoinHandle<String>) {
    mock_http("200 OK", completion(answer)).await
}

/// Like [`mock_llm`], but answers one request per entry of `answers`, in
/// order. The join handle yields every raw request.
pub async fn mock_llm_replies(answers: &[&str]) -> (String, JoinHandle<Vec<String>>) {
    serve(answers.iter().map(|a| ("200 OK", completion(a))).collect()).await
}

/// Starts a one-shot HTTP server on loopback (base URL ends in `/v1`) that
/// answers any request with `status` and `body`.
pub async fn mock_http(status: &'static str, body: String) -> (String, JoinHandle<String>) {
    let (base_url, handle) = serve(vec![(status, body)]).await;
    (base_url, tokio::spawn(async move { handle.await.unwrap().remove(0) }))
}

async fn serve(responses: Vec<(&'static str, String)>) -> (String, JoinHandle<Vec<String>>) {
    serve_as(None, responses).await
}

/// Like [`mock_llm_replies`], but the server says it is Ollama (version
/// `0.12.0`) and answers `/api/chat` with Ollama's native reply shape.
/// `/api/show` reports `context_length` for the model.
pub async fn mock_ollama(answers: &[&str], context_length: u64) -> (String, JoinHandle<Vec<String>>) {
    let show = serde_json::json!({ "model_info": { "general.architecture": "llama", "llama.context_length": context_length } }).to_string();
    let replies = answers
        .iter()
        .map(|a| ("200 OK", serde_json::json!({ "message": { "role": "assistant", "content": a }, "done": true, "done_reason": "stop", "prompt_eval_count": 100 }).to_string()))
        .collect();
    serve_as(Some(show), replies).await
}

/// Serves `responses` in order. `GET /api/version` (the Ollama check) and
/// `POST /api/show` are answered on the side without using a response: with
/// 404 normally, or as Ollama when `ollama_show` is set.
async fn serve_as(ollama_show: Option<String>, responses: Vec<(&'static str, String)>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://127.0.0.1:{}/v1", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async move {
        let mut requests = Vec::new();
        let mut responses = responses.into_iter();
        let mut next = responses.next();
        while let Some((status, body)) = next.take() {
            let (mut sock, _) = listener.accept().await.unwrap();
            let request = read_request(&mut sock).await;
            let side = if request.starts_with("GET /api/version ") {
                Some(ollama_show.as_ref().map(|_| ("200 OK", r#"{"version":"0.12.0"}"#.to_owned())).unwrap_or(("404 Not Found", "404 page not found".to_owned())))
            } else if request.starts_with("POST /api/show ") {
                Some(ollama_show.clone().map(|s| ("200 OK", s)).unwrap_or(("404 Not Found", "404 page not found".to_owned())))
            } else {
                None
            };
            let (status, body) = match side {
                Some(reply) => {
                    next = Some((status, body));
                    reply
                }
                None => {
                    requests.push(request);
                    next = responses.next();
                    (status, body)
                }
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        }
        requests
    });
    (base_url, handle)
}

async fn read_request(sock: &mut TcpStream) -> String {
    let mut buf = vec![0u8; 65536];
    let mut req = Vec::new();
    loop {
        let n = sock.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        req.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&req);
        if let Some(h) = text.find("\r\n\r\n") {
            let len: usize = text
                .lines()
                .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                .unwrap_or(0);
            if req.len() >= h + 4 + len {
                break;
            }
        }
    }
    String::from_utf8_lossy(&req).into_owned()
}

pub fn llm_handle(base_url: &str, plugin_id: &str) -> LlmHandle {
    LlmHandle::new(http_client(), LlmConfig { base_url: base_url.into(), model: "test-model".into(), ..LlmConfig::default() }, plugin_id, false)
}
