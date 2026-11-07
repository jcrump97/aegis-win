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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://127.0.0.1:{}/v1", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, body) in responses {
            let (mut sock, _) = listener.accept().await.unwrap();
            requests.push(read_request(&mut sock).await);
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
    LlmHandle::new(http_client(), LlmConfig { base_url: base_url.into(), model: "test-model".into(), api_key: None }, plugin_id, false)
}
