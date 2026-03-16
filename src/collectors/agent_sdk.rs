//! Agent SDK collector: listens on a Unix domain socket for JSON-Lines events
//! emitted by SDK-instrumented AI agents, providing exact token counts and latency
//! instead of the pcap-based approximations used by the network collector.
//!
//! Socket path: `~/.local/share/atop/agent.sock`
//!
//! Event schema (one JSON object per line):
//! ```json
//! {"ts":1710000000,"pid":1234,"model":"claude-3-5-sonnet","input_tokens":512,"output_tokens":1024,"latency_ms":843}
//! ```

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

/// Aggregated SDK-reported stats per PID (exact values, not pcap estimates)
#[derive(Clone, Default)]
pub struct SdkStats {
    /// Most recently reported model name
    pub model: String,
    /// Cumulative input tokens reported by the agent
    pub input_tokens_total: u64,
    /// Cumulative output tokens reported by the agent
    pub output_tokens_total: u64,
    /// Latency from the most recent event in milliseconds
    pub last_latency_ms: u64,
    /// Total number of API call events received
    pub event_count: u64,
}

/// Snapshot entry returned by `AgentSdkCollector::snapshot()`
#[derive(Clone)]
pub struct SdkEntry {
    pub pid: u32,
    pub stats: SdkStats,
}

/// Status of the SDK listener socket
#[derive(Clone)]
pub enum SdkStatus {
    /// Listening for connections on the socket path
    Listening(PathBuf),
    /// Failed to bind the socket
    Error(String),
}

struct Inner {
    stats: HashMap<u32, SdkStats>,
    status: SdkStatus,
}

/// Background listener that accepts agent SDK connections and accumulates stats.
pub struct AgentSdkCollector {
    inner: Arc<Mutex<Inner>>,
}

impl AgentSdkCollector {
    pub fn new() -> Self {
        let socket_path = sdk_socket_path();
        let status = SdkStatus::Listening(socket_path.clone());
        let inner = Arc::new(Mutex::new(Inner {
            stats: HashMap::new(),
            status,
        }));
        let inner_clone = Arc::clone(&inner);
        thread::Builder::new()
            .name("atop-sdk".into())
            .spawn(move || listen_loop(inner_clone, socket_path))
            .expect("failed to spawn agent SDK listener thread");
        Self { inner }
    }

    /// Return a point-in-time clone of all accumulated SDK stats
    pub fn snapshot(&self) -> Vec<SdkEntry> {
        let g = self.inner.lock().unwrap();
        g.stats
            .iter()
            .map(|(&pid, stats)| SdkEntry { pid, stats: stats.clone() })
            .collect()
    }

    pub fn status(&self) -> SdkStatus {
        self.inner.lock().unwrap().status.clone()
    }
}

// ─── Background listener ──────────────────────────────────────────────────────

fn listen_loop(inner: Arc<Mutex<Inner>>, path: PathBuf) {
    // Ensure the parent directory exists
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            set_error(&inner, &format!("cannot create socket dir: {e}"));
            return;
        }
    }

    // Remove a stale socket file from a previous run
    let _ = std::fs::remove_file(&path);

    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            set_error(&inner, &format!("bind {}: {e}", path.display()));
            return;
        }
    };

    // Accept connections; each client gets its own reader thread
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let inner_clone = Arc::clone(&inner);
                thread::Builder::new()
                    .name("atop-sdk-client".into())
                    .spawn(move || handle_client(inner_clone, stream))
                    .ok();
            }
            Err(_) => break,
        }
    }
}

fn handle_client(inner: Arc<Mutex<Inner>>, stream: std::os::unix::net::UnixStream) {
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        if let Some(event) = parse_event(&line) {
            if let Ok(mut g) = inner.lock() {
                let entry = g.stats.entry(event.pid).or_default();
                if !event.model.is_empty() {
                    entry.model = event.model;
                }
                entry.input_tokens_total += event.input_tokens;
                entry.output_tokens_total += event.output_tokens;
                entry.last_latency_ms = event.latency_ms;
                entry.event_count += 1;
            }
        }
    }
}

fn set_error(inner: &Arc<Mutex<Inner>>, msg: &str) {
    if let Ok(mut g) = inner.lock() {
        g.status = SdkStatus::Error(msg.to_string());
    }
}

// ─── Minimal JSON-Lines parser ────────────────────────────────────────────────

struct ParsedEvent {
    pid: u32,
    model: String,
    input_tokens: u64,
    output_tokens: u64,
    latency_ms: u64,
}

/// Parse a single JSON-Lines event with a fixed schema.
/// Uses simple field extraction — does not handle nested objects or escaped quotes.
fn parse_event(line: &str) -> Option<ParsedEvent> {
    let pid = extract_u64(line, "\"pid\":")? as u32;
    let model = extract_str(line, "\"model\":").unwrap_or_default();
    let input_tokens = extract_u64(line, "\"input_tokens\":").unwrap_or(0);
    let output_tokens = extract_u64(line, "\"output_tokens\":").unwrap_or(0);
    let latency_ms = extract_u64(line, "\"latency_ms\":").unwrap_or(0);
    Some(ParsedEvent { pid, model, input_tokens, output_tokens, latency_ms })
}

/// Extract an unsigned integer after `key` in a JSON string.
fn extract_u64(json: &str, key: &str) -> Option<u64> {
    let start = json.find(key)? + key.len();
    let rest = json[start..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    if end == 0 { return None; }
    rest[..end].parse().ok()
}

/// Extract a JSON string value after `key` (handles simple unescaped strings).
fn extract_str(json: &str, key: &str) -> Option<String> {
    let start = json.find(key)? + key.len();
    let rest = json[start..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let inner = &rest[1..];
    let end = inner.find('"')?;
    Some(inner[..end].to_string())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn sdk_socket_path() -> PathBuf {
    let base = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    base.join(".local/share/atop/agent.sock")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_event() {
        let line = r#"{"ts":1710000000,"pid":1234,"model":"claude-3-5-sonnet","input_tokens":512,"output_tokens":1024,"latency_ms":843}"#;
        let ev = parse_event(line).unwrap();
        assert_eq!(ev.pid, 1234);
        assert_eq!(ev.model, "claude-3-5-sonnet");
        assert_eq!(ev.input_tokens, 512);
        assert_eq!(ev.output_tokens, 1024);
        assert_eq!(ev.latency_ms, 843);
    }

    #[test]
    fn parse_event_missing_optional_fields() {
        // Only pid is required; others default to 0 / empty
        let line = r#"{"pid":999}"#;
        let ev = parse_event(line).unwrap();
        assert_eq!(ev.pid, 999);
        assert_eq!(ev.model, "");
        assert_eq!(ev.input_tokens, 0);
    }

    #[test]
    fn parse_event_missing_pid_returns_none() {
        let line = r#"{"model":"gpt-4o","output_tokens":100}"#;
        assert!(parse_event(line).is_none());
    }

    #[test]
    fn extract_u64_basic() {
        assert_eq!(extract_u64(r#"{"pid":42}"#, "\"pid\":"), Some(42));
        assert_eq!(extract_u64(r#"{"x":0}"#, "\"x\":"), Some(0));
        assert_eq!(extract_u64("{}", "\"missing\":"), None);
    }

    #[test]
    fn extract_str_basic() {
        assert_eq!(
            extract_str(r#"{"model":"gpt-4"}"#, "\"model\":"),
            Some("gpt-4".to_string())
        );
        assert_eq!(extract_str(r#"{"model":123}"#, "\"model\":"), None);
    }
}
