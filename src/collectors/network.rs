use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::thread;

use pcap::Linktype;

/// List of AI API domains to monitor (identified via TLS SNI)
const AI_DOMAINS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "api.cohere.com",
    "api.mistral.ai",
    "generativelanguage.googleapis.com",
];

/// API call statistics per (pid, domain) pair
#[derive(Clone)]
pub struct ApiCallEntry {
    pub pid: u32,
    pub domain: &'static str,
    pub request_count: u64,
}

#[derive(Clone)]
pub enum NetworkStatus {
    /// Capture thread is running normally
    Active,
    /// Capture failed (insufficient permissions or libpcap unavailable)
    Error(String),
}

struct Inner {
    /// (pid, domain) → request count
    entries: HashMap<(u32, &'static str), u64>,
    status: NetworkStatus,
}

/// Network collector: a background thread captures TLS ClientHellos, extracts SNI, and correlates with processes.
pub struct NetworkCollector {
    inner: Arc<Mutex<Inner>>,
}

impl NetworkCollector {
    pub fn new() -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            entries: HashMap::new(),
            status: NetworkStatus::Active,
        }));
        let inner_clone = Arc::clone(&inner);
        thread::Builder::new()
            .name("atop-net".into())
            .spawn(move || capture_loop(inner_clone))
            .expect("failed to spawn network capture thread");
        Self { inner }
    }

    /// Snapshot the current API call statistics (returns a clone for the main thread)
    pub fn snapshot(&self) -> Vec<ApiCallEntry> {
        let guard = self.inner.lock().unwrap();
        guard
            .entries
            .iter()
            .map(|((pid, domain), count)| ApiCallEntry {
                pid: *pid,
                domain,
                request_count: *count,
            })
            .collect()
    }

    pub fn status(&self) -> NetworkStatus {
        self.inner.lock().unwrap().status.clone()
    }
}

// ─── Background capture thread ───────────────────────────────────────────────

fn capture_loop(inner: Arc<Mutex<Inner>>) {
    let device = match pcap::Device::lookup() {
        Ok(Some(d)) => d,
        Ok(None) => {
            set_error(&inner, "no network device found");
            return;
        }
        Err(e) => {
            set_error(&inner, &format!("device lookup failed: {e}"));
            return;
        }
    };

    let mut cap = match pcap::Capture::from_device(device)
        .and_then(|c| c.immediate_mode(true).timeout(200).open())
    {
        Ok(c) => c,
        Err(e) => {
            set_error(&inner, &format!("pcap open failed (need root/BPF?): {e}"));
            return;
        }
    };

    if let Err(e) = cap.filter("tcp dst port 443", true) {
        set_error(&inner, &format!("pcap filter error: {e}"));
        return;
    }

    let link = cap.get_datalink();
    let mut port_pid: HashMap<u16, u32> = HashMap::new();
    // Force an immediate refresh on first run
    let mut last_lsof = Instant::now() - Duration::from_secs(5);

    loop {
        // Refresh the port→PID cache once per second
        if last_lsof.elapsed() >= Duration::from_secs(1) {
            port_pid = build_port_pid_map();
            last_lsof = Instant::now();
        }

        match cap.next_packet() {
            Ok(packet) => {
                if let Some((src_port, sni)) = parse_sni(packet.data, link) {
                    // sni is a String; check whether it matches a known AI API domain
                    if let Some(&domain) =
                        AI_DOMAINS.iter().find(|&&d| sni.eq_ignore_ascii_case(d))
                    {
                        let pid = port_pid.get(&src_port).copied().unwrap_or(0);
                        let mut g = inner.lock().unwrap();
                        *g.entries.entry((pid, domain)).or_insert(0) += 1;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                set_error(&inner, &format!("capture error: {e}"));
                return;
            }
        }
    }
}

fn set_error(inner: &Arc<Mutex<Inner>>, msg: &str) {
    if let Ok(mut g) = inner.lock() {
        g.status = NetworkStatus::Error(msg.to_string());
    }
}

// ─── port→PID mapping (via lsof) ─────────────────────────────────────────────

/// Build a local-port → PID map using `lsof -nP -iTCP -sTCP:ESTABLISHED`.
/// Called infrequently (once per second), so subprocess overhead is acceptable.
fn build_port_pid_map() -> HashMap<u16, u32> {
    let mut map = HashMap::new();
    let output = match std::process::Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:ESTABLISHED"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return map,
    };

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines().skip(1) {
        // Columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        // NAME looks like: 192.168.1.1:54321->18.209.60.130:443
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 9 {
            continue;
        }
        let pid: u32 = match cols[1].parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let name = cols[8];
        // Take the local endpoint before "->", then extract the port after the last ":"
        if let Some(local) = name.split("->").next() {
            if let Some(port_str) = local.rsplit(':').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    map.insert(port, pid);
                }
            }
        }
    }
    map
}

// ─── Raw packet parsing ───────────────────────────────────────────────────────

/// Extract (TCP source port, TLS SNI) from a raw pcap frame.
fn parse_sni(data: &[u8], link: Linktype) -> Option<(u16, String)> {
    let (src_port, payload) = extract_tcp_payload(data, link)?;
    let sni = extract_tls_sni(payload)?;
    Some((src_port, sni))
}

/// Strip the link-layer and IP headers and return (TCP source port, TCP payload).
/// Supports DLT_EN10MB (1) and BSD loopback (0/108).
fn extract_tcp_payload(data: &[u8], link: Linktype) -> Option<(u16, &[u8])> {
    // Strip the link layer to get IPv4 data
    let ip = match link.0 {
        1 => {
            // Ethernet: 14-byte header
            if data.len() < 14 {
                return None;
            }
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            if ethertype != 0x0800 {
                return None; // IPv4 only
            }
            &data[14..]
        }
        0 | 108 => {
            // BSD loopback: 4-byte family prefix
            if data.len() < 4 {
                return None;
            }
            &data[4..]
        }
        _ => return None,
    };

    // Parse IPv4 header
    if ip.len() < 20 {
        return None;
    }
    if (ip[0] >> 4) != 4 {
        return None; // IPv4 only
    }
    if ip[9] != 6 {
        return None; // TCP only
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ip.len() < ihl + 20 {
        return None;
    }

    // Parse TCP header
    let tcp = &ip[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if tcp.len() < data_offset {
        return None;
    }

    Some((src_port, &tcp[data_offset..]))
}

/// 从 TLS ClientHello 中提取 SNI（server_name 扩展）。
fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    // TLS 记录层：content_type(1) version(2) length(2)
    if payload.len() < 5 {
        return None;
    }
    if payload[0] != 0x16 {
        return None; // Handshake
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len {
        return None;
    }

    // 握手层：type(1) length(3) body
    let hs = &payload[5..5 + record_len];
    if hs.len() < 4 || hs[0] != 0x01 {
        return None; // ClientHello
    }
    let body_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
    if hs.len() < 4 + body_len {
        return None;
    }
    let body = &hs[4..4 + body_len];

    // ClientHello layout:
    //   client_version(2) + random(32) + session_id_len(1) + session_id
    //   + cipher_suites_len(2) + cipher_suites
    //   + compression_methods_len(1) + compression_methods
    //   + extensions_len(2) + extensions
    let mut pos = 0usize;
    if body.len() < 2 + 32 + 1 {
        return None;
    }
    pos += 2 + 32; // skip client_version + random

    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;

    if body.len() < pos + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if body.len() < pos + 1 {
        return None;
    }
    let cm_len = body[pos] as usize;
    pos += 1 + cm_len;

    // Extension list
    if body.len() < pos + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(body.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension: list_len(2) entry_type(1) name_len(2) name
            if body.len() < pos + 5 {
                return None;
            }
            let name_len = u16::from_be_bytes([body[pos + 3], body[pos + 4]]) as usize;
            pos += 5;
            if body.len() < pos + name_len {
                return None;
            }
            return String::from_utf8(body[pos..pos + name_len].to_vec()).ok();
        }

        if pos + ext_len > ext_end {
            break;
        }
        pos += ext_len;
    }
    None
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid TLS ClientHello packet with an SNI extension
    fn make_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let name_len = sni_bytes.len() as u16;
        // SNI extension value: list_len(2) + entry_type(1) + name_len(2) + name
        let sni_ext_value_len = 2 + 1 + 2 + sni_bytes.len();
        // Extension: type(2) + ext_len(2) + value
        let ext_len = sni_ext_value_len as u16;

        // extensions block
        let mut exts: Vec<u8> = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type: SNI
        exts.extend_from_slice(&ext_len.to_be_bytes());
        let list_len = (1 + 2 + sni_bytes.len()) as u16;
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.push(0x00); // entry type: host_name
        exts.extend_from_slice(&name_len.to_be_bytes());
        exts.extend_from_slice(sni_bytes);

        // ClientHello body
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version: TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id_len = 0
        body.extend_from_slice(&0x0002u16.to_be_bytes()); // cipher_suites_len = 2
        body.extend_from_slice(&[0xc0, 0x2b]); // one cipher suite
        body.push(0x01); // compression_methods_len = 1
        body.push(0x00); // no compression
        let ext_total = exts.len() as u16;
        body.extend_from_slice(&ext_total.to_be_bytes());
        body.extend_from_slice(&exts);

        // Handshake header: type(1) + length(3)
        let hs_len = body.len() as u32;
        let mut hs: Vec<u8> = Vec::new();
        hs.push(0x01); // ClientHello
        hs.push(((hs_len >> 16) & 0xff) as u8);
        hs.push(((hs_len >> 8) & 0xff) as u8);
        hs.push((hs_len & 0xff) as u8);
        hs.extend_from_slice(&body);

        // TLS record: content_type(1) + version(2) + length(2) + handshake
        let rec_len = hs.len() as u16;
        let mut rec: Vec<u8> = Vec::new();
        rec.push(0x16); // Handshake
        rec.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        rec.extend_from_slice(&rec_len.to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extract_sni_from_client_hello() {
        let payload = make_client_hello("api.anthropic.com");
        let sni = extract_tls_sni(&payload).unwrap();
        assert_eq!(sni, "api.anthropic.com");
    }

    #[test]
    fn non_tls_returns_none() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(extract_tls_sni(payload).is_none());
    }

    #[test]
    fn truncated_returns_none() {
        let full = make_client_hello("api.openai.com");
        assert!(extract_tls_sni(&full[..5]).is_none());
    }
}
