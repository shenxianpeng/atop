use std::collections::HashMap;
use std::net::IpAddr;
use std::net::ToSocketAddrs;
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

/// Aggregated traffic metrics per (pid, domain) pair
#[derive(Default, Clone)]
pub struct ApiStats {
    /// Number of TLS ClientHellos observed (new connection handshakes)
    pub connections: u64,
    /// TLS Application Data records received from the server (proxy for API responses)
    pub rx_records: u64,
    /// Total payload bytes received from the server
    pub rx_bytes: u64,
}

/// Snapshot entry returned by NetworkCollector::snapshot()
#[derive(Clone)]
pub struct ApiCallEntry {
    pub pid: u32,
    pub domain: &'static str,
    pub stats: ApiStats,
}

#[derive(Clone)]
pub enum NetworkStatus {
    /// Capture thread is running normally
    Active,
    /// Capture failed (insufficient permissions or libpcap unavailable)
    Error(String),
}

/// Metadata for a tracked outgoing TLS connection
struct TrackedConn {
    pid: u32,
    domain: &'static str,
}

struct Inner {
    /// local_port → connection metadata (populated on ClientHello detection)
    active_conns: HashMap<u16, TrackedConn>,
    /// (pid, domain) → traffic metrics
    stats: HashMap<(u32, &'static str), ApiStats>,
    status: NetworkStatus,
}

/// Network collector: a background thread captures TLS traffic bidirectionally,
/// tracks connections via SNI, and counts incoming Application Data records.
pub struct NetworkCollector {
    inner: Arc<Mutex<Inner>>,
}

impl NetworkCollector {
    pub fn new() -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            active_conns: HashMap::new(),
            stats: HashMap::new(),
            status: NetworkStatus::Active,
        }));
        let inner_clone = Arc::clone(&inner);
        thread::Builder::new()
            .name("atop-net".into())
            .spawn(move || capture_loop(inner_clone))
            .expect("failed to spawn network capture thread");
        Self { inner }
    }

    /// Snapshot the current traffic statistics (returns a clone for the main thread)
    pub fn snapshot(&self) -> Vec<ApiCallEntry> {
        let guard = self.inner.lock().unwrap();
        guard
            .stats
            .iter()
            .map(|((pid, domain), stats)| ApiCallEntry {
                pid: *pid,
                domain,
                stats: stats.clone(),
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

    // Capture both outgoing (dst 443) and incoming (src 443) TCP traffic
    if let Err(e) = cap.filter("tcp port 443", true) {
        set_error(&inner, &format!("pcap filter error: {e}"));
        return;
    }

    let link = cap.get_datalink();
    let mut port_pid: HashMap<u16, u32> = HashMap::new();
    // ai_ips: resolved IP addresses for known AI API domains
    let mut ai_ips: HashMap<IpAddr, &'static str> = HashMap::new();
    // Force an immediate refresh on first run
    let mut last_lsof = Instant::now() - Duration::from_secs(5);
    let mut last_dns  = Instant::now() - Duration::from_secs(35);

    loop {
        // Re-resolve AI domain IPs every 30 s (handles CDN IP rotation)
        if last_dns.elapsed() >= Duration::from_secs(30) {
            ai_ips = resolve_ai_domain_ips();
            last_dns = Instant::now();
        }

        // Refresh the port→PID cache once per second; also sweep stale connections
        // and bootstrap active_conns for pre-existing connections to AI APIs
        if last_lsof.elapsed() >= Duration::from_secs(1) {
            let entries = build_lsof_entries();

            // Rebuild port→pid lookup
            port_pid = entries.iter().map(|e| (e.local_port, e.pid)).collect();

            if let Ok(mut g) = inner.lock() {
                // Evict connections whose local port is no longer in the lsof map
                g.active_conns.retain(|port, _| port_pid.contains_key(port));

                // Bootstrap: for ESTABLISHED connections to known AI API IPs,
                // insert into active_conns without overwriting live SNI-detected entries
                for entry in &entries {
                    if let Some(remote_ip) = entry.remote_ip {
                        if let Some(&domain) = ai_ips.get(&remote_ip) {
                            g.active_conns
                                .entry(entry.local_port)
                                .or_insert(TrackedConn { pid: entry.pid, domain });
                        }
                    }
                }
            }

            last_lsof = Instant::now();
        }

        match cap.next_packet() {
            Ok(packet) => {
                let Some(info) = extract_tcp_info(packet.data, link) else { continue };

                let is_outgoing = info.dst_port == 443;
                let is_incoming = info.src_port == 443;

                // local_port from the perspective of the monitored process
                let local_port = if is_outgoing { info.src_port } else { info.dst_port };

                // FIN (0x01) or RST (0x04): remove from active tracking (keep historical stats)
                if info.flags & 0x05 != 0 {
                    if let Ok(mut g) = inner.lock() {
                        g.active_conns.remove(&local_port);
                    }
                    continue;
                }

                if is_outgoing {
                    // Detect new TLS connections via ClientHello SNI
                    if let Some(sni) = extract_tls_sni(info.payload) {
                        if let Some(&domain) =
                            AI_DOMAINS.iter().find(|&&d| sni.eq_ignore_ascii_case(d))
                        {
                            let pid = port_pid.get(&local_port).copied().unwrap_or(0);
                            let mut g = inner.lock().unwrap();
                            g.active_conns.insert(local_port, TrackedConn { pid, domain });
                            g.stats.entry((pid, domain)).or_default().connections += 1;
                        }
                    }
                } else if is_incoming {
                    // Count TLS Application Data records arriving from the AI server
                    let payload = info.payload;
                    if payload.len() >= 5 && payload[0] == 0x17 {
                        let record_len =
                            u16::from_be_bytes([payload[3], payload[4]]) as u64;
                        if let Ok(mut g) = inner.lock() {
                            if let Some(conn) = g.active_conns.get(&local_port) {
                                let pid = conn.pid;
                                let domain = conn.domain;
                                let e = g.stats.entry((pid, domain)).or_default();
                                e.rx_records += 1;
                                e.rx_bytes += record_len;
                            }
                        }
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

/// A single ESTABLISHED TCP connection as reported by lsof
struct LsofEntry {
    local_port: u16,
    pid: u32,
    /// Remote IP address (None if parsing failed or address is a hostname)
    remote_ip: Option<IpAddr>,
}

/// Parse `lsof -nP -iTCP -sTCP:ESTABLISHED` output into a list of connection entries.
/// Called infrequently (once per second), so subprocess overhead is acceptable.
fn build_lsof_entries() -> Vec<LsofEntry> {
    let mut entries = Vec::new();
    let output = match std::process::Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:ESTABLISHED"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return entries,
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

        // Split into local and remote parts at "->"
        let mut halves = name.splitn(2, "->");
        let local  = halves.next().unwrap_or("");
        let remote = halves.next().unwrap_or("");

        // Take the local endpoint before "->", then extract the port after the last ":"
        let local_port: u16 = match local.rsplit(':').next().and_then(|p| p.parse().ok()) {
            Some(p) => p,
            None => continue,
        };

        // Extract remote IP: everything before the last ":" in the remote half.
        // Handles IPv4 (18.209.60.130:443) and IPv6 ([::1]:443).
        let remote_ip = remote.rsplit_once(':').and_then(|(ip_part, _)| {
            let ip_str = ip_part.trim_matches(|c: char| c == '[' || c == ']');
            ip_str.parse::<IpAddr>().ok()
        });

        entries.push(LsofEntry { local_port, pid, remote_ip });
    }
    entries
}

// ─── DNS resolution for AI API domains ───────────────────────────────────────

/// Resolve all AI API domain names to their current IP addresses.
/// Returns a map from IP → domain name for use in connection bootstrapping.
/// This is called every 30 s to handle CDN IP rotation.
fn resolve_ai_domain_ips() -> HashMap<IpAddr, &'static str> {
    let mut map = HashMap::new();
    for &domain in AI_DOMAINS {
        if let Ok(addrs) = format!("{domain}:443").to_socket_addrs() {
            for sa in addrs {
                map.insert(sa.ip(), domain);
            }
        }
    }
    map
}

// ─── Raw packet parsing ───────────────────────────────────────────────────────

/// Parsed TCP packet info extracted from a raw pcap frame
struct TcpInfo<'a> {
    src_port: u16,
    dst_port: u16,
    /// TCP flags byte (offset 13 of the TCP header)
    flags: u8,
    /// TCP payload (may be empty for pure ACKs)
    payload: &'a [u8],
}

/// Strip link-layer and IP headers from a raw pcap frame and return TCP metadata.
/// Supports DLT_EN10MB (1) and BSD loopback (0/108).
fn extract_tcp_info<'a>(data: &'a [u8], link: Linktype) -> Option<TcpInfo<'a>> {
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
    if tcp.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if tcp.len() < data_offset {
        return None;
    }

    Some(TcpInfo { src_port, dst_port, flags, payload: &tcp[data_offset..] })
}

/// Extract the SNI hostname from a TLS ClientHello record.
fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    // TLS record layer: content_type(1) version(2) length(2)
    if payload.len() < 5 {
        return None;
    }
    if payload[0] != 0x16 {
        return None; // not a Handshake record
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len {
        return None;
    }

    // Handshake layer: type(1) length(3) body
    let hs = &payload[5..5 + record_len];
    if hs.len() < 4 || hs[0] != 0x01 {
        return None; // not a ClientHello
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

    #[test]
    fn application_data_record_detected() {
        // Minimal TLS Application Data record (content_type 0x17)
        let mut record = vec![0x17u8, 0x03, 0x03]; // type + version
        let payload_len = 20u16;
        record.extend_from_slice(&payload_len.to_be_bytes());
        record.extend_from_slice(&vec![0xabu8; payload_len as usize]); // fake encrypted data

        // Should NOT be parsed as a ClientHello
        assert!(extract_tls_sni(&record).is_none());
        // But the content_type check should work
        assert_eq!(record[0], 0x17);
        assert!(record.len() >= 5);
        let detected_len = u16::from_be_bytes([record[3], record[4]]);
        assert_eq!(detected_len, payload_len);
    }
}
