use std::time::{Duration, Instant};

use sysinfo::System;

use crate::collectors::gpu::{self, GpuStats};
use crate::collectors::network::{ApiCallEntry, NetworkCollector, NetworkStatus};
use crate::collectors::process::{self, ProcessSnapshot, format_uptime};
use crate::storage::RingBuffer;

/// One frame of system-wide metrics pushed into the history ring buffer each refresh
pub struct SystemSnapshot {
    pub cpu_percent: f64,
    pub mem_ratio: f64,
}

/// Sort key for the process table
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Cpu,
    Mem,
}

impl SortKey {
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            SortKey::Cpu => "CPU%",
            SortKey::Mem => "MEM",
        }
    }

    pub fn next(self) -> Self {
        match self {
            SortKey::Cpu => SortKey::Mem,
            SortKey::Mem => SortKey::Cpu,
        }
    }
}

/// Process entry for rendering (already filtered by the verifier)
pub struct ProcessEntry {
    pub pid: u32,
    pub name: String,
    pub agent_type: Option<&'static str>,
    pub is_agent: bool,
    pub cpu_percent: f64,
    pub mem_mb: u64,
    /// Disk read rate in KB/s (delta since last sysinfo refresh ÷ 1 s interval)
    pub disk_read_kb_s: u64,
    /// Disk write rate in KB/s
    pub disk_written_kb_s: u64,
    pub uptime: String,
}

impl From<&ProcessSnapshot> for ProcessEntry {
    fn from(s: &ProcessSnapshot) -> Self {
        Self {
            pid: s.pid,
            name: s.name.clone(),
            agent_type: s.agent_type,
            is_agent: s.is_agent,
            cpu_percent: s.cpu_percent,
            mem_mb: s.memory_bytes / 1024 / 1024,
            disk_read_kb_s: s.disk_read_bytes / 1024,
            disk_written_kb_s: s.disk_written_bytes / 1024,
            uptime: format_uptime(s.run_time_secs),
        }
    }
}

/// API traffic entry for rendering (includes the agent name)
pub struct NetworkEntry {
    pub pid: u32,
    pub agent_name: String,
    pub domain: &'static str,
    /// Number of TLS connections established (ClientHellos)
    pub connections: u64,
    /// TLS Application Data records received from server (proxy for API responses)
    pub rx_records: u64,
    /// Total bytes received from server (used for token/cost estimation and future latency tracking)
    #[allow(dead_code)]
    pub rx_bytes: u64,
    /// Estimated output tokens (rx_bytes / 4 — rough approximation)
    pub est_tokens: u64,
    /// Estimated cost in USD based on domain pricing
    pub est_cost_usd: f64,
    /// Last measured API response latency in milliseconds (0 = not yet measured)
    pub last_latency_ms: u64,
    /// Requests per minute over the last 60-second window (0.0 = not yet computed)
    pub rpm: f64,
}

/// Approximate output token price per 1 000 tokens for each AI API domain.
fn price_per_1k(domain: &str) -> f64 {
    match domain {
        "api.anthropic.com"              => 0.015, // claude-sonnet approximate
        "api.openai.com"                 => 0.010, // gpt-4o approximate
        "generativelanguage.googleapis.com" => 0.007, // gemini-1.5-pro approximate
        _                                => 0.010,
    }
}

/// Global application state
pub struct App {
    pub cpu_percent: f64,
    /// Per-core CPU usage percentages (0–100 each)
    pub cpu_cores: Vec<f32>,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
    pub swap_used_mb: u64,
    pub swap_total_mb: u64,
    /// System load averages: (1 min, 5 min, 15 min)
    pub load_avg: (f64, f64, f64),
    pub processes: Vec<ProcessEntry>,
    pub sort_key: SortKey,
    pub refresh_interval: Duration,
    pub network_entries: Vec<NetworkEntry>,
    pub network_status: NetworkStatus,
    /// Most recent GPU stats (None if not available on this platform/machine)
    pub gpu: Option<GpuStats>,
    /// Historical snapshots for sparkline rendering (last 60 samples ≈ 1 minute @1 fps)
    pub history: RingBuffer<SystemSnapshot>,
    last_refresh: Instant,
    sys: System,
    net: NetworkCollector,
}

impl App {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        let mut app = Self {
            cpu_percent: 0.0,
            cpu_cores: Vec::new(),
            mem_used_mb: 0,
            mem_total_mb: 0,
            swap_used_mb: 0,
            swap_total_mb: 0,
            load_avg: (0.0, 0.0, 0.0),
            processes: Vec::new(),
            sort_key: SortKey::Cpu,
            refresh_interval: Duration::from_secs(1),
            network_entries: Vec::new(),
            network_status: NetworkStatus::Active,
            gpu: None,
            history: RingBuffer::new(60),
            last_refresh: Instant::now(),
            sys,
            net: NetworkCollector::new(),
        };
        app.do_refresh();
        app
    }

    /// Auto-refresh if more than `refresh_interval` has elapsed since the last refresh
    pub fn tick(&mut self) {
        if self.last_refresh.elapsed() >= self.refresh_interval {
            self.do_refresh();
        }
    }

    /// Manually trigger an immediate refresh (F5)
    pub fn refresh(&mut self) {
        self.do_refresh();
    }

    pub fn cycle_sort(&mut self) {
        self.sort_key = self.sort_key.next();
        self.sort_processes();
    }

    fn do_refresh(&mut self) {
        self.sys.refresh_all();
        self.cpu_percent = self.sys.global_cpu_usage() as f64;
        self.cpu_cores = self.sys.cpus().iter().map(|c| c.cpu_usage()).collect();
        self.mem_used_mb = self.sys.used_memory() / 1024 / 1024;
        self.mem_total_mb = self.sys.total_memory() / 1024 / 1024;
        self.swap_used_mb = self.sys.used_swap() / 1024 / 1024;
        self.swap_total_mb = self.sys.total_swap() / 1024 / 1024;
        let la = sysinfo::System::load_average();
        self.load_avg = (la.one, la.five, la.fifteen);

        let snapshots = process::collect(&self.sys);
        self.processes = snapshots.iter().map(ProcessEntry::from).collect();
        self.sort_processes();

        // Enrich ApiCallEntry into NetworkEntry (attach the agent name)
        let pid_to_agent: std::collections::HashMap<u32, &str> = self
            .processes
            .iter()
            .filter_map(|p| p.agent_type.map(|a| (p.pid, a)))
            .collect();

        self.network_entries = self
            .net
            .snapshot()
            .into_iter()
            .map(|e: ApiCallEntry| {
                let agent_name = pid_to_agent
                    .get(&e.pid)
                    .copied()
                    .or_else(|| {
                        // pid=0 means the process could not be associated; try guessing from agent rules
                        None
                    })
                    .unwrap_or(if e.pid == 0 { "unknown" } else { "other" })
                    .to_string();
                let est_tokens = e.stats.rx_bytes / 4;
                let est_cost_usd = (est_tokens as f64 / 1000.0) * price_per_1k(e.domain);
                NetworkEntry {
                    pid: e.pid,
                    agent_name,
                    domain: e.domain,
                    connections: e.stats.connections,
                    rx_records: e.stats.rx_records,
                    rx_bytes: e.stats.rx_bytes,
                    est_tokens,
                    est_cost_usd,
                    last_latency_ms: e.stats.last_latency_ms,
                    rpm: e.stats.rpm,
                }
            })
            .collect();
        // Sort by rx_records descending (most active connections first)
        self.network_entries.sort_by(|a, b| b.rx_records.cmp(&a.rx_records));

        self.network_status = self.net.status();

        // GPU stats (best-effort; runs a subprocess so only do this every ~2 s)
        // We call it on every refresh (1 s interval); the subprocess is fast on most systems.
        self.gpu = gpu::collect();

        // Record history snapshot for sparkline rendering
        let mem_ratio = self.mem_used_mb as f64 / self.mem_total_mb.max(1) as f64;
        self.history.push(SystemSnapshot { cpu_percent: self.cpu_percent, mem_ratio });

        self.last_refresh = Instant::now();
    }

    fn sort_processes(&mut self) {
        match self.sort_key {
            SortKey::Cpu => self.processes.sort_by(|a, b| {
                b.cpu_percent
                    .partial_cmp(&a.cpu_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            SortKey::Mem => self.processes.sort_by(|a, b| b.mem_mb.cmp(&a.mem_mb)),
        }
    }
}

