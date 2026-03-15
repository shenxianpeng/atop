use std::sync::atomic::{AtomicU64, Ordering};

use sysinfo::System;

use crate::agents;
use crate::verifiers::{VerificationResult, Verifiable};

/// Global monotonically increasing snapshot ID, used as the index for `Verifiable::snapshot_id()`
static SNAPSHOT_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Raw process snapshot from a single collection pass
pub struct ProcessSnapshot {
    pub pid: u32,
    pub name: String,
    pub agent_type: Option<&'static str>,
    pub is_agent: bool,
    /// CPU usage as reported by sysinfo (per-core percentage; max = 100 * cpu_count on multi-core machines)
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub run_time_secs: u64,
    /// Bytes read from disk since the last sysinfo refresh (delta, not cumulative)
    pub disk_read_bytes: u64,
    /// Bytes written to disk since the last sysinfo refresh (delta, not cumulative)
    pub disk_written_bytes: u64,
    // Verification context injected at collection time to avoid global-state access in verify()
    pub cpu_core_count: usize,
    pub total_memory_bytes: u64,
    id: u64,
}

impl ProcessSnapshot {
    fn new(
        pid: u32,
        name: String,
        cpu_percent: f64,
        memory_bytes: u64,
        run_time_secs: u64,
        disk_read_bytes: u64,
        disk_written_bytes: u64,
        cpu_core_count: usize,
        total_memory_bytes: u64,
    ) -> Self {
        let agent_type = agents::identify(&name);
        Self {
            pid,
            is_agent: agent_type.is_some(),
            agent_type,
            name,
            cpu_percent,
            memory_bytes,
            run_time_secs,
            disk_read_bytes,
            disk_written_bytes,
            cpu_core_count,
            total_memory_bytes,
            id: SNAPSHOT_COUNTER.fetch_add(1, Ordering::Relaxed),
        }
    }
}

impl Verifiable for ProcessSnapshot {
    fn snapshot_id(&self) -> u64 {
        self.id
    }

    fn verify(&self) -> VerificationResult {
        let max_cpu = 100.0 * self.cpu_core_count as f64;

        if self.pid == 0 {
            return VerificationResult::Failed {
                reason: "pid == 0".into(),
                snapshot_id: self.id,
            };
        }
        if self.cpu_percent > max_cpu {
            return VerificationResult::Failed {
                reason: format!(
                    "cpu_percent {:.1} > max {:.1} ({} cores)",
                    self.cpu_percent, max_cpu, self.cpu_core_count
                ),
                snapshot_id: self.id,
            };
        }
        if self.memory_bytes == 0 || self.memory_bytes > self.total_memory_bytes {
            return VerificationResult::Failed {
                reason: format!(
                    "memory_bytes {} out of range (0, {}]",
                    self.memory_bytes, self.total_memory_bytes
                ),
                snapshot_id: self.id,
            };
        }
        if self.name.is_empty() {
            return VerificationResult::Failed {
                reason: "name is empty".into(),
                snapshot_id: self.id,
            };
        }
        VerificationResult::Ok { snapshot_id: self.id }
    }
}

/// Collect all processes from a sysinfo `System` and filter out invalid snapshots via the verifier.
/// Returns the list of snapshots that passed verification.
pub fn collect(sys: &System) -> Vec<ProcessSnapshot> {
    let cpu_core_count = sys.cpus().len().max(1);
    let total_memory_bytes = sys.total_memory();

    let mut snapshots: Vec<ProcessSnapshot> = sys
        .processes()
        .values()
        .map(|p| {
            let mut name = p.name().to_string_lossy().to_string();
            // Per spec: truncate name to 256 bytes
            name.truncate(256);
            let disk = p.disk_usage();
            ProcessSnapshot::new(
                p.pid().as_u32(),
                name,
                p.cpu_usage() as f64,
                p.memory(),
                p.run_time(),
                disk.read_bytes,
                disk.written_bytes,
                cpu_core_count,
                total_memory_bytes,
            )
        })
        .filter(|s| matches!(s.verify(), VerificationResult::Ok { .. }))
        .collect();

    // Stable sort: is_agent desc first, then pid asc (App re-sorts by user preference later)
    snapshots.sort_by(|a, b| {
        b.is_agent
            .cmp(&a.is_agent)
            .then_with(|| a.pid.cmp(&b.pid))
    });

    snapshots
}

/// Format a runtime in seconds as an HH:MM:SS string
pub fn format_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

#[cfg(test)]
impl ProcessSnapshot {
    fn fixture(pid: u32, name: &str, cpu: f64, mem: u64, cores: usize, total_mem: u64) -> Self {
        let agent_type = agents::identify(name);
        Self {
            pid,
            name: name.to_string(),
            is_agent: agent_type.is_some(),
            agent_type,
            cpu_percent: cpu,
            memory_bytes: mem,
            run_time_secs: 0,
            disk_read_bytes: 0,
            disk_written_bytes: 0,
            cpu_core_count: cores,
            total_memory_bytes: total_mem,
            id: 9999,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifiers::{VerificationResult, Verifiable};

    const CORES: usize = 4;
    const TOTAL_MEM: u64 = 16 * 1024 * 1024 * 1024; // 16 GB

    #[test]
    fn valid_snapshot_passes() {
        let s = ProcessSnapshot::fixture(1, "cursor", 50.0, 512 * 1024 * 1024, CORES, TOTAL_MEM);
        assert!(matches!(s.verify(), VerificationResult::Ok { .. }));
    }

    #[test]
    fn pid_zero_fails() {
        let s = ProcessSnapshot::fixture(0, "test", 1.0, 1024 * 1024, CORES, TOTAL_MEM);
        assert!(matches!(s.verify(), VerificationResult::Failed { .. }));
    }

    #[test]
    fn cpu_over_max_fails() {
        // 4 cores → max = 400.0%
        let s = ProcessSnapshot::fixture(100, "test", 9999.0, 1024 * 1024, CORES, TOTAL_MEM);
        assert!(matches!(s.verify(), VerificationResult::Failed { .. }));
    }

    #[test]
    fn memory_zero_fails() {
        let s = ProcessSnapshot::fixture(100, "test", 10.0, 0, CORES, TOTAL_MEM);
        assert!(matches!(s.verify(), VerificationResult::Failed { .. }));
    }

    #[test]
    fn memory_over_total_fails() {
        let total = 1_000_000_000u64;
        let s = ProcessSnapshot::fixture(100, "test", 10.0, total + 1, CORES, total);
        assert!(matches!(s.verify(), VerificationResult::Failed { .. }));
    }

    #[test]
    fn empty_name_fails() {
        let s = ProcessSnapshot::fixture(100, "", 10.0, 1024 * 1024, CORES, TOTAL_MEM);
        assert!(matches!(s.verify(), VerificationResult::Failed { .. }));
    }

    #[test]
    fn format_uptime_examples() {
        assert_eq!(format_uptime(0), "00:00:00");
        assert_eq!(format_uptime(3661), "01:01:01");
        assert_eq!(format_uptime(86399), "23:59:59");
    }

    #[test]
    fn agent_is_identified_in_snapshot() {
        let s = ProcessSnapshot::fixture(1, "Cursor", 10.0, 1024 * 1024, CORES, TOTAL_MEM);
        assert!(s.is_agent);
        assert_eq!(s.agent_type, Some("Cursor"));
    }
}
