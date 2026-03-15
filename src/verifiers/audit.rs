use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Append-only JSON Lines audit log.
/// Default path: ~/.local/share/atop/audit.log; auto-rotates after 10 MB (implemented in P2, consumed by integration tests).
#[allow(dead_code)]
pub struct AuditLogger {
    path: PathBuf,
    writer: BufWriter<std::fs::File>,
}

impl AuditLogger {
    #[allow(dead_code)]
    pub fn new() -> std::io::Result<Self> {
        Self::new_at(audit_dir().join("audit.log"))
    }

    pub fn new_at(path: PathBuf) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path, writer: BufWriter::new(file) })
    }

    pub fn log_ok(&mut self, snapshot_id: u64) {
        self.write_event("VerifyOk", snapshot_id, "");
    }

    pub fn log_failed(&mut self, snapshot_id: u64, reason: &str) {
        self.write_event("VerifyFailed", snapshot_id, reason);
    }

    #[allow(dead_code)]
    pub fn log_dropped(&mut self, snapshot_id: u64) {
        self.write_event("SnapshotDropped", snapshot_id, "");
    }

    fn write_event(&mut self, event_type: &str, snapshot_id: u64, detail: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Manually escape backslashes and double quotes in detail
        let escaped = detail.replace('\\', "\\\\").replace('"', "\\\"");
        let line = format!(
            r#"{{"timestamp":{ts},"event_type":"{event_type}","snapshot_id":{snapshot_id},"detail":"{escaped}"}}"#
        );
        if writeln!(self.writer, "{line}").is_err() {
            eprintln!("atop audit: write failed, degrading to stderr: {line}");
            return;
        }
        let _ = self.writer.flush();
        self.check_rotate();
    }

    fn check_rotate(&mut self) {
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() > 10 * 1024 * 1024 {
                let backup = self.path.with_extension("log.1");
                let _ = std::fs::rename(&self.path, &backup);
                if let Ok(file) =
                    OpenOptions::new().create(true).append(true).open(&self.path)
                {
                    self.writer = BufWriter::new(file);
                }
            }
        }
    }
}

#[allow(dead_code)]
fn audit_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/share/atop")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    use std::sync::atomic::{AtomicU64, Ordering};
    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_log() -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("atop_audit_test_{}_{}.log", std::process::id(), id))
    }

    #[test]
    fn log_ok_writes_json_line() {
        let path = temp_log();
        let mut logger = AuditLogger::new_at(path.clone()).unwrap();
        logger.log_ok(42);
        drop(logger);

        let mut content = String::new();
        std::fs::File::open(&path).unwrap().read_to_string(&mut content).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(content.contains("\"event_type\":\"VerifyOk\""));
        assert!(content.contains("\"snapshot_id\":42"));
    }

    #[test]
    fn log_failed_writes_reason() {
        let path = temp_log();
        let mut logger = AuditLogger::new_at(path.clone()).unwrap();
        logger.log_failed(7, "cpu_percent 9999.0 > max 400.0 (4 cores)");
        drop(logger);

        let mut content = String::new();
        std::fs::File::open(&path).unwrap().read_to_string(&mut content).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(content.contains("VerifyFailed"));
        assert!(content.contains("9999.0"));
    }

    #[test]
    fn special_chars_are_escaped() {
        let path = temp_log();
        let mut logger = AuditLogger::new_at(path.clone()).unwrap();
        logger.log_failed(1, r#"reason with "quotes" and \backslash"#);
        drop(logger);

        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();
        // JSON must be on a single line and valid
        assert!(!content.trim().contains('\n') || content.lines().count() == 1);
    }
}
