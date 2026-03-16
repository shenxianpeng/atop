/// GPU usage and VRAM statistics collected from platform-specific sources.
#[derive(Clone)]
pub struct GpuStats {
    /// GPU busy percentage (0–100)
    pub utilization_pct: f64,
    /// VRAM currently allocated in MB (0 = unknown)
    pub vram_used_mb: u64,
    /// Total VRAM in MB (0 = unknown / unified memory)
    pub vram_total_mb: u64,
}

/// Attempt to collect GPU statistics. Returns None if no GPU data is available
/// on this platform or if the required tools are absent.
pub fn collect() -> Option<GpuStats> {
    collect_impl()
}

// ─── macOS ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn collect_impl() -> Option<GpuStats> {
    // ioreg -r -c IOAccelerator -d 1 prints GPU performance stats including
    // "Device Utilization %" and "Alloc video memory" for each GPU accelerator.
    let output = std::process::Command::new("ioreg")
        .args(["-r", "-c", "IOAccelerator", "-d", "1"])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    parse_ioreg(&text)
}

#[cfg(target_os = "macos")]
fn parse_ioreg(text: &str) -> Option<GpuStats> {
    let mut max_util: Option<f64> = None;
    let mut vram_used_bytes: u64 = 0;
    let mut vram_total_mb: u64 = 0;

    for line in text.lines() {
        let line = line.trim();

        // "Device Utilization %"=45
        if let Some(val) = extract_key_value(line, "\"Device Utilization %\"=") {
            let util: f64 = val.parse().ok()?;
            max_util = Some(max_util.unwrap_or(0.0_f64).max(util));
        }

        // "Alloc video memory"=1234567 (bytes)
        if let Some(val) = extract_key_value(line, "\"Alloc video memory\"=") {
            if let Ok(bytes) = val.parse::<u64>() {
                vram_used_bytes = vram_used_bytes.saturating_add(bytes);
            }
        }

        // "VRAM,totalMB" = 4096  (dedicated GPU VRAM; absent on Apple Silicon)
        // Note: ioreg uses " = " (with spaces) for top-level properties
        if let Some(val) = extract_key_value(line, "\"VRAM,totalMB\" = ") {
            if let Ok(mb) = val.parse::<u64>() {
                vram_total_mb = vram_total_mb.max(mb);
            }
        }
    }

    Some(GpuStats {
        utilization_pct: max_util.unwrap_or(0.0),
        vram_used_mb: vram_used_bytes / 1024 / 1024,
        vram_total_mb,
    })
}

/// Extract the value after a known key prefix on the same line, stopping at the
/// first non-numeric character (handles integers; negative values are not expected).
#[cfg(target_os = "macos")]
fn extract_key_value<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = line.find(prefix).map(|i| &line[i + prefix.len()..])?;
    // Take digits only (the value may be followed by a comma, brace, or space)
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    if end == 0 { None } else { Some(&rest[..end]) }
}

// ─── Linux ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn collect_impl() -> Option<GpuStats> {
    collect_nvidia().or_else(collect_amd)
}

/// NVIDIA GPU stats via nvidia-smi
#[cfg(target_os = "linux")]
fn collect_nvidia() -> Option<GpuStats> {
    let output = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=utilization.gpu,memory.used,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    // First line: "45, 4096, 8192"
    let line = text.lines().next()?;
    let mut parts = line.split(',');
    let util: f64 = parts.next()?.trim().parse().ok()?;
    let used: u64 = parts.next()?.trim().parse().ok()?;
    let total: u64 = parts.next()?.trim().parse().ok()?;

    Some(GpuStats {
        utilization_pct: util,
        vram_used_mb: used,
        vram_total_mb: total,
    })
}

/// AMD GPU stats via sysfs (DRM)
#[cfg(target_os = "linux")]
fn collect_amd() -> Option<GpuStats> {
    let util_str = std::fs::read_to_string(
        "/sys/class/drm/card0/device/gpu_busy_percent",
    )
    .ok()?;
    let util: f64 = util_str.trim().parse().ok()?;

    let vram_used = std::fs::read_to_string(
        "/sys/class/drm/card0/device/mem_info_vram_used",
    )
    .ok()
    .and_then(|s| s.trim().parse::<u64>().ok())
    .unwrap_or(0);

    let vram_total = std::fs::read_to_string(
        "/sys/class/drm/card0/device/mem_info_vram_total",
    )
    .ok()
    .and_then(|s| s.trim().parse::<u64>().ok())
    .unwrap_or(0);

    Some(GpuStats {
        utilization_pct: util,
        vram_used_mb: vram_used / 1024 / 1024,
        vram_total_mb: vram_total / 1024 / 1024,
    })
}

/// Unsupported platforms: no GPU data available
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn collect_impl() -> Option<GpuStats> {
    None
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn parse_ioreg_typical_output() {
        let sample = concat!(
            "\"PerformanceStatistics\" = {\"Alloc system memory\"=0,",
            "\"Alloc video memory\"=52428800,\"Device Utilization %\"=12}\n",
            "\"VRAM,totalMB\" = 4096\n",
        );
        let stats = parse_ioreg(sample).unwrap();
        assert_eq!(stats.utilization_pct, 12.0);
        assert_eq!(stats.vram_used_mb, 50); // 52428800 / 1024 / 1024 = 50
        assert_eq!(stats.vram_total_mb, 4096);
    }

    #[test]
    fn parse_ioreg_no_gpu_returns_some_with_zeros() {
        // Even with no matching keys, we return Some with zeroed values
        let stats = parse_ioreg("no matching content here").unwrap();
        assert_eq!(stats.utilization_pct, 0.0);
        assert_eq!(stats.vram_used_mb, 0);
    }

    #[test]
    fn parse_ioreg_multiple_gpus_takes_max_util() {
        let sample = r#"
          "Device Utilization %"=10
          "Device Utilization %"=75
          "Device Utilization %"=30
        "#;
        let stats = parse_ioreg(sample).unwrap();
        assert_eq!(stats.utilization_pct, 75.0);
    }
}
