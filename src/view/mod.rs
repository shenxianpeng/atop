use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::storage::RingBuffer;
use crate::app::SystemSnapshot;

use crate::app::{App, SortKey};
use crate::collectors::agent_sdk::SdkStatus;
use crate::collectors::network::NetworkStatus;

pub fn draw(frame: &mut Frame, app: &App, table_state: &mut TableState) {
    let area = frame.area();

    // Top-level: summary bar + process table (flex) + network panel + sdk panel + status bar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),  // summary (CPU/MEM/load/cores/GPU)
            Constraint::Min(0),     // process table
            Constraint::Length(7),  // pcap API traffic panel
            Constraint::Length(5),  // agent SDK panel
            Constraint::Length(1),  // status bar
        ])
        .split(area);

    draw_summary(frame, app, chunks[0]);
    draw_process_table(frame, app, table_state, chunks[1]);
    draw_network_panel(frame, app, chunks[2]);
    draw_sdk_panel(frame, app, chunks[3]);
    draw_status_bar(frame, chunks[4]);
}

fn draw_summary(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let block = Block::default()
        .title(" atop — AI Agent Monitor ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .margin(0)
        .split(inner);

    // CPU gauge + history sparkline
    let cpu_color = if app.cpu_percent > 80.0 {
        Color::Red
    } else if app.cpu_percent > 50.0 {
        Color::Yellow
    } else {
        Color::Green
    };
    let cpu_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(22)])
        .split(rows[0]);
    let cpu_gauge = Gauge::default()
        .label(format!("CPU  {:5.1}%", app.cpu_percent))
        .ratio(app.cpu_percent / 100.0)
        .gauge_style(Style::default().fg(cpu_color));
    frame.render_widget(cpu_gauge, cpu_row[0]);
    let cpu_spark = history_sparkline(&app.history, |s| s.cpu_percent / 100.0, cpu_color);
    frame.render_widget(Paragraph::new(cpu_spark), cpu_row[1]);

    // Memory gauge + history sparkline
    let mem_ratio = app.mem_used_mb as f64 / app.mem_total_mb.max(1) as f64;
    let mem_color = if mem_ratio > 0.8 {
        Color::Red
    } else if mem_ratio > 0.5 {
        Color::Yellow
    } else {
        Color::Blue
    };
    let swap_label = if app.swap_total_mb > 0 {
        format!("  swap {}/{}MB", app.swap_used_mb, app.swap_total_mb)
    } else {
        String::new()
    };
    let mem_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(22)])
        .split(rows[1]);
    let mem_gauge = Gauge::default()
        .label(format!(
            "MEM  {:5.1}%  {}/{}MB{}",
            mem_ratio * 100.0,
            app.mem_used_mb,
            app.mem_total_mb,
            swap_label,
        ))
        .ratio(mem_ratio)
        .gauge_style(Style::default().fg(mem_color));
    frame.render_widget(mem_gauge, mem_row[0]);
    let mem_spark = history_sparkline(&app.history, |s| s.mem_ratio, mem_color);
    frame.render_widget(Paragraph::new(mem_spark), mem_row[1]);

    // Load average line
    let (la1, la5, la15) = app.load_avg;
    let load_color = if la1 > app.cpu_cores.len() as f64 {
        Color::Red
    } else if la1 > app.cpu_cores.len() as f64 * 0.7 {
        Color::Yellow
    } else {
        Color::Green
    };
    let load_line = ratatui::widgets::Paragraph::new(Line::from(vec![
        Span::raw("LOAD  "),
        Span::styled(
            format!("{:.2}  {:.2}  {:.2}", la1, la5, la15),
            Style::default().fg(load_color),
        ),
        Span::styled("  (1/5/15 min)", Style::default().fg(Color::DarkGray)),
    ]));
    frame.render_widget(load_line, rows[2]);

    // Per-core CPU sparkline: one Unicode block per core, colored by load
    let mut spans: Vec<Span> = vec![Span::raw("CORES ")];
    for &pct in &app.cpu_cores {
        let block = cpu_block(pct);
        let color = if pct > 80.0 {
            Color::Red
        } else if pct > 50.0 {
            Color::Yellow
        } else {
            Color::Green
        };
        spans.push(Span::styled(block, Style::default().fg(color)));
    }
    let sparkline = ratatui::widgets::Paragraph::new(Line::from(spans));
    frame.render_widget(sparkline, rows[3]);

    // GPU row (if data is available on this platform)
    if let Some(ref gpu) = app.gpu {
        let gpu_color = if gpu.utilization_pct > 80.0 {
            Color::Red
        } else if gpu.utilization_pct > 50.0 {
            Color::Yellow
        } else {
            Color::Green
        };
        let vram_label = if gpu.vram_total_mb > 0 {
            format!(
                "  VRAM {}/{}MB",
                gpu.vram_used_mb, gpu.vram_total_mb
            )
        } else if gpu.vram_used_mb > 0 {
            format!("  VRAM {}MB alloc", gpu.vram_used_mb)
        } else {
            String::new()
        };
        let gpu_line = ratatui::widgets::Paragraph::new(Line::from(vec![
            Span::raw("GPU   "),
            Span::styled(
                format!("{:5.1}%{}", gpu.utilization_pct, vram_label),
                Style::default().fg(gpu_color),
            ),
        ]));
        frame.render_widget(gpu_line, rows[4]);
    } else {
        // No GPU data: show a dim placeholder so the row isn't blank
        let placeholder = ratatui::widgets::Paragraph::new(Line::from(vec![
            Span::raw("GPU   "),
            Span::styled("n/a", Style::default().fg(Color::DarkGray)),
        ]));
        frame.render_widget(placeholder, rows[4]);
    }
}

fn draw_process_table(
    frame: &mut Frame,
    app: &App,
    table_state: &mut TableState,
    area: ratatui::layout::Rect,
) {
    let cpu_label = if app.sort_key == SortKey::Cpu { "CPU% ▼" } else { "CPU%" };
    let mem_label = if app.sort_key == SortKey::Mem { "MEM(MB) ▼" } else { "MEM(MB)" };
    let col_labels = ["PID", "NAME", "AGENT", cpu_label, mem_label, "RD_KB/s", "WR_KB/s", "UPTIME"];
    let header_cells = col_labels
        .into_iter()
        .map(|h| Cell::from(h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(0);

    let rows: Vec<Row> = app
        .processes
        .iter()
        .map(|p| {
            let agent_style = if p.is_agent {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(p.pid.to_string()),
                Cell::from(p.name.as_str()).style(agent_style),
                Cell::from(p.agent_type.unwrap_or("-")).style(agent_style),
                Cell::from(format!("{:.1}", p.cpu_percent)),
                Cell::from(p.mem_mb.to_string()),
                Cell::from(format_io(p.disk_read_kb_s)),
                Cell::from(format_io(p.disk_written_kb_s)),
                Cell::from(p.uptime.as_str()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),   // PID
            Constraint::Min(20),     // NAME
            Constraint::Length(16),  // AGENT
            Constraint::Length(7),   // CPU%
            Constraint::Length(9),   // MEM(MB)
            Constraint::Length(8),   // RD_KB/s
            Constraint::Length(8),   // WR_KB/s
            Constraint::Length(10),  // UPTIME
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Processes ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );

    frame.render_stateful_widget(table, area, table_state);
}

fn draw_network_panel(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    // Title row: show a different hint depending on capture status
    let title = match &app.network_status {
        NetworkStatus::Active => " AI API Traffic (pcap active) ",
        NetworkStatus::Error(_) => " AI API Traffic (no capture) ",
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Build display lines
    let mut lines: Vec<Line> = Vec::new();

    match &app.network_status {
        NetworkStatus::Error(msg) => {
            lines.push(Line::from(vec![
                Span::styled("  ⚠ ", Style::default().fg(Color::Yellow)),
                Span::styled(msg.as_str(), Style::default().fg(Color::DarkGray)),
            ]));
        }
        NetworkStatus::Active => {
            if app.network_entries.is_empty() {
                lines.push(Line::from(Span::styled(
                    "  Monitoring HTTPS traffic… (no AI API calls detected yet)",
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
    }

    // Header row
    if !app.network_entries.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(
                format!(
                    "{:<7} {:<16} {:<35} {:>6} {:>8} {:>8} {:>7} {:>7} {:>6}",
                    "PID", "AGENT", "DOMAIN", "CONNS", "RX_RECS", "~TOKENS", "~$COST", "LAT_MS", "RPM"
                ),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
        ]));
        // One row per (pid, domain); reserve 1 line for the estimate note
        let max_rows = inner.height.saturating_sub(3) as usize;
        for entry in app.network_entries.iter().take(max_rows) {
            let lat_str = if entry.last_latency_ms == 0 {
                "-".to_string()
            } else {
                entry.last_latency_ms.to_string()
            };
            let rpm_str = if entry.rpm < 0.05 {
                "-".to_string()
            } else {
                format!("{:.1}", entry.rpm)
            };
            lines.push(Line::from(vec![Span::styled(
                format!(
                    "{:<7} {:<16} {:<35} {:>6} {:>8} {:>8} {:>7} {:>7} {:>6}",
                    entry.pid,
                    truncate(&entry.agent_name, 16),
                    entry.domain,
                    entry.connections,
                    entry.rx_records,
                    entry.est_tokens,
                    format!("${:.4}", entry.est_cost_usd),
                    lat_str,
                    rpm_str,
                ),
                Style::default().fg(Color::Cyan),
            )]));
        }
        // Estimate note
        lines.push(Line::from(Span::styled(
            "  ~ output token estimate (rx_bytes÷4); prices approximate",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let para = Paragraph::new(lines);
    frame.render_widget(para, inner);
}

fn draw_sdk_panel(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let socket_path = match &app.sdk_status {
        SdkStatus::Listening(p) => p.display().to_string(),
        SdkStatus::Error(_) => String::new(),
    };
    let title = " Agent SDK (exact) ";
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();

    if app.sdk_entries.is_empty() {
        // Show how to connect; the socket path is shown so users know where to point their SDK
        lines.push(Line::from(Span::styled(
            "  No agents connected via SDK (pcap estimates shown above)",
            Style::default().fg(Color::DarkGray),
        )));
        if !socket_path.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("  Socket: ", Style::default().fg(Color::DarkGray)),
                Span::styled(socket_path, Style::default().fg(Color::Yellow)),
            ]));
        }
    } else {
        // Header
        lines.push(Line::from(Span::styled(
            format!(
                "{:<7} {:<30} {:>12} {:>12} {:>8}",
                "PID", "MODEL", "IN_TOKENS", "OUT_TOKENS", "LAT_MS"
            ),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )));
        let max_rows = inner.height.saturating_sub(1) as usize;
        let mut entries = app.sdk_entries.clone();
        // Sort by total output tokens descending (most active agent first)
        entries.sort_by(|a, b| b.stats.output_tokens_total.cmp(&a.stats.output_tokens_total));
        for entry in entries.iter().take(max_rows) {
            let lat_str = if entry.stats.last_latency_ms == 0 {
                "-".to_string()
            } else {
                entry.stats.last_latency_ms.to_string()
            };
            lines.push(Line::from(Span::styled(
                format!(
                    "{:<7} {:<30} {:>12} {:>12} {:>8}",
                    entry.pid,
                    truncate(&entry.stats.model, 30),
                    entry.stats.input_tokens_total,
                    entry.stats.output_tokens_total,
                    lat_str,
                ),
                Style::default().fg(Color::Green),
            )));
        }
    }

    let para = Paragraph::new(lines);
    frame.render_widget(para, inner);
}

fn draw_status_bar(frame: &mut Frame, area: ratatui::layout::Rect) {
    let spans = Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(":Quit  "),
        Span::styled("↑↓", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(":Select  "),
        Span::styled("F5", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(":Refresh  "),
        Span::styled("F6", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(":Sort"),
    ]);
    let bar = ratatui::widgets::Paragraph::new(spans)
        .style(Style::default().bg(Color::DarkGray));
    frame.render_widget(bar, area);
}

/// Map a CPU usage percentage (0–100) to a Unicode block character for sparkline display.
fn cpu_block(pct: f32) -> &'static str {
    match pct as u32 {
        0..=6   => " ",
        7..=18  => "▁",
        19..=31 => "▂",
        32..=43 => "▃",
        44..=56 => "▄",
        57..=68 => "▅",
        69..=81 => "▆",
        82..=93 => "▇",
        _       => "█",
    }
}

/// Format a KB/s disk I/O value: show "-" when zero to reduce visual noise.
fn format_io(kb_s: u64) -> String {
    if kb_s == 0 { "-".to_string() } else { kb_s.to_string() }
}

/// Render a 20-sample sparkline from the history ring buffer.
/// `extract` maps a snapshot to a ratio in [0.0, 1.0].
/// The sparkline is right-aligned (padded with spaces when fewer than 20 samples exist).
fn history_sparkline<'a>(
    history: &'a RingBuffer<SystemSnapshot>,
    extract: impl Fn(&SystemSnapshot) -> f64,
    color: Color,
) -> Line<'a> {
    const WIDTH: usize = 20;
    let samples: Vec<f64> = history.iter().map(|s| extract(s)).collect();
    let count = samples.len().min(WIDTH);
    let start = samples.len().saturating_sub(WIDTH);
    let recent = &samples[start..];

    let mut spans: Vec<Span> = Vec::new();
    // Pad left with spaces when fewer than WIDTH samples are available
    if recent.len() < WIDTH {
        spans.push(Span::raw(" ".repeat(WIDTH - recent.len())));
    }
    for &ratio in recent.iter().take(count) {
        let pct = (ratio * 100.0).clamp(0.0, 100.0) as f32;
        spans.push(Span::styled(cpu_block(pct), Style::default().fg(color)));
    }
    Line::from(spans)
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        format!("{}…", &s[..s.char_indices().nth(max_chars - 1).map(|(i, _)| i).unwrap_or(s.len())])
    }
}
