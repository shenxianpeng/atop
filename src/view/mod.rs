use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::app::{App, SortKey};
use crate::collectors::network::NetworkStatus;

pub fn draw(frame: &mut Frame, app: &App, table_state: &mut TableState) {
    let area = frame.area();

    // Top-level: summary bar + process table (flex) + network panel + status bar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // summary
            Constraint::Min(0),     // process table
            Constraint::Length(6),  // API call panel
            Constraint::Length(1),  // status bar
        ])
        .split(area);

    draw_summary(frame, app, chunks[0]);
    draw_process_table(frame, app, table_state, chunks[1]);
    draw_network_panel(frame, app, chunks[2]);
    draw_status_bar(frame, chunks[3]);
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
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .margin(0)
        .split(inner);

    // CPU gauge
    let cpu_color = if app.cpu_percent > 80.0 {
        Color::Red
    } else if app.cpu_percent > 50.0 {
        Color::Yellow
    } else {
        Color::Green
    };
    let cpu_gauge = Gauge::default()
        .label(format!("CPU  {:5.1}%", app.cpu_percent))
        .ratio(app.cpu_percent / 100.0)
        .gauge_style(Style::default().fg(cpu_color));
    frame.render_widget(cpu_gauge, rows[0]);

    // Memory gauge
    let mem_ratio = app.mem_used_mb as f64 / app.mem_total_mb.max(1) as f64;
    let mem_color = if mem_ratio > 0.8 {
        Color::Red
    } else if mem_ratio > 0.5 {
        Color::Yellow
    } else {
        Color::Blue
    };
    let mem_gauge = Gauge::default()
        .label(format!(
            "MEM  {:5.1}%  {}/{}MB",
            mem_ratio * 100.0,
            app.mem_used_mb,
            app.mem_total_mb
        ))
        .ratio(mem_ratio)
        .gauge_style(Style::default().fg(mem_color));
    frame.render_widget(mem_gauge, rows[1]);
}

fn draw_process_table(
    frame: &mut Frame,
    app: &App,
    table_state: &mut TableState,
    area: ratatui::layout::Rect,
) {
    let cpu_label = if app.sort_key == SortKey::Cpu { "CPU% ▼" } else { "CPU%" };
    let mem_label = if app.sort_key == SortKey::Mem { "MEM(MB) ▼" } else { "MEM(MB)" };
    let col_labels = ["PID", "NAME", "AGENT", cpu_label, mem_label, "UPTIME"];
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
                Cell::from(p.uptime.as_str()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Min(20),
            Constraint::Length(16),
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(10),
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
        NetworkStatus::Active => " API Calls (pcap active) ",
        NetworkStatus::Error(_) => " API Calls (no capture) ",
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
                format!("{:<7} {:<16} {:<35} {:>8}", "PID", "AGENT", "DOMAIN", "REQUESTS"),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
        ]));
        // One row per (pid, domain); show at most inner.height-1 rows
        let max_rows = inner.height.saturating_sub(1) as usize;
        for entry in app.network_entries.iter().take(max_rows) {
            lines.push(Line::from(vec![Span::styled(
                format!(
                    "{:<7} {:<16} {:<35} {:>8}",
                    entry.pid,
                    truncate(&entry.agent_name, 16),
                    entry.domain,
                    entry.request_count,
                ),
                Style::default().fg(Color::Cyan),
            )]));
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

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        format!("{}…", &s[..s.char_indices().nth(max_chars - 1).map(|(i, _)| i).unwrap_or(s.len())])
    }
}
