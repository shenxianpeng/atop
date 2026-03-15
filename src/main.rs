mod agents;
mod app;
mod collectors;
mod storage;
mod verifiers;
mod view;

use std::{io, time::Duration};

use app::App;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend, widgets::TableState};

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run(&mut terminal);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    let mut app = App::new();
    let mut table_state = TableState::default();
    table_state.select(Some(0));

    loop {
        app.tick();
        terminal.draw(|f| view::draw(f, &app, &mut table_state))?;

        // Poll for events every 250ms to keep UI responsive and handle periodic refresh
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Down => {
                        let next = table_state
                            .selected()
                            .map(|i| (i + 1).min(app.processes.len().saturating_sub(1)))
                            .unwrap_or(0);
                        table_state.select(Some(next));
                    }
                    KeyCode::Up => {
                        let prev = table_state
                            .selected()
                            .map(|i| i.saturating_sub(1))
                            .unwrap_or(0);
                        table_state.select(Some(prev));
                    }
                    KeyCode::F(5) => app.refresh(),
                    KeyCode::F(6) => {
                        app.cycle_sort();
                        // Clamp selection after sort to avoid out-of-bounds
                        if let Some(i) = table_state.selected() {
                            let clamped = i.min(app.processes.len().saturating_sub(1));
                            table_state.select(Some(clamped));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
