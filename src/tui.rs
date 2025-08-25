//
// Copyright (c) Matt Suiche. All rights reserved.
//
// Module Name:
//  tui.rs
//
// Abstract:
//  Terminal User Interface for ELEGANTBOUNCER using ratatui
//
// Author:
//  Matt Suiche (msuiche) 23-Aug-2025
//

use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Gauge, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    io,
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}},
    time::{Duration, Instant},
    path::PathBuf,
    thread,
};
use rayon::prelude::*;

#[derive(Clone)]
pub struct TUIState {
    pub current_files: Vec<String>,  // Changed to show multiple active files
    pub files_scanned: usize,
    pub total_files: usize,
    pub threats: Vec<ThreatInfo>,
    pub start_time: Instant,
    pub scan_complete: bool,
    pub current_status: String,
    pub files_to_scan: Vec<PathBuf>,
}

#[derive(Clone)]
pub struct ThreatInfo {
    pub file_path: String,
    pub threat_type: String,
    pub cve_ids: String,
    pub timestamp: Instant,
}

pub struct App {
    pub state: Arc<Mutex<TUIState>>,
    pub should_quit: Arc<AtomicBool>,
    pub selected_tab: usize,
    pub scroll_position: usize,
}

impl App {
    pub fn new(files: Vec<PathBuf>) -> Self {
        App {
            state: Arc::new(Mutex::new(TUIState {
                current_files: Vec::new(),
                files_scanned: 0,
                total_files: files.len(),
                threats: Vec::new(),
                start_time: Instant::now(),
                scan_complete: false,
                current_status: "Initializing...".to_string(),
                files_to_scan: files,
            })),
            should_quit: Arc::new(AtomicBool::new(false)),
            selected_tab: 0,
            scroll_position: 0,
        }
    }
}

pub fn run_tui_scan(files: Vec<PathBuf>) -> Result<Vec<crate::ScanResult>, Box<dyn std::error::Error>> {
    run_tui_scan_with_origins(files, Vec::new())
}

pub fn run_tui_scan_with_origins(files: Vec<PathBuf>, origins: Vec<Option<String>>) -> Result<Vec<crate::ScanResult>, Box<dyn std::error::Error>> {
    // Setup panic handler to restore terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        original_hook(panic);
    }));
    
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = Arc::new(Mutex::new(App::new(files.clone())));
    let app_clone = Arc::clone(&app);
    let should_quit_clone = Arc::clone(&app.lock().unwrap().should_quit);
    let mut scan_results = Vec::new();

    // Start scanning in background thread with parallelization
    let origins_clone = origins.clone();
    let scan_handle = thread::spawn(move || {
        let files = files.clone();
        let results = Arc::new(Mutex::new(Vec::new()));
        let files_scanned = Arc::new(AtomicUsize::new(0));
        let active_files = Arc::new(Mutex::new(Vec::<String>::new()));
        
        // Use parallel iterator for scanning
        files.par_iter().enumerate().for_each(|(idx, file_path)| {
            // Check if we should abort
            if should_quit_clone.load(Ordering::Relaxed) {
                return;
            }
            
            let thread_id = rayon::current_thread_index().unwrap_or(0);
            
            // Use origin if available, otherwise use file name
            let display_name = if idx < origins_clone.len() {
                if let Some(ref origin) = origins_clone[idx] {
                    origin.clone()
                } else {
                    file_path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string()
                }
            } else {
                file_path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            };
            
            // Add this file to active files for this thread
            {
                let app = app_clone.lock().unwrap();
                let mut state = app.state.lock().unwrap();
                
                // Ensure we have enough slots for all threads
                while state.current_files.len() <= thread_id {
                    state.current_files.push(String::new());
                }
                
                // Update this thread's current file
                state.current_files[thread_id] = format!("[Thread {}] {}", thread_id + 1, display_name);
                state.current_status = format!("Processing {} files in parallel [{}/{}]", 
                    state.current_files.iter().filter(|s| !s.is_empty()).count(),
                    files_scanned.load(Ordering::Relaxed),
                    files.len()
                );
            }

            // Scan the file - pass original name for iOS backups
            let result = if idx < origins_clone.len() {
                if let Some(ref origin) = origins_clone[idx] {
                    // Extract filename from origin path for file type detection
                    let original_name = std::path::Path::new(origin).file_name()
                        .and_then(|n| n.to_str());
                    crate::scan_single_file_with_name(file_path, original_name)
                } else {
                    crate::scan_single_file(file_path)
                }
            } else {
                crate::scan_single_file(file_path)
            };
            
            // Check for threats and update state
            {
                let app = app_clone.lock().unwrap();
                let mut state = app.state.lock().unwrap();
                
                // Use origin for threat display if available
                let threat_display_path = if idx < origins_clone.len() {
                    if let Some(ref origin) = origins_clone[idx] {
                        origin.clone()
                    } else {
                        file_path.display().to_string()
                    }
                } else {
                    file_path.display().to_string()
                };
                
                if result.forcedentry {
                    state.threats.push(ThreatInfo {
                        file_path: threat_display_path.clone(),
                        threat_type: "FORCEDENTRY".to_string(),
                        cve_ids: "CVE-2021-30860".to_string(),
                        timestamp: Instant::now(),
                    });
                }
                if result.blastpass {
                    state.threats.push(ThreatInfo {
                        file_path: threat_display_path.clone(),
                        threat_type: "BLASTPASS".to_string(),
                        cve_ids: "CVE-2023-4863, CVE-2023-41064".to_string(),
                        timestamp: Instant::now(),
                    });
                }
                if result.triangulation {
                    state.threats.push(ThreatInfo {
                        file_path: threat_display_path.clone(),
                        threat_type: "TRIANGULATION".to_string(),
                        cve_ids: "CVE-2023-41990".to_string(),
                        timestamp: Instant::now(),
                    });
                }
                if result.cve_2025_43300 {
                    state.threats.push(ThreatInfo {
                        file_path: threat_display_path.clone(),
                        threat_type: "CVE-2025-43300".to_string(),
                        cve_ids: "CVE-2025-43300".to_string(),
                        timestamp: Instant::now(),
                    });
                }
                
                // Update files scanned count
                let count = files_scanned.fetch_add(1, Ordering::Relaxed) + 1;
                state.files_scanned = count;
            }
            
            // Store result
            {
                let mut res = results.lock().unwrap();
                res.push(result);
            }
            
            // Clear this thread's current file when done
            {
                let app = app_clone.lock().unwrap();
                let mut state = app.state.lock().unwrap();
                if thread_id < state.current_files.len() {
                    state.current_files[thread_id].clear();
                }
            }
        });
        
        // Check if aborted
        if should_quit_clone.load(Ordering::Relaxed) {
            let app = app_clone.lock().unwrap();
            let mut state = app.state.lock().unwrap();
            state.current_status = "Scan aborted by user".to_string();
        } else {
            // Mark scan as complete
            let app = app_clone.lock().unwrap();
            let mut state = app.state.lock().unwrap();
            state.scan_complete = true;
            state.current_status = "Scan Complete".to_string();
        }
        
        // Return results
        Arc::try_unwrap(results)
            .map(|mutex| mutex.into_inner().unwrap())
            .unwrap_or_else(|arc| arc.lock().unwrap().clone())
    });

    // Main UI loop
    let mut user_quit = false;
    loop {
        terminal.draw(|f| {
            let app = app.lock().unwrap();
            draw_ui(f, &app);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                let mut app = app.lock().unwrap();
                if handle_input(&mut app, key) {
                    user_quit = true;
                    app.should_quit.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
        
        // Don't auto-exit - let user review results and quit when ready
    }

    // Signal abort if user quit
    if user_quit {
        let app = app.lock().unwrap();
        app.should_quit.store(true, Ordering::Relaxed);
    }

    // Wait for scan thread to complete or timeout
    match scan_handle.join() {
        Ok(results) => scan_results = results,
        Err(_) => {
            // Thread panicked or was terminated
            scan_results = Vec::new();
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(scan_results)
}

fn handle_input(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            app.should_quit.store(true, Ordering::Relaxed);
            true
        }
        KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
            app.should_quit.store(true, Ordering::Relaxed);
            true
        }
        KeyCode::Tab => {
            app.selected_tab = (app.selected_tab + 1) % 3;
            false
        }
        KeyCode::Up => {
            if app.scroll_position > 0 {
                app.scroll_position -= 1;
            }
            false
        }
        KeyCode::Down => {
            let state = app.state.lock().unwrap();
            if app.scroll_position < state.threats.len().saturating_sub(1) {
                app.scroll_position += 1;
            }
            false
        }
        _ => false,
    }
}

fn draw_ui(f: &mut Frame, app: &App) {
    let state = app.state.lock().unwrap();
    
    // Create main layout with grid
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(20),    // Main content
            Constraint::Length(3),  // Footer
        ])
        .split(f.size());

    // Draw header
    draw_header(f, chunks[0]);

    // Split main content into grid
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),  // Left panel
            Constraint::Percentage(50),  // Right panel
        ])
        .split(chunks[1]);

    // Left panel - split into progress and current status
    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),   // Progress section
            Constraint::Min(5),      // Current file section
        ])
        .split(main_chunks[0]);

    draw_progress(f, left_chunks[0], &state);
    draw_current_scan(f, left_chunks[1], &state);

    // Right panel - split into statistics and threats
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),   // Statistics
            Constraint::Min(5),      // Threats list
        ])
        .split(main_chunks[1]);

    draw_statistics(f, right_chunks[0], &state);
    draw_threats(f, right_chunks[1], &state, app.scroll_position);

    // Draw footer
    draw_footer(f, chunks[2], &state);
}

fn draw_header(f: &mut Frame, area: Rect) {
    let header = Paragraph::new(Line::from(vec![
        Span::raw(" "),
        Span::styled("ELEGANTBOUNCER", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(" v0.2 - "),
        Span::styled("Mobile Exploit Detection", Style::default().fg(Color::Gray)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan))
    )
    .alignment(Alignment::Center);
    
    f.render_widget(header, area);
}

fn draw_progress(f: &mut Frame, area: Rect, state: &TUIState) {
    let progress_percent = if state.total_files > 0 {
        (state.files_scanned as f64 / state.total_files as f64) * 100.0
    } else {
        0.0
    };

    let block = Block::default()
        .title(" Scan Progress ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Yellow));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Length(1),
        ])
        .split(inner);

    // Progress bar
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(Color::Green).bg(Color::Black))
        .percent(progress_percent as u16)
        .label(format!("{:.1}%", progress_percent));
    f.render_widget(gauge, chunks[1]);

    // File counter
    let counter = Paragraph::new(format!("{} / {} files processed", 
        state.files_scanned, 
        state.total_files
    ))
    .alignment(Alignment::Center)
    .style(Style::default().fg(Color::White));
    f.render_widget(counter, chunks[2]);
}

fn draw_current_scan(f: &mut Frame, area: Rect, state: &TUIState) {
    let status_color = if state.scan_complete {
        Color::Green
    } else {
        Color::Yellow
    };

    let mut content = vec![
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::Gray)),
            Span::styled(&state.current_status, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Active Scans:", Style::default().fg(Color::Gray).add_modifier(Modifier::BOLD)),
        ]),
    ];
    
    // Show all active scanning threads
    let active_files: Vec<&String> = state.current_files.iter()
        .filter(|f| !f.is_empty())
        .collect();
    
    if state.scan_complete {
        content.push(Line::from(vec![
            Span::styled("  ✓ All files processed successfully", Style::default().fg(Color::Green)),
        ]));
        content.push(Line::from(""));
        content.push(Line::from(vec![
            Span::styled(format!("  Total: {} files scanned", state.files_scanned), Style::default().fg(Color::White)),
        ]));
        content.push(Line::from(vec![
            Span::styled(format!("  Threats: {} detected", state.threats.len()), 
                Style::default().fg(if state.threats.is_empty() { Color::Green } else { Color::Red })),
        ]));
    } else if active_files.is_empty() {
        content.push(Line::from(vec![
            Span::styled("  Waiting for files...", Style::default().fg(Color::DarkGray)),
        ]));
    } else {
        for file in active_files.iter().take(8) {  // Show up to 8 active threads
            content.push(Line::from(vec![
                Span::styled("  • ", Style::default().fg(Color::Cyan)),
                Span::styled(file.as_str(), Style::default().fg(Color::White)),
            ]));
        }
    }

    let paragraph = Paragraph::new(content)
        .block(
            Block::default()
                .title(" Current Activity ")
                .title_alignment(Alignment::Center)
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Blue))
        )
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw_statistics(f: &mut Frame, area: Rect, state: &TUIState) {
    let elapsed = state.start_time.elapsed();
    let scan_rate = if elapsed.as_secs() > 0 {
        state.files_scanned as f64 / elapsed.as_secs() as f64
    } else {
        0.0
    };

    let num_threads = num_cpus::get().min(8);
    
    let stats = vec![
        Line::from(vec![
            Span::styled("Parallel Threads: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{}", num_threads), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Elapsed Time: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{:02}:{:02}", elapsed.as_secs() / 60, elapsed.as_secs() % 60), 
                Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Scan Rate: ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{:.1} files/sec", scan_rate), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Threats Found: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", state.threats.len()),
                Style::default().fg(if state.threats.is_empty() { Color::Green } else { Color::Red })
                    .add_modifier(Modifier::BOLD)
            ),
        ]),
    ];

    let paragraph = Paragraph::new(stats)
        .block(
            Block::default()
                .title(" Statistics ")
                .title_alignment(Alignment::Center)
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Magenta))
        );

    f.render_widget(paragraph, area);
}

fn draw_threats(f: &mut Frame, area: Rect, state: &TUIState, scroll: usize) {
    let block = Block::default()
        .title(format!(" Threats ({}) ", state.threats.len()))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(
            if state.threats.is_empty() { Color::Green } else { Color::Red }
        ));

    if state.threats.is_empty() {
        let no_threats = Paragraph::new("No threats detected")
            .block(block)
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Green));
        f.render_widget(no_threats, area);
    } else {
        let items: Vec<ListItem> = state.threats
            .iter()
            .skip(scroll)
            .take(area.height.saturating_sub(2) as usize)
            .map(|threat| {
                let content = vec![
                    Line::from(vec![
                        Span::styled("► ", Style::default().fg(Color::Red)),
                        Span::styled(&threat.threat_type, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(vec![
                        Span::raw("  "),
                        Span::styled(&threat.file_path, Style::default().fg(Color::White)),
                    ]),
                    Line::from(vec![
                        Span::raw("  CVE: "),
                        Span::styled(&threat.cve_ids, Style::default().fg(Color::Yellow)),
                    ]),
                    Line::from(""),
                ];
                ListItem::new(content)
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .style(Style::default().fg(Color::White));

        f.render_widget(list, area);
    }
}

fn draw_footer(f: &mut Frame, area: Rect, state: &TUIState) {
    let footer_text = if state.scan_complete {
        vec![
            Span::styled("✓ Scan Complete! ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw("Review results and press "),
            Span::styled("q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" when done | "),
            Span::styled("↑↓", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" to scroll threats"),
        ]
    } else {
        vec![
            Span::styled("⟳ Scanning... ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw("Press "),
            Span::styled("q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" to abort | "),
            Span::styled("↑↓", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" to scroll"),
        ]
    };

    let footer = Paragraph::new(Line::from(footer_text))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray))
        )
        .alignment(Alignment::Center);

    f.render_widget(footer, area);
}