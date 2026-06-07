mod app;
mod firewall;
mod logger;
mod services;
mod ui;

use app::{ActiveScreen, App, FormField};
use firewall::{FirewallBackend, FirewallRule, RuleAction, UfwBackend, IptablesBackend, NftablesBackend};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

static TERMINAL_RESTORE: std::sync::Once = std::sync::Once::new();

fn restore_terminal() {
    TERMINAL_RESTORE.call_once(|| {
        let _ = disable_raw_mode();
        let mut stdout = std::io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, crossterm::cursor::Show);
    });
}

fn detect_backend(forced_backend: &str) -> Box<dyn FirewallBackend> {
    let ufw = UfwBackend::new();
    let nft = NftablesBackend::new();
    let ipt = IptablesBackend::new();

    match forced_backend.to_lowercase().as_str() {
        "ufw" => Box::new(ufw),
        "nftables" => Box::new(nft),
        "iptables" => Box::new(ipt),
        _ => {
            // Auto-detect priority
            if ufw.is_active() && ufw.is_enabled() {
                Box::new(ufw)
            } else if nft.is_active() && nft.is_enabled() {
                Box::new(nft)
            } else if ipt.is_active() {
                // Check if iptables is legacy vs wrapper
                if firewall::iptables::is_iptables_legacy("/sbin/iptables") {
                    Box::new(ipt)
                } else if nft.is_active() {
                    Box::new(nft) // Prefer nftables if iptables is a wrapper
                } else {
                    Box::new(ipt)
                }
            } else if ufw.is_active() {
                Box::new(ufw)
            } else if nft.is_active() {
                Box::new(nft)
            } else {
                Box::new(ipt)
            }
        }
    }
}

fn check_privileges() {
    unsafe {
        if libc::geteuid() != 0 {
            eprintln!("Error: nsmam must be run as root/sudo.");
            eprintln!("Try running: sudo nsmam");
            std::process::exit(1);
        }
    }
}

fn is_multiplexer_active() -> bool {
    std::env::var("TMUX").is_ok()
        || std::env::var("STY").is_ok()
        || std::env::var("TERM")
            .map(|t| t.starts_with("screen") || t.starts_with("tmux"))
            .unwrap_or(false)
}

fn main() -> Result<(), anyhow::Error> {
    // 1. Root Privilege check
    check_privileges();

    // 2. Multiplexer check
    let multiplexer_detected = is_multiplexer_active();

    // 3. Load configuration
    let config_path = "/etc/nsmam/config.toml";
    let mut app = App::new(config_path, multiplexer_detected);

    // 4. Initialize firewall backend
    let backend = detect_backend(&app.config.backend);
    if let Err(e) = app.refresh_rules(&*backend) {
        eprintln!("Warning: Failed to fetch initial ruleset: {}", e);
    }
    app.refresh_services();

    // 5. Signal Handler Setup
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let sighup_flag = Arc::new(AtomicBool::new(false));

    let s_flag = shutdown_flag.clone();
    let h_flag = sighup_flag.clone();

    // Hook standard UNIX termination signals
    use signal_hook::consts::signal::*;
    use signal_hook::iterator::Signals;
    let mut signals = Signals::new(&[SIGINT, SIGTERM, SIGHUP])?;
    std::thread::spawn(move || {
        for sig in signals.forever() {
            match sig {
                SIGHUP => {
                    h_flag.store(true, Ordering::SeqCst);
                    s_flag.store(true, Ordering::SeqCst);
                    break;
                }
                SIGINT | SIGTERM => {
                    s_flag.store(true, Ordering::SeqCst);
                    break;
                }
                _ => {}
            }
        }
    });

    // 6. Setup Panic Hook to clean terminal
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        default_hook(info);
    }));

    // 7. Setup TUI Terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, crossterm::cursor::Hide)?;
    let tui_backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(tui_backend)?;

    // 8. Main Application Loop
    while !shutdown_flag.load(Ordering::SeqCst) {
        // Render screen
        terminal.draw(|f| ui::draw(f, &mut app, &*backend))?;

        // Poll events
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match &app.active_screen {
                        ActiveScreen::Main => match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                shutdown_flag.store(true, Ordering::SeqCst);
                            }
                            KeyCode::Char('a') => {
                                app.init_add_rule_form();
                                app.active_screen = ActiveScreen::AddRule;
                            }
                            KeyCode::Char('e') => {
                                if !app.rules.is_empty() && app.selected_rule_index < app.rules.len() {
                                    let rule = app.rules[app.selected_rule_index].clone();
                                    app.init_edit_rule_form(&rule);
                                    app.active_screen = ActiveScreen::EditRule;
                                }
                            }
                            KeyCode::Char('d') => {
                                if !app.rules.is_empty() && app.selected_rule_index < app.rules.len() {
                                    let rule = app.rules[app.selected_rule_index].clone();
                                    app.selected_rule_to_delete = Some(rule);
                                    app.active_screen = ActiveScreen::ConfirmDelete;
                                }
                            }
                            KeyCode::Char('t') => {
                                let new_state = !backend.is_enabled();
                                let action_name = if new_state { "enable" } else { "disable" };
                                if let Err(e) = backend.toggle(new_state) {
                                    app.active_screen = ActiveScreen::Error(e.to_string());
                                } else {
                                    let _ = app.logger.log_action(backend.name(), action_name, "Toggled firewall state");
                                    let _ = app.refresh_rules(&*backend);
                                }
                            }
                            KeyCode::Char('f') => {
                                if let Err(e) = backend.flush_all() {
                                    app.active_screen = ActiveScreen::Error(e.to_string());
                                } else {
                                    let _ = app.logger.log_action(backend.name(), "flush_all", "Flushed all input firewall rules");
                                    let _ = app.refresh_rules(&*backend);
                                }
                            }
                            KeyCode::Char('r') => {
                                let _ = app.refresh_rules(&*backend);
                                app.refresh_services();
                            }
                            KeyCode::Up => {
                                if app.selected_rule_index > 0 {
                                    app.selected_rule_index -= 1;
                                }
                            }
                            KeyCode::Down => {
                                if !app.rules.is_empty() && app.selected_rule_index < app.rules.len() - 1 {
                                    app.selected_rule_index += 1;
                                }
                            }
                            _ => {}
                        },
                        ActiveScreen::AddRule | ActiveScreen::EditRule => match key.code {
                            KeyCode::Esc => {
                                app.editing_rule_id = None;
                                app.active_screen = ActiveScreen::Main;
                            }
                            KeyCode::Tab => {
                                app.active_form_field = match app.active_form_field {
                                    FormField::Port => FormField::Protocol,
                                    FormField::Protocol => FormField::Action,
                                    FormField::Action => FormField::Source,
                                    FormField::Source => FormField::SelectService,
                                    FormField::SelectService => FormField::Submit,
                                    FormField::Submit => FormField::Cancel,
                                    FormField::Cancel => FormField::Port,
                                };
                            }
                            KeyCode::BackTab => {
                                app.active_form_field = match app.active_form_field {
                                    FormField::Port => FormField::Cancel,
                                    FormField::Protocol => FormField::Port,
                                    FormField::Action => FormField::Protocol,
                                    FormField::Source => FormField::Action,
                                    FormField::SelectService => FormField::Source,
                                    FormField::Submit => FormField::SelectService,
                                    FormField::Cancel => FormField::Submit,
                                };
                            }
                            KeyCode::Char(' ') | KeyCode::Right => match app.active_form_field {
                                FormField::Protocol => {
                                    app.form_proto = match app.form_proto.as_str() {
                                        "tcp" => "udp".to_string(),
                                        "udp" => "any".to_string(),
                                        _ => "tcp".to_string(),
                                    };
                                }
                                FormField::Action => {
                                    app.form_action = match app.form_action {
                                        RuleAction::Allow => RuleAction::Deny,
                                        RuleAction::Deny => RuleAction::Reject,
                                        RuleAction::Reject => RuleAction::Allow,
                                    };
                                }
                                _ => {}
                            },
                            KeyCode::Left => match app.active_form_field {
                                FormField::Protocol => {
                                    app.form_proto = match app.form_proto.as_str() {
                                        "tcp" => "any".to_string(),
                                        "udp" => "tcp".to_string(),
                                        _ => "udp".to_string(),
                                    };
                                }
                                FormField::Action => {
                                    app.form_action = match app.form_action {
                                        RuleAction::Allow => RuleAction::Reject,
                                        RuleAction::Deny => RuleAction::Allow,
                                        RuleAction::Reject => RuleAction::Deny,
                                    };
                                }
                                _ => {}
                            },
                            KeyCode::Up => {
                                if app.active_form_field == FormField::SelectService && app.selected_service_index > 0 {
                                    app.selected_service_index -= 1;
                                }
                            }
                            KeyCode::Down => {
                                if app.active_form_field == FormField::SelectService 
                                    && !app.services.is_empty() 
                                    && app.selected_service_index < app.services.len() - 1 
                                {
                                    app.selected_service_index += 1;
                                }
                            }
                            KeyCode::Enter => match app.active_form_field {
                                FormField::SelectService => {
                                    if !app.services.is_empty() && app.selected_service_index < app.services.len() {
                                        let selected = &app.services[app.selected_service_index];
                                        app.form_port = selected.local_port.to_string();
                                        app.form_proto = selected.protocol.replace("6", ""); // Normalizes tcp6 -> tcp
                                        app.active_form_field = FormField::Port;
                                    }
                                }
                                FormField::Submit => {
                                    let rule = FirewallRule {
                                        id: app.editing_rule_id.clone().unwrap_or_default(),
                                        port: app.form_port.clone(),
                                        protocol: app.form_proto.clone(),
                                        action: app.form_action,
                                        source: app.form_source.clone(),
                                        destination: "Anywhere".to_string(),
                                    };

                                    if matches!(app.active_screen, ActiveScreen::EditRule) {
                                        if let Some(ref edit_id) = app.editing_rule_id {
                                            let old_rule = app.rules.iter().find(|r| &r.id == edit_id).cloned();
                                            if let Some(old) = old_rule {
                                                if let Err(e) = backend.edit_rule(edit_id, &rule) {
                                                    app.active_screen = ActiveScreen::Error(e.to_string());
                                                } else {
                                                    let _ = app.logger.log_action(
                                                        backend.name(),
                                                        "edit_rule",
                                                        &format!("Edited rule {} to action={}, port={}, source={}", edit_id, rule.action, rule.port, rule.source)
                                                    );
                                                    app.transaction_log.push(app::TransactionAction::RuleEdited(old, rule));
                                                    app.editing_rule_id = None;
                                                    let _ = app.refresh_rules(&*backend);
                                                    app.active_screen = ActiveScreen::Main;
                                                }
                                            } else {
                                                app.active_screen = ActiveScreen::Error("Old rule not found".to_string());
                                            }
                                        } else {
                                            app.active_screen = ActiveScreen::Error("No rule ID to edit".to_string());
                                        }
                                    } else {
                                        if let Err(e) = backend.add_rule(&rule) {
                                            app.active_screen = ActiveScreen::Error(e.to_string());
                                        } else {
                                            let _ = app.logger.log_action(
                                                backend.name(), 
                                                "add_rule", 
                                                &format!("Added {} rule on port {} from {}", rule.action, rule.port, rule.source)
                                            );
                                            app.transaction_log.push(app::TransactionAction::RuleAdded(rule));
                                            let _ = app.refresh_rules(&*backend);
                                            app.active_screen = ActiveScreen::Main;
                                        }
                                    }
                                }
                                FormField::Cancel => {
                                    app.editing_rule_id = None;
                                    app.active_screen = ActiveScreen::Main;
                                }
                                _ => {}
                            },
                            KeyCode::Char(c) => match app.active_form_field {
                                FormField::Port => {
                                    app.form_port.push(c);
                                }
                                FormField::Source => {
                                    app.form_source.push(c);
                                }
                                _ => {}
                            },
                            KeyCode::Backspace => match app.active_form_field {
                                FormField::Port => {
                                    app.form_port.pop();
                                }
                                FormField::Source => {
                                    app.form_source.pop();
                                }
                                _ => {}
                            },
                            _ => {}
                        },
                        ActiveScreen::ConfirmDelete => match key.code {
                            KeyCode::Char('y') | KeyCode::Char('Y') => {
                                if let Some(rule) = &app.selected_rule_to_delete {
                                    if let Err(e) = backend.delete_rule(&rule.id) {
                                        app.active_screen = ActiveScreen::Error(e.to_string());
                                    } else {
                                        let _ = app.logger.log_action(
                                            backend.name(), 
                                            "delete_rule", 
                                            &format!("Deleted rule {} on port {}", rule.id, rule.port)
                                        );
                                        app.transaction_log.push(app::TransactionAction::RuleDeleted(rule.clone()));
                                        let _ = app.refresh_rules(&*backend);
                                        app.active_screen = ActiveScreen::Main;
                                    }
                                }
                            }
                            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                                app.selected_rule_to_delete = None;
                                app.active_screen = ActiveScreen::Main;
                            }
                            _ => {}
                        },
                        ActiveScreen::Error(_) => match key.code {
                            KeyCode::Esc | KeyCode::Enter => {
                                app.active_screen = ActiveScreen::Main;
                            }
                            _ => {}
                        },
                    }
                }
            }
        }
    }

    // 9. Shutdown Cleanup
    restore_terminal();

    // 10. Check if rollback is required due to SIGHUP
    if sighup_flag.load(Ordering::SeqCst) {
        // Print status or write it directly since terminal alternate screen is disabled
        println!("[NSMAM] SIGHUP connection loss detected! Reverting session firewall changes...");
        if let Err(e) = app.rollback_all(&*backend) {
            eprintln!("[NSMAM] Error during rollback: {}", e);
        } else {
            println!("[NSMAM] Rollback complete. Connection safely terminated.");
        }
    } else {
        println!("[NSMAM] NSMAM closed cleanly.");
    }

    Ok(())
}
