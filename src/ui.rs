use crate::app::{ActiveScreen, App, FormField};
use crate::firewall::{FirewallBackend, FirewallRule, RuleAction};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Wrap},
    Frame,
};

/// Helper to render a centered rect for popups
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

pub fn draw(f: &mut Frame, app: &mut App, backend: &dyn FirewallBackend) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(5),    // Main content (Table & Help)
            Constraint::Length(3), // Status / Warning bar
        ])
        .split(f.size());

    // 1. Draw Header
    let backend_status = if backend.is_enabled() {
        Span::styled("ENABLED (DROP BY DEFAULT)", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("DISABLED (ALLOW BY DEFAULT)", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD))
    };

    let header_text = vec![Line::from(vec![
        Span::styled(" NSMAM ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" | Active Backend: "),
        Span::styled(backend.name(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" | Firewall Status: "),
        backend_status,
    ])];
    
    let header = Paragraph::new(header_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Network Security Manager ")
                .title(Line::from(vec![Span::styled(" made by Steph-ux ", Style::default().fg(Color::Gray))]).right_aligned())
        );
    f.render_widget(header, main_layout[0]);

    // 2. Draw Main Content (Rules list & Hotkeys)
    let content_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(75), // Rules list
            Constraint::Percentage(25), // Quick Help panel
        ])
        .split(main_layout[1]);

    // Draw Rules Table
    let header_cells = ["Index", "Port", "Protocol", "Action", "Source", "Destination"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    
    let header_row = Row::new(header_cells).height(1).bottom_margin(1);

    let rows: Vec<Row> = app
        .rules
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let action_style = match r.action {
                RuleAction::Allow => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                RuleAction::Deny => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                RuleAction::Reject => Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
            };

            let row_style = if i == app.selected_rule_index {
                Style::default().bg(Color::Rgb(30, 30, 46)).fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            };

            Row::new(vec![
                ratatui::widgets::Cell::from(r.id.clone()),
                ratatui::widgets::Cell::from(r.port.clone()),
                ratatui::widgets::Cell::from(r.protocol.clone().to_uppercase()),
                ratatui::widgets::Cell::from(r.action.to_string()).style(action_style),
                ratatui::widgets::Cell::from(r.source.clone()),
                ratatui::widgets::Cell::from(r.destination.clone()),
            ])
            .style(row_style)
            .height(1)
        })
        .collect();

    let rules_table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Percentage(20),
            Constraint::Percentage(15),
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::ALL).title(" Active Firewall Rules "))
    .highlight_symbol(">> ");
    
    f.render_widget(rules_table, content_layout[0]);

    // Draw Quick Help Panel
    let help_text = vec![
        Line::from(vec![Span::styled("[A]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw("  Add Rule")]),
        Line::from(vec![Span::styled("[E]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw("  Edit Selected")]),
        Line::from(vec![Span::styled("[D]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw("  Delete Selected")]),
        Line::from(vec![Span::styled("[T]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw("  Toggle Firewall Status")]),
        Line::from(vec![Span::styled("[F]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw("  Flush All Rules")]),
        Line::from(vec![Span::styled("[R]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw("  Refresh Rules/Services")]),
        Line::from(""),
        Line::from(vec![Span::styled("[↑/↓]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw(" Select Rule")]),
        Line::from(vec![Span::styled("[Q]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)), Span::raw("  Quit & Clean Terminal")]),
    ];
    let help_paragraph = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title(" Command Operations "));
    f.render_widget(help_paragraph, content_layout[1]);

    // 3. Draw Status / Warning Bar
    let status_text = if app.multiplexer_detected {
        Line::from(vec![
            Span::styled(" WARNING: ", Style::default().fg(Color::Black).bg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled(" Multiplexer detected (tmux/screen). SIGHUP-based rollback will NOT trigger if SSH drops.", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" LOCKOUT PROTECTION ACTIVE: ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw(" Abrupt connection loss (SIGHUP) will instantly rollback all applied session rules."),
        ])
    };
    
    let status_bar = Paragraph::new(status_text)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(status_bar, main_layout[2]);

    // 4. Draw Modals (if active)
    match &app.active_screen {
        ActiveScreen::AddRule | ActiveScreen::EditRule => {
            let is_edit = matches!(app.active_screen, ActiveScreen::EditRule);
            let popup_rect = centered_rect(80, 70, f.size());
            f.render_widget(Clear, popup_rect);

            let title = if is_edit { " Edit Firewall Rule " } else { " Add New Firewall Rule " };
            let popup_block = Block::default()
                .borders(Borders::ALL)
                .title(title);
            f.render_widget(popup_block, popup_rect);

            // Split popup into Form (left) and Listening Services Sidebar (right)
            let inner_rect = popup_rect.inner(&ratatui::layout::Margin { horizontal: 2, vertical: 2 });
            let popup_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(inner_rect);

            // Draw Form fields on the left
            let form_fields_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Port
                    Constraint::Length(3), // Protocol
                    Constraint::Length(3), // Action
                    Constraint::Length(3), // Source
                    Constraint::Length(3), // Submit/Cancel buttons
                ])
                .split(popup_layout[0]);

            // Form styles depending on focus
            let get_style = |field: FormField| {
                if app.active_form_field == field {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                }
            };

            // Port input box
            let port_widget = Paragraph::new(app.form_port.as_str())
                .block(Block::default().borders(Borders::ALL).title(" Destination Port ").border_style(get_style(FormField::Port)));
            f.render_widget(port_widget, form_fields_layout[0]);

            // Protocol selector
            let proto_widget = Paragraph::new(app.form_proto.as_str())
                .block(Block::default().borders(Borders::ALL).title(" Protocol (TAB/Space) ").border_style(get_style(FormField::Protocol)));
            f.render_widget(proto_widget, form_fields_layout[1]);

            // Action selector
            let action_widget = Paragraph::new(app.form_action.to_string())
                .block(Block::default().borders(Borders::ALL).title(" Action (TAB/Space) ").border_style(get_style(FormField::Action)));
            f.render_widget(action_widget, form_fields_layout[2]);

            // Source input box
            let source_widget = Paragraph::new(app.form_source.as_str())
                .block(Block::default().borders(Borders::ALL).title(" Source IP/Subnet ").border_style(get_style(FormField::Source)));
            f.render_widget(source_widget, form_fields_layout[3]);

            // Submit / Cancel Buttons
            let btn_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(form_fields_layout[4]);

            let submit_style = if app.active_form_field == FormField::Submit {
                Style::default().bg(Color::Green).fg(Color::Black).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Green)
            };
            let submit_label = if is_edit { "[ Save Changes ]" } else { "[ Submit Rule ]" };
            let submit_btn = Paragraph::new(submit_label)
                .style(submit_style)
                .block(Block::default().borders(Borders::ALL).border_style(submit_style));
            f.render_widget(submit_btn, btn_layout[0]);

            let cancel_style = if app.active_form_field == FormField::Cancel {
                Style::default().bg(Color::Red).fg(Color::Black).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Red)
            };
            let cancel_btn = Paragraph::new("[ Cancel ]")
                .style(cancel_style)
                .block(Block::default().borders(Borders::ALL).border_style(cancel_style));
            f.render_widget(cancel_btn, btn_layout[1]);

            // Draw Listening Services on the right
            let service_list_style = if app.active_form_field == FormField::SelectService {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };

            let services_items: Vec<ListItem> = app
                .services
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let text = format!("  {}/{} ({})", s.local_port, s.protocol, s.process_name);
                    let item_style = if i == app.selected_service_index && app.active_form_field == FormField::SelectService {
                        Style::default().bg(Color::Yellow).fg(Color::Black).add_modifier(Modifier::BOLD)
                    } else if i == app.selected_service_index {
                        Style::default().bg(Color::Rgb(40, 40, 60)).fg(Color::White)
                    } else {
                        Style::default().fg(Color::Gray)
                    };
                    ListItem::new(text).style(item_style)
                })
                .collect();

            let services_block = Block::default()
                .borders(Borders::ALL)
                .title(" Discovered System Services (Use Arrow Keys) ")
                .border_style(service_list_style);
            
            let services_list = List::new(services_items).block(services_block);
            f.render_widget(services_list, popup_layout[1]);
        }
        ActiveScreen::ConfirmDelete => {
            let popup_rect = centered_rect(50, 30, f.size());
            f.render_widget(Clear, popup_rect);

            let popup_block = Block::default()
                .borders(Borders::ALL)
                .title(" Confirm Rule Deletion ")
                .border_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));
            
            let rule_to_del = app.selected_rule_to_delete.as_ref().map(|r| {
                format!(
                    "Rule Index: {}\nPort: {}\nProtocol: {}\nAction: {}\nSource: {}",
                    r.id, r.port, r.protocol, r.action, r.source
                )
            }).unwrap_or_default();

            let prompt_text = format!(
                "Are you sure you want to delete this rule?\n\n{}\n\n[y] Yes, Delete  |  [n] No, Cancel",
                rule_to_del
            );

            let prompt = Paragraph::new(prompt_text)
                .block(popup_block)
                .wrap(Wrap { trim: true });
            
            f.render_widget(prompt, popup_rect);
        }
        ActiveScreen::Error(msg) => {
            let popup_rect = centered_rect(60, 40, f.size());
            f.render_widget(Clear, popup_rect);

            let popup_block = Block::default()
                .borders(Borders::ALL)
                .title(" Operation Error ")
                .border_style(Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD));
            
            let error_text = format!(
                "An error occurred while executing the firewall command:\n\n{}\n\nPress [Esc] or [Enter] to dismiss.",
                msg
            );

            let prompt = Paragraph::new(error_text)
                .block(popup_block)
                .wrap(Wrap { trim: true });
            
            f.render_widget(prompt, popup_rect);
        }
        ActiveScreen::Main => {}
    }
}
