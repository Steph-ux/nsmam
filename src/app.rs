use crate::firewall::{FirewallBackend, FirewallRule, RuleAction};
use crate::logger::Logger;
use crate::services::{self, SocketInfo};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub backend: String,  // "auto", "ufw", "nftables", "iptables"
    pub log_file: String, // default "/var/log/nsmam.log"
}

impl Default for Config {
    fn default() -> Self {
        Self {
            backend: "auto".to_string(),
            log_file: "/var/log/nsmam.log".to_string(),
        }
    }
}

pub fn load_config(path: &str) -> Config {
    if let Ok(content) = fs::read_to_string(path) {
        if let Ok(config) = toml::from_str::<Config>(&content) {
            return config;
        }
    }
    Config::default()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveScreen {
    Main,
    AddRule,
    ConfirmDelete,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormField {
    Port,
    Protocol,
    Action,
    Source,
    SelectService,
    Submit,
    Cancel,
}

#[derive(Debug, Clone)]
pub enum TransactionAction {
    RuleAdded(FirewallRule),
    RuleDeleted(FirewallRule),
}

pub struct App {
    pub config: Config,
    pub active_screen: ActiveScreen,
    pub rules: Vec<FirewallRule>,
    pub selected_rule_index: usize,
    pub services: Vec<SocketInfo>,
    pub selected_service_index: usize,
    pub transaction_log: Vec<TransactionAction>,
    pub logger: Logger,
    pub multiplexer_detected: bool,
    
    // Form fields
    pub form_port: String,
    pub form_proto: String, // "tcp", "udp", "any"
    pub form_action: RuleAction,
    pub form_source: String,
    pub active_form_field: FormField,
    pub selected_rule_to_delete: Option<FirewallRule>,
}

impl App {
    pub fn new(config_path: &str, multiplexer_detected: bool) -> Self {
        let config = load_config(config_path);
        let logger = Logger::new(&config.log_file);
        
        Self {
            config,
            active_screen: ActiveScreen::Main,
            rules: Vec::new(),
            selected_rule_index: 0,
            services: Vec::new(),
            selected_service_index: 0,
            transaction_log: Vec::new(),
            logger,
            multiplexer_detected,
            form_port: String::new(),
            form_proto: "tcp".to_string(),
            form_action: RuleAction::Allow,
            form_source: "Anywhere".to_string(),
            active_form_field: FormField::Port,
            selected_rule_to_delete: None,
        }
    }

    pub fn refresh_rules(&mut self, backend: &dyn FirewallBackend) -> Result<(), crate::firewall::FirewallError> {
        self.rules = backend.get_rules()?;
        if self.rules.is_empty() {
            self.selected_rule_index = 0;
        } else if self.selected_rule_index >= self.rules.len() {
            self.selected_rule_index = self.rules.len() - 1;
        }
        Ok(())
    }

    pub fn refresh_services(&mut self) {
        if let Ok(scanned) = services::get_listening_services() {
            self.services = scanned;
        }
        if self.services.is_empty() {
            self.selected_service_index = 0;
        } else if self.selected_service_index >= self.services.len() {
            self.selected_service_index = self.services.len() - 1;
        }
    }

    pub fn init_add_rule_form(&mut self) {
        self.form_port = String::new();
        self.form_proto = "tcp".to_string();
        self.form_action = RuleAction::Allow;
        self.form_source = "Anywhere".to_string();
        self.active_form_field = FormField::Port;
        self.selected_service_index = 0;
        self.refresh_services();
    }

    pub fn rollback_all(&mut self, backend: &dyn FirewallBackend) -> Result<(), crate::firewall::FirewallError> {
        let _ = self.logger.log_action(backend.name(), "rollback_start", "Abrupt session termination (SIGHUP) - reverting changes");
        
        // Revert transactions in reverse order
        while let Some(action) = self.transaction_log.pop() {
            match action {
                TransactionAction::RuleAdded(rule) => {
                    // Revert adding by deleting the rule.
                    // We must fetch current rules list to find rule's new ID if UFW/nft changed the numbering
                    if let Ok(current_rules) = backend.get_rules() {
                        // Match rules on port, proto, action, source
                        if let Some(matching_rule) = current_rules.iter().find(|r| {
                            r.port == rule.port 
                            && r.protocol == rule.protocol 
                            && r.action == rule.action 
                            && r.source == rule.source
                        }) {
                            let _ = backend.delete_rule(&matching_rule.id);
                            let _ = self.logger.log_action(backend.name(), "rollback_delete", &format!("Deleted rule on port {}", rule.port));
                        }
                    }
                }
                TransactionAction::RuleDeleted(rule) => {
                    // Revert deleting by re-adding the rule
                    let _ = backend.add_rule(&rule);
                    let _ = self.logger.log_action(backend.name(), "rollback_re_add", &format!("Re-added rule on port {}", rule.port));
                }
            }
        }
        
        let _ = self.logger.log_action(backend.name(), "rollback_complete", "Successfully rolled back all session rules");
        Ok(())
    }
}
