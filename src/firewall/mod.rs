pub mod ufw;
pub mod iptables;
pub mod nftables;

pub use ufw::UfwBackend;
pub use iptables::IptablesBackend;
pub use nftables::NftablesBackend;

use std::fmt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("Command execution failed: {0}")]
    CommandFailed(String),
    
    #[error("Failed to parse output: {0}")]
    ParseError(String),
    
    #[error("Backend not supported or missing binary: {0}")]
    NotSupported(String),
    
    #[error("Action execution failed: {0}")]
    ExecutionFailed(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    Allow,
    Deny,
    Reject,
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleAction::Allow => write!(f, "ALLOW"),
            RuleAction::Deny => write!(f, "DENY"),
            RuleAction::Reject => write!(f, "REJECT"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FirewallRule {
    pub id: String,          // Line number or handle
    pub port: String,        // E.g., "22", "80", "8000:8010", "any"
    pub protocol: String,    // "tcp", "udp", "any"
    pub action: RuleAction,
    pub source: String,      // E.g., "Anywhere", "192.168.0.0/24"
    pub destination: String, // E.g., "Anywhere"
}

pub trait FirewallBackend {
    fn name(&self) -> &str;
    fn is_active(&self) -> bool;
    fn is_enabled(&self) -> bool;
    fn get_default_policy(&self) -> Result<String, FirewallError>;
    fn get_rules(&self) -> Result<Vec<FirewallRule>, FirewallError>;
    fn add_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError>;
    fn edit_rule(&self, rule_id: &str, new_rule: &FirewallRule) -> Result<(), FirewallError>;
    fn delete_rule(&self, rule_id: &str) -> Result<(), FirewallError>;
    fn toggle(&self, enable: bool) -> Result<(), FirewallError>;
    fn flush_all(&self) -> Result<(), FirewallError>;
}
