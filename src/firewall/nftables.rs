use super::{FirewallBackend, FirewallError, FirewallRule, RuleAction};
use regex::Regex;
use std::process::Command;

pub struct NftablesBackend {
    binary_path: String,
}

impl NftablesBackend {
    pub fn new() -> Self {
        Self {
            binary_path: "/sbin/nft".to_string(),
        }
    }

    pub fn with_path(path: &str) -> Self {
        Self {
            binary_path: path.to_string(),
        }
    }

    fn run_cmd(&self, args: &[&str]) -> Result<String, FirewallError> {
        let output = Command::new(&self.binary_path)
            .args(args)
            .output()?;
        
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let err_msg = String::from_utf8_lossy(&output.stderr).to_string();
            Err(FirewallError::CommandFailed(err_msg))
        }
    }

    fn initialize_table(&self) -> Result<(), FirewallError> {
        // Create table
        self.run_cmd(&["add", "table", "inet", "nsmam"])?;
        // Create base input chain
        self.run_cmd(&[
            "add",
            "chain",
            "inet",
            "nsmam",
            "input",
            "{ type filter hook input priority filter ; policy accept ; }",
        ])?;
        Ok(())
    }

    fn persist_rules(&self) -> Result<(), FirewallError> {
        let shell_cmd = format!("{} list ruleset > /etc/nftables.conf", self.binary_path);
        let status = Command::new("sh").args(&["-c", &shell_cmd]).status()?;
        if !status.success() {
            return Err(FirewallError::ExecutionFailed(
                "Failed to save nftables ruleset to /etc/nftables.conf".to_string()
            ));
        }
        Ok(())
    }
}

pub fn parse_nftables_rules(stdout: &str) -> Result<Vec<FirewallRule>, FirewallError> {
    let mut rules = Vec::new();
    
    let re_handle = Regex::new(r"handle\s+(\d+)").unwrap();
    let re_source = Regex::new(r"ip\s+saddr\s+(\S+)").unwrap();
    let re_dport = Regex::new(r"(tcp|udp)?\s*dport\s+(\S+)").unwrap();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() 
            || trimmed.starts_with("table") 
            || trimmed.starts_with("chain") 
            || trimmed.starts_with("type") 
            || trimmed == "}" 
            || trimmed.starts_with("type filter")
        {
            continue;
        }

        if let Some(h_caps) = re_handle.captures(trimmed) {
            let handle = h_caps.get(1).unwrap().as_str().to_string();

            let action = if trimmed.contains("accept") {
                RuleAction::Allow
            } else if trimmed.contains("drop") {
                RuleAction::Deny
            } else if trimmed.contains("reject") {
                RuleAction::Reject
            } else {
                continue;
            };

            let source = re_source
                .captures(trimmed)
                .map(|caps| caps.get(1).unwrap().as_str().to_string())
                .unwrap_or_else(|| "Anywhere".to_string());

            let mut port = "any".to_string();
            let mut protocol = "any".to_string();

            if let Some(dp_caps) = re_dport.captures(trimmed) {
                if let Some(proto_match) = dp_caps.get(1) {
                    protocol = proto_match.as_str().to_string();
                }
                port = dp_caps.get(2).unwrap().as_str().to_string();
            }

            rules.push(FirewallRule {
                id: handle,
                port,
                protocol,
                action,
                source,
                destination: "Anywhere".to_string(),
            });
        }
    }
    Ok(rules)
}

pub fn parse_nftables_policy(stdout: &str) -> Result<String, FirewallError> {
    // Look for: policy accept; or policy drop;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.contains("policy") {
            if trimmed.contains("drop") {
                return Ok("DROP".to_string());
            } else if trimmed.contains("accept") {
                return Ok("ACCEPT".to_string());
            }
        }
    }
    Ok("ACCEPT".to_string())
}

impl FirewallBackend for NftablesBackend {
    fn name(&self) -> &str {
        "nftables"
    }

    fn is_active(&self) -> bool {
        std::path::Path::new(&self.binary_path).exists()
    }

    fn is_enabled(&self) -> bool {
        // check if nft service or ruleset listing is successful
        if let Ok(output) = Command::new(&self.binary_path).arg("list").arg("ruleset").output() {
            output.status.success()
        } else {
            false
        }
    }

    fn get_default_policy(&self) -> Result<String, FirewallError> {
        let stdout = match self.run_cmd(&["list", "chain", "inet", "nsmam", "input"]) {
            Ok(out) => out,
            Err(_) => {
                // Table doesn't exist, default policy is accept
                return Ok("ACCEPT".to_string());
            }
        };
        parse_nftables_policy(&stdout)
    }

    fn get_rules(&self) -> Result<Vec<FirewallRule>, FirewallError> {
        let stdout = match self.run_cmd(&["-a", "list", "chain", "inet", "nsmam", "input"]) {
            Ok(out) => out,
            Err(_) => {
                // Table doesn't exist yet, return empty rules list
                return Ok(Vec::new());
            }
        };
        parse_nftables_rules(&stdout)
    }

    fn add_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError> {
        let _ = self.initialize_table(); // Ensure table and chain are created

        let mut cmd_args = vec!["add", "rule", "inet", "nsmam", "input"];
        
        let mut source_arg = String::new();
        if rule.source != "Anywhere" && !rule.source.is_empty() {
            source_arg = format!("ip saddr {}", rule.source);
            cmd_args.push(&source_arg);
        }

        let mut proto_port_arg = String::new();
        if rule.protocol != "any" && !rule.port.is_empty() && rule.port != "any" {
            proto_port_arg = format!("{} dport {}", rule.protocol, rule.port);
            cmd_args.push(&proto_port_arg);
        } else if !rule.port.is_empty() && rule.port != "any" {
            proto_port_arg = format!("dport {}", rule.port);
            cmd_args.push(&proto_port_arg);
        }

        let target = match rule.action {
            RuleAction::Allow => "accept",
            RuleAction::Deny => "drop",
            RuleAction::Reject => "reject",
        };
        cmd_args.push(target);

        // Execute add rule
        self.run_cmd(&cmd_args)?;
        self.persist_rules()?;
        Ok(())
    }

    fn edit_rule(&self, rule_id: &str, new_rule: &FirewallRule) -> Result<(), FirewallError> {
        let _ = self.initialize_table(); // Ensure table and chain exist

        let mut cmd_args = vec!["replace", "rule", "inet", "nsmam", "input", "handle", rule_id];
        
        let mut source_arg = String::new();
        if new_rule.source != "Anywhere" && !new_rule.source.is_empty() {
            source_arg = format!("ip saddr {}", new_rule.source);
            cmd_args.push(&source_arg);
        }

        let mut proto_port_arg = String::new();
        if new_rule.protocol != "any" && !new_rule.port.is_empty() && new_rule.port != "any" {
            proto_port_arg = format!("{} dport {}", new_rule.protocol, new_rule.port);
            cmd_args.push(&proto_port_arg);
        } else if !new_rule.port.is_empty() && new_rule.port != "any" {
            proto_port_arg = format!("dport {}", new_rule.port);
            cmd_args.push(&proto_port_arg);
        }

        let target = match new_rule.action {
            RuleAction::Allow => "accept",
            RuleAction::Deny => "drop",
            RuleAction::Reject => "reject",
        };
        cmd_args.push(target);

        // Execute replace rule
        self.run_cmd(&cmd_args)?;
        self.persist_rules()?;
        Ok(())
    }

    fn delete_rule(&self, rule_id: &str) -> Result<(), FirewallError> {
        self.run_cmd(&["delete", "rule", "inet", "nsmam", "input", "handle", rule_id])?;
        self.persist_rules()?;
        Ok(())
    }

    fn toggle(&self, enable: bool) -> Result<(), FirewallError> {
        let _ = self.initialize_table(); // Ensure table and chain exist
        
        let policy = if enable { "drop" } else { "accept" };
        let cmd = format!("chain inet nsmam input {{ policy {} ; }}", policy);
        self.run_cmd(&["-c", &cmd])?; // Wait, running nft with raw config block
        
        // Alternatively run directly:
        // nft "add chain inet nsmam input { policy drop ; }"
        let status = Command::new(&self.binary_path)
            .args(&["add", "chain", "inet", "nsmam", "input", &format!("{{ policy {} ; }}", policy)])
            .status()?;
        if !status.success() {
            return Err(FirewallError::ExecutionFailed("Failed to toggle nftables policy".to_string()));
        }
        self.persist_rules()?;
        Ok(())
    }

    fn flush_all(&self) -> Result<(), FirewallError> {
        // Delete the entire nsmam table
        let _ = self.run_cmd(&["delete", "table", "inet", "nsmam"]);
        self.persist_rules()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nftables_rules_mock() {
        let mock_stdout = "table inet nsmam {\n\
            chain input {\n\
                type filter hook input priority filter; policy accept;\n\
                ip saddr 192.168.0.0/24 tcp dport 22 accept # handle 4\n\
                udp dport 87 accept # handle 5\n\
                tcp dport 80 drop # handle 6\n\
            }\n\
        }";

        let rules = parse_nftables_rules(mock_stdout).unwrap();
        assert_eq!(rules.len(), 3);

        assert_eq!(rules[0].id, "4");
        assert_eq!(rules[0].port, "22");
        assert_eq!(rules[0].protocol, "tcp");
        assert_eq!(rules[0].action, RuleAction::Allow);
        assert_eq!(rules[0].source, "192.168.0.0/24");

        assert_eq!(rules[1].id, "5");
        assert_eq!(rules[1].port, "87");
        assert_eq!(rules[1].protocol, "udp");
        assert_eq!(rules[1].action, RuleAction::Allow);
        assert_eq!(rules[1].source, "Anywhere");

        assert_eq!(rules[2].id, "6");
        assert_eq!(rules[2].port, "80");
        assert_eq!(rules[2].protocol, "tcp");
        assert_eq!(rules[2].action, RuleAction::Deny);
        assert_eq!(rules[2].source, "Anywhere");
    }

    #[test]
    fn test_parse_nftables_policy_mock() {
        let mock_stdout = "table inet nsmam {\n\
            chain input {\n\
                type filter hook input priority filter; policy drop;\n\
            }\n\
        }";
        let policy = parse_nftables_policy(mock_stdout).unwrap();
        assert_eq!(policy, "DROP");
    }
}
