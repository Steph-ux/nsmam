use super::{FirewallBackend, FirewallError, FirewallRule, RuleAction};
use regex::Regex;
use std::process::Command;

pub struct IptablesBackend {
    binary_path: String,
}

impl IptablesBackend {
    pub fn new() -> Self {
        Self {
            binary_path: "/sbin/iptables".to_string(),
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

    fn persist_rules(&self) -> Result<(), FirewallError> {
        // Try Debian/Ubuntu netfilter-persistent save
        if let Ok(output) = Command::new("which").arg("netfilter-persistent").output() {
            if output.status.success() {
                let save_status = Command::new("netfilter-persistent").arg("save").status();
                if let Ok(status) = save_status {
                    if status.success() {
                        return Ok(());
                    }
                }
            }
        }
        
        // Fallback: detect OS files and save
        let save_path = if std::path::Path::new("/etc/iptables/rules.v4").exists() {
            "/etc/iptables/rules.v4"
        } else if std::path::Path::new("/etc/sysconfig/iptables").exists() {
            "/etc/sysconfig/iptables"
        } else {
            // Default to Debian path if directory exists, else RHEL path
            if std::path::Path::new("/etc/iptables").exists() {
                "/etc/iptables/rules.v4"
            } else {
                "/etc/sysconfig/iptables"
            }
        };

        // Run: sh -c "iptables-save > save_path"
        let shell_cmd = format!("{} -S > {}", self.binary_path, save_path);
        let status = Command::new("sh").args(&["-c", &shell_cmd]).status()?;
        if !status.success() {
            return Err(FirewallError::ExecutionFailed(format!(
                "Failed to save iptables rules to {}", save_path
            )));
        }

        Ok(())
    }
}

pub fn is_iptables_legacy(binary_path: &str) -> bool {
    if let Ok(output) = Command::new(binary_path).arg("-V").output() {
        let out = String::from_utf8_lossy(&output.stdout);
        !out.contains("nf_tables")
    } else {
        true
    }
}

pub fn parse_iptables_rules(stdout: &str) -> Result<Vec<FirewallRule>, FirewallError> {
    let mut rules = Vec::new();
    let mut line_num = 1;

    let re_source = Regex::new(r"-s\s+(\S+)").unwrap();
    let re_dest = Regex::new(r"-d\s+(\S+)").unwrap();
    let re_proto = Regex::new(r"-p\s+(\S+)").unwrap();
    let re_dport = Regex::new(r"--dport\s+(\S+)").unwrap();
    let re_target = Regex::new(r"-j\s+(\S+)").unwrap();

    for line in stdout.lines() {
        if line.starts_with("-A INPUT") {
            let action_str = re_target
                .captures(line)
                .map(|caps| caps.get(1).unwrap().as_str())
                .unwrap_or("");
            
            let action = match action_str {
                "ACCEPT" => RuleAction::Allow,
                "DROP" => RuleAction::Deny,
                "REJECT" => RuleAction::Reject,
                _ => continue, // Skip internal/custom target rules
            };

            let port = re_dport
                .captures(line)
                .map(|caps| caps.get(1).unwrap().as_str().to_string())
                .unwrap_or_else(|| "any".to_string());

            let protocol = re_proto
                .captures(line)
                .map(|caps| caps.get(1).unwrap().as_str().to_string())
                .unwrap_or_else(|| "any".to_string());

            let source = re_source
                .captures(line)
                .map(|caps| caps.get(1).unwrap().as_str().to_string())
                .unwrap_or_else(|| "Anywhere".to_string());

            let destination = re_dest
                .captures(line)
                .map(|caps| caps.get(1).unwrap().as_str().to_string())
                .unwrap_or_else(|| "Anywhere".to_string());

            rules.push(FirewallRule {
                id: line_num.to_string(),
                port,
                protocol,
                action,
                source,
                destination,
            });
            line_num += 1;
        }
    }
    Ok(rules)
}

pub fn parse_iptables_policy(stdout: &str) -> Result<String, FirewallError> {
    for line in stdout.lines() {
        if line.starts_with("-P INPUT") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Ok(parts[2].to_string());
            }
        }
    }
    Ok("ACCEPT".to_string())
}

impl FirewallBackend for IptablesBackend {
    fn name(&self) -> &str {
        "iptables"
    }

    fn is_active(&self) -> bool {
        std::path::Path::new(&self.binary_path).exists()
    }

    fn is_enabled(&self) -> bool {
        // iptables is "enabled" if the kernel module is loaded and there is at least one active rule or the policy is DROP.
        // For simplicity, we check if we can run "iptables -L".
        if let Ok(output) = Command::new(&self.binary_path).arg("-L").output() {
            output.status.success()
        } else {
            false
        }
    }

    fn get_default_policy(&self) -> Result<String, FirewallError> {
        let stdout = self.run_cmd(&["-S", "INPUT"])?;
        parse_iptables_policy(&stdout)
    }

    fn get_rules(&self) -> Result<Vec<FirewallRule>, FirewallError> {
        let stdout = self.run_cmd(&["-S", "INPUT"])?;
        parse_iptables_rules(&stdout)
    }

    fn add_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError> {
        let mut args = vec!["-A", "INPUT"];

        // Format source
        if rule.source != "Anywhere" && !rule.source.is_empty() {
            args.push("-s");
            args.push(&rule.source);
        }

        // Format protocol
        if rule.protocol != "any" {
            args.push("-p");
            args.push(&rule.protocol);
            
            // Format port
            if rule.port != "any" && !rule.port.is_empty() {
                args.push("--dport");
                args.push(&rule.port);
            }
        }

        // Format action
        let target = match rule.action {
            RuleAction::Allow => "ACCEPT",
            RuleAction::Deny => "DROP",
            RuleAction::Reject => "REJECT",
        };
        args.push("-j");
        args.push(target);

        self.run_cmd(&args)?;
        self.persist_rules()?;
        Ok(())
    }

    fn edit_rule(&self, rule_id: &str, new_rule: &FirewallRule) -> Result<(), FirewallError> {
        let mut args = vec!["-R", "INPUT", rule_id];

        // Format source
        if new_rule.source != "Anywhere" && !new_rule.source.is_empty() {
            args.push("-s");
            args.push(&new_rule.source);
        }

        // Format protocol
        if new_rule.protocol != "any" {
            args.push("-p");
            args.push(&new_rule.protocol);
            
            // Format port
            if new_rule.port != "any" && !new_rule.port.is_empty() {
                args.push("--dport");
                args.push(&new_rule.port);
            }
        }

        // Format action
        let target = match new_rule.action {
            RuleAction::Allow => "ACCEPT",
            RuleAction::Deny => "DROP",
            RuleAction::Reject => "REJECT",
        };
        args.push("-j");
        args.push(target);

        self.run_cmd(&args)?;
        self.persist_rules()?;
        Ok(())
    }

    fn delete_rule(&self, rule_id: &str) -> Result<(), FirewallError> {
        // Delete by line number
        self.run_cmd(&["-D", "INPUT", rule_id])?;
        self.persist_rules()?;
        Ok(())
    }

    fn toggle(&self, enable: bool) -> Result<(), FirewallError> {
        // iptables does not have a simple global toggle.
        // We set the default policy of INPUT chain.
        let policy = if enable { "DROP" } else { "ACCEPT" };
        self.run_cmd(&["-P", "INPUT", policy])?;
        self.persist_rules()?;
        Ok(())
    }

    fn flush_all(&self) -> Result<(), FirewallError> {
        self.run_cmd(&["-F", "INPUT"])?;
        self.persist_rules()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iptables_rules_mock() {
        let mock_stdout = "-P INPUT ACCEPT\n\
        -P FORWARD DROP\n\
        -P OUTPUT ACCEPT\n\
        -A INPUT -s 192.168.0.0/24 -p tcp -m tcp --dport 22 -j ACCEPT\n\
        -A INPUT -p udp -m udp --dport 87 -j ACCEPT\n\
        -A INPUT -p tcp -m tcp --dport 80 -j DROP";

        let rules = parse_iptables_rules(mock_stdout).unwrap();
        assert_eq!(rules.len(), 3);

        assert_eq!(rules[0].id, "1");
        assert_eq!(rules[0].port, "22");
        assert_eq!(rules[0].protocol, "tcp");
        assert_eq!(rules[0].action, RuleAction::Allow);
        assert_eq!(rules[0].source, "192.168.0.0/24");

        assert_eq!(rules[1].id, "2");
        assert_eq!(rules[1].port, "87");
        assert_eq!(rules[1].protocol, "udp");
        assert_eq!(rules[1].action, RuleAction::Allow);
        assert_eq!(rules[1].source, "Anywhere");

        assert_eq!(rules[2].id, "3");
        assert_eq!(rules[2].port, "80");
        assert_eq!(rules[2].protocol, "tcp");
        assert_eq!(rules[2].action, RuleAction::Deny);
        assert_eq!(rules[2].source, "Anywhere");
    }

    #[test]
    fn test_parse_iptables_policy_mock() {
        let mock_stdout = "-P INPUT DROP\n\
        -P FORWARD DROP\n\
        -P OUTPUT ACCEPT";
        let policy = parse_iptables_policy(mock_stdout).unwrap();
        assert_eq!(policy, "DROP");
    }
}
