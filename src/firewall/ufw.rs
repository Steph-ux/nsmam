use super::{FirewallBackend, FirewallError, FirewallRule, RuleAction};
use regex::Regex;
use std::process::Command;

pub struct UfwBackend {
    binary_path: String,
}

impl UfwBackend {
    pub fn new() -> Self {
        Self {
            binary_path: "/sbin/ufw".to_string(),
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
}

pub fn parse_ufw_status(stdout: &str) -> Result<Vec<FirewallRule>, FirewallError> {
    let mut rules = Vec::new();
    // Regex matching UFW numbered rules:
    // E.g.: [ 1] 22/tcp                     ALLOW IN    192.168.0.0/24
    // E.g.: [22] 80                         DENY IN     Anywhere
    // E.g.: [ 3] 87/udp (v6)                ALLOW IN    Anywhere (v6)
    let re = Regex::new(r"^\s*\[\s*(\d+)\]\s+(\S+)(?:\s+\(v6\))?\s+(ALLOW|DENY|REJECT)(?:\s+IN|\s+OUT)?\s+(.+?)(?:\s+\(v6\))?\s*$").map_err(|e| FirewallError::ParseError(e.to_string()))?;

    for line in stdout.lines() {
        if let Some(caps) = re.captures(line) {
            let id = caps.get(1).unwrap().as_str().to_string();
            let port_proto = caps.get(2).unwrap().as_str();
            let action_str = caps.get(3).unwrap().as_str();
            let source = caps.get(4).unwrap().as_str().trim().to_string();

            let action = match action_str {
                "ALLOW" => RuleAction::Allow,
                "DENY" => RuleAction::Deny,
                "REJECT" => RuleAction::Reject,
                _ => continue,
            };

            let (port, proto) = if port_proto.contains('/') {
                let parts: Vec<&str> = port_proto.split('/').collect();
                (parts[0].to_string(), parts[1].to_string())
            } else {
                (port_proto.to_string(), "any".to_string())
            };

            rules.push(FirewallRule {
                id,
                port,
                protocol: proto,
                action,
                source,
                destination: "Anywhere".to_string(),
            });
        }
    }
    Ok(rules)
}

pub fn parse_ufw_policy(stdout: &str) -> Result<String, FirewallError> {
    // Look for line like: "Default: deny (incoming), allow (outgoing), disabled (routed)"
    for line in stdout.lines() {
        if line.starts_with("Default:") {
            let parts: Vec<&str> = line.split(',').collect();
            if !parts.is_empty() {
                let incoming = parts[0].replace("Default:", "").replace("(incoming)", "").trim().to_string();
                return Ok(incoming.to_uppercase());
            }
        }
    }
    Ok("DENY".to_string()) // Safe default
}

impl FirewallBackend for UfwBackend {
    fn name(&self) -> &str {
        "UFW"
    }

    fn is_active(&self) -> bool {
        std::path::Path::new(&self.binary_path).exists()
    }

    fn is_enabled(&self) -> bool {
        if let Ok(stdout) = self.run_cmd(&["status"]) {
            stdout.contains("Status: active")
        } else {
            false
        }
    }

    fn get_default_policy(&self) -> Result<String, FirewallError> {
        let stdout = self.run_cmd(&["status", "verbose"])?;
        parse_ufw_policy(&stdout)
    }

    fn get_rules(&self) -> Result<Vec<FirewallRule>, FirewallError> {
        let stdout = self.run_cmd(&["status", "numbered"])?;
        parse_ufw_status(&stdout)
    }

    fn add_rule(&self, rule: &FirewallRule) -> Result<(), FirewallError> {
        let action_str = match rule.action {
            RuleAction::Allow => "allow",
            RuleAction::Deny => "deny",
            RuleAction::Reject => "reject",
        };

        let mut args = vec![action_str];

        // Format protocol
        if rule.protocol != "any" {
            args.push("proto");
            args.push(&rule.protocol);
        }

        // Format source
        let src = if rule.source.eq_ignore_ascii_case("Anywhere") || rule.source.is_empty() {
            "any"
        } else {
            &rule.source
        };
        args.push("from");
        args.push(src);

        // Format port
        if rule.port != "any" && !rule.port.is_empty() {
            args.push("to");
            args.push("any");
            args.push("port");
            args.push(&rule.port);
        }

        self.run_cmd(&args)?;
        Ok(())
    }

    fn edit_rule(&self, rule_id: &str, new_rule: &FirewallRule) -> Result<(), FirewallError> {
        let action_str = match new_rule.action {
            RuleAction::Allow => "allow",
            RuleAction::Deny => "deny",
            RuleAction::Reject => "reject",
        };

        // Note: The insert+delete approach creates a small transient window (~100ms)
        // where both rules coexist in the UFW ruleset before the old rule is deleted.
        let mut args = vec!["insert", rule_id, action_str];

        // Format protocol
        if new_rule.protocol != "any" {
            args.push("proto");
            args.push(&new_rule.protocol);
        }

        // Format source
        let src = if new_rule.source.eq_ignore_ascii_case("Anywhere") || new_rule.source.is_empty() {
            "any"
        } else {
            &new_rule.source
        };
        args.push("from");
        args.push(src);

        // Format port
        if new_rule.port != "any" && !new_rule.port.is_empty() {
            args.push("to");
            args.push("any");
            args.push("port");
            args.push(&new_rule.port);
        }

        // Execute insert
        self.run_cmd(&args)?;

        // The old rule shifts down by 1 to rule_id + 1. We delete it now.
        if let Ok(id_num) = rule_id.parse::<usize>() {
            let old_rule_id = (id_num + 1).to_string();
            self.delete_rule(&old_rule_id)?;
        } else {
            return Err(FirewallError::ExecutionFailed("Invalid rule ID format for UFW edit".to_string()));
        }

        Ok(())
    }

    fn delete_rule(&self, rule_id: &str) -> Result<(), FirewallError> {
        self.run_cmd(&["--force", "delete", rule_id])?;
        Ok(())
    }

    fn toggle(&self, enable: bool) -> Result<(), FirewallError> {
        if enable {
            self.run_cmd(&["--force", "enable"])?;
        } else {
            self.run_cmd(&["disable"])?;
        }
        Ok(())
    }

    fn flush_all(&self) -> Result<(), FirewallError> {
        self.run_cmd(&["--force", "reset"])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ufw_status_mock() {
        let mock_stdout = "Status: active\n\
        \n\
             To                         Action      From\n\
             --                         ------      ----\n\
        [ 1] 22/tcp                     ALLOW IN    192.168.0.0/24\n\
        [ 2] 87/udp                     ALLOW IN    Anywhere\n\
        [ 3] 80                         DENY IN     Anywhere\n\
        [ 4] 443 (v6)                   ALLOW IN    Anywhere (v6)";

        let rules = parse_ufw_status(mock_stdout).unwrap();
        assert_eq!(rules.len(), 4);

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
        assert_eq!(rules[2].protocol, "any");
        assert_eq!(rules[2].action, RuleAction::Deny);
        assert_eq!(rules[2].source, "Anywhere");

        assert_eq!(rules[3].id, "4");
        assert_eq!(rules[3].port, "443");
        assert_eq!(rules[3].protocol, "any");
        assert_eq!(rules[3].action, RuleAction::Allow);
        assert_eq!(rules[3].source, "Anywhere");
    }

    #[test]
    fn test_parse_ufw_policy_mock() {
        let mock_stdout = "Status: active\n\
        Logging: on (low)\n\
        Default: deny (incoming), allow (outgoing), disabled (routed)\n\
        New profiles: skip";
        
        let policy = parse_ufw_policy(mock_stdout).unwrap();
        assert_eq!(policy, "DENY");
    }
}
