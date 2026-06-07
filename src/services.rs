use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketInfo {
    pub local_ip: String,
    pub local_port: u16,
    pub protocol: String, // "tcp", "tcp6", "udp", "udp6"
    pub process_name: String,
    pub pid: Option<i32>,
}

fn parse_ipv4_hex(hex_str: &str) -> Option<String> {
    if hex_str.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(hex_str, 16).ok()?;
    // Little-endian translation
    let ip = Ipv4Addr::from(val.swap_bytes());
    Some(ip.to_string())
}

fn parse_ipv6_hex(hex_str: &str) -> Option<String> {
    if hex_str.len() != 32 {
        return None;
    }
    let mut segments = [0u16; 8];
    for i in 0..8 {
        let chunk = &hex_str[i * 4..(i + 1) * 4];
        let val = u32::from_str_radix(chunk, 16).ok()?;
        // /proc/net/tcp6 stores each 32-bit block in host byte order (little-endian on x86)
        segments[i] = (val.swap_bytes() & 0xFFFF) as u16;
    }
    // Convert segments array of little-endian u16s
    // To construct the standard Ipv6Addr, we read them in big-endian order
    // But since the kernel stores them as 4 u32s in host byte order:
    let mut octets = [0u8; 16];
    for part in 0..4 {
        let word_hex = &hex_str[part * 8..(part + 1) * 8];
        let word_val = u32::from_str_radix(word_hex, 16).ok()?;
        let word_bytes = word_val.to_ne_bytes(); // Read as native bytes
        octets[part * 4..(part + 1) * 4].copy_from_slice(&word_bytes);
    }
    let ip = Ipv6Addr::from(octets);
    Some(ip.to_string())
}

/// Builds a mapping from socket inode numbers to (process_name, pid)
fn get_inode_process_map() -> HashMap<u64, (String, i32)> {
    let mut map = HashMap::new();
    let proc_dir = Path::new("/proc");
    if let Ok(entries) = fs::read_dir(proc_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<i32>() {
                let fd_dir = path.join("fd");
                if let Ok(fd_entries) = fs::read_dir(fd_dir) {
                    for fd_entry in fd_entries.flatten() {
                        if let Ok(target) = fs::read_link(fd_entry.path()) {
                            let target_str = target.to_string_lossy();
                            if target_str.starts_with("socket:[") && target_str.ends_with(']') {
                                let inode_str = &target_str[8..target_str.len() - 1];
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    let mut proc_name = "unknown".to_string();
                                    if let Ok(comm) = fs::read_to_string(path.join("comm")) {
                                        proc_name = comm.trim().to_string();
                                    }
                                    map.insert(inode, (proc_name, pid));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

fn parse_proc_net_file(
    file_path: &str,
    protocol: &str,
    inode_map: &HashMap<u64, (String, i32)>,
) -> Result<Vec<SocketInfo>, anyhow::Error> {
    let mut list = Vec::new();
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return Ok(list), // Skip if file is missing (e.g. IPv6 disabled)
    };

    let is_tcp = protocol.starts_with("tcp");

    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        // Filter state: for TCP, we only care about state 0A (TCP_LISTEN)
        // For UDP, state doesn't mean LISTEN, we scan all entries
        if is_tcp && parts[3] != "0A" {
            continue;
        }

        let local_addr = parts[1];
        let inode_val = parts[9].parse::<u64>().unwrap_or(0);

        let addr_parts: Vec<&str> = local_addr.split(':').collect();
        if addr_parts.len() != 2 {
            continue;
        }

        let ip_hex = addr_parts[0];
        let port_hex = addr_parts[1];

        let ip = if ip_hex.len() == 8 {
            parse_ipv4_hex(ip_hex)
        } else {
            parse_ipv6_hex(ip_hex)
        };

        let port = u16::from_str_radix(port_hex, 16).ok();

        if let (Some(ip_str), Some(port_val)) = (ip, port) {
            let (proc_name, pid) = if inode_val > 0 {
                inode_map
                    .get(&inode_val)
                    .cloned()
                    .map(|(name, pid)| (name, Some(pid)))
                    .unwrap_or_else(|| ("unknown".to_string(), None))
            } else {
                ("unknown".to_string(), None)
            };

            list.push(SocketInfo {
                local_ip: ip_str,
                local_port: port_val,
                protocol: protocol.to_string(),
                process_name: proc_name,
                pid,
            });
        }
    }

    Ok(list)
}

pub fn get_listening_services() -> Result<Vec<SocketInfo>, anyhow::Error> {
    let inode_map = get_inode_process_map();
    let mut services = Vec::new();

    services.extend(parse_proc_net_file("/proc/net/tcp", "tcp", &inode_map)?);
    services.extend(parse_proc_net_file("/proc/net/tcp6", "tcp6", &inode_map)?);
    services.extend(parse_proc_net_file("/proc/net/udp", "udp", &inode_map)?);
    services.extend(parse_proc_net_file("/proc/net/udp6", "udp6", &inode_map)?);

    // De-duplicate listening services (e.g. if bound to multiple interfaces, group them)
    // For TUI simplicity, we return them sorted by port
    services.sort_by_key(|s| s.local_port);

    Ok(services)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_hex() {
        assert_eq!(parse_ipv4_hex("0100007F").unwrap(), "127.0.0.1");
        assert_eq!(parse_ipv4_hex("00000000").unwrap(), "0.0.0.0");
        assert_eq!(parse_ipv4_hex("invalid"), None);
    }

    #[test]
    fn test_parse_proc_net_tcp_mock() {
        let mock_tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
        0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0        0 12345 1 0000000000000000\n\
        1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000     0 67890 1 0000000000000000\n\
        2: 0100007F:0050 00000000:0000 03 00000000:00000000 00:00000000 00000000  1000     0 11111 1 0000000000000000"; // State 03 is NOT listen

        let mut inode_map = HashMap::new();
        inode_map.insert(12345, ("sshd".to_string(), 123));
        inode_map.insert(67890, ("nginx".to_string(), 456));

        // Create temporary mock file
        let path = "./test_proc_net_tcp";
        fs::write(path, mock_tcp).unwrap();

        let result = parse_proc_net_file(path, "tcp", &inode_map).unwrap();
        assert_eq!(result.len(), 2);

        assert_eq!(result[0].local_ip, "0.0.0.0");
        assert_eq!(result[0].local_port, 22);
        assert_eq!(result[0].process_name, "sshd");
        assert_eq!(result[0].pid, Some(123));

        assert_eq!(result[1].local_ip, "127.0.0.1");
        assert_eq!(result[1].local_port, 8080); // 1F90 hex is 8080 dec
        assert_eq!(result[1].process_name, "nginx");
        assert_eq!(result[1].pid, Some(456));

        fs::remove_file(path).unwrap();
    }
}
