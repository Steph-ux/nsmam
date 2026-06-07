<p align="center">
  <img src="assets/nsmam_banner.png" width="400" alt="NSMAM Banner">
</p>

# NSMAM (Network Security Manager All-in-One Monitor)

A lightweight, premium Text User Interface (TUI) firewall manager written in Rust. It provides a unified, interactive dashboard to monitor and manipulate system rules for **UFW**, **nftables**, and **iptables** in Linux environments (Debian, Ubuntu, CentOS, RHEL).

## Features

- **Unified Firewall Control**: Abstracted operations supporting UFW, nftables, and iptables.
- **Dynamic Service Detection**: Scans active listening sockets directly via `/proc/net` (IPv4/v6, TCP/UDP) to easily select target ports/protocols instead of typing them manually.
- **SSH Lockout Protection**: Automatically tracks session rule changes and reverts them instantly in reverse order if connection is lost (interceptor for `SIGHUP` signal).
- **Security Audit Logs**: Structured logging of all firewall operations to `/var/log/nsmam.log` tracking timestamps, backend used, and the real executing user (`SUDO_USER` / `DOAS_USER`).
- **Multiplexer Detection**: Warns the administrator if running inside a terminal multiplexer (`tmux` or `screen`) where connection drops may bypass the SIGHUP signal.

## Requirements

- **Linux OS** (Debian, Ubuntu, RHEL, CentOS)
- **Rust Toolchain** (`cargo` & `rustc` version 1.80+) *only if compiling from source*.

## Installation

You can install NSMAM using either the precompiled standalone binary (no Rust/Cargo toolchain required) or by compiling from source.

### Option 1: Precompiled Standalone Binary (Recommended)

1. Download the latest `nsmam-x86_64-linux` static binary from the [GitHub Releases](https://github.com/Steph-ux/nsmam/releases).
2. Install it to your system path:
   ```bash
   sudo cp nsmam-x86_64-linux /usr/local/bin/nsmam
   sudo chmod +x /usr/local/bin/nsmam
   ```

### Option 2: Compile from Source

Run the automated installer script:
```bash
sudo ./install.sh
```
The script will auto-detect your active firewall backend (or prompt you to force one), configure log file privileges (`640` owned by `root:adm`), compile the release binary, and install it to `/usr/local/bin/nsmam`.

## Usage

Launch the TUI interface with root privileges:

```bash
sudo nsmam
```

By default, NSMAM loads the forced backend configured in `/etc/nsmam/config.toml` (or auto-detects if missing). You can manually override the backend on launch using command-line arguments:

```bash
# Force a specific backend (ufw, iptables, or nftables)
sudo nsmam --backend iptables
# Or using positional argument
sudo ./nsmam-x86_64-linux ufw
```

### Key Bindings

| Key | Action |
| --- | --- |
| `a` | Open Add Rule form |
| `d` | Delete selected rule |
| `t` | Toggle firewall state (Enable/Disable) |
| `f` | Flush all rules |
| `r` | Refresh rules and services |
| `↑` / `↓` | Select rules / navigate service list |
| `Tab` / `BackTab` | Navigate form inputs |
| `Space` / `Enter` | Choose selector values / Submit forms |
| `Esc` / `q` | Cancel modals / Quit TUI |

## License

MIT License.
