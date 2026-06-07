#!/bin/bash
set -e

# 1. Check root privilege
if [ "$EUID" -ne 0 ]; then
    echo "Error: install.sh must be run as root/sudo."
    echo "Try running: sudo ./install.sh"
    exit 1
fi

# 2. Check cargo & rustc presence
if ! command -v cargo &> /dev/null || ! command -v rustc &> /dev/null; then
    echo "Error: Cargo and Rust are required to compile and install NSMAM."
    echo "Please install Rust (https://rustup.rs) and try again."
    exit 1
fi

echo "============================================="
echo "        NSMAM Installation Script            "
echo "============================================="

# 3. Prompt user for firewall backend selection
BACKEND="auto"
if [ -n "$1" ]; then
    BACKEND="$1"
elif command -v whiptail &> /dev/null && [ -t 0 ]; then
    CHOICE=$(whiptail --title "NSMAM Firewall Backend" --menu "Select your default firewall backend:" 15 60 4 \
        "1" "Auto-detect active backend (Default)" \
        "2" "Force UFW" \
        "3" "Force nftables" \
        "4" "Force iptables" 3>&1 1>&2 2>&3)
    case $CHOICE in
        1) BACKEND="auto";;
        2) BACKEND="ufw";;
        3) BACKEND="nftables";;
        4) BACKEND="iptables";;
    esac
elif [ -t 0 ]; then
    echo "Select your default firewall backend:"
    echo "  1) Auto-detect active backend (Default)"
    echo "  2) Force UFW"
    echo "  3) Force nftables"
    echo "  4) Force iptables"
    read -p "Enter choice [1-4]: " choice
    case $choice in
        2) BACKEND="ufw";;
        3) BACKEND="nftables";;
        4) BACKEND="iptables";;
        *) BACKEND="auto";;
    esac
else
    echo "Non-interactive shell detected, defaulting to: auto"
    BACKEND="auto"
fi

echo "Selected backend: $BACKEND"

# 4. Create configuration directory
echo "Creating /etc/nsmam/ configuration..."
mkdir -p /etc/nsmam
cat <<EOF > /etc/nsmam/config.toml
backend = "$BACKEND"
log_file = "/var/log/nsmam.log"
EOF
chmod 644 /etc/nsmam/config.toml

# 5. Initialize log file with correct permissions
echo "Initializing /var/log/nsmam.log..."
touch /var/log/nsmam.log
chmod 640 /var/log/nsmam.log

if getent group adm >/dev/null; then
    chown root:adm /var/log/nsmam.log
    echo "Log file owned by root:adm"
else
    chown root:root /var/log/nsmam.log
    echo "Log file owned by root:root (adm group not found)"
fi

# 6. Compile and build Rust TUI
echo "Compiling NSMAM (this may take a minute)..."
cargo build --release

# 7. Install binary
echo "Installing nsmam to /usr/local/bin/nsmam..."
cp target/release/nsmam /usr/local/bin/nsmam
chmod 755 /usr/local/bin/nsmam
chown root:root /usr/local/bin/nsmam

echo "============================================="
echo "NSMAM has been successfully installed!"
echo "Run it now using: sudo nsmam"
echo "============================================="
