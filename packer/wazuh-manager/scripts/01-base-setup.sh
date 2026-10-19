#!/usr/bin/env bash
#
# 01-base-setup.sh - Base system configuration for SentryLens Wazuh Manager VM
# Runs after Ubuntu autoinstall completes

set -euo pipefail

SSH_USERNAME="${SSH_USERNAME:-sentrylens}"
SSH_PASSWORD="${SSH_PASSWORD:-sentrylens}"

log() { echo -e "\033[36m==>\033[0m $*"; }
ok()   { echo -e "\033[32mOK\033[0m  $*"; }
warn() { echo -e "\033[33m!!\033[0m  $*"; }
err()  { echo -e "\033[31mXX\033[0m  $*"; }

log "Starting base system setup..."

# Update system
log "Updating package lists..."
apt-get update -y

log "Upgrading packages..."
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install essential packages
log "Installing essential packages..."
apt-get install -y \
    curl \
    wget \
    gnupg \
    lsb-release \
    ca-certificates \
    python3 \
    python3-pip \
    python3-venv \
    net-tools \
    iproute2 \
    jq \
    unzip \
    tar \
    gzip \
    htop \
    vim \
    git \
    netcat-openbsd \
    socat \
    tcpdump \
    tshark \
    wireshark-common \
    virtualbox-guest-utils \
    virtualbox-guest-dkms \
    linux-headers-$(uname -r)

# Configure timezone
log "Setting timezone to UTC..."
timedatectl set-timezone UTC

# Configure SSH for better security and compatibility
log "Configuring SSH..."
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh

# Disable automatic updates (we'll handle updates manually)
log "Disabling automatic updates..."
systemctl disable apt-daily-upgrade.timer apt-daily.timer 2>/dev/null || true
apt-get remove -y unattended-upgrades 2>/dev/null || true

# Create directories for SentryLens
log "Creating SentryLens directories..."
mkdir -p /opt/sentrylens/{scripts,logs,config,network}
mkdir -p /var/log/sentrylens
mkdir -p /home/${SSH_USERNAME}/.ssh
chown -R ${SSH_USERNAME}:${SSH_USERNAME} /home/${SSH_USERNAME}/.ssh
chmod 700 /home/${SSH_USERNAME}/.ssh

# Configure log rotation for SentryLens
cat > /etc/logrotate.d/sentrylens <<'EOF'
/var/log/sentrylens/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 sentrylens adm
    sharedscripts
    postrotate
        systemctl reload sentrylens-network > /dev/null 2>&1 || true
    endscript
}
EOF

# Set up bash aliases and environment
cat >> /home/${SSH_USERNAME}/.bashrc <<'EOF'

# SentryLens aliases
alias wazuh-status='systemctl status wazuh-manager wazuh-indexer wazuh-dashboard'
alias wazuh-logs='journalctl -u wazuh-manager -u wazuh-indexer -u wazuh-dashboard -f'
alias wazuh-passwords='sudo tar -O -xvf ~/wazuh-install/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt 2>/dev/null || echo "Passwords not found"'
alias sl-logs='tail -f /var/log/sentrylens/*.log 2>/dev/null'
alias sl-network='sudo tshark -i any -f "tcp port 1514 or tcp port 1515" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e _ws.col.Info'

# Wazuh API helpers
wazuh-api() {
    local endpoint="${1:-/}"
    local manager_ip=$(hostname -I | awk '{print $1}')
    curl -k -u "wazuh-wui:$(wazuh-passwords | grep 'wazuh-wui' | awk '{print $2}')" \
         "https://${manager_ip}:55000${endpoint}" 2>/dev/null | jq .
}

export PATH="$PATH:/opt/sentrylens/scripts"
EOF

chown ${SSH_USERNAME}:${SSH_USERNAME} /home/${SSH_USERNAME}/.bashrc

# Configure sudo for passwordless operation for the sentrylens user
log "Configuring sudo..."
echo "${SSH_USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${SSH_USERNAME}
chmod 440 /etc/sudoers.d/${SSH_USERNAME}

# Increase file limits
log "Configuring file limits..."
cat >> /etc/security/limits.conf <<'EOF'

# SentryLens / Wazuh limits
sentrylens soft nofile 65536
sentrylens hard nofile 65536
root soft nofile 65536
root hard nofile 65536
EOF

# Kernel parameters for better network performance
log "Configuring kernel parameters..."
cat >> /etc/sysctl.d/99-sentrylens.conf <<'EOF'
# Network performance for Wazuh/tshark
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 8192

# Allow non-root tshark capture
kernel.unprivileged_bpf_disabled = 1
EOF

sysctl --system >/dev/null 2>&1 || true

# Add sentrylens user to wireshark group for packet capture
usermod -a -G wireshark ${SSH_USERNAME} 2>/dev/null || true

ok "Base system setup completed"