#!/usr/bin/env bash
#
# 01-base-setup.sh - Base system configuration for SentryLens Kali Attacker VM

set -euo pipefail

SSH_USERNAME="${SSH_USERNAME:-kali}"
SSH_PASSWORD="${SSH_PASSWORD:-kali}"

log() { echo -e "\033[36m==>\033[0m $*"; }
ok()   { echo -e "\033[32mOK\033[0m  $*"; }
warn() { echo -e "\033[33m!!\033[0m  $*"; }
err()  { echo -e "\033[31mXX\033[0m  $*"; }

log "Starting Kali base system setup..."

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

# Configure SSH
log "Configuring SSH..."
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh

# Disable automatic updates
log "Disabling automatic updates..."
systemctl disable apt-daily-upgrade.timer apt-daily.timer 2>/dev/null || true
apt-get remove -y unattended-upgrades 2>/dev/null || true

# Create directories for SentryLens
log "Creating SentryLens directories..."
mkdir -p /opt/sentrylens/{scripts,logs,config,attacks}
mkdir -p /var/log/sentrylens
mkdir -p /home/${SSH_USERNAME}/.ssh
chown -R ${SSH_USERNAME}:${SSH_USERNAME} /home/${SSH_USERNAME}/.ssh
chmod 700 /home/${SSH_USERNAME}/.ssh

# Set up bash aliases and environment
cat >> /home/${SSH_USERNAME}/.bashrc <<'EOF'

# SentryLens Kali aliases
alias sl-attacks='ls -la /opt/sentrylens/attacks/'
alias sl-network='sudo tshark -i any -f "tcp port 1514 or tcp port 1515 or tcp port 445 or tcp port 3389" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e _ws.col.Info'
alias msfconsole='msfconsole -q'

# Attack helpers
attack-smb() {
    local target="${1:-}"
    if [ -z "${target}" ]; then
        echo "Usage: attack-smb <target_ip>"
        return 1
    fi
    echo "Running SMB enumeration against ${target}..."
    crackmapexec smb ${target} -u '' -p '' --shares 2>/dev/null || smbclient -L //${target} -N 2>/dev/null || enum4linux -a ${target}
}

attack-rdp() {
    local target="${1:-}"
    local user="${2:-Administrator}"
    local passlist="${3:-/usr/share/wordlists/rockyou.txt}"
    if [ -z "${target}" ]; then
        echo "Usage: attack-rdp <target_ip> [user] [passlist]"
        return 1
    fi
    echo "Testing RDP on ${target}..."
    hydra -l "${user}" -P "${passlist}" rdp://${target} -t 4 -V
}

attack-smb-brute() {
    local target="${1:-}"
    local userlist="${2:-/usr/share/wordlists/userlist.txt}"
    local passlist="${3:-/usr/share/wordlists/rockyou.txt}"
    if [ -z "${target}" ]; then
        echo "Usage: attack-smb-brute <target_ip> [userlist] [passlist]"
        return 1
    fi
    crackmapexec smb ${target} -u ${userlist} -p ${passlist} --local-auth 2>/dev/null
}

export PATH="$PATH:/opt/sentrylens/scripts"
EOF

chown ${SSH_USERNAME}:${SSH_USERNAME} /home/${SSH_USERNAME}/.bashrc

# Configure sudo
log "Configuring sudo..."
echo "${SSH_USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${SSH_USERNAME}
chmod 440 /etc/sudoers.d/${SSH_USERNAME}

# Increase file limits
log "Configuring file limits..."
cat >> /etc/security/limits.conf <<'EOF'

# SentryLens / Kali limits
kali soft nofile 65536
kali hard nofile 65536
root soft nofile 65536
root hard nofile 65536
EOF

# Kernel parameters
log "Configuring kernel parameters..."
cat >> /etc/sysctl.d/99-sentrylens.conf <<'EOF'
# Network performance for attack tools
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF

sysctl --system >/dev/null 2>&1 || true

# Add user to wireshark group
usermod -a -G wireshark ${SSH_USERNAME} 2>/dev/null || true

ok "Kali base system setup completed"