#!/usr/bin/env bash
#
# 03-configure-network.sh - Configure network for SentryLens

set -euo pipefail

SSH_USERNAME="${SSH_USERNAME:-sentrylens}"
SSH_PASSWORD="${SSH_PASSWORD:-sentrylens}"

log() { echo -e "\033[36m==>\033[0m $*"; }
ok()   { echo -e "\033[32mOK\033[0m  $*"; }
warn() { echo -e "\033[33m!!\033[0m  $*"; }
err()  { echo -e "\033[31mXX\033[0m  $*"; }

log "Configuring network..."

# Get the primary network interface
PRIMARY_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "${PRIMARY_IFACE}" ]; then
    PRIMARY_IFACE=$(ls /sys/class/net/ | grep -E '^(eth|ens|enp)' | head -1)
fi

log "Primary interface: ${PRIMARY_IFACE}"

# Configure static IP via netplan (optional - we'll keep DHCP but make it predictable)
# Create a netplan config that ensures consistent interface naming
cat > /etc/netplan/99-sentrylens.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${PRIMARY_IFACE}:
      dhcp4: true
      dhcp-identifier: mac
      optional: true
EOF

netplan apply 2>/dev/null || true

# Wait for network to be ready
log "Waiting for network..."
for i in {1..30}; do
    if ip addr show "${PRIMARY_IFACE}" | grep -q "inet "; then
        break
    fi
    sleep 1
done

IP_ADDR=$(ip addr show "${PRIMARY_IFACE}" | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
log "VM IP address: ${IP_ADDR}"

# Save IP to a known location for SentryLens
echo "${IP_ADDR}" > /opt/sentrylens/config/vm-ip.txt
chown ${SSH_USERNAME}:${SSH_USERNAME} /opt/sentrylens/config/vm-ip.txt

# Configure firewall (UFW) - allow Wazuh ports
log "Configuring firewall..."
apt-get install -y ufw

# Reset to defaults
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow 22/tcp comment 'SSH'

# Allow Wazuh ports
ufw allow 1514/tcp comment 'Wazuh Agent Logs'
ufw allow 1515/tcp comment 'Wazuh Agent Registration'
ufw allow 55000/tcp comment 'Wazuh Manager API'
ufw allow 9200/tcp comment 'Wazuh Indexer API'
ufw allow 443/tcp comment 'Wazuh Dashboard'

# Allow tshark/tcpdump for network monitoring
# (no specific ports needed - raw socket capture)

# Enable firewall
ufw --force enable
ok "Firewall configured and enabled"

# Configure systemd-resolved for better DNS
log "Configuring DNS..."
systemctl enable systemd-resolved
systemctl start systemd-resolved

# Create network monitoring directory
mkdir -p /var/log/sentrylens/network
chown -R ${SSH_USERNAME}:${SSH_USERNAME} /var/log/sentrylens/network

# Create a simple network capture script for tshark
cat > /opt/sentrylens/scripts/capture-network.sh <<'CAPEOF'
#!/usr/bin/env bash
# Network packet capture for SentryLens Red vs Blue
# Captures metadata only (no payload) to CSV

set -euo pipefail

OUTPUT_DIR="/var/log/sentrylens/network"
OUTPUT_FILE="${OUTPUT_DIR}/network-$(date +%Y%m%d-%H%M%S).csv"
INTERFACE="${1:-any}"
DURATION="${2:-3600}"  # Default 1 hour

mkdir -p "${OUTPUT_DIR}"

# CSV header
echo "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,length,tcp_flags,info" > "${OUTPUT_FILE}"

# Capture with tshark - metadata only, no payload
# Filter for relevant traffic: Wazuh agent ports + common attack vectors
tshark -i "${INTERFACE}" \
    -a duration:${DURATION} \
    -f "tcp port 1514 or tcp port 1515 or tcp port 22 or tcp port 445 or tcp port 3389 or tcp port 5985 or tcp port 5986 or udp port 137 or udp port 138 or udp port 139" \
    -T fields \
    -e frame.time_epoch \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e tcp.dstport \
    -e udp.srcport \
    -e udp.dstport \
    -e _ws.col.Protocol \
    -e frame.len \
    -e tcp.flags \
    -e _ws.col.Info \
    -E header=y \
    -E separator=, \
    -E quote=d \
    -E occurrence=f \
    >> "${OUTPUT_FILE}" 2>/dev/null

# Convert epoch to readable timestamp
awk -F, 'NR==1{print; next} {$1=strftime("%Y-%m-%d %H:%M:%S", $1); print}' OFS=, "${OUTPUT_FILE}" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "${OUTPUT_FILE}"

echo "Capture saved to: ${OUTPUT_FILE}"
CAPEOF

chmod +x /opt/sentrylens/scripts/capture-network.sh
chown ${SSH_USERNAME}:${SSH_USERNAME} /opt/sentrylens/scripts/capture-network.sh

# Create systemd service for continuous network monitoring
cat > /etc/systemd/system/sentrylens-network.service <<'SVC_EOF'
[Unit]
Description=SentryLens Network Monitor (tshark)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sentrylens
Group=sentrylens
ExecStart=/opt/sentrylens/scripts/capture-network.sh any 86400
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/sentrylens/network
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
SVC_EOF

# Also create a timer for periodic captures (every hour, rotate)
cat > /etc/systemd/system/sentrylens-network.timer <<'TIMER_EOF'
[Unit]
Description=Run SentryLens network capture hourly

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=5m

[Install]
WantedBy=timers.target
TIMER_EOF

cat > /etc/systemd/system/sentrylens-network-capture.service <<'CAPSVC_EOF'
[Unit]
Description=SentryLens Network Capture (hourly)
After=network-online.target

[Service]
Type=oneshot
User=sentrylens
Group=sentrylens
ExecStart=/opt/sentrylens/scripts/capture-network.sh any 3600
StandardOutput=journal
StandardError=journal
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
CAPSVC_EOF

systemctl daemon-reload
systemctl enable sentrylens-network-capture.timer
systemctl start sentrylens-network-capture.timer
ok "Network monitoring service configured"

# Configure logrotate for network captures
cat > /etc/logrotate.d/sentrylens-network <<'EOF'
/var/log/sentrylens/network/*.csv {
    hourly
    rotate 168  # Keep 1 week of hourly captures
    compress
    delaycompress
    missingok
    notifempty
    create 640 sentrylens adm
    sharedscripts
    postrotate
        systemctl reload sentrylens-network-capture > /dev/null 2>&1 || true
    endscript
}
EOF

ok "Network configuration completed"