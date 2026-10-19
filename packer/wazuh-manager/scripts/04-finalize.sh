#!/usr/bin/env bash
#
# 04-finalize.sh - Finalize VM for distribution

set -euo pipefail

SSH_USERNAME="${SSH_USERNAME:-sentrylens}"
SSH_PASSWORD="${SSH_PASSWORD:-sentrylens}"

log() { echo -e "\033[36m==>\033[0m $*"; }
ok()   { echo -e "\033[32mOK\033[0m  $*"; }
warn() { echo -e "\033[33m!!\033[0m  $*"; }
err()  { echo -e "\033[31mXX\033[0m  $*"; }

log "Finalizing VM for distribution..."

# Clean up package cache
log "Cleaning package cache..."
apt-get clean
apt-get autoclean
apt-get autoremove -y
rm -rf /var/lib/apt/lists/*
ok "Package cache cleaned"

# Remove temporary files
log "Removing temporary files..."
rm -rf /tmp/* /var/tmp/*
rm -rf /home/${SSH_USERNAME}/.cache
ok "Temporary files removed"

# Remove SSH host keys (will be regenerated on first boot)
log "Removing SSH host keys..."
rm -f /etc/ssh/ssh_host_*
ok "SSH host keys removed"

# Remove machine-id (will be regenerated on first boot)
log "Removing machine-id..."
> /etc/machine-id
> /var/lib/dbus/machine-id
ok "Machine ID cleared"

# Remove cloud-init artifacts
log "Cleaning cloud-init..."
cloud-init clean --logs --seed 2>/dev/null || true
rm -rf /var/lib/cloud/instances/*
rm -rf /var/lib/cloud/data/*
ok "Cloud-init cleaned"

# Remove bash history
log "Clearing bash history..."
> /home/${SSH_USERNAME}/.bash_history
> /root/.bash_history
ok "Bash history cleared"

# Create first-boot service to regenerate keys and configure
log "Creating first-boot service..."
cat > /etc/systemd/system/sentrylens-firstboot.service <<'EOF'
[Unit]
Description=SentryLens First Boot Configuration
Before=network-online.target
Wants=network-online.target
ConditionPathExists=!/etc/sentrylens/.firstboot_done

[Service]
Type=oneshot
ExecStart=/opt/sentrylens/scripts/first-boot.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /opt/sentrylens/scripts
cat > /opt/sentrylens/scripts/first-boot.sh <<'FIRSTBOOT'
#!/usr/bin/env bash
#
# First boot configuration - runs once on initial VM boot

set -euo pipefail

log() { echo "[FIRSTBOOT] $*" | systemd-cat -t sentrylens-firstboot; }

log "Running first-boot configuration..."

# Regenerate SSH host keys
log "Regenerating SSH host keys..."
ssh-keygen -A
systemctl restart ssh

# Generate new machine-id
log "Generating new machine-id..."
systemd-machine-id-setup

# Get new IP address
PRIMARY_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "${PRIMARY_IFACE}" ]; then
    PRIMARY_IFACE=$(ls /sys/class/net/ | grep -E '^(eth|ens|enp)' | head -1)
fi

IP_ADDR=$(ip addr show "${PRIMARY_IFACE}" | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
log "New IP address: ${IP_ADDR}"

# Update Wazuh configuration with new IP if needed
# (Wazuh binds to 0.0.0.0 so this is mostly for reference)
echo "${IP_ADDR}" > /opt/sentrylens/config/vm-ip.txt

# Mark first boot as done
mkdir -p /etc/sentrylens
touch /etc/sentrylens/.firstboot_done

log "First-boot configuration completed"
FIRSTBOOT

chmod +x /opt/sentrylens/scripts/first-boot.sh
systemctl enable sentrylens-firstboot.service
ok "First-boot service created and enabled"

# Create a welcome message / MOTD
log "Creating welcome message..."
cat > /etc/motd <<'MOTD_EOF'

   _____ _           _     _____           _
  / ____| |         | |   / ____|         | |
 | (___ | |__   ___ | |_ | (___  _ __   __| | _____  __
  \___ \| '_ \ / _ \| __| \___ \| '_ \ / _` |/ _ \ \/ /
  ____) | | | | (_) | |_  ____) | | | | (_| | (_) >  <
 |_____/|_| |_|\___/ \__| |_____/|_| |_|\__,_|\___/_/\_\

                        Wazuh Manager VM
                        Version: {{VERSION}}
                        Built: {{BUILD_DATE}}

============================================================
ACCESS INFORMATION:
============================================================
Dashboard:     https://<VM_IP>/
Manager API:   https://<VM_IP>:55000
Indexer API:   https://<VM_IP>:9200

Username:      admin
Password:      Check /home/sentrylens/wazuh-install/wazuh-passwords.txt
               or run: wazuh-passwords

============================================================
SENTRYLENS INTEGRATION:
============================================================
Backend .env configuration:
  WAZUH_MANAGER_URL=https://<VM_IP>:55000
  WAZUH_MANAGER_USER=wazuh-wui
  WAZUH_MANAGER_PASSWORD=<from passwords file>

  WAZUH_INDEXER_URL=https://<VM_IP>:9200
  WAZUH_INDEXER_USER=admin
  WAZUH_INDEXER_PASSWORD=<from passwords file>

============================================================
USEFUL COMMANDS:
============================================================
wazuh-status        - Check Wazuh services status
wazuh-logs          - Follow Wazuh service logs
wazuh-passwords     - Show Wazuh passwords
sl-logs             - Follow SentryLens logs
sl-network          - Live network capture (tshark)

============================================================
DOCUMENTATION:
============================================================
https://github.com/your-org/SentryLens
MOTD_EOF

# Replace version placeholders
VERSION=$(cat /opt/sentrylens/config/version.txt 2>/dev/null || echo "1.0.0")
BUILD_DATE=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
sed -i "s/{{VERSION}}/${VERSION}/g" /etc/motd
sed -i "s/{{BUILD_DATE}}/${BUILD_DATE}/g" /etc/motd

# Save version info
echo "${VERSION}" > /opt/sentrylens/config/version.txt
echo "${BUILD_DATE}" > /opt/sentrylens/config/build-date.txt

# Create a simple health check script
cat > /opt/sentrylens/scripts/health-check.sh <<'HEALTH_EOF'
#!/usr/bin/env bash
# Health check for SentryLens Wazuh Manager VM

check_service() {
    local svc=$1
    if systemctl is-active --quiet "$svc"; then
        echo "✓ $svc: running"
        return 0
    else
        echo "✗ $svc: $(systemctl is-active "$svc" 2>/dev/null || echo "not found")"
        return 1
    fi
}

echo "=== SentryLens Wazuh Manager Health Check ==="
echo

FAILED=0
check_service wazuh-manager || FAILED=1
check_service wazuh-indexer || FAILED=1
check_service wazuh-dashboard || FAILED=1
check_service ssh || FAILED=1
check_service sentrylens-network-capture.timer || FAILED=1

echo
if [ $FAILED -eq 0 ]; then
    echo "All services healthy ✓"
    exit 0
else
    echo "Some services unhealthy ✗"
    exit 1
fi
HEALTH_EOF

chmod +x /opt/sentrylens/scripts/health-check.sh

# Create version file
cat > /opt/sentrylens/config/version.txt <<EOF
${VERSION}
EOF

cat > /opt/sentrylens/config/build-info.json <<EOF
{
  "version": "${VERSION}",
  "build_date": "${BUILD_DATE}",
  "ubuntu_version": "22.04.5",
  "wazuh_version": "4.14.0",
  "builder": "packer",
  "project": "SentryLens"
}
EOF

# Set proper ownership
chown -R ${SSH_USERNAME}:${SSH_USERNAME} /opt/sentrylens
chown -R ${SSH_USERNAME}:${SSH_USERNAME} /var/log/sentrylens

# Disable root login
log "Disabling root login..."
passwd -l root 2>/dev/null || true

# Final sync
sync

ok "VM finalization completed"
log "VM is ready for packaging!"