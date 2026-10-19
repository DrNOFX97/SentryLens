#!/usr/bin/env bash
#
# 04-finalize.sh - Finalize Kali VM for distribution

set -euo pipefail

SSH_USERNAME="${SSH_USERNAME:-kali}"
SSH_PASSWORD="${SSH_PASSWORD:-kali}"

log() { echo -e "\033[36m==>\033[0m $*"; }
ok()   { echo -e "\033[32mOK\033[0m  $*"; }
warn() { echo -e "\033[33m!!\033[0m  $*"; }
err()  { echo -e "\033[31mXX\033[0m  $*"; }

log "Finalizing Kali VM for distribution..."

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
rm -rf /home/${SSH_USERNAME}/go/pkg/mod/cache 2>/dev/null || true
ok "Temporary files removed"

# Remove SSH host keys
log "Removing SSH host keys..."
rm -f /etc/ssh/ssh_host_*
ok "SSH host keys removed"

# Remove machine-id
log "Removing machine-id..."
> /etc/machine-id
> /var/lib/dbus/machine-id
ok "Machine ID cleared"

# Clean cloud-init
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

# Remove Neo4j data (will be reinitialized on first boot)
log "Cleaning Neo4j data..."
systemctl stop neo4j 2>/dev/null || true
rm -rf /var/lib/neo4j/data/* 2>/dev/null || true
ok "Neo4j data cleared"

# Create first-boot service
log "Creating first-boot service..."
cat > /etc/systemd/system/sentrylens-firstboot.service <<'EOF'
[Unit]
Description=SentryLens Kali First Boot Configuration
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
set -euo pipefail

log() { echo "[FIRSTBOOT] $*" | systemd-cat -t sentrylens-firstboot; }

log "Running Kali first-boot configuration..."

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

# Initialize Neo4j for BloodHound
log "Initializing Neo4j..."
systemctl start neo4j
sleep 10
cypher-shell -u neo4j -p neo4j "ALTER CURRENT USER SET PASSWORD FROM 'neo4j' TO 'bloodhound';" 2>/dev/null || true

# Update Nuclei templates
log "Updating Nuclei templates..."
sudo -u kali bash -c '
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    nuclei -update-templates 2>/dev/null || true
' 2>/dev/null || true

# Mark first boot as done
mkdir -p /etc/sentrylens
touch /etc/sentrylens/.firstboot_done

log "First-boot configuration completed"
FIRSTBOOT

chmod +x /opt/sentrylens/scripts/first-boot.sh
systemctl enable sentrylens-firstboot.service
ok "First-boot service created and enabled"

# Create welcome message
log "Creating welcome message..."
VERSION=$(cat /opt/sentrylens/config/version.txt 2>/dev/null || echo "1.0.0")
BUILD_DATE=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

cat > /etc/motd <<MOTD_EOF

    _  __     _ _     _     _           _
   | |/ /    | (_)   | |   | |         | |
   | ' / __ _| |_ ___| |__ | |__  _   _| |_ ___
   |  < / _\` | | / __| '_ \| '_ \| | | | __/ _ \\
   | . \ (_| | | \__ \ | | | |_) | |_| | ||  __/
   |_|_\\_\\__,_|_|_|___/_| |_|_.__/ \\__,_|\\__\\___|

                        Attacker VM
                        Version: ${VERSION}
                        Built: ${BUILD_DATE}

============================================================
PRE-INSTALLED ATTACK TOOLS:
============================================================
Network/Recon:     nmap, masscan, naabu, httpx, dnsx, subfinder
SMB/AD:            crackmapexec, impacket, enum4linux, bloodhound, ldapdomaindump
Password Attacks:  hydra, john, hashcat, kerbrute, passpol
Web:               nuclei, nikto, wpscan, gobuster, dirb, sqlmap
Post-Exploitation: metasploit, empire, pypykatz, certipy, mitm6
Wireless:          aircrack-ng, wifite, kismet
Pivoting:          proxychains4, sshuttle, chisel, ligolo-ng

============================================================
SENTRYLENS ATTACK SCENARIOS:
============================================================
Run attacks with logging for Red vs Blue correlation:

  python3 /opt/sentrylens/attacks/run_attack.py smb_enum <target_ip>
  python3 /opt/sentrylens/attacks/run_attack.py blank_password_check <target_ip>
  python3 /opt/sentrylens/attacks/run_attack.py account_lockout_spray <target_ip>
  python3 /opt/sentrylens/attacks/run_attack.py lateral_movement_schtasks <target_ip> <user> <pass>
  python3 /opt/sentrylens/attacks/run_attack.py brute_force_rdp <target_ip>

Results logged to: /opt/sentrylens/attacks/attack_log.jsonl
(Compatible with SentryLens attack_scenarios.py)

============================================================
TARGET VALIDATION:
============================================================
By default, only documentation networks are allowed:
  127.0.0.0/8, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32

To attack real targets, use --allow-any-target flag or configure
/opt/sentrylens/config/attack_targets.json

Check target: python3 /opt/sentrylens/scripts/validate_target.py <ip>

============================================================
USEFUL ALIASES:
============================================================
sl-attacks        - List attack results
sl-network        - Live network capture
msfconsole        - Quiet Metasploit start

============================================================
DOCUMENTATION:
============================================================
https://github.com/your-org/SentryLens
MOTD_EOF

# Save version info
echo "${VERSION}" > /opt/sentrylens/config/version.txt
echo "${BUILD_DATE}" > /opt/sentrylens/config/build-date.txt

cat > /opt/sentrylens/config/build-info.json <<EOF
{
  "version": "${VERSION}",
  "build_date": "${BUILD_DATE}",
  "kali_version": "2024.3",
  "builder": "packer",
  "project": "SentryLens",
  "role": "attacker"
}
EOF

# Set proper ownership
chown -R ${SSH_USERNAME}:${SSH_USERNAME} /opt/sentrylens
chown -R ${SSH_USERNAME}:${SSH_USERNAME} /var/log/sentrylens 2>/dev/null || true

# Disable root login
log "Disabling root login..."
passwd -l root 2>/dev/null || true

# Final sync
sync

ok "Kali VM finalization completed"
log "VM is ready for packaging!"