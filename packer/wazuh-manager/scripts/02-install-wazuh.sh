#!/usr/bin/env bash
#
# 02-install-wazuh.sh - Install Wazuh (Indexer + Manager + Dashboard)
# Based on the project's install-wazuh.sh but adapted for Packer

set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.14.0}"
SSH_USERNAME="${SSH_USERNAME:-sentrylens}"
SSH_PASSWORD="${SSH_PASSWORD:-sentrylens}"

WORKDIR="/home/${SSH_USERNAME}/wazuh-install"
INSTALL_SCRIPT="wazuh-install.sh"
PASSWORDS_ARCHIVE="wazuh-install-files.tar"
PASSWORDS_ENTRY="wazuh-install-files/wazuh-passwords.txt"

log() { echo -e "\033[36m==>\033[0m $*"; }
ok()   { echo -e "\033[32mOK\033[0m  $*"; }
warn() { echo -e "\033[33m!!\033[0m  $*"; }
err()  { echo -e "\033[31mXX\033[0m  $*"; }

log "Starting Wazuh ${WAZUH_VERSION} installation..."

# Create work directory
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"
chown -R ${SSH_USERNAME}:${SSH_USERNAME} "${WORKDIR}"

# Download Wazuh installer
log "Downloading wazuh-install.sh..."
if ! sudo -u ${SSH_USERNAME} curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"; then
    err "Failed to download wazuh-install.sh"
    exit 1
fi

if [ ! -s "${INSTALL_SCRIPT}" ]; then
    err "Downloaded installer is empty"
    exit 1
fi

chmod +x "${INSTALL_SCRIPT}"
chown ${SSH_USERNAME}:${SSH_USERNAME} "${INSTALL_SCRIPT}"
ok "Download completed"

# Run Wazuh installer (single-node quickstart)
log "Running Wazuh installer (this may take 10-20 minutes)..."
# The -a flag installs all components: indexer, manager, dashboard
sudo bash "./${INSTALL_SCRIPT}" -a

ok "Wazuh installer completed"

# Extract and save passwords
log "Extracting generated passwords..."
if [ ! -f "${PASSWORDS_ARCHIVE}" ]; then
    err "Password archive not found: ${WORKDIR}/${PASSWORDS_ARCHIVE}"
    exit 1
fi

PASSWORDS_OUTPUT=$(sudo tar -O -xvf "${PASSWORDS_ARCHIVE}" "${PASSWORDS_ENTRY}" 2>/dev/null)

echo
echo "========================================================="
warn " WAZUH PASSWORDS GENERATED - SAVE THESE SECURELY!"
echo "========================================================="
echo "${PASSWORDS_OUTPUT}"
echo "========================================================="
echo

# Save passwords to a readable file for the user
echo "${PASSWORDS_OUTPUT}" > "${WORKDIR}/wazuh-passwords.txt"
chmod 600 "${WORKDIR}/wazuh-passwords.txt"
chown ${SSH_USERNAME}:${SSH_USERNAME} "${WORKDIR}/wazuh-passwords.txt"
ok "Passwords saved to ${WORKDIR}/wazuh-passwords.txt (chmod 600)"

# Also save to a known location for the SentryLens backend to find
mkdir -p /opt/sentrylens/config
cp "${WORKDIR}/wazuh-passwords.txt" /opt/sentrylens/config/wazuh-passwords.txt
chmod 600 /opt/sentrylens/config/wazuh-passwords.txt
chown ${SSH_USERNAME}:${SSH_USERNAME} /opt/sentrylens/config/wazuh-passwords.txt

# Verify services are running
log "Verifying Wazuh services..."
SERVICES=(wazuh-manager wazuh-indexer wazuh-dashboard)
ALL_RUNNING=1

for svc in "${SERVICES[@]}"; do
    STATE=$(systemctl is-active "${svc}" 2>/dev/null || true)
    if [ "${STATE}" = "active" ]; then
        ok "${svc}: active (running)"
    else
        err "${svc}: state = '${STATE:-unknown}' (expected: active)"
        ALL_RUNNING=0
    fi
done

if [ "${ALL_RUNNING}" -eq 1 ]; then
    ok "All Wazuh services are running"
else
    warn "Some services may not be fully started yet"
fi

# Configure Wazuh Manager API for external access
log "Configuring Wazuh Manager API..."
MANAGER_CONF="/var/ossec/etc/ossec.conf"
if [ -f "${MANAGER_CONF}" ]; then
    # Ensure API is listening on all interfaces
    sed -i 's/<address>127.0.0.1<\/address>/<address>0.0.0.0<\/address>/' "${MANAGER_CONF}"
    systemctl restart wazuh-manager
    ok "Wazuh Manager API configured for external access"
fi

# Configure Wazuh Indexer for external access
log "Configuring Wazuh Indexer..."
INDEXER_CONF="/etc/wazuh-indexer/opensearch.yml"
if [ -f "${INDEXER_CONF}" ]; then
    sed -i 's/network.host: .*/network.host: 0.0.0.0/' "${INDEXER_CONF}"
    systemctl restart wazuh-indexer
    ok "Wazuh Indexer configured for external access"
fi

# Configure Wazuh Dashboard for external access
log "Configuring Wazuh Dashboard..."
DASHBOARD_CONF="/etc/wazuh-dashboard/opensearch_dashboards.yml"
if [ -f "${DASHBOARD_CONF}" ]; then
    sed -i 's/server.host: .*/server.host: "0.0.0.0"/' "${DASHBOARD_CONF}"
    systemctl restart wazuh-dashboard
    ok "Wazuh Dashboard configured for external access"
fi

# Wait for services to stabilize
log "Waiting for services to stabilize..."
sleep 30

# Final verification
log "Final service verification..."
for svc in "${SERVICES[@]}"; do
    STATE=$(systemctl is-active "${svc}" 2>/dev/null || true)
    if [ "${STATE}" = "active" ]; then
        ok "${svc}: active"
    else
        warn "${svc}: ${STATE:-unknown}"
    fi
done

# Get VM IP for display
IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}')

echo
echo "========================================================="
ok "Wazuh installation completed successfully"
echo "========================================================="
echo
echo "Access the Wazuh Dashboard at: https://${IP_ADDR:-<VM_IP>}"
echo "Username: admin"
echo "Password: (see ${WORKDIR}/wazuh-passwords.txt)"
echo
echo "Manager API: https://${IP_ADDR:-<VM_IP>}:55000"
echo "Indexer API: https://${IP_ADDR:-<VM_IP>}:9200"
echo
echo "To retrieve passwords later:"
echo "  cat ${WORKDIR}/wazuh-passwords.txt"
echo "  or: wazuh-passwords (bash alias)"
echo