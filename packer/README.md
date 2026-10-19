# SentryLens VM Images

This directory contains the Packer templates and build scripts for creating pre-configured VM images for the SentryLens cybersecurity laboratory.

## Available VMs

| VM | Role | Hypervisors | Description |
|----|------|-------------|-------------|
| **Wazuh Manager** | SIEM Server | VirtualBox (OVA), Hyper-V (VHDX) | Ubuntu 22.04 with Wazuh Indexer, Manager, and Dashboard pre-installed |
| **Kali Attacker** | Attack Platform | VirtualBox (OVA) | Kali Linux with Red Team tools pre-configured for SentryLens attack scenarios |

## Quick Start (Using Pre-built VMs)

### Option 1: Download from GitHub Releases

1. Go to the [Releases page](https://github.com/your-org/SentryLens/releases)
2. Download the latest release assets:
   - `sentrylens-wazuh-manager-virtualbox.ova` - For VirtualBox
   - `sentrylens-wazuh-manager-hyperv.vhdx` - For Hyper-V
   - `sentrylens-kali-attacker-virtualbox.ova` - For VirtualBox
3. Verify checksums using the `.sha256` files or `manifest.json`
4. Import into your hypervisor

### Option 2: Build Yourself

See [Building VMs](#building-vms) below.

## VM Details

### Wazuh Manager VM

**Specifications:**
- OS: Ubuntu Server 22.04 LTS
- RAM: 8 GB (minimum), 12 GB recommended
- vCPU: 4
- Disk: 60 GB dynamic
- Network: Bridged (recommended) or NAT

**Pre-installed Software:**
- Wazuh Indexer (OpenSearch)
- Wazuh Manager
- Wazuh Dashboard
- tshark/Wireshark for network capture
- Python 3.12 with SentryLens dependencies
- VirtualBox Guest Additions (VirtualBox version)

**Default Credentials:**
| Service | Username | Password |
|---------|----------|----------|
| OS (SSH) | `sentrylens` | `sentrylens` |
| Wazuh Dashboard | `admin` | Generated on first boot (see below) |

**Getting Wazuh Passwords:**
After first boot, run inside the VM:
```bash
wazuh-passwords
# or
cat /home/sentrylens/wazuh-install/wazuh-passwords.txt
```

**Accessing the Dashboard:**
1. Get VM IP: `ip a` (inside VM)
2. Open browser: `https://<VM_IP>/`
3. Accept self-signed certificate warning
4. Login with `admin` and password from above

**SentryLens Backend Configuration:**
```env
WAZUH_MANAGER_URL=https://<VM_IP>:55000
WAZUH_MANAGER_USER=wazuh-wui
WAZUH_MANAGER_PASSWORD=<from wazuh-passwords.txt>

WAZUH_INDEXER_URL=https://<VM_IP>:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=<from wazuh-passwords.txt>

SENTRYLENS_API_KEY=<generate with: openssl rand -hex 32>
```

### Kali Attacker VM

**Specifications:**
- OS: Kali Linux 2024.3
- RAM: 4 GB
- vCPU: 2
- Disk: 40 GB dynamic
- Network: Bridged (required for attacking other VMs)

**Pre-installed Tools:**
- Network/Recon: nmap, masscan, naabu, httpx, dnsx, subfinder
- SMB/AD: crackmapexec, impacket, enum4linux, bloodhound, ldapdomaindump
- Password Attacks: hydra, john, hashcat, kerbrute, passpol
- Web: nuclei, nikto, wpscan, gobuster, dirb, sqlmap
- Post-Exploitation: metasploit, empire, pypykatz, certipy, mitm6
- Pivoting: proxychains4, sshuttle, chisel, ligolo-ng

**Default Credentials:**
| Service | Username | Password |
|---------|----------|----------|
| OS (SSH) | `kali` | `kali` |

**Running Attack Scenarios:**
```bash
# SMB Enumeration (MITRE T1021.002)
python3 /opt/sentrylens/attacks/run_attack.py smb_enum <target_ip>

# Blank Password Check (MITRE T1110.003)
python3 /opt/sentrylens/attacks/run_attack.py blank_password_check <target_ip>

# Password Spray (MITRE T1110.003)
python3 /opt/sentrylens/attacks/run_attack.py account_lockout_spray <target_ip>

# Lateral Movement via Scheduled Tasks (MITRE T1053.005)
python3 /opt/sentrylens/attacks/run_attack.py lateral_movement_schtasks <target_ip> <user> <pass>

# RDP Brute Force (MITRE T1110.001)
python3 /opt/sentrylens/attacks/run_attack.py brute_force_rdp <target_ip>
```

Results are logged to `/opt/sentrylens/attacks/attack_log.jsonl` in the format expected by SentryLens `attack_scenarios.py`.

**Target Validation:**
By default, only documentation networks are allowed:
- `127.0.0.0/8` (loopback)
- `192.0.2.0/24` (TEST-NET-1)
- `198.51.100.0/24` (TEST-NET-2)
- `203.0.113.0/24` (TEST-NET-3)
- `2001:db8::/32` (documentation prefix)

To attack real targets, use `--allow-any-target` or configure `/opt/sentrylens/config/attack_targets.json`:
```json
{
  "allowlist": ["192.168.1.0/24", "10.0.0.0/8"]
}
```

## Building VMs

### Prerequisites

- **Packer** 1.10+ ([install](https://www.packer.io/downloads))
- **VirtualBox** 7.0+ (for VirtualBox builds)
- **Hyper-V** on Windows 10/11 Pro/Enterprise (for Hyper-V builds)
- Hardware virtualization enabled in BIOS/UEFI

### Build Commands

**Build all VMs (Windows PowerShell):**
```powershell
cd packer
.\build-all.ps1 -Version "1.2.0"
```

**Build only Wazuh Manager for VirtualBox:**
```powershell
.\build-all.ps1 -Version "1.2.0" -OnlyWazuh -SkipHyperV
```

**Build only Kali Attacker:**
```powershell
.\build-all.ps1 -Version "1.2.0" -OnlyKali -SkipHyperV
```

**Build with custom timestamp:**
```powershell
.\build-all.ps1 -Version "1.2.0" -BuildTimestamp "20261011"
```

### Build Output

After successful build, artifacts are in:
```
packer/
├── wazuh-manager/
│   ├── output-sentrylens-wazuh-manager-virtualbox-YYYYMMDD/
│   │   └── sentrylens-wazuh-manager-virtualbox-YYYYMMDD.ova (or .box)
│   └── output-sentrylens-wazuh-manager-hyperv-YYYYMMDD/
│       └── sentrylens-wazuh-manager-hyperv-YYYYMMDD.vhdx
└── kali-attacker/
    └── output-sentrylens-kali-attacker-virtualbox-YYYYMMDD/
        └── sentrylens-kali-attacker-virtualbox-YYYYMMDD.ova (or .box)
```

### Package for Distribution

```powershell
cd packer
.\package-release.ps1 -Version "1.2.0" -BuildTimestamp "20261011"
```

This creates a release package in `packer/releases/sentrylens-v1.2.0-20261011/` with:
- OVA/VHDX files
- SHA256 checksums
- Individual VM README.md files
- Overall release README.md
- `manifest.json` with metadata
- `verify-release.ps1` for checksum verification

## First Boot Behavior

On first boot, each VM automatically:
1. Regenerates SSH host keys
2. Generates a new machine-id
3. Updates Wazuh/Nuclei templates (Kali)
4. Initializes Neo4j for BloodHound (Kali)
5. Starts all services
6. Marks first-boot as complete

Wait ~2 minutes after boot for initialization to complete.

## Security Checklist (Post-Deployment)

- [ ] Change default OS passwords (`passwd`)
- [ ] Change Wazuh Dashboard admin password
- [ ] Configure SSH key-based authentication, disable password auth
- [ ] Review and restrict firewall rules (UFW)
- [ ] Update all packages: `apt update && apt upgrade`
- [ ] Configure log rotation and monitoring
- [ ] Set up backup strategy for Wazuh data

## Troubleshooting

### Wazuh Services Not Starting
```bash
# Check service status
wazuh-status

# View logs
wazuh-logs

# Restart services
sudo systemctl restart wazuh-manager wazuh-indexer wazuh-dashboard
```

### Network Issues
```bash
# Check IP
ip a

# Test connectivity to Wazuh Manager
nc -zv <manager_ip> 1514
nc -zv <manager_ip> 55000

# Check firewall
sudo ufw status
```

### VirtualBox Import Fails
- Ensure VirtualBox 7.0+ is installed
- Enable VT-x/AMD-V in BIOS
- Disable Hyper-V if running on Windows host
- Verify OVA checksum matches

### Hyper-V Import Fails
- Ensure Hyper-V is enabled
- Use Generation 2 VM settings
- Disable Secure Boot
- Ensure sufficient RAM (8 GB minimum)

## Automated Builds (GitHub Actions)

VM images are automatically built on:
- New release published
- Manual workflow dispatch

See `.github/workflows/build-vms.yml` for details.

Artifacts are uploaded as GitHub Release assets for easy download.

## File Structure

```
packer/
├── build-all.ps1              # Main build script
├── package-release.ps1        # Release packaging script
├── wazuh-manager/
│   ├── ubuntu-wazuh-virtualbox.pkr.hcl
│   ├── ubuntu-wazuh-hyperv.pkr.hcl
│   ├── http/
│   │   └── user-data          # Cloud-init autoinstall config
│   └── scripts/
│       ├── 01-base-setup.sh
│       ├── 02-install-wazuh.sh
│       ├── 03-configure-network.sh
│       └── 04-finalize.sh
└── kali-attacker/
    ├── kali-attacker-virtualbox.pkr.hcl
    ├── http/
    │   └── user-data
    └── scripts/
        ├── 01-base-setup.sh
        ├── 02-install-tools.sh
        ├── 03-configure-attack-tools.sh
        └── 04-finalize.sh
```

## License

See [LICENSE](../LICENSE) in the repository root.