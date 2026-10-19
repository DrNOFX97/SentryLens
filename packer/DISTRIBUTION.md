# VM Distribution Strategy

This document describes how SentryLens VM images are built, packaged, and distributed to users.

## Overview

The SentryLens project provides two pre-configured VM images:
1. **Wazuh Manager** - Ubuntu 22.04 with Wazuh SIEM stack
2. **Kali Attacker** - Kali Linux with Red Team tools

These are distributed as:
- **VirtualBox OVA** - Cross-platform, recommended for most users
- **Hyper-V VHDX** - Native Windows hypervisor format

## Build Process

### Automated (GitHub Actions)

VMs are built automatically on:
- New GitHub Release published
- Manual workflow dispatch

The workflow (`.github/workflows/build-vms.yml`):
1. Spawns Ubuntu runners for VirtualBox builds
2. Spawns Windows runners for Hyper-V builds (requires self-hosted runner with Hyper-V)
3. Runs Packer templates
4. Packages artifacts with checksums
5. Uploads as Release assets

### Manual Build

For custom builds or testing:
```powershell
cd packer
.\build-all.ps1 -Version "1.2.0"
.\package-release.ps1 -Version "1.2.0"
```

## Distribution Channels

### Primary: GitHub Releases

**Pros:**
- Integrated with repository
- Versioned with tags
- Automatic checksum verification
- CDN delivery
- Free for public repos

**Cons:**
- 2 GB file size limit per asset
- 60 GB total storage limit
- No private repo downloads without auth

**Mitigation for large files:**
- Split large OVAs if needed (not expected - OVAs ~3-5 GB compressed)
- Use GitHub Packages for larger artifacts
- Document external mirrors

### Secondary: External Storage (Optional)

For larger distributions or private access:
- **AWS S3 + CloudFront** - Scalable, pay-per-use
- **Azure Blob Storage** - Good for Hyper-V VHDX
- **Google Cloud Storage** - Alternative
- **Self-hosted** - Full control

### Tertiary: Vagrant Cloud

For Vagrant users:
- Publish `.box` files to Vagrant Cloud
- Enables `vagrant init sentrylens/wazuh-manager`

## Release Artifacts

Each release contains:

```
sentrylens-v1.2.0-20261011/
├── README.md                    # This file
├── manifest.json                # Machine-readable manifest
├── verify-release.ps1           # Checksum verification script
├── sentrylens-wazuh-manager-virtualbox/
│   ├── sentrylens-wazuh-manager-virtualbox.ova
│   ├── sentrylens-wazuh-manager-virtualbox.ova.sha256
│   └── README.md
├── sentrylens-wazuh-manager-hyperv/
│   ├── sentrylens-wazuh-manager-hyperv.vhdx
│   ├── sentrylens-wazuh-manager-hyperv.vhdx.sha256
│   └── README.md
└── sentrylens-kali-attacker-virtualbox/
    ├── sentrylens-kali-attacker-virtualbox.ova
    ├── sentrylens-kali-attacker-virtualbox.ova.sha256
    └── README.md
```

### manifest.json Schema

```json
{
  "version": "1.2.0",
  "build_timestamp": "20261011",
  "release_name": "sentrylens-v1.2.0-20261011",
  "vms": [
    {
      "name": "sentrylens-wazuh-manager-virtualbox",
      "type": "wazuh-manager",
      "hypervisor": "virtualbox",
      "artifact": "sentrylens-wazuh-manager-virtualbox.ova",
      "sha256": "a1b2c3d4...",
      "size_bytes": 3221225472,
      "size_human": "3.0 GB"
    }
  ]
}
```

## Versioning

Format: `v<MAJOR>.<MINOR>.<PATCH>-<YYYYMMDD>`

Examples:
- `v1.0.0-20261011` - First release
- `v1.1.0-20261115` - Minor update
- `v2.0.0-20270101` - Major update

Git tags match: `vm-v1.0.0-20261011`

## Checksum Verification

Users should verify downloads:

```powershell
# Windows
Get-FileHash -Path sentrylens-wazuh-manager-virtualbox.ova -Algorithm SHA256

# Linux/macOS
sha256sum sentrylens-wazuh-manager-virtualbox.ova

# Or use provided script
.\verify-release.ps1 -ReleaseDir .
```

## Security Considerations

### Default Credentials

VMs ship with default credentials that **must be changed on first boot**:
- OS: `sentrylens`/`sentrylens` (Wazuh) or `kali`/`kali` (Kali)
- Wazuh Dashboard: `admin`/random (generated on first boot)

### First Boot Hardening

VMs automatically:
- Regenerate SSH host keys
- Generate new machine-id
- Start all services

Users should additionally:
- Change all default passwords
- Configure SSH key-only auth
- Review firewall rules
- Apply security updates

### Supply Chain

- Builds run in GitHub Actions (ephemeral runners)
- Packer templates are version-controlled
- Base ISOs downloaded from official sources with checksums
- No secrets in build process
- Artifacts signed with SHA256 (GPG signing optional)

## Maintenance

### Update Schedule

- **Monthly**: Security updates, Wazuh/Kali version bumps
- **Per Release**: New SentryLens features requiring VM changes
- **On Demand**: Critical security patches

### Deprecation

- Maintain last 3 major versions
- Document migration path
- 6-month notice before removing old downloads

## Cost Estimation (GitHub)

| Item | Free Tier | Paid |
|------|-----------|------|
| Actions minutes | 2,000/mo | $0.008/min |
| Storage | 500 MB | $0.008/GB/mo |
| Bandwidth | 1 GB/mo | $0.08/GB |

Estimated monthly for VM builds: ~$5-10 (well within free tier for moderate usage)

## Future Improvements

1. **GPG signing** of release artifacts
2. **SBOM generation** for each VM
3. **Automated vulnerability scanning** of built images
4. **Delta updates** for incremental downloads
5. **Vagrant Cloud publishing** for Vagrant users
6. **ARM64 builds** for Apple Silicon