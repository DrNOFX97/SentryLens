<#
.SYNOPSIS
    Packages built VM images into distributable release artifacts.

.DESCRIPTION
    This script takes the Packer output and creates:
    - VirtualBox OVA files (for Wazuh Manager and Kali Attacker)
    - Hyper-V VHDX files (for Wazuh Manager)
    - Checksums (SHA256)
    - Release manifest JSON
    - README for each VM

.PARAMETER Version
    Version string (default: 1.0.0)

.PARAMETER BuildTimestamp
    Build timestamp (default: current date YYYYMMDD)

.PARAMETER OutputDir
    Directory to place packaged releases (default: ./releases)

.PARAMETER PackerOutputDir
    Packer output directory (default: ./packer output directories)

.EXAMPLE
    .\package-release.ps1 -Version "1.2.0" -BuildTimestamp "20261011"

.EXAMPLE
    .\package-release.ps1 -OutputDir "D:\VM_Releases"
#>

[CmdletBinding()]
param(
    [string]$Version = "1.0.0",
    [string]$BuildTimestamp = "",
    [string]$OutputDir = ".\releases",
    [string]$PackerOutputDir = ""
)

$ErrorActionPreference = "Stop"

function Write-Step { param([string]$Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "OK  $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "!!  $Message" -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host "XX  $Message" -ForegroundColor Red }

if ([string]::IsNullOrWhiteSpace($BuildTimestamp)) {
    $BuildTimestamp = Get-Date -Format "yyyyMMdd"
}

$releaseName = "sentrylens-v$Version-$BuildTimestamp"
$releaseDir = Join-Path $OutputDir $releaseName

Write-Step "Creating release directory: $releaseDir"
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

$baseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$manifest = @{
    version = $Version
    build_timestamp = $BuildTimestamp
    release_name = $releaseName
    vms = @()
}

# Function to package a VM
function Package-VM {
    param(
        [string]$VmName,
        [string]$PackerOutputSubdir,
        [string]$VmType,  # "wazuh-manager" or "kali-attacker"
        [string]$Hypervisor  # "virtualbox" or "hyperv"
    )

    Write-Step "Packaging $VmName ($Hypervisor)..."

    $sourceDir = if ($PackerOutputDir) {
        Join-Path $PackerOutputDir $PackerOutputSubdir
    } else {
        Join-Path $baseDir $PackerOutputSubdir
    }

    $vmDir = Join-Path $releaseDir $VmName
    New-Item -ItemType Directory -Path $vmDir -Force | Out-Null

    $artifactPath = ""
    $artifactName = ""

    if ($Hypervisor -eq "virtualbox") {
        # Look for OVA or box file
        $ovaFiles = Get-ChildItem -Path $sourceDir -Filter "*.ova" -ErrorAction SilentlyContinue
        $boxFiles = Get-ChildItem -Path $sourceDir -Filter "*.box" -ErrorAction SilentlyContinue

        if ($ovaFiles.Count -gt 0) {
            $artifactPath = $ovaFiles[0].FullName
            $artifactName = "$VmName.ova"
        } elseif ($boxFiles.Count -gt 0) {
            # Convert box to OVA using VBoxManage
            $boxPath = $boxFiles[0].FullName
            $artifactPath = Join-Path $vmDir "$VmName.ova"
            
            Write-Step "Converting Vagrant box to OVA..."
            # Import box then export as OVA
            $importName = "$VmName-import"
            & VBoxManage import $boxPath --vsys 0 --vmname $importName 2>&1 | Out-Null
            & VBoxManage export $importName -o $artifactPath 2>&1 | Out-Null
            & VBoxManage unregistervm $importName --delete 2>&1 | Out-Null
            $artifactName = "$VmName.ova"
        } else {
            Write-Warn "No OVA or box file found in $sourceDir"
            return
        }
    } elseif ($Hypervisor -eq "hyperv") {
        # Look for VHDX
        $vhdxFiles = Get-ChildItem -Path $sourceDir -Filter "*.vhdx" -ErrorAction SilentlyContinue
        if ($vhdxFiles.Count -gt 0) {
            $artifactPath = $vhdxFiles[0].FullName
            $artifactName = "$VmName.vhdx"
        } else {
            Write-Warn "No VHDX file found in $sourceDir"
            return
        }
    }

    if (-not (Test-Path $artifactPath)) {
        Write-Warn "Artifact not found: $artifactPath"
        return
    }

    # Copy to release directory
    $destPath = Join-Path $vmDir $artifactName
    Write-Step "Copying artifact to release..."
    Copy-Item -Path $artifactPath -Destination $destPath -Force

    # Generate SHA256
    Write-Step "Generating SHA256 checksum..."
    $sha256 = Get-FileHash -Path $destPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
    $sha256Path = "$destPath.sha256"
    Set-Content -Path $sha256Path -Value "$sha256  $artifactName"

    # Create VM-specific README
    $readmePath = Join-Path $vmDir "README.md"
    $readmeContent = Generate-VMReadme -VmName $VmName -VmType $VmType -Hypervisor $Hypervisor -Version $Version -BuildTimestamp $BuildTimestamp -Sha256 $sha256 -ArtifactName $artifactName
    Set-Content -Path $readmePath -Value $readmeContent -Encoding UTF8

    # Add to manifest
    $vmInfo = @{
        name = $VmName
        type = $VmType
        hypervisor = $Hypervisor
        artifact = $artifactName
        sha256 = $sha256
        size_bytes = (Get-Item $destPath).Length
        size_human = Format-Bytes ((Get-Item $destPath).Length)
    }
    $manifest.vms += $vmInfo

    Write-Ok "Packaged $VmName: $artifactName ($($vmInfo.size_human), SHA256: $($sha256.Substring(0,16))...)"
}

function Format-Bytes {
    param([long]$Bytes)
    $units = @("B", "KB", "MB", "GB", "TB")
    $i = 0
    while ($Bytes -ge 1024 -and $i -lt $units.Count - 1) {
        $Bytes /= 1024
        $i++
    }
    return "{0:N1} {1}" -f $Bytes, $units[$i]
}

function Generate-VMReadme {
    param(
        [string]$VmName,
        [string]$VmType,
        [string]$Hypervisor,
        [string]$Version,
        [string]$BuildTimestamp,
        [string]$Sha256,
        [string]$ArtifactName
    )

    $readme = @"
# $VmName

**SentryLens $VmType VM** - Version $Version (Build: $BuildTimestamp)

## Hypervisor
$($Hypervisor.ToUpper())

## File
- **Artifact:** `$ArtifactName`
- **SHA256:** `$Sha256`

## Default Credentials
| User | Password |
|------|----------|
"@

    if ($VmType -eq "wazuh-manager") {
        $readme += @"
| sentrylens | sentrylens |
| admin (Wazuh) | See `/home/sentrylens/wazuh-install/wazuh-passwords.txt` |
"@
    } else {
        $readme += @"
| kali | kali |
"@
    }

    $readme += @"
## Network
- **Default:** DHCP (Bridged/External)
- **Wazuh Manager ports:** 1514/TCP (agent), 1515/TCP (registration), 55000/TCP (Manager API), 9200/TCP (Indexer API), 443/TCP (Dashboard)
- **Kali Attacker:** No listening services by default

## First Boot
On first boot, the VM will:
1. Regenerate SSH host keys
2. Generate a new machine-id
3. Update Wazuh/Nuclei templates (Kali)
4. Start all services automatically

Wait ~2 minutes after boot for initialization to complete.

## Quick Start

### Wazuh Manager VM
1. Import the OVA/VHDX into VirtualBox/Hyper-V
2. Start the VM
3. Get the IP address: `ip a` (inside VM) or check your router/DHCP
4. Access Dashboard: `https://<VM_IP>/`
5. Get passwords: `wazuh-passwords` (bash alias) or `cat /home/sentrylens/wazuh-install/wazuh-passwords.txt`

### Kali Attacker VM
1. Import the OVA into VirtualBox
2. Start the VM
3. Get the IP address: `ip a`
4. Run attack scenarios:
   ```bash
   python3 /opt/sentrylens/attacks/run_attack.py smb_enum <target_ip>
   python3 /opt/sentrylens/attacks/run_attack.py blank_password_check <target_ip>
   ```

## SentryLens Backend Configuration
For the Wazuh Manager VM, configure your `scripts/.env`:
```env
WAZUH_MANAGER_URL=https://<VM_IP>:55000
WAZUH_MANAGER_USER=wazuh-wui
WAZUH_MANAGER_PASSWORD=<from wazuh-passwords.txt>

WAZUH_INDEXER_URL=https://<VM_IP>:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=<from wazuh-passwords.txt>

SENTRYLENS_API_KEY=<generate with: openssl rand -hex 32>
```

## Security Notes
- **Change default passwords immediately** after first boot
- The VM uses self-signed certificates - accept browser warnings
- Default SSH allows password auth - consider switching to key-only
- Firewall (UFW) is enabled with only required ports open

## Support
- Documentation: https://github.com/your-org/SentryLens
- Issues: https://github.com/your-org/SentryLens/issues

---
*Built with Packer on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC") UTC*
"@

    return $readme
}

# Package each VM
Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Host "PACKAGING RELEASE: $releaseName" -ForegroundColor DarkGray
Write-Host "=========================================================" -ForegroundColor DarkGray

# Wazuh Manager VirtualBox
Package-VM -VmName "sentrylens-wazuh-manager-virtualbox" -PackerOutputSubdir "wazuh-manager\output-sentrylens-wazuh-manager-virtualbox-$BuildTimestamp" -VmType "wazuh-manager" -Hypervisor "virtualbox"

# Wazuh Manager Hyper-V
Package-VM -VmName "sentrylens-wazuh-manager-hyperv" -PackerOutputSubdir "wazuh-manager\output-sentrylens-wazuh-manager-hyperv-$BuildTimestamp" -VmType "wazuh-manager" -Hypervisor "hyperv"

# Kali Attacker VirtualBox
Package-VM -VmName "sentrylens-kali-attacker-virtualbox" -PackerOutputSubdir "kali-attacker\output-sentrylens-kali-attacker-virtualbox-$BuildTimestamp" -VmType "kali-attacker" -Hypervisor "virtualbox"

# Write manifest
$manifestPath = Join-Path $releaseDir "manifest.json"
$manifestJson = $manifest | ConvertTo-Json -Depth 10
Set-Content -Path $manifestPath -Value $manifestJson -Encoding UTF8
Write-Ok "Manifest written to $manifestPath"

# Generate overall release README
$releaseReadme = @"
# SentryLens VM Release $Version ($BuildTimestamp)

This release contains pre-built VM images for the SentryLens cybersecurity laboratory.

## Contents

| VM | Hypervisor | File | SHA256 |
|----|------------|------|--------|
"@

foreach ($vm in $manifest.vms) {
    $releaseReadme += "| $($vm.name) | $($vm.hypervisor) | $($vm.artifact) | $($vm.sha256.Substring(0,16))... |`n"
}

$releaseReadme += @"

## Verification

Verify each artifact:
```powershell
# PowerShell
Get-FileHash -Path <artifact> -Algorithm SHA256

# Linux/macOS
sha256sum <artifact>
```

Compare with the `.sha256` files or `manifest.json`.

## Quick Start

See individual VM README.md files for detailed instructions.

### Minimal Lab (Wazuh Manager only)
1. Import `sentrylens-wazuh-manager-virtualbox.ova` into VirtualBox
2. Start VM, note IP address
3. Configure SentryLens backend `.env` with VM IP and Wazuh credentials
4. Run SentryLens backend and frontend

### Full Lab (Wazuh Manager + Kali Attacker)
1. Import both OVAs into VirtualBox
2. Configure both VMs on the same network (Bridged recommended)
3. Run attack scenarios from Kali against Windows agent monitored by Wazuh
4. View Red vs Blue correlation in SentryLens dashboard

## Default Credentials

| VM | OS User | OS Password | Wazuh Dashboard |
|----|---------|-------------|-----------------|
| Wazuh Manager | sentrylens | sentrylens | admin / (see passwords file) |
| Kali Attacker | kali | kali | N/A |

**CHANGE ALL PASSWORDS ON FIRST BOOT**

## Requirements

- **VirtualBox 7.0+** (for OVA) or **Hyper-V on Windows 10/11 Pro/Enterprise** (for VHDX)
- Minimum 16 GB RAM recommended (8 GB for Wazuh Manager + 4 GB for Kali + host)
- 100+ GB free disk space
- Hardware virtualization enabled in BIOS/UEFI

## License

See LICENSE file in the SentryLens repository.

---
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC") UTC
"@

$releaseReadmePath = Join-Path $releaseDir "README.md"
Set-Content -Path $releaseReadmePath -Value $releaseReadme -Encoding UTF8
Write-Ok "Release README written to $releaseReadmePath"

# Create a simple verification script
$verifyScript = @"
# Verify Release Artifacts
param([string]`$ReleaseDir = '.')

Write-Host \"Verifying release artifacts in \$ReleaseDir...\"

`$manifest = Get-Content (Join-Path `$ReleaseDir 'manifest.json') | ConvertFrom-Json
`$allOk = \$true

foreach (`$vm in `\$manifest.vms) {
    `\$artifactPath = Join-Path `\$ReleaseDir `\$vm.name `\$vm.artifact
    if (Test-Path `\$artifactPath) {
        `\$hash = Get-FileHash -Path `\$artifactPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
        if (`\$hash -eq `\$vm.sha256) {
            Write-Host \"[OK] `\$vm.artifact: SHA256 matches\" -ForegroundColor Green
        } else {
            Write-Host \"[FAIL] `\$vm.artifact: SHA256 MISMATCH!\" -ForegroundColor Red
            Write-Host \"  Expected: `\$vm.sha256\" -ForegroundColor Red
            Write-Host \"  Got:      `\$hash\" -ForegroundColor Red
            `\$allOk = \$false
        }
    } else {
        Write-Host \"[MISSING] `\$vm.artifact not found\" -ForegroundColor Yellow
        `\$allOk = \$false
    }
}

if (`\$allOk) {
    Write-Host \"`nAll artifacts verified successfully!\" -ForegroundColor Green
    exit 0
} else {
    Write-Host \"`nVerification FAILED!\" -ForegroundColor Red
    exit 1
}
"@

$verifyPath = Join-Path $releaseDir "verify-release.ps1"
Set-Content -Path $verifyPath -Value $verifyScript -Encoding UTF8

Write-Host ""
Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Ok "Release packaged successfully!"
Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Host "Release directory: $releaseDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "Contents:"
Get-ChildItem -Path $releaseDir -Recurse -File | ForEach-Object {
    $size = Format-Bytes $_.Length
    Write-Host "  $($_.FullName.Substring($releaseDir.Length + 1)) ($size)"
}