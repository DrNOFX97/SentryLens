<#
.SYNOPSIS
    Builds all SentryLens VM images using Packer.

.DESCRIPTION
    This script builds VM images for:
    - Wazuh Manager (VirtualBox OVA + Hyper-V VHDX)
    - Kali Attacker (VirtualBox OVA)

    Requires Packer to be installed and in PATH.

.PARAMETER Version
    Version string for the build (default: 1.0.0)

.PARAMETER BuildTimestamp
    Custom timestamp for the build (default: current date YYYYMMDD)

.PARAMETER SkipVirtualBox
    Skip VirtualBox builds

.PARAMETER SkipHyperV
    Skip Hyper-V builds

.PARAMETER OnlyWazuh
    Only build Wazuh Manager VM

.PARAMETER OnlyKali
    Only build Kali Attacker VM

.EXAMPLE
    .\build-all.ps1 -Version "1.2.0"

.EXAMPLE
    .\build-all.ps1 -OnlyWazuh -SkipHyperV

.EXAMPLE
    .\build-all.ps1 -BuildTimestamp "20261011"
#>

[CmdletBinding()]
param(
    [string]$Version = "1.0.0",
    [string]$BuildTimestamp = "",
    [switch]$SkipVirtualBox,
    [switch]$SkipHyperV,
    [switch]$OnlyWazuh,
    [switch]$OnlyKali
)

$ErrorActionPreference = "Stop"

function Write-Step { param([string]$Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "OK  $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "!!  $Message" -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host "XX  $Message" -ForegroundColor Red }

# Carrega packer/.env (gitignored) para o ambiente do processo: é dele que
# vêm as passwords das VMs (SENTRYLENS_WAZUH_SSH_PASSWORD,
# SENTRYLENS_KALI_SSH_PASSWORD). Nunca há default no .pkr.hcl de propósito;
# sem .env, o packer falha com "ssh_password is required", não com uma
# password previsível. Ver packer/.env.example.
$envFile = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) ".env"
if (Test-Path $envFile) {
    Write-Step "A carregar packer/.env..."
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$' -and -not $_.TrimStart().StartsWith('#')) {
            [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], "Process")
        }
    }
} else {
    Write-Warn "packer/.env não existe (copia packer/.env.example); as passwords das VMs têm de vir de lá."
}

function Get-RequiredEnv {
    param([string]$Name)
    $value = [System.Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($value)) {
        Write-Err "Variável $Name não definida em packer/.env."
        exit 1
    }
    return $value
}

# Check for Packer
Write-Step "Checking for Packer..."
$packerPath = Get-Command packer -ErrorAction SilentlyContinue
if (-not $packerPath) {
    Write-Err "Packer not found in PATH. Install from https://www.packer.io/downloads"
    exit 1
}
Write-Ok "Found Packer: $($packerPath.Source)"

# Check for VirtualBox
if (-not $SkipVirtualBox) {
    Write-Step "Checking for VirtualBox..."
    $vboxPath = Get-Command VBoxManage -ErrorAction SilentlyContinue
    if (-not $vboxPath) {
        Write-Warn "VirtualBox not found (VBoxManage not in PATH). VirtualBox builds will fail."
    } else {
        Write-Ok "Found VirtualBox: $($vboxPath.Source)"
    }
}

# Check for Hyper-V
if (-not $SkipHyperV) {
    Write-Step "Checking for Hyper-V..."
    $hypervModule = Get-Module -ListAvailable Hyper-V
    if (-not $hypervModule) {
        Write-Warn "Hyper-V module not available. Hyper-V builds will fail."
    } else {
        Write-Ok "Hyper-V module available"
    }
}

# Set timestamp
if ([string]::IsNullOrWhiteSpace($BuildTimestamp)) {
    $BuildTimestamp = Get-Date -Format "yyyyMMdd"
}
Write-Host "Build version: $Version" -ForegroundColor Gray
Write-Host "Build timestamp: $BuildTimestamp" -ForegroundColor Gray

$packerArgs = @(
    "-var", "version=$Version",
    "-var", "build_timestamp=$BuildTimestamp"
)

$baseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$wazuhDir = Join-Path $baseDir "wazuh-manager"
$kaliDir = Join-Path $baseDir "kali-attacker"

$results = @{}

# Build Wazuh Manager VirtualBox
if (-not $OnlyKali -and -not $SkipVirtualBox) {
    Write-Step "Building Wazuh Manager (VirtualBox)..."
    try {
        $wazuhPassword = Get-RequiredEnv "SENTRYLENS_WAZUH_SSH_PASSWORD"
        $labCidr = [System.Environment]::GetEnvironmentVariable("SENTRYLENS_LAB_NETWORK_CIDR", "Process")
        $result = packer build @packerArgs @("-var", "ssh_password=$wazuhPassword", "-var", "lab_network_cidr=$labCidr") @("-only=wazuh-manager-virtualbox", "$wazuhDir\ubuntu-wazuh-virtualbox.pkr.hcl")
        $results["wazuh-virtualbox"] = "SUCCESS"
        Write-Ok "Wazuh Manager VirtualBox build completed"
    } catch {
        $results["wazuh-virtualbox"] = "FAILED: $_"
        Write-Err "Wazuh Manager VirtualBox build failed: $_"
    }
}

# Build Wazuh Manager Hyper-V
if (-not $OnlyKali -and -not $SkipHyperV) {
    Write-Step "Building Wazuh Manager (Hyper-V)..."
    try {
        $wazuhPassword = Get-RequiredEnv "SENTRYLENS_WAZUH_SSH_PASSWORD"
        $labCidr = [System.Environment]::GetEnvironmentVariable("SENTRYLENS_LAB_NETWORK_CIDR", "Process")
        $result = packer build @packerArgs @("-var", "ssh_password=$wazuhPassword", "-var", "lab_network_cidr=$labCidr") @("-only=wazuh-manager-hyperv", "$wazuhDir\ubuntu-wazuh-hyperv.pkr.hcl")
        $results["wazuh-hyperv"] = "SUCCESS"
        Write-Ok "Wazuh Manager Hyper-V build completed"
    } catch {
        $results["wazuh-hyperv"] = "FAILED: $_"
        Write-Err "Wazuh Manager Hyper-V build failed: $_"
    }
}

# Build Kali Attacker VirtualBox
if (-not $OnlyWazuh -and -not $SkipVirtualBox) {
    Write-Step "Building Kali Attacker (VirtualBox)..."
    try {
        $kaliPassword = Get-RequiredEnv "SENTRYLENS_KALI_SSH_PASSWORD"
        $result = packer build @packerArgs @("-var", "ssh_password=$kaliPassword") @("-only=kali-attacker-virtualbox", "$kaliDir\kali-attacker-virtualbox.pkr.hcl")
        $results["kali-virtualbox"] = "SUCCESS"
        Write-Ok "Kali Attacker VirtualBox build completed"
    } catch {
        $results["kali-virtualbox"] = "FAILED: $_"
        Write-Err "Kali Attacker VirtualBox build failed: $_"
    }
}

# Summary
Write-Host ""
Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Host "BUILD SUMMARY" -ForegroundColor DarkGray
Write-Host "=========================================================" -ForegroundColor DarkGray

$allSuccess = $true
foreach ($build in $results.Keys) {
    $status = $results[$build]
    if ($status -eq "SUCCESS") {
        Write-Ok "$build: $status"
    } else {
        Write-Err "$build: $status"
        $allSuccess = $false
    }
}

Write-Host ""
if ($allSuccess) {
    Write-Ok "All builds completed successfully!"
    exit 0
} else {
    Write-Err "Some builds failed. Check output above."
    exit 1
}