<#
.SYNOPSIS
    Automatiza a Parte 1 e Parte 2 do guia docs/LAB_WAZUH_HYPERV.md:
    ativa o Hyper-V, cria o Virtual Switch e cria a VM Ubuntu Server
    (Geração 2) já configurada com specs e firmware corretos.

.DESCRIPTION
    Este script NÃO instala o Ubuntu. Para depois de criar a VM e diz-te
    para montares a ISO manualmente e arrancares a instalação (passo
    interativo — Parte 2.4 do guia).

.NOTES
    - Corre em PowerShell como Administrador.
    - Se o Hyper-V ainda não estava ativo, o script ativa a feature e
      PARA, avisando que é preciso reiniciar o PC antes de correr o
      resto (criação de switch/VM só funciona depois do reboot).
    - Corre o script outra vez depois de reiniciar para continuar
      (a ativação do Hyper-V é detetada e saltada automaticamente).

.EXAMPLE
    .\setup-hyperv-lab.ps1

.EXAMPLE
    .\setup-hyperv-lab.ps1 -VMName "Wazuh-Lab" -MemoryGB 12 -IsoPath "C:\ISOs\ubuntu-22.04.4-live-server-amd64.iso"
#>

[CmdletBinding()]
param(
    # --- Virtual Switch ---
    [string]$SwitchName = "Lab-Wazuh",
    # Tipo de switch: External (na mesma sub-rede do host, recomendado
    # pelo guia) ou Internal (isolado). Ver Parte 1.2 do guia.
    [ValidateSet("External", "Internal")]
    [string]$SwitchType = "External",
    # Nome do adaptador de rede físico a usar quando -SwitchType External.
    # Deixa em branco para o script escolher automaticamente o primeiro
    # adaptador Ethernet/Wi-Fi ativo.
    [string]$NetAdapterName = "",

    # --- VM ---
    [string]$VMName = "Wazuh-Manager",
    [int]$MemoryGB = 8,
    [int]$CPUCount = 4,
    [int]$DiskGB = 60,
    # Pasta onde ficam o VHDX e os ficheiros da VM. Por omissão usa a
    # localização padrão do Hyper-V no host.
    [string]$VMPath = "",
    # Caminho para a ISO do Ubuntu Server 22.04 (Parte 2.1 do guia).
    # Podes deixar vazio e montar a ISO manualmente mais tarde no
    # Hyper-V Manager.
    [string]$IsoPath = ""
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Warn2 {
    param([string]$Message)
    Write-Host "!!  $Message" -ForegroundColor Yellow
}

function Write-Ok {
    param([string]$Message)
    Write-Host "OK  $Message" -ForegroundColor Green
}

# --- Verificar que corre como Administrador ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este script tem de correr num PowerShell como Administrador." -ForegroundColor Red
    exit 1
}

Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Host " Setup do Laboratorio Wazuh em Hyper-V (Partes 1 e 2)" -ForegroundColor DarkGray
Write-Host "=========================================================" -ForegroundColor DarkGray

# ---------------------------------------------------------------------
# PARTE 1.1 — Verificar / ativar o Hyper-V
# ---------------------------------------------------------------------
Write-Step "A verificar se o Hyper-V esta ativo..."

$hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All

if ($hyperv.State -eq "Enabled") {
    Write-Ok "Hyper-V ja esta ativo."
} else {
    Write-Warn2 "Hyper-V nao esta ativo. A ativar agora..."
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart

    Write-Host ""
    Write-Warn2 "Hyper-V foi ativado mas precisa de REINICIAR o computador"
    Write-Warn2 "antes de continuar. Reinicia e corre este script outra vez"
    Write-Warn2 "para criar o Virtual Switch e a VM."
    Write-Host ""
    exit 0
}

# A partir daqui os cmdlets Hyper-V (New-VMSwitch, New-VM, ...) já
# existem porque a feature está ativa.
Import-Module Hyper-V -ErrorAction Stop

# ---------------------------------------------------------------------
# PARTE 1.2 — Criar o Virtual Switch
# ---------------------------------------------------------------------
Write-Step "A verificar o Virtual Switch '$SwitchName'..."

$existingSwitch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue

if ($existingSwitch) {
    Write-Ok "Virtual Switch '$SwitchName' ja existe (tipo: $($existingSwitch.SwitchType)). A reutilizar."
} else {
    if ($SwitchType -eq "External") {
        if ([string]::IsNullOrWhiteSpace($NetAdapterName)) {
            # Escolhe o primeiro adaptador físico "Up" (Ethernet ou Wi-Fi)
            $adapter = Get-NetAdapter | Where-Object {
                $_.Status -eq "Up" -and $_.HardwareInterface -eq $true
            } | Select-Object -First 1

            if (-not $adapter) {
                Write-Host "Nao foi possivel encontrar automaticamente um adaptador de rede fisico ativo." -ForegroundColor Red
                Write-Host "Corre novamente com -NetAdapterName '<nome>' (ver 'Get-NetAdapter')." -ForegroundColor Red
                exit 1
            }
            $NetAdapterName = $adapter.Name
            Write-Host "   Adaptador escolhido automaticamente: $NetAdapterName"
        }

        Write-Step "A criar Virtual Switch Externo '$SwitchName' ligado a '$NetAdapterName'..."
        New-VMSwitch -Name $SwitchName -NetAdapterName $NetAdapterName -AllowManagementOS $true | Out-Null
    } else {
        Write-Step "A criar Virtual Switch Interno '$SwitchName'..."
        New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
    }
    Write-Ok "Virtual Switch '$SwitchName' criado."
}

# ---------------------------------------------------------------------
# PARTE 2.2/2.3 — Criar a VM (Geracao 2, specs do guia) + firmware
# ---------------------------------------------------------------------
Write-Step "A verificar se a VM '$VMName' ja existe..."

$existingVM = Get-VM -Name $VMName -ErrorAction SilentlyContinue

if ($existingVM) {
    Write-Warn2 "Ja existe uma VM chamada '$VMName'. O script nao vai recria-la."
    Write-Warn2 "Apaga-a primeiro (Remove-VM) ou usa -VMName com outro nome."
    exit 1
}

$memoryBytes = $MemoryGB * 1GB
$diskBytes = $DiskGB * 1GB

$newVMParams = @{
    Name               = $VMName
    Generation         = 2
    MemoryStartupBytes = $memoryBytes
    SwitchName         = $SwitchName
    NewVHDPath         = $null   # definido abaixo consoante VMPath
    NewVHDSizeBytes    = $diskBytes
}

if (-not [string]::IsNullOrWhiteSpace($VMPath)) {
    $newVMParams["Path"] = $VMPath
    $newVMParams["NewVHDPath"] = Join-Path $VMPath "$VMName\$VMName.vhdx"
} else {
    $newVMParams.Remove("NewVHDPath") | Out-Null
    # Sem -Path nem -NewVHDPath explícitos, o Hyper-V usa a localização
    # padrão configurada no host (Hyper-V Settings).
}

Write-Step "A criar a VM '$VMName' (Geracao 2, $MemoryGB GB RAM, disco dinamico $DiskGB GB)..."
$vm = New-VM @newVMParams
Write-Ok "VM '$VMName' criada."

# vCPU (Parte 2.2 — "depois de criada, em Settings -> Processor")
Write-Step "A configurar $CPUCount vCPU..."
Set-VMProcessor -VMName $VMName -Count $CPUCount

# Memória dinâmica desligada por omissão no New-VM (fica fixa em
# $MemoryGB); se preferires memória dinâmica, ajusta aqui.
Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false

# Geração 2 -> garantir que o disco criado fica em primeiro na ordem
# de arranque, à frente do DVD (ajustado outra vez depois de montar a ISO).
Write-Step "A configurar Secure Boot (desativado) — Parte 2.3 do guia..."
Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
Write-Ok "Secure Boot desativado."

# DVD virtual para a ISO do Ubuntu
Write-Step "A adicionar unidade de DVD virtual..."
$dvd = Add-VMDvdDrive -VMName $VMName -Passthru

if (-not [string]::IsNullOrWhiteSpace($IsoPath)) {
    if (Test-Path $IsoPath) {
        Write-Step "A montar a ISO fornecida: $IsoPath"
        Set-VMDvdDrive -VMName $VMName -Path $IsoPath
        Write-Ok "ISO montada."
    } else {
        Write-Warn2 "O caminho indicado em -IsoPath nao existe: $IsoPath"
        Write-Warn2 "Monta a ISO manualmente mais tarde."
    }
} else {
    Write-Warn2 "Nenhuma ISO indicada (-IsoPath). Vais ter de a montar manualmente."
}

# Ordem de arranque: DVD primeiro (para instalar), depois o disco.
$dvdDrive = Get-VMDvdDrive -VMName $VMName
$hardDrive = Get-VMHardDiskDrive -VMName $VMName
Set-VMFirmware -VMName $VMName -BootOrder $dvdDrive, $hardDrive

Write-Host ""
Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Ok "VM '$VMName' criada e configurada com sucesso."
Write-Host "=========================================================" -ForegroundColor DarkGray

Write-Host ""
Write-Host "Resumo:" -ForegroundColor Cyan
Write-Host "  VM             : $VMName"
Write-Host "  Geracao        : 2"
Write-Host "  RAM            : $MemoryGB GB"
Write-Host "  vCPU           : $CPUCount"
Write-Host "  Disco          : $DiskGB GB (dinamico)"
Write-Host "  Switch         : $SwitchName ($SwitchType)"
Write-Host "  Secure Boot    : Desativado"
Write-Host "  ISO montada    : $(if ($IsoPath) { $IsoPath } else { 'NAO — monta manualmente' })"
Write-Host ""

Write-Host "PROXIMOS PASSOS MANUAIS (nao automatizaveis com seguranca):" -ForegroundColor Yellow
Write-Host "  1. Se ainda nao montaste a ISO, faz Settings -> DVD Drive -> Image file"
Write-Host "     no Hyper-V Manager e escolhe o ubuntu-22.04.x-live-server-amd64.iso."
Write-Host "  2. Confirma nas definicoes do host (BIOS/UEFI) que a virtualizacao de"
Write-Host "     hardware (Intel VT-x / AMD-V) esta ativa — ver scripts/README.md."
Write-Host "  3. Liga a VM (Start-VM -Name '$VMName') e abre a consola (vmconnect)"
Write-Host "     para acompanhar o instalador do Ubuntu Server — Parte 2.4 do guia"
Write-Host "     (idioma, disco, utilizador, e marcar 'Install OpenSSH server')."
Write-Host "  4. Depois de instalado e reiniciado, confirma o IP com 'ip a' dentro"
Write-Host "     da VM (Parte 2.5) e liga por SSH a partir do Windows."
Write-Host "  5. Dentro da VM, copia e corre scripts/install-wazuh.sh (Parte 3)."
Write-Host ""
