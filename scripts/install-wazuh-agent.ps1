<#
.SYNOPSIS
    Automatiza a Parte 5 do guia docs/LAB_WAZUH_HYPERV.md — instala o
    agente Wazuh no Windows (anfitrião ou outra VM Windows a monitorizar).

.DESCRIPTION
    Descarrega o instalador MSI do Wazuh Agent, instala em modo
    silencioso já apontado para o manager indicado, arranca o serviço
    e confirma o estado com Get-Service.

.NOTES
    Corre em PowerShell como Administrador.

.EXAMPLE
    .\install-wazuh-agent.ps1 -WazuhManagerIP 192.168.1.150

.EXAMPLE
    .\install-wazuh-agent.ps1 -WazuhManagerIP 192.168.1.150 -AgentVersion 4.14.7-1
#>

[CmdletBinding()]
param(
    # IP do Wazuh manager (a VM Ubuntu criada com setup-hyperv-lab.ps1
    # e configurada com install-wazuh.sh). Obrigatório.
    [Parameter(Mandatory = $true)]
    [string]$WazuhManagerIP,

    # Versão do pacote do agente Windows (ver
    # https://packages.wazuh.com/4.x/windows/ para versões disponíveis).
    [string]$AgentVersion = "4.14.7-1",

    # Nome com que o agente se regista no dashboard. Por omissão usa o
    # nome do computador.
    [string]$AgentName = $env:COMPUTERNAME,

    # Caminho onde guardar o instalador MSI temporariamente.
    [string]$InstallerPath = "$env:TEMP\wazuh-agent.msi"
)

$ErrorActionPreference = "Stop"

function Write-Step { param([string]$m) Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "OK  $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "!!  $m" -ForegroundColor Yellow }

# --- Verificar que corre como Administrador ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este script tem de correr num PowerShell como Administrador." -ForegroundColor Red
    exit 1
}

# --- Validar IP ---
if ($WazuhManagerIP -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
    Write-Host "O valor de -WazuhManagerIP nao parece um IPv4 valido: '$WazuhManagerIP'" -ForegroundColor Red
    exit 1
}

Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Host " Instalacao do Agente Wazuh no Windows (Parte 5)" -ForegroundColor DarkGray
Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Host "Manager    : $WazuhManagerIP"
Write-Host "Nome agente: $AgentName"
Write-Host "Versao MSI : $AgentVersion"

# ---------------------------------------------------------------------
# Testar conectividade ao manager antes de instalar (evita instalar
# e ficar sem saber porque não regista)
# ---------------------------------------------------------------------
Write-Step "A testar conectividade com o manager em $WazuhManagerIP (porta 1514)..."
$portTest = Test-NetConnection -ComputerName $WazuhManagerIP -Port 1514 -WarningAction SilentlyContinue

if ($portTest.TcpTestSucceeded) {
    Write-Ok "Porta 1514/TCP acessivel."
} else {
    Write-Warn2 "Nao foi possivel alcancar $WazuhManagerIP na porta 1514/TCP."
    Write-Warn2 "Confirma o IP da VM e as regras de firewall (ver Parte 5 / Troubleshooting do guia)."
    Write-Warn2 "A continuar mesmo assim — a instalacao prossegue mas o agente pode nao registar."
}

# ---------------------------------------------------------------------
# Download do MSI
# ---------------------------------------------------------------------
$downloadUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$AgentVersion.msi"

Write-Step "A descarregar o instalador de $downloadUrl..."
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $InstallerPath -UseBasicParsing
} catch {
    Write-Host "Falha no download: $_" -ForegroundColor Red
    Write-Host "Confirma a versao (-AgentVersion) em https://packages.wazuh.com/4.x/windows/" -ForegroundColor Red
    exit 1
}
Write-Ok "Download concluido: $InstallerPath"

# ---------------------------------------------------------------------
# Instalação silenciosa
# ---------------------------------------------------------------------
Write-Step "A instalar o agente (modo silencioso)..."

$msiArgs = @(
    "/i", "`"$InstallerPath`"",
    "/q",
    "WAZUH_MANAGER=$WazuhManagerIP",
    "WAZUH_AGENT_NAME=$AgentName"
)

$process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList $msiArgs

if ($process.ExitCode -ne 0) {
    Write-Host "msiexec terminou com codigo de saida $($process.ExitCode)." -ForegroundColor Red
    Write-Host "Corre 'msiexec /i $InstallerPath' sem /q para ver o assistente e diagnosticar." -ForegroundColor Red
    exit 1
}
Write-Ok "Instalacao concluida (exit code 0)."

# ---------------------------------------------------------------------
# Arrancar o serviço
# ---------------------------------------------------------------------
Write-Step "A arrancar o servico WazuhSvc..."

try {
    Start-Service -Name "WazuhSvc"
} catch {
    Write-Warn2 "Start-Service falhou ($_), a tentar 'NET START WazuhSvc'..."
    NET START WazuhSvc | Out-Null
}

# Pequena espera para o serviço estabilizar antes de verificar
Start-Sleep -Seconds 3

# ---------------------------------------------------------------------
# Confirmar estado
# ---------------------------------------------------------------------
Write-Step "A confirmar o estado do servico..."

$service = Get-Service -Name "*wazuh*" -ErrorAction SilentlyContinue

if (-not $service) {
    Write-Host "Nao encontrei nenhum servico 'wazuh*' instalado. A instalacao falhou." -ForegroundColor Red
    exit 1
}

$service | Format-Table -AutoSize

if ($service.Status -eq "Running") {
    Write-Ok "WazuhSvc esta 'Running'."
} else {
    Write-Host "WazuhSvc nao esta 'Running' (estado atual: $($service.Status))." -ForegroundColor Red
    Write-Host "Tenta 'Restart-Service WazuhSvc' e consulta os Event Logs (Application) para detalhes." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Ok "Agente Wazuh instalado e a correr."
Write-Host "=========================================================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Proximos passos manuais (Parte 6 do guia):" -ForegroundColor Yellow
Write-Host "  1. No Wazuh Dashboard -> Management/Endpoints -> confirma que"
Write-Host "     '$AgentName' aparece como 'Active'."
Write-Host "  2. Gera um evento de teste (ex: logon falhado / runas com password errada)."
Write-Host "  3. No Dashboard -> Threat Hunting -> Security Events -> procura"
Write-Host "     'rule.id: 60122' ou '4625' para confirmar que chega em segundos."
Write-Host ""
Write-Host "Portas necessarias entre este Windows e o manager ($WazuhManagerIP):" -ForegroundColor DarkGray
Write-Host "  1514/TCP (logs), 1515/TCP (registo inicial)" -ForegroundColor DarkGray
Write-Host ""
