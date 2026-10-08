# Arranca o laboratorio (3 VMs do VirtualBox, headless) e o backend
# SentryLens em segundo plano (sem janela de consola), com stdout/stderr
# redirecionados para scripts/backend.log.
# Pensado para ser chamado pela tarefa agendada "SentryLens-Backend" (logon
# do utilizador) ou manualmente de manha.
#
# As VMs do laboratorio correm atualmente em VirtualBox (nao Hyper-V, ver
# CLAUDE.md). Arrancar aqui e idempotente: uma VM ja ligada e ignorada.
# Usa -SkipVMs para so arrancar o backend (ex.: VMs ja ligadas a mao).

param(
    [switch]$SkipVMs
)

$ErrorActionPreference = "Stop"

$ScriptsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = Join-Path $ScriptsDir ".venv\Scripts\python.exe"
$LogFile = Join-Path $ScriptsDir "backend.log"

# Nomes das VMs tal como aparecem em `VBoxManage list vms` (ver scripts/README.md).
$LabVMs = @("Wazuh-Manager", "win11_00634_FN-alvo", "Kali-Atacante")

function Get-VBoxManagePath {
    $cmd = Get-Command "VBoxManage.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $default = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    if (Test-Path $default) { return $default }
    return $null
}

if (-not $SkipVMs) {
    $vbox = Get-VBoxManagePath
    if (-not $vbox) {
        Write-Warning "VBoxManage.exe nao encontrado - a saltar o arranque das VMs do laboratorio. Usa -SkipVMs para silenciar este aviso."
    } else {
        $running = & $vbox list runningvms
        foreach ($vm in $LabVMs) {
            if ($running -match [regex]::Escape("`"$vm`"")) {
                Write-Host "VM ja ligada: $vm"
            } else {
                Write-Host "A arrancar VM headless: $vm"
                & $vbox startvm $vm --type headless
            }
        }
    }
}

if (-not (Test-Path $PythonExe)) {
    Write-Error "Python do .venv nao encontrado em '$PythonExe'. Corre 'python -m venv .venv' + 'pip install -r requirements.txt' dentro de scripts/ primeiro."
    exit 1
}

Set-Location $ScriptsDir

Start-Process -FilePath $PythonExe `
    -ArgumentList "-m", "uvicorn", "main:app", "--port", "8001" `
    -WorkingDirectory $ScriptsDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $LogFile `
    -RedirectStandardError "$LogFile.err"
