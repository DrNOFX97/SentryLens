<#
.SYNOPSIS
    Arranca o laboratório SentryLens completo: as 3 VMs, o backend e o
    frontend, e abre o dashboard no browser.

.DESCRIPTION
    Ordem:
      1. VM Wazuh-Manager (headless — é um servidor Ubuntu sem GUI útil,
         mesma escolha da tarefa agendada "Wazuh-Manager-VM").
      2. VMs Kali-Atacante e win11_00634_FN-alvo (janela normal — são as
         que se usam interativamente para lançar/observar ataques).
      3. Espera a VM do Wazuh estabilizar antes de arrancar o backend
         (nos primeiros 1-3 min depois de arrancar, /api/agents e
         /api/alerts costumam devolver 502 — ver README).
      4. Backend (scripts/start-backend.ps1, porta 8001).
      5. Frontend (scripts/start-frontend.ps1, porta 5500) — este já
         abre o dashboard no browser por si.

    Cada VM só é arrancada se ainda não estiver em execução (idempotente
    — corre à vontade sem duplicar processos).

.NOTES
    Requer VirtualBox instalado no caminho por omissão. Ajusta
    $VBoxManage se o teu estiver noutro sítio.
#>

$ErrorActionPreference = "Stop"

$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$RepoRoot = $PSScriptRoot
$ScriptsDir = Join-Path $RepoRoot "scripts"

# --- VMs a arrancar: nome -> tipo de janela ---
$Vms = [ordered]@{
    "Wazuh-Manager"       = "headless"
    "Kali-Atacante"       = "gui"
    "win11_00634_FN-alvo" = "gui"
}

function Get-RunningVmNames {
    & $VBoxManage list runningvms 2>$null | ForEach-Object {
        if ($_ -match '^"([^"]+)"') { $Matches[1] }
    }
}

Write-Host "== 1. VMs =="
$running = @(Get-RunningVmNames)
foreach ($name in $Vms.Keys) {
    if ($running -contains $name) {
        Write-Host "  [ja a correr] $name"
        continue
    }
    $type = $Vms[$name]
    Write-Host "  [a arrancar, $type] $name"
    & $VBoxManage startvm $name --type $type | Out-Null
}

Write-Host "== 2. A esperar o Wazuh-Manager estabilizar (90s) =="
Write-Host "  (normal /api/agents e /api/alerts devolverem 502 nos primeiros minutos)"
Start-Sleep -Seconds 90

Write-Host "== 3. Backend (porta 8001) =="
& (Join-Path $ScriptsDir "start-backend.ps1")

Write-Host "== 4. Frontend (porta 5500) + browser =="
& (Join-Path $ScriptsDir "start-frontend.ps1")

Write-Host "== Feito. Dashboard: http://localhost:5500/index.html =="
