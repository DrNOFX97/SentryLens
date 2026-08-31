# Arranca o servidor estático do frontend SentryLens em segundo plano
# (sem janela de consola) e abre o dashboard no browser.
#
# Existe porque abrir index.html diretamente por duplo-clique (file://)
# deixou de funcionar depois do CORS do backend ficar restrito a
# localhost/127.0.0.1 (correção de segurança de 2026-08-31) — file://
# envia Origin: null, que essa restrição não reconhece de propósito.
# Servir sempre por http://localhost mantém o CORS seguro sem exigir
# que o utilizador abra um servidor à mão todos os dias.
#
# Pensado para ser chamado pela tarefa agendada "SentryLens-Frontend"
# (logon do utilizador), depois de "SentryLens-Backend".

$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path -Parent $PSScriptRoot
$PythonExe = "C:\Users\Fernando Nuno\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0\python.exe"
$Port = 5500
$LogFile = Join-Path $PSScriptRoot "frontend.log"

Set-Location $ProjectDir

Start-Process -FilePath $PythonExe `
    -ArgumentList "-m", "http.server", $Port `
    -WorkingDirectory $ProjectDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $LogFile `
    -RedirectStandardError "$LogFile.err"

# Dá tempo ao servidor para abrir a porta antes de tentar abrir o browser.
Start-Sleep -Seconds 2
Start-Process "http://localhost:$Port/index.html"
