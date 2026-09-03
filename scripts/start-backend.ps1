# Arranca o backend SentryLens em segundo plano (sem janela de consola),
# com stdout/stderr redirecionados para scripts/backend.log.
# Pensado para ser chamado pela tarefa agendada "SentryLens-Backend" (logon do utilizador).

$ErrorActionPreference = "Stop"

$ScriptsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = "C:\Python314\python.exe"
$LogFile = Join-Path $ScriptsDir "backend.log"

Set-Location $ScriptsDir

Start-Process -FilePath $PythonExe `
    -ArgumentList "-m", "uvicorn", "main:app", "--port", "8001" `
    -WorkingDirectory $ScriptsDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $LogFile `
    -RedirectStandardError "$LogFile.err"
