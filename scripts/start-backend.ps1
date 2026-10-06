# Arranca o backend SentryLens em segundo plano (sem janela de consola),
# com stdout/stderr redirecionados para scripts/backend.log.
# Pensado para ser chamado pela tarefa agendada "SentryLens-Backend" (logon do utilizador).

$ErrorActionPreference = "Stop"

$ScriptsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = Join-Path $ScriptsDir ".venv\Scripts\python.exe"
$LogFile = Join-Path $ScriptsDir "backend.log"

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
