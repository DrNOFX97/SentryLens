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
# Usa scripts/serve_frontend.py em vez de `python -m http.server`:
# esse serve a raiz do projeto inteira, incluindo scripts/.env (as
# passwords reais do Wazuh ficavam descarregáveis por qualquer pedido
# HTTP direto) e por omissão liga a todas as interfaces de rede, não
# só a este PC. Achado pela revisão de segurança automática logo a
# seguir a esta tarefa ter ficado a correr permanentemente.
#
# Pensado para ser chamado pela tarefa agendada "SentryLens-Frontend"
# (logon do utilizador), depois de "SentryLens-Backend".

$ErrorActionPreference = "Stop"

$ScriptsDir = $PSScriptRoot
$PythonExe = Join-Path $ScriptsDir ".venv\Scripts\python.exe"
$Port = 5500
$LogFile = Join-Path $ScriptsDir "frontend.log"

if (-not (Test-Path $PythonExe)) {
    Write-Error "Python do .venv nao encontrado em '$PythonExe'. Corre 'python -m venv .venv' dentro de scripts/ primeiro."
    exit 1
}

$ServeScript = Join-Path $ScriptsDir "serve_frontend.py"

# Start-Process -ArgumentList com um array NAO cita elementos com espacos
# (bug conhecido do Windows PowerShell 5.1) — como o caminho do repo tem
# um espaco ("Fernando Nuno"), isso partia o argumento a meio e o Python
# recebia um caminho truncado como se fosse o script a correr. Por isso
# aqui vai tudo numa unica string, com o caminho entre aspas.
Start-Process -FilePath $PythonExe `
    -ArgumentList "`"$ServeScript`" $Port" `
    -WorkingDirectory $ScriptsDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $LogFile `
    -RedirectStandardError "$LogFile.err"

# Dá tempo ao servidor para abrir a porta antes de tentar abrir o browser.
Start-Sleep -Seconds 2
Start-Process "http://localhost:$Port/index.html"
