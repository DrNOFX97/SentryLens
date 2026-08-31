# 🔒 SentryLens

**Dashboard de Cibersegurança — Projeto CET (curso de cibersegurança)**

SentryLens é um dashboard que liga a um laboratório Wazuh real (SIEM
open-source) e mostra, em tempo quase-real, os alertas de segurança
gerados pelos Windows Security Event Logs de uma máquina monitorizada —
com nome amigável, severidade e recomendação de ação para cada tipo de
evento, em vez de IDs numéricos crus.

O projeto tem duas fases que partilham a mesma lógica de classificação:

| Fase | O que faz | Onde está |
|---|---|---|
| **Fase 1** | Analisa ficheiros de log estáticos (XML exportado do Windows Event Viewer) e gera um relatório | `log_analyzer_real.py` (não incluído neste repo — script standalone de uma sessão anterior) |
| **Fase 2** *(este repo)* | Liga-se ao vivo a um laboratório Wazuh (Hyper-V) via API e mostra os alertas num dashboard web | `scripts/` (backend) + `index.html` / `app.js` / `style.css` (frontend) |

A classificação de Event ID → nome amigável / severidade / recomendação
é **exatamente a mesma lógica da Fase 1**, centralizada em
`scripts/event_catalog.py`, para que as duas fases "falem a mesma
língua".

---

## Arquitetura

```
┌─────────────────────────── Windows (anfitrião real) ───────────────────────────┐
│                                                                                  │
│   Wazuh Agent (WazuhSvc) ──── envia Windows Event Logs ────┐                    │
│                                                              │                   │
│   Browser ──abre──► index.html + app.js + style.css         │                   │
│                          │                                  │                   │
│                          │ fetch() para /api/*               │                   │
│                          ▼                                  │                   │
│                   FastAPI backend (scripts/main.py)          │                   │
│                   porta 8001 (uvicorn)                       │                   │
│                          │                                  │                   │
└──────────────────────────┼──────────────────────────────────┼───────────────────┘
                            │                                  │
                            │ Manager API (55000, JWT)          │  agente Windows
                            │ Indexer API (9200, Basic Auth)    │  regista-se aqui
                            ▼                                  ▼
                ┌───────────────────────────────────────────────────┐
                │         VM Ubuntu Server (Hyper-V, switch          │
                │         externo "Lab-Wazuh") — 192.168.1.143       │
                │                                                     │
                │   wazuh-manager   wazuh-indexer   wazuh-dashboard  │
                │   (analisa logs)  (OpenSearch,     (UI web do       │
                │                    guarda alertas)  Wazuh, porta 443)│
                └───────────────────────────────────────────────────┘
```

O backend nunca fala diretamente com o agente — ele consulta as duas
APIs do Wazuh Manager/Indexer, que já têm os alertas processados.

> ⚠️ **Nota sobre o hypervisor:** o diagrama acima e o resto deste
> README (scripts `setup-hyperv-lab.ps1`, `CLAUDE.md`) descrevem o
> caminho Hyper-V. Na prática, a VM `Wazuh-Manager` usada neste PC
> corre em **VirtualBox** (`VBoxManage list vms` confirma-o), com
> Hyper-V desativado ao nível do SO — as duas coisas não coexistem
> facilmente na mesma máquina. Os endpoints/portas/credenciais são
> iguais independentemente do hypervisor; só o arranque automático da
> VM (ver secção seguinte) usa `VBoxManage`, não `Set-VM`.

---

## 📊 Estado atual do projeto

> Última verificação: sessão de desenvolvimento de 2026-08-31.

- ✅ Laboratório Wazuh montado e a correr (VM `Wazuh-Manager`, IP
  `192.168.1.143` — ver nota sobre VirtualBox/Hyper-V acima).
- ✅ Backend FastAPI completo (`scripts/main.py`, `wazuh_client.py`,
  `event_catalog.py`, `system_monitor.py`) e testado de ponta a ponta
  com dados reais do Wazuh.
- ✅ **Monitorização do sistema local muito mais detalhada**
  (`system_monitor.py`): CPU (modelo, frequência, núcleos), RAM
  (módulos físicos — fabricante, part number, capacidade, velocidade,
  geração DDR, via WMI), disco (por partição: device, filesystem, **e
  o disco físico por trás — modelo e SSD/HDD**, via
  `Get-PhysicalDisk`), interfaces de rede, histórico de violações de
  threshold. Tudo Windows-only (WMI/PowerShell), com fallback vazio
  silencioso se algum comando falhar — nunca derruba o resto dos specs.
- ✅ **Frontend reorganizado em 4 abas** (`index.html` + `app.js`):
  - **Visão Geral** — KPIs, cartão de resumo do sistema (clicável, leva
    à aba Sistema) e os 3 gráficos de análise.
  - **Alertas** — banner de força bruta + tabela densa (uma linha por
    alerta, todos os campos sempre visíveis, incl. log completo).
  - **Agentes** — tabela com nome, IP, SO, estado, último keep-alive.
  - **Sistema** — lista vertical (uma linha larga por métrica: CPU,
    RAM, cada disco, rede), interfaces de rede, alertas ativos,
    histórico de violações resolvidas, gráfico de uso.
- ✅ **Identidade visual própria** — paleta extraída do logo (navy +
  ciano elétrico, tokens CSS em `style.css`) em vez de azul de SaaS
  genérico; tipografia Space Grotesk (títulos/valores) + Inter (corpo)
  + JetBrains Mono (IPs, Event IDs, timestamps, logs).
- ✅ **Arranque automático configurado** neste PC — ver
  [secção dedicada](#-arranque-automático) abaixo: VM sobe sozinha ao
  iniciar sessão, `wazuh-manager` reinicia sozinho se falhar por race
  condition no boot, backend arranca em segundo plano.
- ⚠️ **Porta 8000 ocupada** neste PC por um serviço Windows de
  terceiros (`httpd.exe` / `IBXDashboard`) — o backend usa **porta
  8001** (ver [Nota sobre a porta 8000](#nota-sobre-a-porta-8000)).
- ⚠️ **Só há telemetria do lado Linux (o próprio manager)** — nenhum
  agente Windows registado neste host ainda (Parte 5 do guia por
  correr). `/api/agents` só mostra o manager auto-monitorizado
  (`fnuno`, `127.0.0.1`, `os: Ubuntu`), alertas vêm classificados como
  `"Evento não catalogado" / severity: info` (PAM, sudo, systemd), e
  "Top Eventos" fica vazio (nenhum tem `windows_event_id`). Para ver os
  23 Event IDs classificados e testar deteção de força bruta, falta
  instalar o agente Windows (ver
  [Parte 5 do guia](docs/LAB_WAZUH_HYPERV.md#parte-5--instalar-o-agente-wazuh-no-windows)).
- ❌ `log_analyzer_real.py` (script standalone da Fase 1) não está
  neste repo — existiu apenas numa sessão de trabalho anterior.
- ❌ Sem autenticação no dashboard, sem websockets, sem persistência
  própria de histórico — ver [Próximos passos](#-próximos-passos).

---

## 📁 Estrutura do repositório

```
Dashboard cybersec/
├── README.md                    ← este ficheiro
├── CLAUDE.md                    ← instruções do projeto para o Claude Code
├── index.html                   ← frontend: página do dashboard
├── app.js                       ← frontend: lógica (fetch às APIs, render)
├── style.css                    ← frontend: estilos (tema escuro)
├── logo.png
│
├── scripts/                     ← backend FastAPI + automação do laboratório
│   ├── main.py                  ← app FastAPI, endpoints REST
│   ├── wazuh_client.py          ← cliente para Manager API + Indexer API
│   ├── event_catalog.py         ← classificação de Event IDs (Fase 1 reaproveitada)
│   ├── requirements.txt         ← dependências Python do backend
│   ├── .env                     ← credenciais reais (não versionar!)
│   ├── .env.example             ← template de configuração
│   ├── README.md                ← guia dos scripts de automação do laboratório
│   ├── system_monitor.py        ← specs/saúde da máquina local (CPU/RAM/disco/rede)
│   ├── setup-hyperv-lab.ps1     ← 1) cria Hyper-V switch + VM (Windows, Admin)
│   ├── install-wazuh.sh         ← 2) instala o Wazuh dentro da VM (via SSH)
│   ├── install-wazuh-agent.ps1  ← 3) instala o agente no Windows (Admin)
│   └── start-backend.ps1        ← wrapper usado pela tarefa agendada (ver Arranque automático)
│
└── docs/
    ├── README.md                ← guia detalhado de setup do backend/frontend
    └── LAB_WAZUH_HYPERV.md      ← guia passo-a-passo completo do laboratório
                                    (cobre VirtualBox *e* Hyper-V — este
                                    projeto usa o caminho Hyper-V)
```

---

## ✅ Pré-requisitos

- Windows 10/11 Pro, Enterprise ou Education (Hyper-V não existe na
  edição Home).
- Virtualização de hardware (Intel VT-x / AMD-V) ativa na BIOS/UEFI.
- Python 3.12+ instalado e no PATH.
- Uma VM Ubuntu Server 22.04 LTS com Wazuh instalado, acessível na
  rede local (ver secção seguinte).

---

## 1. Montar o laboratório Wazuh

Guia completo: [`docs/LAB_WAZUH_HYPERV.md`](docs/LAB_WAZUH_HYPERV.md).
Resumo dos 3 scripts automatizados, **corridos manualmente por esta
ordem** (nunca em automático — envolvem reiniciar o PC e mexer em
virtualização):

| # | Script | Onde corre | O que automatiza |
|---|---|---|---|
| 1 | `scripts/setup-hyperv-lab.ps1` | Windows anfitrião (PowerShell, Admin) | Ativa Hyper-V, cria o Virtual Switch `Lab-Wazuh` (externo) e a VM (Geração 2, 8 GB RAM, 4 vCPU, 60 GB disco dinâmico, Secure Boot desativado) |
| — | *(manual)* instalação do Ubuntu Server | Consola Hyper-V | Interativo de propósito — idioma, disco, utilizador, e sobretudo marcar **"Install OpenSSH server"** |
| 2 | `scripts/install-wazuh.sh` | Dentro da VM Ubuntu (via SSH) | `apt update/upgrade`, `wazuh-install.sh -a`, mostra as passwords geradas, confirma manager/indexer/dashboard `active (running)` |
| — | *(manual)* login no Dashboard Wazuh | Browser do Windows | `https://<IP_DA_VM>` → aceitar certificado autoassinado → login `admin` |
| 3 | `scripts/install-wazuh-agent.ps1 -WazuhManagerIP <IP_DA_VM>` | Windows a monitorizar (PowerShell, Admin) | Descarrega o MSI do agente, instala silenciosamente, arranca `WazuhSvc`, confirma `Running` |
| — | *(manual)* validação final | Wazuh Dashboard | Management → Endpoints → agente `Active`; gerar logon falhado de propósito e confirmar `rule.id 60122` / Event ID `4625` em Threat Hunting |

Detalhes de cada parâmetro (`Get-Help .\setup-hyperv-lab.ps1 -Full`) e
a lista de passos propositadamente **não** automatizados (BIOS/UEFI,
instalador interativo, etc.) estão em
[`scripts/README.md`](scripts/README.md).

---

## 2. Configurar e correr o backend

```bash
cd scripts
pip install -r requirements.txt
cp .env.example .env    # depois editar com os valores reais
```

Editar `scripts/.env`:

```env
# Wazuh Manager API (porta 55000)
WAZUH_MANAGER_URL=https://<IP_DA_VM>:55000
WAZUH_MANAGER_USER=wazuh-wui
WAZUH_MANAGER_PASSWORD=<password real>

# Wazuh Indexer API (porta 9200)
WAZUH_INDEXER_URL=https://<IP_DA_VM>:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=<password real>
```

Ambas as passwords vêm do ficheiro gerado durante a instalação do
Wazuh (dentro da VM):

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Correr o backend:

```bash
uvicorn main:app --reload --port 8001
```

Confirmar que está de pé:

```bash
curl http://localhost:8001/api/health
# {"status":"ok","timestamp":"2026-08-28T21:47:37.019106"}
```

Documentação interativa (Swagger) em `http://localhost:8001/docs`.

### Nota sobre a porta 8000

O default "óbvio" para uma app FastAPI seria a porta 8000, mas **neste
PC essa porta já está ocupada** por um serviço Windows de terceiros:

```
> tasklist | findstr 8000-relacionado
httpd.exe   4940   Services

> tasklist /svc /fi "PID eq 4940"
httpd.exe   4940   IBXDashboard
```

É um Apache (`httpd.exe`) a correr como serviço persistente chamado
`IBXDashboard`, sem relação nenhuma com este projeto. Por isso o
backend e a documentação usam **8001** como porta default — não é
preciso mexer no serviço `IBXDashboard` nem investigar mais, só usar
8001 sempre que correres `uvicorn` aqui.

---

## 🚀 Arranque automático

Configurado neste PC para que, ao iniciar sessão, tudo suba sozinho —
três peças independentes:

| # | O quê | Onde | Como |
|---|---|---|---|
| 1 | VM `Wazuh-Manager` arranca em headless | Windows Task Scheduler | Tarefa `Wazuh-Manager-VM`, trigger "ao iniciar sessão", corre `VBoxManage startvm "Wazuh-Manager" --type headless` |
| 2 | `wazuh-manager` resiste a falhar no boot | VM (systemd override) | `/etc/systemd/system/wazuh-manager.service.d/override.conf` — `Restart=on-failure`, `RestartSec=15` (o `wazuh-apid` por vezes morre por race condition com o Indexer a arrancar ao mesmo tempo) |
| 3 | Backend FastAPI arranca em segundo plano | Windows Task Scheduler | Tarefa `SentryLens-Backend`, trigger "ao iniciar sessão", corre `scripts/start-backend.ps1` (uvicorn escondido, logs em `scripts/backend.log`) |

Gerir as tarefas: `Get-ScheduledTask -TaskName "SentryLens-Backend","Wazuh-Manager-VM"`
no PowerShell, ou pela app "Agendador de Tarefas" do Windows.
`Unregister-ScheduledTask -TaskName <nome>` remove uma.

É normal, nos primeiros 1–3 minutos depois do login, `/api/agents`,
`/api/alerts`, etc. devolverem `502` enquanto a VM e os serviços Wazuh
ainda estão a arrancar — o backend não falha, só não consegue
contactar o Wazuh ainda.

---

## 3. Servir o frontend

O frontend é HTML/CSS/JS puro (`index.html`, `app.js`, `style.css`, na
raiz do repo, ao lado uns dos outros). `app.js` aponta para
`API_BASE = "http://localhost:8001"`.

**Opção A — servidor estático simples (recomendado, evita problemas de
CORS/cache que acontecem ao abrir via `file://`):**

```bash
python -m http.server 5500
```

Depois abrir `http://localhost:5500/index.html`.

**Opção B — abrir diretamente:**

Duplo-clique em `index.html`. Funciona, mas alguns browsers bloqueiam
`fetch()` para `localhost` a partir de `file://` — se o dashboard
ficar preso em "a carregar...", usa a Opção A.

O dashboard atualiza automaticamente a cada 30 segundos, ou
manualmente com o botão "🔄 Atualizar". O indicador no canto superior
direito mostra:

- **● ligado ao Wazuh** (verde) — todos os pedidos à API tiveram
  sucesso.
- **● sem ligação** (vermelho) — pelo menos um pedido falhou (backend
  em baixo, ou backend incapaz de contactar o Wazuh — ver consola do
  browser, F12, para o erro exato).

A interface está organizada em 4 abas:

| Aba | Conteúdo |
|---|---|
| 📊 **Visão Geral** | KPIs (total/severidade/agentes ativos), cartão de resumo do sistema (clicável → aba Sistema), gráficos de análise |
| 🚨 **Alertas** | Banner de força bruta (quando há suspeitos) + tabela densa com todos os campos de cada alerta, incl. log completo |
| 🖥️ **Agentes** | Tabela de agentes Wazuh — nome, IP, SO, estado, último keep-alive |
| ⚙️ **Sistema** | CPU/RAM/disco/rede desta máquina em detalhe (modelo, módulos, SSD/HDD), interfaces de rede, alertas de sistema ativos, histórico de violações, gráfico de uso |

---

## 4. Endpoints da API

Todos devolvem JSON. CORS está aberto (`allow_origins=["*"]`) — restringir
antes de expor isto fora de uma rede de confiança.

### `GET /api/health`
Confirma que o backend está de pé (não testa ligação ao Wazuh).
```json
{"status": "ok", "timestamp": "2026-08-28T21:47:37.019106"}
```

### `GET /api/agents`
Lista de agentes Wazuh e o seu estado atual (via Manager API).
```json
{
  "agents": [
    {"id": "001", "name": "DESKTOP-ABC", "ip": "192.168.1.50",
     "status": "active", "os": "Windows 11", "last_keep_alive": "..."}
  ],
  "summary": { "connection": {"active": 1, "disconnected": 0, "never_connected": 0} }
}
```
Erro → `502` `{"detail": "Erro ao contactar Wazuh Manager: ..."}`.

### `GET /api/alerts`
Alertas recentes, já enriquecidos com a classificação de Event ID.

| Parâmetro | Tipo | Default | Descrição |
|---|---|---|---|
| `hours` | int (1–168) | 24 | Janela temporal |
| `min_level` | int (0–16) | 0 | Nível mínimo de severidade *Wazuh* (`rule.level`) |
| `agent_name` | string | — | Filtra por nome de agente |
| `severity` | string | — | Filtra pela severidade *classificada* (`critical`/`high`/`medium`/`low`) |

```json
{
  "total": 3,
  "alerts": [
    {
      "timestamp": "2026-08-28T21:40:00Z",
      "agent_name": "DESKTOP-ABC",
      "agent_ip": "192.168.1.50",
      "rule_id": "60122",
      "rule_description": "Failed logon attempt",
      "wazuh_level": 10,
      "windows_event_id": 4625,
      "friendly_name": "Failed Logon",
      "severity": "high",
      "recommendation": "Implementar bloqueio de conta após N falhas. Investigar origem dos IPs. Considerar MFA.",
      "full_log": "..."
    }
  ]
}
```
Erro → `502` `{"detail": "Erro ao contactar Wazuh Indexer: ..."}`.

### `GET /api/stats`
KPIs agregados para os cartões do dashboard.

| Parâmetro | Tipo | Default |
|---|---|---|
| `hours` | int (1–168) | 24 |

```json
{
  "window_hours": 24,
  "total_alerts": 42,
  "by_severity": {"high": 10, "medium": 20, "info": 12},
  "top_events": [{"event_id": 4625, "name": "Failed Logon", "count": 8}],
  "by_agent": {"DESKTOP-ABC": 42}
}
```

### `GET /api/brute-force`
Deteção de força bruta: agrupa Event ID `4625` (Failed Logon) por
utilizador-alvo e assinala quem excedeu o `threshold`.

| Parâmetro | Tipo | Default |
|---|---|---|
| `hours` | int (1–168) | 24 |
| `threshold` | int (≥1) | 5 |

```json
{
  "window_hours": 24,
  "threshold": 5,
  "suspects": [
    {"user": "administrador", "failed_attempts": 7,
     "last_attempt": "2026-08-28T21:39:00Z", "source_agent": "DESKTOP-ABC"}
  ]
}
```

### Endpoints de sistema (`system_monitor.py` — a máquina local, não o Wazuh)

Não dependem do Wazuh; falham (500) só se algo correr mal a recolher
specs desta própria máquina.

| Endpoint | Descrição |
|---|---|
| `GET /api/system/specs` | Snapshot atual: CPU (modelo/freq/núcleos/uso), RAM (uso + módulos físicos), disco por partição (uso + modelo/SSD-HDD do disco físico), interfaces de rede, última medição de velocidade |
| `GET /api/system/alerts` | Violações de threshold **ativas** neste momento (RAM/disco/rede), com duração |
| `GET /api/system/history` | Violações **já resolvidas** (histórico persistido em `scripts/system_alerts_history.json`) |
| `GET /api/system/usage-history` | Buffer em memória (~1h, amostra a cada 30s) de CPU/RAM/disco — alimenta o gráfico "Histórico de uso" |
| `POST /api/system/speedtest` | Força uma medição de velocidade de rede imediata (Ookla Speedtest CLI), ignora a cache |

Thresholds atuais (`system_monitor.THRESHOLDS`): RAM aviso/crítico
85%/95%, disco 80%/90%, rede (download/upload) aviso abaixo de 700
Mbps, crítico abaixo de 500 Mbps.

---

## 5. Catálogo de Event IDs (`scripts/event_catalog.py`)

23 Event IDs do Windows Security Log, reaproveitados tal como
validados na Fase 1 — mapa central `CRITICAL_EVENTS` (nome + severidade)
e `RECOMMENDATIONS` (ação sugerida), combinados por `classify_alert()`:

| Event ID | Nome | Severidade |
|---|---|---|
| 4625 | Failed Logon | high |
| 4672 | Special Privileges Assigned | high |
| 4698 | Scheduled Task Created | high |
| 4699 | Scheduled Task Deleted | medium |
| 4700 | Scheduled Task Disabled | low |
| 4701 | Scheduled Task Updated | medium |
| 4702 | Scheduled Task Renamed | low |
| 4703 | Scheduled Task Enabled | low |
| 4704 | User Right Assigned | high |
| 4713 | Kerberos Policy Changed | high |
| 4719 | Security Policy Changed | high |
| 4720 | User Account Created | medium |
| 4722 | User Account Enabled | low |
| 4723 | Password Change Attempt | low |
| 4724 | Password Reset Attempt | medium |
| 4726 | User Account Deleted | high |
| 4728 | Member Added to Global Group | high |
| 4732 | Member Added to Local Group | medium |
| 4738 | User Account Changed | medium |
| 4756 | Member Added to Universal Group | high |
| 4797 | User Account Locked Out | medium |
| 5140 | Network Share Accessed | low |
| 5145 | Network Share Permission Checked | low |

Um Event ID fora desta lista (ou `None`, quando o alerta não vem de um
log Windows) recebe uma classificação por defeito segura:
`{"friendly_name": "Evento não catalogado", "severity": "info",
"recommendation": "Consultar documentação Wazuh para este rule.id."}`
— nunca rebenta o backend.

Para adicionar um Event ID novo: acrescentar uma entrada a
`CRITICAL_EVENTS` (e opcionalmente a `RECOMMENDATIONS`) em
`scripts/event_catalog.py`. Não é preciso tocar em `main.py`.

---

## 🐛 Troubleshooting

**Frontend mostra "● sem ligação"**
→ Confirma que o backend está a correr (`uvicorn main:app --port 8001`)
→ Abre a consola do browser (F12) e vê o erro exato — normalmente um
`Error: Erro ao contactar Wazuh Manager/Indexer` vindo de `app.js`

**Erro 502 "Erro ao contactar Wazuh Manager/Indexer"**
→ Confirma o IP e as passwords em `scripts/.env`
→ Confirma que a VM está `Running` no Hyper-V Manager
→ Testa conectividade básica primeiro: `ping <IP_DA_VM>` e
`Test-NetConnection <IP_DA_VM> -Port 55000`
→ Testa a autenticação diretamente:
```bash
curl -k -u wazuh-wui:PASSWORD -X POST "https://IP_DA_VM:55000/security/user/authenticate?raw=true"
```
Se isto falhar, o problema é de rede/credenciais, não do backend.

**`uvicorn` falha com `WinError 10013` na porta 8000**
→ Ver [Nota sobre a porta 8000](#nota-sobre-a-porta-8000) — usa
`--port 8001`.

**CORS bloqueado no browser**
→ O backend já tem CORS aberto (`allow_origins=["*"]`)
→ Confirma que estás a aceder ao frontend via `http://localhost:5500`
e não via `file://` diretamente (ver [Servir o frontend](#3-servir-o-frontend), Opção A)

**Nenhum alerta aparece mesmo com o agente `Active`**
→ Gera um evento de teste na máquina Windows (ex: `runas` com password
errada, dá Event ID 4625)
→ Confirma no próprio Wazuh Dashboard (`https://IP_DA_VM`) se os
alertas lá aparecem — se sim e aqui não, o problema está na query ao
índice (`wazuh-alerts-*` pode ter um nome ligeiramente diferente
consoante a versão; confirma em Indexer Management → Index Patterns)

**`ModuleNotFoundError: No module named 'fastapi'` (ou `httpx`, `uvicorn`)**
→ `pip install -r scripts/requirements.txt` no mesmo ambiente Python
que vais usar para correr `uvicorn`

---

## 🚀 Próximos passos

1. **Autenticação no dashboard** — atualmente qualquer pessoa na rede
   local consegue aceder; para produção, adicionar login simples.
2. **Websockets** — substituir o polling de 30s por atualização em
   tempo real.
3. **Persistência própria** — guardar histórico de alertas numa base
   de dados própria (o Wazuh só guarda 90 dias por default).
4. **Exportar relatório** — botão para gerar um relatório HTML com
   dados ao vivo, no mesmo espírito do relatório da Fase 1.
5. Se precisares de reprocessar ficheiros XML estáticos (Fase 1), o
   `log_analyzer_real.py` original existe apenas numa sessão de
   trabalho anterior — recuperar/recriar antes de precisar dele.

---

## 📚 Referências

- [`docs/LAB_WAZUH_HYPERV.md`](docs/LAB_WAZUH_HYPERV.md) — guia
  completo do laboratório (VirtualBox e Hyper-V).
- [`docs/README.md`](docs/README.md) — guia de setup do backend/frontend
  (nota: descreve uma estrutura `backend/`/`frontend/` que já não
  reflete o layout atual do repo — usa este README como fonte de
  verdade sobre a estrutura real).
- [`scripts/README.md`](scripts/README.md) — detalhe dos 3 scripts de
  automação do laboratório e o que cada um **não** automatiza de
  propósito.
