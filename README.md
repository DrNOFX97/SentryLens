# 🔒 SentryLens

**Dashboard de Cibersegurança — Projeto CET (curso de cibersegurança)**

<p align="center">
  <img src="logo.png" alt="SentryLens" width="420"
       style="background:#0a1622;border-radius:14px;padding:20px 30px;">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PYTHON-3.12%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/FASTAPI-0.115.0-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI 0.115.0">
  <img src="https://img.shields.io/badge/SQLITE-indice_de_historico-003B57?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/WAZUH-integracao_SIEM-0B7D92?style=flat-square" alt="Integração com Wazuh">
</p>

SentryLens é um dashboard que liga a um laboratório Wazuh real (SIEM
open-source) e mostra, em tempo quase-real, os alertas de segurança
gerados pelos Windows Security Event Logs de uma máquina monitorizada —
com nome amigável, severidade e recomendação de ação para cada tipo de
evento, em vez de IDs numéricos crus.

O projeto tem duas fases que partilham a mesma lógica de classificação:

| Fase | O que faz | Onde está |
|---|---|---|
| **Fase 1** | Analisa ficheiros de log estáticos (JSON ou CSV) e gera um relatório HTML | [`log_analyzer.py`](log_analyzer.py) — ver [`QUICKSTART.md`](QUICKSTART.md) |
| **Fase 2** *(este repo)* | Liga-se ao vivo a um laboratório Wazuh (VirtualBox/Hyper-V) via API e mostra os alertas num dashboard web | `scripts/` (backend) + `index.html` / `app.js` / `style.css` (frontend) |

A classificação de Event ID → nome amigável / severidade / recomendação
é a mesma lógica da Fase 1, centralizada em `scripts/event_catalog.py`.

### Stack técnica

| Camada | Tecnologia |
|---|---|
| Backend | Python 3.12+, [FastAPI](https://fastapi.tiangolo.com/) 0.115.0, Uvicorn 0.32.0 |
| Integração SIEM | Wazuh (Manager API + Indexer API/OpenSearch) via `httpx` |
| Tempo real | WebSocket nativo do FastAPI (`/ws/alerts`) |
| Persistência | JSONL (histórico bruto/conformidade) + SQLite (índice de consulta) |
| Machine Learning | scikit-learn 1.5.2 (Isolation Forest) |
| Frontend | HTML/CSS/JavaScript puro (sem framework nem build step), Chart.js |
| Testes | 12 scripts standalone (`scripts/test_*.py`) — sem pytest, ver [Testes](#-testes) |
| SO alvo | Windows 10/11 (WMI/PowerShell para specs do sistema) |

---

## Arquitetura

```mermaid
flowchart TB
    subgraph WIN["Windows (anfitrião real)"]
        AGENT["Wazuh Agent (WazuhSvc)"]
        BROWSER(["Browser"])
        FRONTEND["index.html + app.js + style.css"]
        BACKEND["FastAPI backend (scripts/main.py)<br/>porta 8001 (uvicorn)"]
    end

    subgraph VM["VM Ubuntu Server (switch externo 'Lab-Wazuh')"]
        MANAGER["wazuh-manager<br/>(analisa logs)"]
        INDEXER["wazuh-indexer<br/>(OpenSearch, guarda alertas)"]
        DASHBOARD["wazuh-dashboard<br/>(UI web do Wazuh, porta 443)"]
    end

    BROWSER -->|abre| FRONTEND
    FRONTEND -->|"fetch() para /api/*"| BACKEND
    FRONTEND -->|"WebSocket /ws/alerts (?api_key=...)"| BACKEND
    BACKEND -->|"Manager API 55000, JWT"| MANAGER
    BACKEND -->|"Indexer API 9200, Basic Auth — polling interno a cada 10s"| INDEXER
    AGENT -->|"envia Windows Event Logs"| MANAGER
```

O backend nunca fala diretamente com o agente — consulta as duas APIs do
Wazuh Manager/Indexer, que já têm os alertas processados.

> ⚠️ A VM `Wazuh-Manager` usada neste PC corre em **VirtualBox**
> (`VBoxManage list vms` confirma-o), não em Hyper-V — os scripts de
> setup (`setup-hyperv-lab.ps1`) e o guia
> [`docs/LAB_WAZUH_HYPERV.md`](docs/LAB_WAZUH_HYPERV.md) descrevem o
> caminho Hyper-V, mas endpoints/portas/credenciais são iguais em
> qualquer um dos dois hypervisors; só o arranque automático (ver
> [Arranque automático](#-arranque-automático)) usa `VBoxManage`.

---

## Funcionalidades

- Dashboard web com 9 abas — ver tabela em [Servir o frontend](#3-servir-o-frontend).
- Classificação de 23 Event IDs do Windows Security Log em nome
  amigável + severidade + recomendação (ver [Catálogo de Event
  IDs](#5-catálogo-de-event-ids-scriptsevent_catalogpy)).
- Atualização em tempo real por WebSocket (`/ws/alerts`), com fallback
  automático para polling a cada 30s se a ligação falhar.
- Autenticação por API key em todos os endpoints `/api/*`.
- Persistência própria de histórico de alertas (JSONL + índice SQLite),
  para além dos 90 dias de retenção do Wazuh Indexer.
- Exportação de relatório HTML autónomo (`GET /api/export/report`).
- Avaliação de conformidade regulatória (RGPD/NIS2/AI Act) por alerta.
- Classificação NIS2 sugerida a partir de CAE/colaboradores/faturação
  já conhecidos (sem pesquisa automática online).
- Deteção de anomalias por Machine Learning (Isolation Forest), lado a
  lado com a classificação por regras.
- Monitorização detalhada do sistema local (CPU, RAM, disco físico por
  modelo/SSD-HDD, rede) via WMI/PowerShell.
- Arranque automático configurado neste PC (VM + backend + frontend, ao
  iniciar sessão) — ver [secção dedicada](#-arranque-automático).

> ⚠️ Sem distinção entre múltiplos utilizadores — a API key é
> partilhada, não é login (ver [Próximos passos](#-próximos-passos)).

---

## 📁 Estrutura do repositório

```
Dashboard cybersec/
├── README.md                    ← este ficheiro
├── CLAUDE.md                    ← instruções do projeto para o Claude Code
├── index.html / app.js / style.css ← frontend
├── logo.png
│
├── log_analyzer.py              ← Fase 1: analisa logs estáticos, gera relatório HTML
├── sample_events.json / report.html / report.json / QUICKSTART.md ← Fase 1
├── HARDENING_CHECKLIST.md       ← checklist de hardening Windows, referência autónoma
├── INCIDENT_RESPONSE.md         ← playbook de resposta a incidentes, referência autónoma
│
├── scripts/                     ← backend FastAPI + automação do laboratório
│   ├── main.py                  ← app FastAPI, endpoints REST + WebSocket
│   ├── wazuh_client.py          ← cliente para Manager API + Indexer API
│   ├── event_catalog.py         ← classificação de Event IDs
│   ├── websocket_alerts.py      ← ConnectionManager + alert_poll_loop (/ws/alerts, 10s)
│   ├── history_store.py         ← persistência JSONL (alerts.jsonl, compliance.jsonl)
│   ├── history_index.py         ← índice SQLite sobre o histórico
│   ├── compliance_evaluator.py / compliance_rules.yaml / org_profile.py ← motor RGPD/NIS2/AI Act
│   ├── nis2_lookup.py           ← classificação NIS2 sugerida (sem scraping)
│   ├── report_generator.py      ← gerador de relatório HTML autónomo
│   ├── lifecycle.py / rbac.py / admin_activity.py ← painéis de ciclo de vida/RBAC/admin
│   ├── ml_anomalies.py / feature_extractor.py / train_anomaly_model.py ← deteção por ML
│   ├── system_monitor.py        ← specs/saúde da máquina local
│   ├── test_*.py                ← 12 scripts de teste standalone (ver Testes)
│   ├── requirements.txt         ← dependências Python do backend
│   ├── .env / .env.example      ← credenciais reais (não versionar) / template
│   ├── README.md                ← guia dos scripts de automação do laboratório
│   ├── setup-hyperv-lab.ps1     ← 1) cria Hyper-V switch + VM (Windows, Admin)
│   ├── install-wazuh.sh         ← 2) instala o Wazuh dentro da VM (via SSH)
│   ├── install-wazuh-agent.ps1  ← 3) instala o agente no Windows (Admin)
│   ├── start-backend.ps1 / start-frontend.ps1 ← wrappers das tarefas agendadas
│   └── historico/ · models/     ← dados gerados em runtime (gitignored)
│
└── docs/
    ├── README.md                ← guia legado (estrutura antiga) — ver aviso no topo do ficheiro
    └── LAB_WAZUH_HYPERV.md      ← guia passo-a-passo do laboratório (VirtualBox e Hyper-V)
```

---

## ✅ Pré-requisitos

- Windows 10/11 Pro, Enterprise ou Education (Hyper-V não existe na
  edição Home) — ou VirtualBox, se seguires o caminho usado neste PC.
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
| — | *(manual)* instalação do Ubuntu Server | Consola Hyper-V | Interativo de propósito — idioma, disco, utilizador, e marcar **"Install OpenSSH server"** |
| 2 | `scripts/install-wazuh.sh` | Dentro da VM Ubuntu (via SSH) | `apt update/upgrade`, `wazuh-install.sh -a`, mostra as passwords geradas, confirma manager/indexer/dashboard `active (running)` |
| — | *(manual)* login no Dashboard Wazuh | Browser do Windows | `https://<IP_DA_VM>` → aceitar certificado autoassinado → login `admin` |
| 3 | `scripts/install-wazuh-agent.ps1 -WazuhManagerIP <IP_DA_VM>` | Windows a monitorizar (PowerShell, Admin) | Descarrega o MSI do agente, instala silenciosamente, arranca `WazuhSvc`, confirma `Running` |
| — | *(manual)* validação final | Wazuh Dashboard | Management → Endpoints → agente `Active`; gerar logon falhado de propósito e confirmar `rule.id 60122` / Event ID `4625` em Threat Hunting |

Detalhes de cada parâmetro (`Get-Help .\setup-hyperv-lab.ps1 -Full`) e a
lista de passos propositadamente **não** automatizados estão em
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

# Obrigatória — sem ela, todos os pedidos a /api/* são recusados com 401
SENTRYLENS_API_KEY=<gerar, ver secção Autenticação por API key>
```

Ambas as passwords do Wazuh vêm do ficheiro gerado durante a instalação
(dentro da VM):

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Correr o backend:

```bash
uvicorn main:app --reload --port 8001
```

Confirmar que está de pé:

```bash
curl -H "X-API-Key: <a tua SENTRYLENS_API_KEY>" http://localhost:8001/api/health
# {"status":"ok","timestamp":"2026-08-28T21:47:37.019106"}
```

Sem o header, este pedido devolve `401`.

> Não há documentação interativa (Swagger/`/docs`) — desativada de
> propósito (`docs_url=None` em `main.py`), porque as rotas automáticas
> do FastAPI não passam pela mesma proteção de API key das rotas
> registadas via `@app.get`/`@app.post`.

### Nota sobre a porta 8000

Neste PC, a porta 8000 já está ocupada por um serviço Windows de
terceiros (`httpd.exe`, serviço `IBXDashboard`, sem relação com este
projeto) — por isso o backend usa **8001** como porta default.

---

## 🚀 Arranque automático

Configurado neste PC para que, ao iniciar sessão, tudo suba sozinho:

| # | O quê | Onde | Como |
|---|---|---|---|
| 1 | VM `Wazuh-Manager` arranca em headless | Windows Task Scheduler | Tarefa `Wazuh-Manager-VM`, `VBoxManage startvm "Wazuh-Manager" --type headless` |
| 2 | `wazuh-manager` resiste a falhar no boot | VM (systemd override) | `Restart=on-failure`, `RestartSec=15` (mitiga race condition com o Indexer a arrancar ao mesmo tempo) |
| 3 | Backend FastAPI arranca em segundo plano | Windows Task Scheduler | Tarefa `SentryLens-Backend`, corre `scripts/start-backend.ps1` (logs em `scripts/backend.log`) |
| 4 | Frontend arranca e abre no browser | Windows Task Scheduler | Tarefa `SentryLens-Frontend`, atraso de 10s, corre `scripts/start-frontend.ps1` (logs em `scripts/frontend.log`) |

Gerir as tarefas: `Get-ScheduledTask -TaskName "SentryLens-Backend","SentryLens-Frontend","Wazuh-Manager-VM"`
no PowerShell, ou pela app "Agendador de Tarefas" do Windows.

É normal, nos primeiros 1–3 minutos depois do login, os endpoints
devolverem `502` enquanto a VM e os serviços Wazuh ainda estão a
arrancar.

---

## 3. Servir o frontend

O frontend é HTML/CSS/JS puro, na raiz do repo. `app.js` aponta para
`API_BASE = "http://localhost:8001"`.

**Opção A — automático (já configurado neste PC):** a tarefa
`SentryLens-Frontend` serve o frontend em `localhost:5500` e abre o
browser sozinha — ver [Arranque automático](#-arranque-automático).

**Opção B — servidor estático manual:**

```bash
python -m http.server 5500
```

Depois abrir `http://localhost:5500/index.html`.

**Opção C — abrir diretamente (não recomendado):** duplo-clique em
`index.html` não funciona — o CORS do backend está restrito a
`localhost`/`127.0.0.1`, e `file://` envia `Origin: null`, que essa
restrição não reconhece de propósito. Usa a Opção A ou B.

O dashboard liga-se por WebSocket ao carregar a página e atualiza-se
imediatamente quando chega um alerta novo (ver [WebSocket em tempo
real](#-websocket-em-tempo-real-wsalerts)); o polling fixo de 30s
continua a existir só como *fallback*. O indicador no canto superior
direito mostra **● ligado ao Wazuh** (verde) ou **● sem ligação**
(vermelho, consultar a consola do browser para o erro exato).

A interface está organizada em 9 abas:

| Aba | Conteúdo |
|---|---|
| 📊 **Visão Geral** | KPIs (total/severidade/agentes ativos), resumo do sistema, gráficos de análise |
| 🚨 **Alertas** | Banner de força bruta + tabela densa com todos os campos de cada alerta |
| 🖥️ **Agentes** | Tabela de agentes Wazuh — nome, IP, SO, estado, último keep-alive |
| ⚙️ **Sistema** | CPU/RAM/disco/rede desta máquina em detalhe, interfaces de rede, histórico de violações |
| 📋 **Ciclo de Vida** | Contagens, timeline e deteções de risco no ciclo de vida de contas |
| 🔑 **Privilégios** | Desvios RBAC — grupos atribuídos fora do baseline cargo→grupos permitidos |
| 👤 **Contas Admin** | Atividade de contas administrativas — privilégios especiais, tarefas agendadas |
| 🧠 **ML Anomalias** | Deteção por Isolation Forest lado a lado com a classificação por regras |
| 🛡️ **Conformidade** | Veredito RGPD/NIS2/AI Act por alerta, resumo agregado, perfil da organização |

---

## 🧪 Testes

Sem laboratório Wazuh ligado — tudo mockado (`AsyncMock` sobre
`WazuhIndexerClient`/`WazuhManagerClient`). Sem framework (nem pytest):
12 scripts standalone em `scripts/`, cada um imprime `[OK]`/`[FALHOU]`
por caso e sai com `sys.exit(1)` se algo falhar.

```bash
cd scripts
python test_with_mock.py         # classificação, /api/stats, /api/brute-force
python test_new_panels.py        # /api/lifecycle, /api/privileges, /api/admin-activity
python test_ml_anomalies.py      # /api/ml-anomalies
python test_auth.py              # autenticação por API key (401/200, /docs desligado)
python test_websocket_alerts.py  # /ws/alerts — auth por query param, _poll_once
python test_history_store.py     # persistência JSONL de histórico
python test_history_index.py     # índice SQLite + /api/history/query
python test_compliance.py        # motor RGPD/NIS2/AI Act + /api/compliance
python test_nis2_lookup.py       # classificação NIS2 sugerida + /api/nis2-lookup
python test_report_generator.py  # gerador + /api/export/report
python test_system_monitor.py    # THRESHOLDS + /api/system/thresholds
python test_feature_extractor.py # extração de features de ML (não usa TestClient)
```

Todos definem `SENTRYLENS_API_KEY` em `os.environ` **antes** de
`import main` e fazem `main.app.router.on_startup.clear()` para não
arrancar os loops de background. Correm no `.venv` de `scripts/` — o
Python global desta máquina não tem `scikit-learn`/`joblib`/`PyYAML`
instalados.

---

## 4. Endpoints da API

Todos devolvem JSON, com uma exceção: `GET /api/export/report` devolve
o relatório em HTML como ficheiro para download. CORS restringido a
origens loopback (`localhost`/`127.0.0.1`, qualquer porta). Todos os
endpoints `/api/*` (incluindo `/api/health`) exigem uma API key no
header `X-API-Key`.

### 🔑 Autenticação por API key

Mecanismo propositadamente simples — uma única key partilhada, sem
sessões, sem múltiplos utilizadores, sem JWT — adequado a uma
ferramenta de laboratório local, não a uma aplicação exposta à
internet.

1. **Gerar uma key forte:**
   ```bash
   openssl rand -hex 32                                    # Linux/macOS/Git Bash
   -join ((1..32) | ForEach-Object { "{0:x2}" -f (Get-Random -Maximum 256) })   # PowerShell
   ```
2. **Backend** — `SENTRYLENS_API_KEY=<key>` em `scripts/.env`.
3. **Frontend** — mesma key na constante `API_KEY` em `app.js`.

**Fail-closed:** sem `SENTRYLENS_API_KEY` definida, ou com `X-API-Key`
em falta/errado, a API devolve sempre `401`
(`{"detail": "API key inválida ou em falta"}`) — nunca fica aberta por
omissão.

> ⚠️ Como o frontend é JavaScript estático entregue tal-e-qual ao
> browser, a key fica visível no código-fonte para quem aceder à
> página. Aceitável só porque o CORS restringe a `localhost`/`127.0.0.1`
> num dashboard de laboratório de um único utilizador — não é um
> modelo de segurança válido para uma aplicação multi-utilizador ou
> exposta à internet. Sem rotação nem múltiplas keys nesta fase.

### 🔌 WebSocket em tempo real (`/ws/alerts`)

O backend mantém um ciclo interno (`alert_poll_loop`) que consulta o
Wazuh Indexer a cada **10s** à procura de alertas novos, identificados
pelo `_id` do documento no OpenSearch. Quando um cliente está ligado a
`/ws/alerts`, cada alerta novo é enviado (*pushed*) assim que aparece.

```
ws://localhost:8001/ws/alerts?api_key=<a mesma SENTRYLENS_API_KEY>
```

O handshake de WebSocket do browser não permite headers HTTP
arbitrários, por isso a autenticação aqui é por **query param**, não
por `X-API-Key`. Sem o parâmetro, ou com valor errado, o servidor fecha
a ligação com o código `1008` antes de a aceitar.

Mensagem enviada a cada alerta novo: `{"type": "new_alert", "alert": {...}}`
— o objeto `alert` tem a mesma forma de um item de `GET /api/alerts`.

Se a ligação cair, o frontend tenta reconectar com *backoff* de 1s, 2s,
4s, 8s, 16s (5 tentativas); se todas falharem, mostra um aviso e passa
a depender do polling de 30s, tentando recuperar a ligação a cada 30s.

**Testes:** `scripts/test_websocket_alerts.py`.

### 🗄️ Histórico próprio de alertas e índice SQLite

O Wazuh Indexer apaga alertas com mais de 90 dias (retenção). O mesmo
`alert_poll_loop` do WebSocket persiste cada alerta novo em paralelo,
sem criar um segundo poller:

- **JSONL** (`scripts/history_store.py`) — `scripts/historico/AAAA/MM-mês/AAAA-MM-DD-alerts.jsonl`
  (e `-compliance.jsonl` para o veredito de conformidade), *append-only*.
- **Índice SQLite** (`scripts/history_index.py`) —
  `scripts/historico/index.sqlite3`, uma tabela `history_index` com as
  colunas filtráveis (`date`, `severity`, vereditos RGPD/NIS2/AI Act) e
  um ponteiro (ficheiro + offset em bytes) para o registo completo no
  JSONL correspondente.

Ambos configuráveis via `SENTRYLENS_HISTORY_DIR` (default:
`scripts/historico`); pasta no `.gitignore`, é dado gerado em runtime.

**Limitações conhecidas:** sem paginação além de `limit` na query
(sempre os N mais recentes); sem endpoint de escrita — a indexação só
acontece via `alert_poll_loop`; sem reconstrução automática do índice
a partir dos JSONL se `index.sqlite3` for apagado.

**Endpoint:** `GET /api/history/query` (ver tabela abaixo).

### 📄 Exportar relatório HTML (`GET /api/export/report`)

Gera um ficheiro HTML autónomo (CSS embutido, sem pedidos a recursos
externos) com o estado atual do dashboard (KPIs, alertas, agentes,
sistema), pronto para guardar offline ou anexar a um relatório. Cada
uma das 4 fontes de dados internas pode falhar independentemente sem
derrubar o relatório — a secção correspondente fica marcada como
"indisponível". Todo o texto dinâmico é escapado com `html.escape()`
contra XSS. Botão "📄 Exportar relatório" no header do dashboard.

### 🛡️ Conformidade regulatória (RGPD, NIS2, AI Act)

Cada alerta recente é avaliado contra 3 normas, com veredito explícito
("aplicável" ou "verificado e não aplicável", nunca omitido em
silêncio):

- **RGPD** — depende da categoria do alerta (autenticação, grupos,
  ciclo de vida de contas e atividade privilegiada envolvem dados
  pessoais → aplicável).
- **NIS2** — depende do perfil da organização **e** da severidade
  (`critical`/`high`) do alerta.
- **AI Act** — aplicável se a organização tiver um componente de IA
  ativo (aqui, a deteção de anomalias por Isolation Forest).

O perfil da organização (`scripts/org_profile.py`) é fixo por agora —
o CET não é uma empresa real (`estatuto_nis2_aplicavel=False`,
`processa_dados_pessoais=True`, `tem_componentes_ia_ativos=True`). As
regras e textos de justificação vivem em
[`scripts/compliance_rules.yaml`](scripts/compliance_rules.yaml). Cada
veredito é também registado em `compliance.jsonl` (auditoria), mesmo
quando "não aplicável" em todas as normas. Visível no relatório HTML
exportável e na aba **🛡️ Conformidade** do dashboard.

**Endpoint:** `GET /api/compliance?hours=24`:

```json
{
  "total": 42,
  "org_profile": {"nome": "SentryLens (laboratório CET)", "estatuto_nis2_aplicavel": false},
  "summary": {"rgpd": {"aplicavel": 30, "verificado_e_nao_aplicavel": 12}},
  "alerts": [{"friendly_name": "Failed Logon", "compliance": {"rgpd": {"estado": "aplicavel", "justificacao": "..."}}}]
}
```

### 🔎 Classificação NIS2 sugerida (`GET /api/nis2-lookup`)

Dado um CAE (e opcionalmente colaboradores/faturação/exceções já
conhecidas), sugere se uma empresa provavelmente cai no âmbito da NIS2
— **sem consultar nada online**. `lookup_nis2_classification()` é uma
função pura, sem I/O; ir buscar os dados reais de uma empresa continua
a ser um passo manual do utilizador (decisão de escopo, para não
construir um *scraper* frágil contra sites de terceiros).

Critério de dimensão: mais de 50 colaboradores **ou** mais de
10.000.000 EUR de faturação. Exceções que aplicam a NIS2
independentemente da dimensão: `fornecedor_confianca_qualificado`,
`registo_dominio`, `telecomunicacoes`, `administracao_publica`.

O mapeamento CAE→setor usa as categorias da Diretiva (UE) 2022/2555
cruzadas com a CAE-Rev.3 portuguesa, como aproximação de boa-fé — não é
uma transcrição do Decreto-Lei n.º 125/2025 (transposição nacional,
posterior ao conhecimento treinado do modelo que escreveu este código).
Por isso a função nunca devolve um veredito definitivo, só indícios com
grau de confiança, terminando sempre com:

> "Classificação sugerida, a confirmar junto do CNCS — não é
> aconselhamento jurídico."

Não está ligado a `org_profile.py` — é *standalone*; chamá-lo não altera
o perfil fixo usado pela camada de conformidade.

**Testes:** `scripts/test_nis2_lookup.py`.

### Tabela de endpoints

| Method | Endpoint | Parâmetros principais | Descrição |
|---|---|---|---|
| GET | `/api/health` | — | Confirma que o backend está de pé |
| GET | `/api/agents` | — | Lista de agentes Wazuh e estado atual |
| GET | `/api/alerts` | `hours`, `min_level`, `agent_name`, `severity` | Alertas recentes, classificados |
| GET | `/api/stats` | `hours` | KPIs agregados |
| GET | `/api/brute-force` | `hours`, `threshold` | Agrupa Event ID 4625 por utilizador-alvo |
| GET | `/api/ml-anomalies` | `hours` (máx. 168) | Deteção por Isolation Forest vs. regras |
| GET | `/api/export/report` | `hours` | Relatório HTML autónomo (download) |
| GET | `/api/compliance` | `hours` | Veredito RGPD/NIS2/AI Act por alerta |
| GET | `/api/nis2-lookup` | `cae_principal` (obrig.), `cae_secundarios`, `nipc`, `colaboradores`, `faturacao_eur`, `excecao_conhecida` | Classificação NIS2 sugerida |
| GET | `/api/history/query` | `date_from`, `date_to`, `severity`, `rgpd_estado`, `nis2_estado`, `ai_act_estado`, `limit` (máx. 1000) | Consulta o histórico via índice SQLite |
| GET | `/api/lifecycle` | — | Ciclo de vida de contas |
| GET | `/api/privileges` | — | Desvios RBAC |
| GET | `/api/admin-activity` | — | Atividade de contas administrativas |
| GET | `/api/system/specs` | — | Snapshot de CPU/RAM/disco/rede da máquina local |
| GET | `/api/system/alerts` | — | Violações de threshold ativas |
| GET | `/api/system/history` | — | Violações já resolvidas |
| GET | `/api/system/usage-history` | — | Buffer ~1h de uso (gráfico) |
| GET | `/api/system/thresholds` | — | Dict de thresholds (`cpu`/`ram`/`disk`/`network`) |
| POST | `/api/system/speedtest` | — | Força medição de velocidade de rede |

Erros seguem `502 {"detail": "Erro ao contactar Wazuh Manager/Indexer: ..."}`
quando a falha vem do Wazuh, ou `503` em `/api/ml-anomalies` se o
modelo ainda não foi treinado. Os endpoints de sistema (não dependem do
Wazuh) falham com `500` só se a recolha de specs desta máquina falhar.

Thresholds atuais (`system_monitor.THRESHOLDS`): CPU 80%/95%, RAM
85%/95%, disco 80%/90%, rede (download/upload) aviso abaixo de 700
Mbps / crítico abaixo de 500 Mbps (lógica invertida — dispara quando a
velocidade desce).

---

## 5. Catálogo de Event IDs (`scripts/event_catalog.py`)

23 Event IDs do Windows Security Log — mapa central `CRITICAL_EVENTS`
(nome + severidade) e `RECOMMENDATIONS` (ação sugerida):

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
| 4797 | Blank Password Query Attempt | medium |
| 5140 | Network Share Accessed | low |
| 5145 | Network Share Permission Checked | low |

Um Event ID fora desta lista (ou `None`) recebe uma classificação por
defeito segura (`severity: "info"`) — nunca rebenta o backend. Para
adicionar um Event ID novo: acrescentar uma entrada a `CRITICAL_EVENTS`
em `scripts/event_catalog.py`; não é preciso tocar em `main.py`.

---

## 6. Deteção de anomalias por Machine Learning

> ⚠️ **Nada disto foi treinado ou validado com dados reais do
> laboratório.** O modelo é treinado sobre um fixture sintético; os
> números abaixo provam que o *pipeline* funciona de ponta a ponta —
> não são uma estimativa de taxa de deteção em produção. Validação real
> requer correr `attack_scenarios.py` contra o laboratório, exportar
> com `export_snapshot.py`, e retreinar. Ainda não aconteceu.

O painel **🧠 ML Anomalias** usa um `IsolationForest` (scikit-learn)
lado a lado com a classificação por regras já existente — um segundo
ponto de vista, nunca um substituto de `event_catalog.py`.

**Features** (`scripts/feature_extractor.py`, módulo partilhado entre
treino e inferência): `hour_of_day`, `day_of_week`, `event_id_encoded`,
`failed_attempts_last_hour`, `has_special_privileges`,
`is_new_source_ip`, `severity_encoded`.

**Retreinar:**

```bash
cd scripts
python train_anomaly_model.py
```

Lê `sample_events_real.json` + `sample_attack_log.jsonl` por default
(aceita `--events`/`--attack-log`), escreve
`scripts/models/isolation_forest.pkl` + `scaler.pkl` (não versionados —
o endpoint devolve `503` até existirem) e
`scripts/ml_training_report.json` (este é committed).

**Resultados no fixture sintético** (36 eventos, 5 ataques rotulados):

| | Precisão | Recall | F1 |
|---|---|---|---|
| ML (Isolation Forest) | 0,4286 | 0,6 | 0,5 |
| Regras (`event_catalog.py`) | 0,625 | 1,0 | 0,7692 |

3 alertas sinalizados por ambas as abordagens, 4 só pelo ML, 5 só pelas
regras — uma divergência genuína, é esse contraste que é o ponto do
exercício.

`scripts/attack_scenarios.py` corre-se manualmente na VM Kali contra o
agente Windows, e regista cada cenário em `attack_log.jsonl` para
rotular os eventos correspondentes do Wazuh.
`scripts/export_snapshot.py` exporta alertas + stats + esse log para
`scripts/snapshots/`, fechando o ciclo para quando houver laboratório
real disponível.

> O seletor de período partilhado do dashboard (7/30/90 dias) fica
> limitado a 168h (7 dias) só neste painel — escolher "30" ou "90 dias"
> continua a mostrar só os últimos 7 dias de análise de ML.

---

## 🐛 Troubleshooting

**Frontend mostra "● sem ligação"**
→ Confirma que o backend está a correr (`uvicorn main:app --port 8001`) e vê a consola do browser (F12) para o erro exato.

**Erro 502 "Erro ao contactar Wazuh Manager/Indexer"**
→ Confirma IP e passwords em `scripts/.env`, que a VM está a correr
(`VBoxManage list runningvms`), e testa a autenticação diretamente:
```bash
curl -k -u wazuh-wui:PASSWORD -X POST "https://IP_DA_VM:55000/security/user/authenticate?raw=true"
```

**VM `Running` mas não responde à rede**
→ Causa observada: soft lockups do kernel por I/O do OpenSearch quando
o disco `C:\` está quase cheio (o dashboard já assinala isto na aba
Sistema). Remédio imediato: `VBoxManage controlvm "Wazuh-Manager" poweroff`
seguido de `startvm ... --type headless`. Remédio de fundo: libertar
espaço em `C:\` ou mover o armazenamento da VM para outro disco.

**Erro 401 Unauthorized**
→ `SENTRYLENS_API_KEY` não definida em `scripts/.env`, ou a constante
`API_KEY` em `app.js` não é exatamente igual — reinicia o `uvicorn`
depois de editar `.env` (variáveis só são lidas no arranque).

**Dashboard nunca atualiza em tempo real**
→ Handshake de WebSocket com `api_key` errado/em falta falha
silenciosamente (código `1008`) — confirma na consola (F12 → Network →
"WS"). Não é bloqueante: o dashboard continua a funcionar via polling
de 30s.

**`uvicorn` falha com `WinError 10013` na porta 8000**
→ Ver [Nota sobre a porta 8000](#nota-sobre-a-porta-8000) — usa `--port 8001`.

**CORS bloqueado no browser**
→ Acede via `localhost`/`127.0.0.1`, nunca `file://` diretamente.
Acesso a partir de outro dispositivo na rede exige alargar o CORS e
repensar autenticação, não é só reverter a restrição.

**Nenhum alerta aparece mesmo com o agente `Active`**
→ Gera um evento de teste (ex: `runas` com password errada → Event ID
4625) e confirma no próprio Wazuh Dashboard se aparece lá; se sim e
aqui não, o índice `wazuh-alerts-*` pode ter um nome diferente
consoante a versão.

**`ModuleNotFoundError: No module named 'fastapi'`**
→ `pip install -r scripts/requirements.txt` no mesmo ambiente Python
usado para correr `uvicorn`.

---

## 🚀 Próximos passos

1. **Autenticação multi-utilizador** — a API key partilhada já bloqueia
   acesso não autenticado na rede local, mas não distingue
   utilizadores; para produção real, evoluir para login por utilizador
   (ex: JWT).
2. **Pesquisa automática de dados para a classificação NIS2** — a
   lógica de decisão a partir de CAE/colaboradores/faturação já
   conhecidos está feita (`scripts/nis2_lookup.py` +
   `GET /api/nis2-lookup`); falta ir buscar esses dados automaticamente
   a partir de um NIPC (ex: Racius, informacaoempresarial.pt) e ligar o
   resultado a `org_profile.py`, hoje fixo.

---

## 📚 Referências

- [`docs/LAB_WAZUH_HYPERV.md`](docs/LAB_WAZUH_HYPERV.md) — guia completo do laboratório (VirtualBox e Hyper-V).
- [`docs/README.md`](docs/README.md) — guia legado de setup, com aviso de estrutura desatualizada no topo.
- [`scripts/README.md`](scripts/README.md) — detalhe dos 3 scripts de automação do laboratório.
- [`HARDENING_CHECKLIST.md`](HARDENING_CHECKLIST.md) e [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) — referências autónomas.
