# SentryLens

**Dashboard de cibersegurança que junta três fontes de deteção — alertas do Wazuh, tráfego de rede e Machine Learning — e mede o quão bem detetam ataques simulados.**

<p align="center">
  <img src="logo.png" alt="SentryLens" width="420"
       style="background:#0a1622;border-radius:14px;padding:20px 30px;">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PYTHON-3.12%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/FASTAPI-0.115.0-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI 0.115.0">
  <img src="https://img.shields.io/badge/SQLITE-indice_de_historico-003B57?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/WAZUH-integracao_SIEM-0B7D92?style=flat-square" alt="Integração com Wazuh">
  <img src="https://img.shields.io/github/v/release/your-org/SentryLens?label=VM%20Release&style=flat-square&logo=virtualbox&logoColor=white" alt="VM Release">
</p>

O SentryLens liga-se a um laboratório [Wazuh](https://wazuh.com/) (SIEM open-source) e mostra, quase em tempo real, os alertas de segurança gerados pelos Windows Security Event Logs de uma máquina monitorizada. Cada evento aparece com nome legível, severidade e recomendação de ação, em vez de um Event ID numérico.

Além dos alertas, o projeto:

- captura e analisa **tráfego de rede** do laboratório (tshark/Wireshark);
- aplica um modelo de **Machine Learning** (Isolation Forest) como segunda opinião sobre os mesmos alertas;
- avalia cada alerta contra o **RGPD, a NIS2 e o AI Act**;
- cruza **ataques simulados (Red Team)** com o que foi detetado (Blue Team), medindo cobertura e tempo até à deteção.

Nasceu como projeto do curso de cibersegurança do CET e foi pensado como laboratório de aprendizagem: tudo corre localmente, numa VM, sem serviços externos.

---

## Como funciona

O SentryLens tem três camadas de deteção que olham para o mesmo laboratório de ângulos diferentes:

| Camada | O que vê | Como |
|---|---|---|
| **Wazuh** | Logs do host (Windows Event IDs) | O agente envia os eventos ao Wazuh Manager; o backend consulta o Manager e o Indexer por API e classifica cada alerta por regras. |
| **Rede (tshark / Wireshark)** | Tráfego entre o atacante e os alvos | O `tshark` corre na VM e grava metadados de cada pacote num ficheiro CSV. O backend lê esse ficheiro por SSH a cada 5 s e deteta padrões suspeitos. |
| **Machine Learning** | Comportamento fora do normal | Um Isolation Forest avalia cada alerta com 7 features (hora, Event ID, falhas recentes, IP novo, etc.). |

Nenhuma camada substitui as outras: o Wazuh não vê o tráfego de rede, e as regras só apanham o que alguém previu.

```mermaid
flowchart TB
    KALI["VM Kali (atacante)"]

    subgraph WIN["Windows monitorizado"]
        AGENT["Agente Wazuh"]
        BACKEND["Backend FastAPI<br/>porta 8001"]
        FRONTEND["Frontend estático<br/>porta 5500"]
    end

    subgraph VM["VM do laboratório (Ubuntu)"]
        MANAGER["wazuh-manager"]
        INDEXER["wazuh-indexer<br/>(OpenSearch)"]
        TSHARK["tshark<br/>/var/log/sentrylens/network.csv"]
    end

    BROWSER(["Browser"])

    KALI -->|"ataques simulados"| AGENT
    AGENT -->|"Windows Event Logs"| MANAGER
    MANAGER --> INDEXER
    BACKEND -->|"Manager API :55000"| MANAGER
    BACKEND -->|"Indexer API :9200, poll de 10 s"| INDEXER
    BACKEND -->|"SSH, leitura a cada 5 s"| TSHARK
    BROWSER --> FRONTEND
    FRONTEND -->|"REST /api/* e WebSocket"| BACKEND
```

O backend nunca fala diretamente com o agente: usa as APIs do Wazuh, que já têm os alertas processados.

---

## Funcionalidades

O dashboard tem 26 abas:

| Aba | Conteúdo |
|---|---|
| **Visão Geral** | KPIs (total, severidade, agentes ativos), resumo do sistema e gráficos |
| **Alertas** | Alertas classificados, com deteção de força bruta (Event ID 4625) |
| **Agentes** | Agentes Wazuh: nome, IP, SO, estado e último keep-alive |
| **Sistema** | CPU, RAM, disco e rede da máquina local, com histórico de violações de limiar |
| **Ciclo de Vida** | Criação, alteração e remoção de contas, com deteções de risco |
| **Privilégios** | Desvios RBAC face a uma baseline de cargos e grupos permitidos |
| **Contas Admin** | Atividade das contas administrativas: privilégios especiais, tarefas agendadas |
| **ML Anomalias** | Isolation Forest lado a lado com a classificação por regras |
| **Conformidade** | Veredito RGPD, NIS2 e AI Act por alerta |
| **Red vs Blue** | Ataques simulados vs. deteções, e rede em tempo real |
| **Live SOC** | Feed de alertas ao vivo e saúde do SIEM (Manager/Indexer, agentes, atraso de ingestão) |
| **Incidentes** | Agrupamento automático de alertas e deteções de rede em incidentes, com estados, timeline e notas |
| **Attack Registry / Attack Timeline** | Registo de ataques: esperado vs. real (regra/ML/rede) e incidentes ligados; só leitura |
| **Attack Library** | Catálogo de referência dos cenários de ataque (risco, sensores esperados, limpeza); só leitura, nunca executa nada |
| **Vaccines** | Vaccines propostas a partir de ataques não detetados ou só parcialmente detetados: regra proposta, origem (ataque, cenário, MITRE, incidentes) e cadeia de substituição; só leitura, nunca aplicadas no Wazuh |
| **Live Traffic / Network Detections / PCAP Evidence** | Resumos dedicados da captura de rede e evidência de metadados persistida (nunca payload nem PCAP real) |

Também inclui:

- Classificação de 31 Event IDs do Windows Security Log.
- Atualização em tempo real por WebSocket (`/ws/alerts`), com *fallback* para polling de 30 s.
- Histórico próprio em JSONL com índice SQLite, para além dos 90 dias do Wazuh Indexer.
- Exportação de um relatório HTML autónomo (`GET /api/export/report`).
- Autenticação por API key em todos os endpoints.
- Vista unificada de deteções (`GET /api/detections`): regra, ML e rede num tipo comum (`DetectionEvent`).
- Métricas SOC (`GET /api/metrics`): MTTD, MTTR, cobertura e taxa de deteção, com FN/FP, em 3 painéis (MTTD / MTTR, Detection Coverage, Detection Rate). Sem dados mostram "Sem dados"; com alertas truncados avisam que os valores são limites inferiores.
- Triagem experimental de incidentes via JEV (`POST /api/incidents/{id}/triage`): desligada por omissão e anonimizada.
- Vaccine Engine (`GET /api/vaccines`): propostas de regra de deteção guardadas num store SQLite com estado fixo `proposed`, geradas pelo backend em segundo plano.

---

## Conformidade: como é disparada

A conformidade não depende de ninguém a pedir. Corre automaticamente para cada alerta novo:

1. O backend consulta o Wazuh Indexer a cada **10 segundos** e identifica os alertas ainda não vistos (deduplicação pelo `_id` do documento).
2. Para cada alerta novo, avalia o **RGPD**, a **NIS2** e o **AI Act** com o perfil da organização e as regras de `scripts/compliance_rules.yaml`.
3. Grava o alerta e o veredito em ficheiros JSONL e indexa-os em SQLite, para consulta rápida.

O resultado de cada norma é sempre explícito — `aplicavel` ou `verificado_e_nao_aplicavel` — acompanhado de uma justificação. Nunca há um veredito em branco.

| Norma | Quando se aplica |
|---|---|
| **RGPD** | A categoria do alerta envolve dados pessoais: autenticação, gestão de grupos, ciclo de vida de contas ou atividade privilegiada. |
| **NIS2** | A entidade está classificada como sujeita à NIS2 **e** o alerta é de severidade crítica ou alta, o que pode exigir comunicação ao CNCS. |
| **AI Act** | O perfil da organização tem um componente de IA ativo (aqui, o Isolation Forest). Depende só do perfil, não do alerta. |

Os mesmos vereditos estão disponíveis sob pedido em `GET /api/compliance` e no relatório exportado.

> O perfil da organização (`scripts/org_profile.py`) é fixo, porque o projeto é um laboratório e não uma empresa real. No perfil incluído a entidade **não** está classificada como sujeita à NIS2, por isso esse veredito devolve "não aplicável" até alterares o perfil. O AI Act devolve sempre "aplicável" enquanto o modelo de ML estiver ativo.

---

## Red vs Blue

A aba **Red vs Blue** responde à pergunta "quanto do que atacámos foi detetado?".

- **Red Team:** `scripts/attack_scenarios.py` corre-se manualmente na VM Kali contra o agente Windows. Cada tentativa fica registada em `attack_log.jsonl`, com a técnica MITRE ATT&CK. Há 5 cenários: `smb_enum`, `blank_password_check`, `account_lockout_spray`, `lateral_movement_schtasks` e `brute_force_rdp`.
- **Blue Team:** um alerta conta como deteção de uma tentativa se o IP do agente coincidir com o alvo **e** o Event ID for um dos esperados para esse cenário, dentro de uma janela de tempo (300 s por omissão).
- **Métricas:** cobertura, tempo médio até à deteção (MTTD) e se o ataque foi apanhado por regra, por ML, por ambos ou por nenhum.
- **Rede em tempo real:** painel com os pacotes e as deteções de rede mais recentes.

As deteções de rede (`scripts/network_detections.py`) usam limiares fixos:

| Deteção | Condição |
|---|---|
| Port scan | 15 ou mais portos de destino distintos, do mesmo origem para o mesmo destino, em 30 s |
| Brute force | 20 ou mais tentativas de ligação ao mesmo porto, em 30 s |
| Pico de volume | 500 ou mais pacotes do mesmo IP de origem em 10 s |

Só conta como tentativa de ligação um pacote TCP com SYN e sem ACK, para as respostas do alvo não serem confundidas com um segundo ataque.

---

## Vaccines

Uma **vaccine** é uma proposta de regra de deteção para um ataque que o SOC não apanhou. É só uma proposta: nunca é aplicada no Wazuh, não traz comandos e o estado é sempre `proposed` (aprovar ou rejeitar fica para o R12).

- **De onde vem:** o veredito do Red vs Blue. Só os ataques `not_detected` ou `partial` geram uma vaccine (`detected` e `unknown` nunca). O motor (`scripts/vaccine_engine.py`) propõe uma entrada por sensor em falta: uma regra com os Event IDs do cenário, uma janela de 300 s e `min_count` 1, ou, para ML e rede, uma recomendação em texto. Cada vaccine valida-se (`validate_vaccine`) antes de ser gravada.
- **Quando aparece:** o backend corre um ciclo no arranque e depois a cada 5 min (`main._vaccine_loop`, `scripts/vaccine_ingest.py`) e só grava vaccines de ataques com mais de 10 min, para os alertas terem tempo de chegar. Na prática uma vaccine demora cerca de 10 a 15 min a aparecer.
- **Onde fica:** `scripts/vaccines.sqlite3` (`scripts/vaccine_store.py`, ignorado pelo git). O `GET` só lê e nunca cria o ficheiro; só o ciclo escreve. Quando o veredito de um ataque muda, a vaccine anterior fica guardada com `superseded_by`.
- **Variáveis de ambiente opcionais:** `SENTRYLENS_VACCINE_INTERVAL_SECONDS` (omissão 300), `SENTRYLENS_VACCINE_WINDOW_HOURS` (168), `SENTRYLENS_VACCINE_SETTLE_SECONDS` (600) e `SENTRYLENS_VACCINES_DB_PATH` (omissão `scripts/vaccines.sqlite3`).
- **O que a aba mostra:** em 💉 Candidates, a lista das vaccines com filtros por ataque, técnica MITRE e "Incluir substituídas", uma linha com o estado do gerador (última execução ou o código do erro) e, ao escolher uma linha, o detalhe com a origem, as propostas e a cadeia de substituição, sempre com o aviso "Proposta — não aplicada no Wazuh".
- **Limites:** o id (`vac-` + 12 hex) deteta troca ou duplicação mas não autentica; o estado do gerador é em memória (volta a "ainda não correu" depois de reiniciar o backend); com alertas truncados o risco fica sinalizado. Detalhes em [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) e [`docs/API.md`](docs/API.md).

---

## Machine Learning

O painel **ML Anomalias** usa um `IsolationForest` (scikit-learn), um modelo não supervisionado: aprende o que é um alerta normal neste ambiente e assinala o que se afasta disso. Serve de **segunda opinião** sobre as regras, não de substituto.

### Resultados medidos, e o que eles provam

O primeiro ciclo com dados reais (14 de setembro de 2026) mediu, sobre **35 eventos processáveis** de 500 alertas capturados no laboratório — números que vêm do artefacto [`scripts/ml_training_report.json`](scripts/ml_training_report.json), gerado pelo `--report` do `train_anomaly_model.py`; ainda **não** há nenhuma versão registada no registo de modelos que os produza:

| | Precisão | Recall | F1 |
|---|---|---|---|
| ML (Isolation Forest) | 0,86 | 0,30 | 0,44 |
| Regras (`event_catalog.py`) | 0,88 | 0,35 | 0,50 |

**Isto é um registo histórico, não um resultado reproduzível hoje.** A medição foi feita com o `scripts/attack_log.jsonl` de 14 de setembro, que registava os 5 ataques lançados nessa sessão. O `attack_log.jsonl` que existe no repositório hoje é de **6 de outubro de 2026** e **não cobre** a janela do dataset: avaliá-lo contra estes eventos dá **0 ataques rotulados** e recall 0 **por definição** — não por falha do modelo. O comando de avaliação avisa-o quando isso acontece, em vez de publicar o número a zero.

Para uma avaliação rotulada a sério: lança os ataques com `scripts/attack_scenarios.py`, exporta os alertas **na mesma janela** com `scripts/export_raw_events.py`, e avalia com `python model_registry.py evaluate vN --events ... --attack-log ... --dataset-origin real`. O resultado fica gravado no `metadata.json` **daquela versão** e é o que a aba 📐 Evaluation mostra. Nenhum número aparece no dashboard sem dizer que versão mediu e sobre que dataset.

Para treinar o modelo:

```bash
cd scripts
python model_registry.py train v1 --events <ficheiro.json> --dataset-origin real
```

É este comando — e não o `train_anomaly_model.py` — quem cria a pasta da versão `models/vN/`, escreve o `metadata.json`, grava o `models/ACTIVE` a apontar para ela e verifica o SHA-256 dos `.pkl` **antes** de a activar. O `v1` do comando é um rótulo: o id final é o seguinte livre no registo (`next_version_id`, `max+1`). Até existirem versões registadas, `GET /api/ml-anomalies` devolve `503`. Metodologia, features e o ciclo de validação completo estão em [`docs/ML.md`](docs/ML.md).

`train_anomaly_model.py` continua a existir como **primitiva de treino**, e é o que o comando usa por dentro: carrega o dataset, treina o `IsolationForest` e faz `joblib.dump` de dois `.pkl` na pasta de `--models-dir`, que é obrigatória. Não toca no registo — não cria `models/vN/`, não escreve `metadata.json`, não mexe no `ACTIVE`. Por isso `--models-dir` tem de apontar para fora de `models/`, que é o que o próprio `save_model` avisa. O `--report <ficheiro>` é opt-in e grava o resumo como artefacto avulso (ex.: `ml_training_report.json`), nunca dentro do registo.

### Registo de modelos

- **Versões:** cada execução de `model_registry.py train` cria uma nova pasta `models/vN/` (ex.: `v1`, `v2`) com `isolation_forest.pkl`, `scaler.pkl` e `metadata.json`. A pasta `models/ACTIVE` aponta para a versão atualmente ativa.
- **Adopt:** `python model_registry.py adopt --models-dir models` regista o que já existe em `scripts/models/` como `v1` e a activa. Se `v1` já existir, recusa.
- **SHA-256:** antes de a pasta `vN` ficar visível, o SHA-256 dos `.pkl` é verificado contra os bytes originais. Deteta corrupção e troca acidental, mas não autentica quem escreve — quem reescreve `models/` reescreve também o `metadata.json`.
- **`ACTIVE`:** depois de um adopt ou de um treino, é necessário reiniciar o backend (`uvicorn main:app --reload`) para que a cache do modelo seja atualizada e a nova versão seja carregada.
- **API:** `GET /api/ml/models` devolve o registo completo de todas as versões, incluindo a ativa, com os metadados, SHA-256 e estado de avaliação.
- **Limitação:** até à primeira versão registada, o que o backend carrega é o modelo legado (`scripts/models/isolation_forest.pkl` + `scaler.pkl`), que não tem verificação de integridade. A partir da primeira versão registada, o backend carrega uma versão com SHA-256 verificado.

---

## Início rápido

### Opção A: Usar VMs Pré-configuradas (Recomendado)

A forma mais rápida de começar é usar as VMs já prontas com Wazuh e Kali pré-instalados:

1. **Baixar as VMs** da [página de Releases](https://github.com/your-org/SentryLens/releases):
   - `sentrylens-wazuh-manager-virtualbox.ova` — Wazuh Manager (Ubuntu 22.04 + Wazuh)
   - `sentrylens-kali-attacker-virtualbox.ova` — Kali Attacker (opcional, para Red vs Blue)

2. **Importar no VirtualBox**: File → Import Appliance → selecionar o `.ova`

3. **Iniciar as VMs** e obter os IPs:
   ```bash
   # Dentro da VM Wazuh Manager
   ip a
   ```

4. **Obter credenciais do Wazuh**:
   ```bash
   # Dentro da VM Wazuh Manager
   wazuh-passwords
   ```

5. **Configurar o backend** (ver abaixo) com o IP da VM e as credenciais obtidas.

> **Nota**: As VMs Hyper-V (`.vhdx`) também estão disponíveis para quem usa Hyper-V em vez de VirtualBox.

Ver detalhes completos em [`packer/README.md`](packer/README.md).

---

### Opção B: Instalação Manual

Se preferires montar o laboratório do zero:

#### Pré-requisitos

- Python 3.12 ou superior.
- Um laboratório Wazuh acessível por rede: uma VM Ubuntu Server 22.04 com Wazuh instalado, em VirtualBox ou Hyper-V. O guia [`docs/LAB_WAZUH_HYPERV.md`](docs/LAB_WAZUH_HYPERV.md) descreve a montagem passo a passo.
- Windows 10/11 como máquina monitorizada (a monitorização do sistema local usa WMI/PowerShell).
- Opcional, para a captura de rede: `tshark` na VM e acesso SSH por chave. O serviço de exemplo está em `scripts/deploy/`.
- Opcional, para os ataques simulados: uma VM Kali.

### 1. Configurar o backend

```bash
cd scripts
python -m venv .venv
.venv\Scripts\activate          # Windows (PowerShell/cmd)
pip install -r requirements.txt
cp .env.example .env            # depois edita com os valores reais
```

No `.env` define, no mínimo, o endereço e as credenciais do Wazuh e a API key:

```env
WAZUH_MANAGER_URL=https://<IP_DA_VM>:55000
WAZUH_MANAGER_USER=wazuh-wui
WAZUH_MANAGER_PASSWORD=<password>

WAZUH_INDEXER_URL=https://<IP_DA_VM>:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=<password>

# Obrigatória: sem ela, todos os pedidos a /api/* devolvem 401
SENTRYLENS_API_KEY=<valor aleatório forte, ex.: openssl rand -hex 32>
```

As passwords do Wazuh estão no ficheiro gerado durante a instalação, dentro da VM:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Para ativar a captura de rede, preenche também `VM_SSH_HOST`, `VM_SSH_USER` e `VM_SSH_KEY_PATH`. Com `VM_SSH_HOST` vazio, essa funcionalidade fica desligada e o resto continua a funcionar.

Arranca o backend:

```bash
uvicorn main:app --port 8001
```

Confirma que está de pé:

```bash
curl -H "X-API-Key: <a tua chave>" http://localhost:8001/api/health
```

A porta por omissão é a **8001**, porque a 8000 costuma estar ocupada por outros serviços. Sem o header, o pedido devolve `401`.

### 2. Servir o frontend

O frontend é HTML/CSS/JavaScript puro, sem passo de build. Define em `app.js` a constante `API_KEY` com o mesmo valor do `.env` e serve-o por HTTP:

```bash
cd scripts
python serve_frontend.py 5500
```

Abre `http://localhost:5500/index.html`.

Não abras o `index.html` com duplo-clique: o CORS do backend só aceita `localhost`/`127.0.0.1`, e um ficheiro aberto diretamente envia `Origin: null`. Também não uses `python -m http.server` a partir da raiz do repositório, porque expõe o `scripts/.env` com as credenciais. O `serve_frontend.py` serve apenas uma lista fixa de ficheiros e só escuta em `127.0.0.1`.

Os scripts `scripts/start-backend.ps1` e `scripts/start-frontend.ps1` arrancam cada um dos serviços em segundo plano e podem ser ligados a uma tarefa agendada do Windows para arrancar no início de sessão.

### Fase 1: análise de ficheiros de log

O projeto começou com um analisador de logs estáticos, sem dependências externas, que partilha a mesma classificação de Event IDs:

```bash
python log_analyzer.py --input sample_events.json --output report.html
```

Ver [`QUICKSTART.md`](QUICKSTART.md).

---

## Testes

48 scripts standalone, sem pytest (`python run_all_tests.py` corre-os todos em paralelo). Correm sem laboratório, porque o Wazuh e o SSH estão simulados. Cada um imprime `[OK]` ou `[FALHOU]` por caso e termina com código 1 se algo falhar.

```bash
cd scripts
python test_with_mock.py        # classificação, /api/stats, /api/brute-force
python test_auth.py             # autenticação por API key
python test_compliance.py       # motor RGPD/NIS2/AI Act
python test_ml_anomalies.py     # /api/ml-anomalies
python test_redblue.py          # correlação Red vs Blue
python test_network_detections.py
python test_frontend_static.py  # frontend: contratos estáticos (gitignore, handlers inline, modais, CSS)
python test_ui_helpers.py       # frontend: helpers puros de ui_helpers.js (node:vm)
python test_vaccines_api.py     # vaccines: rotas, ciclo e garantias negativas
python test_defender_catalog.py # catálogo de eventos do Defender (por canal, separado de CRITICAL_EVENTS)
# ... e os restantes test_*.py
```

Usa o `.venv` de `scripts/`: precisam de `scikit-learn`, `joblib` e `PyYAML`.

---

## API

Todos os endpoints `/api/*` exigem o header `X-API-Key` e devolvem JSON (exceto o relatório, que devolve HTML). Os principais:

| Método | Endpoint | Descrição |
|---|---|---|
| GET | `/api/alerts` | Alertas recentes, classificados |
| GET | `/api/stats` | KPIs agregados |
| GET | `/api/compliance` | Veredito RGPD/NIS2/AI Act por alerta |
| GET | `/api/ml-anomalies` | Isolation Forest vs. regras |
| GET | `/api/ml/models` | Registo de modelos (versões, ativa, adopt, avaliação) |
| GET | `/api/redblue/metrics` | Cobertura e MTTD por cenário de ataque |
| GET | `/api/redblue/network` | Snapshot da captura de rede |
| GET | `/api/detections` | Vista unificada recente dos detetores (regra/ML/rede) |
| GET | `/api/metrics` | MTTD, MTTR, cobertura e taxa de deteção (FN/FP) |
| GET | `/api/incidents` | Incidentes (rotas `/api/incidents/*`) |
| GET | `/api/attacks` | Registo de ataques, esperado vs. real |
| GET | `/api/attack-library` | Catálogo de cenários de ataque |
| GET | `/api/vaccines` | Vaccines propostas (R11), filtros e estado do gerador |
| GET | `/api/vaccines/{id}` | Detalhe de uma vaccine: regra proposta e origem |
| GET | `/api/network/live-traffic` \| `detections` \| `evidence` | Resumos dedicados de rede |
| GET | `/api/siem/health` | Saúde do SIEM |
| GET | `/api/history/query` | Consulta ao histórico (índice SQLite) |
| GET | `/api/export/report` | Relatório HTML autónomo |
| POST | `/api/ws-ticket` | Ticket de uso único (30 s) para abrir um WebSocket |
| WS | `/ws/alerts` | Alertas novos em tempo real |
| WS | `/ws/network` | Pacotes e deteções de rede em tempo real |

Os WebSockets autenticam-se com `?ticket=...`: o browser pede primeiro `POST /api/ws-ticket` (com `X-API-Key`) e abre o socket com o ticket devolvido, porque os browsers não enviam headers personalizados no handshake. O ticket é opaco, de uso único, expira em 30 s e vive só em memória; `?api_key=` deixou de ser aceite. A lista completa, com parâmetros, está em [`docs/API.md`](docs/API.md).

---

## Segurança

Como o próprio dashboard está protegido (tudo verificado no código; detalhe e histórico de auditorias em [`docs/SECURITY.md`](docs/SECURITY.md)):

- **API key por rota, fail-closed.** Cada rota REST `/api/*` declara `dependencies=_REQUIRE_API_KEY` (header `X-API-Key`), nunca a nível de app. Sem `SENTRYLENS_API_KEY` definida, tudo devolve `401`. A comparação usa `secrets.compare_digest` (sem fuga por tempo). Os WebSockets `/ws/alerts` e `/ws/network` autenticam-se à parte, com um ticket de uso único obtido em `POST /api/ws-ticket` (que exige a API key); a chave já não vai no URL.
- **Sem Swagger nem `/docs`**, de propósito: as rotas automáticas do FastAPI não passam pela proteção por API key (`docs_url=None`).
- **CORS restrito** a `localhost` e `127.0.0.1` (qualquer porta), por `allow_origin_regex`. É uma camada adicional, não substitui a API key.
- **Servidor do frontend com whitelist.** `scripts/serve_frontend.py` só serve ficheiros de uma lista fixa (`ALLOWED_FILES`), liga só a `127.0.0.1` e envia `X-Content-Type-Options: nosniff` e `Cache-Control: no-store`. Por isso não expõe `scripts/.env`, ao contrário de `python -m http.server` na raiz.
- **Content-Security-Policy.** `serve_frontend.py` envia CSP nas respostas HTML: `script-src 'self'` (sem `unsafe-inline`), `connect-src` só para `'self'` e loopback (`http`/`ws` em `127.0.0.1` e `localhost`), `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`. `style-src` mantém `'unsafe-inline'` só porque o HTML e o JS usam atributos `style=""`.
- **Sem handlers inline.** Nenhum `onclick=` (ou outro `on*=`) no HTML ou nos `*.js`; a interação usa `data-action`/`data-id` com listeners delegados. `scripts/test_frontend_static.py` falha se algum reaparecer. Esta regra nasceu de uma XSS confirmada na aba Equipa SOC.
- **Escape de todo o texto dinâmico.** O frontend passa os dados por `escapeHtml()` antes de os inserir no HTML; o relatório HTML exportado pelo backend usa `html.escape()`, porque é aberto fora do dashboard.
- **Triagem JEV opt-in.** `POST /api/incidents/{id}/triage` é a única rota que envia dados para fora (`api.typesafe.ai`). Só funciona com `SENTRYLENS_JEV_ENABLED` e `TYPESAFE_API_KEY` definidas; caso contrário não chama a rede. Envia só agregados anonimizados.
- **Vaccines só em leitura.** Uma vaccine é sempre uma proposta (`proposed`); a API recusa qualquer escrita com `405`.
- **Sem recursos externos.** O Chart.js 4.5.1 e as fontes são servidos localmente a partir de `vendor/` (o hash SHA-384 do Chart.js é verificado por `test_frontend_static.py`); o dashboard abre sem internet.
- **`WAZUH_VERIFY_SSL=false` por omissão**, porque o laboratório usa o certificado autoassinado do instalador do Wazuh. Muda para `true` se tiveres um certificado válido.
- Nunca versiones o `scripts/.env`.

Limitações conhecidas (ainda por fazer, Ondas 2 a 8 da auditoria ao frontend):

- A chave é entregue ao browser por `/config.js` (só same-origin, gerado a partir de `scripts/.env`).

---

## Estrutura do repositório

```
├── index.html, app.js, redblue.js, style.css   frontend estático
├── log_analyzer.py                              Fase 1: análise de logs estáticos
├── scripts/                                     backend FastAPI
│   ├── main.py                                  endpoints REST e WebSocket
│   ├── wazuh_client.py                          clientes do Manager e do Indexer
│   ├── event_catalog.py                         classificação de Event IDs
│   ├── compliance_evaluator.py / .yaml          motor RGPD, NIS2 e AI Act
│   ├── network_monitor.py / network_detections.py   captura e deteção de rede
│   ├── ml_anomalies.py / feature_extractor.py / train_anomaly_model.py   Machine Learning
│   ├── model_registry.py, ml_evaluation.py, export_raw_events.py   registo, avaliação e exportação
│   ├── attack_scenarios.py / redblue_correlator.py  Red vs Blue
│   ├── incident_*.py, attack_registry.py, attack_library.py/.yaml   incidentes, registo e biblioteca de ataques
│   ├── vaccine_engine.py / vaccine_store.py / vaccine_ingest.py   vaccines propostas (R11)
│   ├── detection_event.py, network_soc.py, siem_health.py   deteções unificadas, painéis de rede, saúde do SIEM
│   ├── history_store.py / history_index.py      histórico JSONL e índice SQLite
│   ├── deploy/                                  serviço tshark e logrotate da VM
│   └── test_*.py                                48 testes standalone
└── docs/                                        API, ML e guia do laboratório
```

---

## Limitações e próximos passos

- **API key partilhada:** não há login nem distinção entre utilizadores. Para uso real, evoluir para autenticação por utilizador.
- **Perfil da organização fixo:** a conformidade usa um perfil estático. Falta ligar `scripts/nis2_lookup.py` a dados reais de uma empresa.
- **ML com pouca amostra e sem versão registada:** hoje `scripts/models/` só tem os dois `.pkl` soltos (`isolation_forest.pkl` + `scaler.pkl`), sem pasta `vN/`, sem `ACTIVE` e sem `metadata.json` — ainda não foi corrido nenhum `train` nem nenhum `adopt`, logo não há versão nem avaliação registadas, e o que o backend carrega continua a ser o legado, sem verificação de integridade. E o dataset de referência também não é reavaliável hoje: o `attack_log.jsonl` actual só cobre 2026-10-06 e não rotula a janela de 2026-09-14.
- **Deteção de rede por limiares fixos:** não aprende uma linha de base do tráfego normal.
- **Só Windows:** a monitorização do sistema local usa WMI e PowerShell.

---

## Documentação

- [`docs/API.md`](docs/API.md): referência completa da API, autenticação e WebSockets.
- [`docs/ML.md`](docs/ML.md): metodologia do ML, resultados e correlação Red vs Blue.
- [`docs/LAB_WAZUH_HYPERV.md`](docs/LAB_WAZUH_HYPERV.md): montagem do laboratório (VirtualBox e Hyper-V).
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md): problemas conhecidos.
- [`scripts/README.md`](scripts/README.md): scripts de automação do laboratório.
- [`HARDENING_CHECKLIST.md`](HARDENING_CHECKLIST.md) e [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md): referências autónomas.
