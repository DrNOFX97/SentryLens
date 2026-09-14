# Referência da API

> Ver [README.md](../README.md) para instalação e arranque. Este
> ficheiro documenta em detalhe os endpoints REST e o WebSocket do
> backend (`scripts/main.py`).

Todos os endpoints devolvem JSON, com uma exceção:
`GET /api/export/report` devolve o relatório em HTML como ficheiro para
download. CORS restringido a origens loopback (`localhost`/`127.0.0.1`,
qualquer porta). Todos os endpoints `/api/*` (incluindo `/api/health`)
exigem uma API key no header `X-API-Key`.

## 🔑 Autenticação por API key

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

Não há documentação interativa (Swagger/`/docs`) — desativada de
propósito (`docs_url=None` em `main.py`), porque as rotas automáticas
do FastAPI não passam pela mesma proteção de API key das rotas
registadas via `@app.get`/`@app.post`.

## 🔌 WebSocket em tempo real (`/ws/alerts`)

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

## 🗄️ Histórico próprio de alertas e índice SQLite

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

## 📄 Exportar relatório HTML (`GET /api/export/report`)

Gera um ficheiro HTML autónomo (CSS embutido, sem pedidos a recursos
externos) com o estado atual do dashboard (KPIs, alertas, agentes,
sistema), pronto para guardar offline ou anexar a um relatório. Cada
uma das 4 fontes de dados internas pode falhar independentemente sem
derrubar o relatório — a secção correspondente fica marcada como
"indisponível". Todo o texto dinâmico é escapado com `html.escape()`
contra XSS. Botão "📄 Exportar relatório" no header do dashboard.

## 🛡️ Conformidade regulatória (RGPD, NIS2, AI Act)

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
[`../scripts/compliance_rules.yaml`](../scripts/compliance_rules.yaml).
Cada veredito é também registado em `compliance.jsonl` (auditoria),
mesmo quando "não aplicável" em todas as normas. Visível no relatório
HTML exportável e na aba **🛡️ Conformidade** do dashboard.

**Endpoint:** `GET /api/compliance?hours=24`:

```json
{
  "total": 42,
  "org_profile": {"nome": "SentryLens (laboratório CET)", "estatuto_nis2_aplicavel": false},
  "summary": {"rgpd": {"aplicavel": 30, "verificado_e_nao_aplicavel": 12}},
  "alerts": [{"friendly_name": "Failed Logon", "compliance": {"rgpd": {"estado": "aplicavel", "justificacao": "..."}}}]
}
```

## 🔎 Classificação NIS2 sugerida (`GET /api/nis2-lookup`)

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

| Parâmetro | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `cae_principal` | string | Sim | CAE principal |
| `cae_secundarios` | string | Não | CAEs secundários, separados por vírgula |
| `nipc` | string | Não | Só devolvido na resposta, não validado |
| `colaboradores` | int (≥0) | Não | Número de colaboradores |
| `faturacao_eur` | float (≥0) | Não | Faturação anual em EUR |
| `excecao_conhecida` | string | Não | Uma das 4 exceções listadas acima |

**Testes:** `scripts/test_nis2_lookup.py`.

## Tabela de endpoints

| Method | Endpoint | Parâmetros principais | Descrição |
|---|---|---|---|
| GET | `/api/health` | — | Confirma que o backend está de pé |
| GET | `/api/agents` | — | Lista de agentes Wazuh e estado atual |
| GET | `/api/alerts` | `hours`, `min_level`, `agent_name`, `severity` | Alertas recentes, classificados |
| GET | `/api/stats` | `hours` | KPIs agregados |
| GET | `/api/brute-force` | `hours`, `threshold` | Agrupa Event ID 4625 por utilizador-alvo |
| GET | `/api/ml-anomalies` | `hours` (máx. 168) | Deteção por Isolation Forest vs. regras — ver [ML.md](ML.md) |
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

## Catálogo de Event IDs (`scripts/event_catalog.py`)

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
