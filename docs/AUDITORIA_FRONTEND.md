# Auditoria ao frontend do SentryLens

Data: 2026-10-16 · Ramo: `roadmap-v2-r9-ml-registry` · Âmbito: só leitura (nenhum ficheiro de código alterado, nenhum commit).

## 0. Âmbito, método e limites

**O que foi auditado.** A cópia de trabalho atual, incluindo alterações ainda por commitar em `app.js`, `index.html`, `style.css` e `ml_evaluation.js`, e o ficheiro `overview.js`, que ainda não está no git. Li na íntegra os 16 ficheiros do frontend: `index.html`, `style.css`, `app.js`, `overview.js`, `redblue.js`, `incidents.js`, `soc_team.js`, `live_soc.js`, `attack_registry.js`, `attack_library.js`, `detections.js`, `metrics.js`, `network_soc.js`, `ml_models.js`, `ml_evaluation.js` e `vaccines.js`. A lista do pedido deixava de fora `overview.js`, `soc_team.js`, `ml_models.js`, `ml_evaluation.js` e `vaccines.js`; foram auditados à mesma, porque são carregados pelo `index.html`. Do lado do backend cruzei `scripts/main.py` (rotas, limites `Query`, modelos Pydantic), `scripts/serve_frontend.py`, `scripts/compliance_evaluator.py`, `docs/SECURITY.md` e `docs/ROADMAP_STATUS.md`.

**Skills aplicadas.** `frontend-design`: direção estética, tipografia e consistência. `dataviz`: forma dos gráficos, cor e acessibilidade. Corri de facto o validador de paletas da skill (`validate_palette.js`). Não existe skill de revisão de acessibilidade utilizável sem o Chrome DevTools MCP, e a skill `security-review` revê diffs de um ramo, não uma base de código inteira. Por isso, a acessibilidade e a segurança foram feitas à mão, com as verificações descritas em baixo.

**Verificação funcional (Playwright, Chromium).** Servi o frontend com o próprio `serve_frontend.py` numa porta livre (5599). O teu backend estava ligado na 8001 e **não lhe toquei**. Simulei as falhas só dentro do browser de teste, intercetando os pedidos para `:8001`:

| Cenário | Como foi simulado | Resultado |
|---|---|---|
| Backend desligado | pedidos para `:8001` abortados (`connectionrefused`) e WebSocket fechado | 26 abas percorridas, uma captura de cada |
| 401 | todas as respostas com `401 {"detail": "Invalid or missing API key"}` | 11 abas verificadas |
| 502 (Wazuh em baixo) | todas as respostas com `502 {"detail": "Erro ao contactar o Wazuh Indexer"}` | 11 abas verificadas |
| Wazuh em baixo, máquina local OK | `/api/system/*` com respostas mínimas válidas e o resto a 502 | indicador do cabeçalho verificado |
| Responsividade | 390, 1024 e 1920 px de largura | scroll horizontal e altura do cabeçalho medidos |
| Teclado | 9 × Tab a partir do topo | foco visível medido |
| XSS | `renderAnalystsTable()` chamada com um nome malicioso | confirmada (ver S1) |

As capturas ficaram fora do repositório, em `C:\tmp\claude\C--Users-Fernando-Nuno-OneDrive-Projetos-SentryLens\5d0ce0fe-a6b9-4fa3-b500-85e586705203\scratchpad\shots\`.

**O que ficou por verificar:**

- Renderização com dados reais do laboratório. Não usei o backend real, para não depender do estado das VMs nem expor dados.
- Firefox e Safari. Só corri Chromium; há um risco concreto de datas inválidas nesses browsers (ver R6).
- Leitor de ecrã real.
- Projetor físico.
- Carga real do `/ws/network` durante um ataque.
- O conteúdo do relatório exportado.
- A triagem JEV e o botão «Treinar». Não os acionei, porque escrevem no backend ou contactam um serviço externo.

Os textos de erro dos cenários 401/502 foram escolhidos por mim. Imitam o formato `{"detail": ...}` do FastAPI, mas não foram copiados das respostas reais.

---

## 1. Resumo executivo

O frontend tem mais base do que «esboço» sugere. Várias abas recentes (Vaccines, Attack Registry, Live SOC, Overview, Models e Evaluation) tratam a honestidade dos dados com cuidado raro: «Sem dados» nunca aparece como 0, uma fonte em baixo não esconde as outras, os códigos de erro são traduzidos. O problema é a desigualdade. As abas antigas (`app.js`, `soc_team.js`) partem as mesmas regras, e algumas delas no sítio mais visível do ecrã.

Os 10 achados que mais pesam, por ordem:

1. **[Crítico] XSS confirmada na Equipa SOC** (`soc_team.js:111-112`). O nome do analista é escapado com `escapeHtml()`, mas entra num `onclick="...('${nome}')"`. O browser desfaz o `&#39;` antes de executar o JavaScript. Com o nome `Ana'),document.title=('XSS-OK`, um clique em «Desativar» executou código. A página tem a API key em `window.SENTRYLENS_CONFIG`, por isso a XSS dá controlo total da API, incluindo as rotas POST.
2. **[Crítico] O cabeçalho mente sobre o estado do Wazuh** (`app.js:1284-1301`). Com todos os pedidos ao Wazuh a devolver 502 e a máquina local OK, o cabeçalho mostra «● ligado ao Wazuh» a verde ao lado do banner «Erro ao contactar o Wazuh Indexer» (captura `overview-390.png`). A causa é uma regressão das alterações por commitar: `loadStats`, `loadAgents` e `loadAlerts` passaram a apanhar o erro, e o `Promise.all` deixou de falhar.
3. **[Crítico] A aba Equipa SOC bloqueia a aplicação.** `.modal { display:flex }` (`style.css:892`) sobrepõe-se ao atributo `hidden`. Ao abrir a aba, os três modais aparecem empilhados por cima de tudo e intercetam todos os cliques; não se consegue sair da aba com o rato (captura `soc-team-modal-bug.png`). O Playwright não conseguiu clicar no menu durante 30 s.
4. **[Crítico] Barras verdes a 100 % sem dados.** `.progress-fill` não tem `width` inicial e o fundo por omissão é verde (`style.css:598-603`). Sem backend, o Overview e a aba Sistema mostram CPU/RAM/Disco/Rede cheios a verde, o que se lê como «tudo saudável» quando não há dado nenhum.
5. **[Crítico] A API key está em claro nos logs.** O WebSocket autentica com `?api_key=` e o uvicorn grava o caminho completo no access log: 32 ocorrências em `scripts/backend.log.err` e `scripts/backend.log-PC-Vicente.err`. Este segundo ficheiro **não está coberto pelo `.gitignore`** (aparece como `??` no `git status`): um `git add -A` publica a chave. A pasta `.playwright-mcp/` tem mais 8 logs antigos com a chave (essa pasta está ignorada pelo git, mas sincroniza para o OneDrive).
6. **[Importante] Botões que fingem funcionar.** Na Equipa SOC, «Apagar turno» e «Apagar regra» pedem confirmação e depois dizem «não implementado» (`soc_team.js:300-304`, `393-397`). O «Editar analista» deixa mudar o nome, mas o PATCH nem leva o campo (`soc_team.js:147`; `AnalystUpdate` não tem `name`). Nos Incidentes, «👤 Meus incidentes» lê `CURRENT_USER`, que não existe em lado nenhum, e mostra todos os incidentes (`incidents.js:217-220`).
7. **[Importante] Estados presos em «A carregar...».** Com o backend em baixo, há 38 ocorrências de «A carregar...» que nunca mudam, espalhadas por 13 abas. A aba Sistema não tem `try/catch` nenhum (`app.js:551`) e não mostra sequer um banner de erro. Noutras abas, o banner de erro convive com o «A carregar...», o que é contraditório.
8. **[Importante] Quatro MTTD diferentes no mesmo dashboard.** Overview: mediana em 168 h. Incidentes: média no período escolhido. Red vs Blue: média das tentativas em 7 dias. Métricas: mediana e p90. Um avaliador vê quatro números diferentes com o mesmo nome e passa a duvidar de todos.
9. **[Importante] Polling em segundo plano pesado para uma VM com 1 vCPU.** Com o Overview aberto e sem tocar em nada, o dashboard faz cerca de 15 pedidos a cada 30 s, mesmo com o separador escondido. Entre eles estão `/api/redblue/metrics` (até 1000 alertas e pontuação ML), `/api/ml-anomalies` e `/api/compliance`. Cada alerta recebido por WebSocket dispara ainda mais 9.
10. **[Importante] Sistema de design incompleto.** Há só 6 tokens de cor e 80 cores hexadecimais distintas no CSS, mais 14 em JS. Não há tema escuro nem `prefers-reduced-motion`. Os badges de severidade têm texto branco com contraste entre 2,16:1 e 3,82:1 (o mínimo AA é 4,5:1). Na paleta de severidade, Alto e Médio são indistinguíveis mesmo com visão normal (validador: ΔE 6,2, abaixo do limite de 15).

---

## 2. Mapa do frontend

O menu não tem 22 entradas: tem **38 entradas em 13 grupos**. São 26 abas com dados e 12 itens «planeados», que abrem a página genérica «Sem dados — ainda não implementado». A navegação usa botões com `aria-current="page"`, um padrão de navegação, não de separadores; é a escolha certa, e não precisa de `role="tablist"`.

Todos os endpoints consumidos existem em `scripts/main.py`. O único com incompatibilidade de parâmetros é `summary-by-tier`.

| # | Aba (grupo) | Ficheiro → função | Endpoint(s) | Existe? |
|---|---|---|---|---|
| 1 | Overview (Visão Geral) | `overview.js` → `ovwRefresh`; `app.js` → `loadStats`, `loadAgents`, `loadSystemPanel`, gráficos | `/api/siem/health`, `/api/incidents`, `/api/metrics`, `/api/vaccines`, `/api/stats`, `/api/agents`, `/api/system/*` | Sim |
| 2 | Alertas (SOC) | `app.js` → `loadAlerts`, `loadBruteForce` | `/api/alerts`, `/api/brute-force` | Sim |
| 3 | Incidentes (SOC) | `incidents.js` → `refreshIncidentsTab`, `selectIncident`, `incTriage`, `incAssign` | `/api/incidents[/{id}[/status,/notes,/triage,/assignment]]`, `/api/incidents/backfill` | Sim |
| 4 | Equipa SOC (SOC) | `soc_team.js` → `stInit` e 6 funções `load*` | `/api/soc/analysts`, `shifts`, `escalation-rules`, `on-call`, `primary`, `sla-breaches`, `summary-by-tier` | Sim; `summary-by-tier` tem `le=720`, mas o frontend envia 2160 com «90 dias» → 422 |
| — | Investigações (SOC) | planeado R3 | — | — |
| 5 | Red vs Blue (Red Team) | `redblue.js` → `refreshRedBlueTab`, `connectNetworkSocket` | `/api/redblue/metrics`, `/api/redblue/attack-log`, `/api/redblue/network`, `/api/health`, `/api/agents`, `/ws/network` | Sim |
| 6 | Attack Library | `attack_library.js` → `refreshAttackLibrary` | `/api/attack-library[/{id}]` | Sim |
| 7 | Attack Registry | `attack_registry.js` → `refreshAttacks`, `selectAttack` | `/api/attacks[/{id}]` | Sim |
| 8 | Attack Timeline | `attack_registry.js` → `renderAttackTimeline` (mesmo pedido) | `/api/attacks` | Sim |
| 9 | Detections (Blue Team) | `detections.js` → `refreshDetections` | `/api/detections` | Sim |
| — | Response, Playbooks | planeado R21 | — | — |
| 10 | Live Traffic (Network) | `network_soc.js` → `refreshLiveTraffic` | `/api/network/live-traffic` | Sim |
| 11 | Network Detections | `network_soc.js` → `refreshNetworkDetections` | `/api/network/detections` | Sim |
| 12 | PCAP / Evidence | `network_soc.js` → `refreshPcapEvidence` | `/api/network/evidence` | Sim |
| 13 | Agentes (Wazuh) | `app.js` → `loadAgents` | `/api/agents` | Sim |
| 14 | Live SOC (Wazuh) | `live_soc.js` → `lsRefreshHealth`, `lsLoadInitialFeed` e o evento `sentrylens:new-alert` | `/api/siem/health`, `/api/alerts?hours=1`, `/ws/alerts` (via `app.js`) | Sim |
| 15 | Ciclo de Vida (IAM) | `app.js` → `loadLifecyclePanel` | `/api/lifecycle` | Sim |
| 16 | Privilégios | `app.js` → `loadPrivilegesPanel` | `/api/privileges` | Sim |
| 17 | Contas Admin | `app.js` → `loadAdminActivityPanel` | `/api/admin-activity` | Sim |
| 18 | Anomalias (ML) | `app.js` → `loadMlAnomaliesPanel` | `/api/ml-anomalies` | Sim |
| 19 | Models (ML) | `ml_models.js` → `mlmRefresh`, `mlmDoTrain` | `/api/ml/models`, `POST /api/ml/train` | Sim (a rota `POST .../activate` existe, mas não tem UI, de propósito) |
| 20 | Evaluation (ML) | `ml_evaluation.js` → `mleRefresh`, `mleRefreshLive` | `/api/ml/models`, `/api/ml-anomalies` | Sim |
| 21 | Candidates (Vaccines) | `vaccines.js` → `vacRefresh`, `vacSelect` | `/api/vaccines[/{id}]` | Sim |
| — | Validation, Approved, Regression | planeados R12/R14 | — | — |
| — | Coverage, Techniques, Gaps (MITRE) | planeados R16 | — | — |
| 22 | MTTD / MTTR (Métricas) | `metrics.js` → `refreshMetrics` → `metRenderMttd` | `/api/metrics?hours=168` | Sim |
| 23 | Detection Coverage | `metrics.js` → `metRenderCoverage` | o mesmo pedido | Sim |
| 24 | Detection Rate | `metrics.js` → `metRenderRate` | o mesmo pedido | Sim |
| 25 | Conformidade (Relatórios) | `app.js` → `loadCompliancePanel` | `/api/compliance` | Sim |
| — | Security Reports (R19), Executive (R20) | planeados | — | — |
| 26 | Sistema | `app.js` → `loadSystemPanel`, `forceSpeedtest` | `/api/system/specs`, `alerts`, `usage-history`, `history`, `POST speedtest` | Sim |
| — | Settings | planeado R22 | — | — |
| — | Cabeçalho | `app.js` → `exportReport` | `/api/export/report` | Sim |

Rotas do backend sem UI: `/api/history/query`, `/api/nis2-lookup`, `/api/system/thresholds`, `PATCH /api/incidents/{id}/team`, `POST .../escalate`, `PATCH .../sla` e `POST /api/ml/models/{v}/activate`.

### Mapa de janelas temporais (o problema dos 168 h)

Há três seletores globais ou locais, mais limites fixos por rota. O resultado é que o utilizador nunca sabe que janela está a ver:

| Aba | Janela usada | Limite do backend | Avisa o utilizador? |
|---|---|---|---|
| Overview: chips e KPIs | fixa, 168 h | 168 | Sim, «(7 dias)» |
| Overview e Alertas: alertas | «Janela temporal», até 168 h | 168 | Sim |
| Ciclo de Vida, Privilégios, Contas Admin | «Período», até 90 dias | 90 dias | Sim |
| Anomalias | min(Período, 7 dias) | 168 h | Sim, numa nota |
| **Conformidade** | min(Período, 7 dias) | 168 h | **Não**: com «90 dias» escolhidos, mostra 7 dias em silêncio |
| **Incidentes, Attack Registry/Timeline** | min(Período, 30 dias) | 720 h | **Não**: «90 dias» passa a 30 em silêncio |
| **Equipa SOC → Resumo por Tier** | Período × 24 | 720 h | **Não**: «90 dias» dá **422** |
| Red vs Blue, Métricas | fixa, 168 h | 168 | Sim (nota ou «Janela de 168 h») |
| Detections | seletor próprio (1/24/168 h) | 168 | Sim |
| Evaluation (bloco ao vivo) | seletor próprio (1/24/72/168 h) | 168 | Sim |

---

## 3. Análise aba a aba (pela ordem do menu)

### Resumo

| Aba | Nota | Principal problema |
|---|---|---|
| Overview | 6 | O cabeçalho diz «ligado» com o Wazuh em baixo; barras verdes sem dados; três gráficos em branco sem estado vazio |
| Alertas | 5 | Ordena por severidade e corta em 100 sem avisar; gráfico temporal salta as horas sem alertas |
| Incidentes | 6 | Filtro «Meus incidentes» falso; atribuição em texto livre ignora a Equipa SOC; refresca a cada alerta, sem limite |
| Equipa SOC | 2 | Modais bloqueiam a página; XSS; três botões falsos; 422 com «90 dias» |
| Red vs Blue | 5 | Texto desatualizado («não regista ações de resposta»); 4 banners «Failed to fetch»; redesenha 200 linhas a cada pacote |
| Attack Library | 7 | Erro do detalhe vai para um painel escondido e ninguém o vê |
| Attack Registry | 7 | Sólido; falta ordenação e paginação além de 500 linhas |
| Attack Timeline | 5 | É uma lista, não uma linha temporal; não mostra o intervalo ataque → deteção |
| Detections | 6 | O filtro de fonte não atualiza os KPIs; mais um seletor de janela |
| Live Traffic | 4 | «Live» com polling de 30 s; só tabelas de contagens, sem uma barra |
| Network Detections | 5 | Detalhe em JSON cru; duplica o painel de rede do Red vs Blue |
| PCAP / Evidence | 5 | O nome promete PCAP que não existe; data em campo de texto livre |
| Agentes | 5 | Erro em texto cru dentro da tabela; agentes aparecem em três sítios |
| Live SOC | 7 | «Backend inacessível» para qualquer erro, incluindo 401 |
| Ciclo de Vida | 4 | Fica em «A carregar...» quando falha; 5 linhas com cores de estado usadas como categorias |
| Privilégios | 5 | Gráfico de barras vertical com nomes de grupos longos |
| Contas Admin | 4 | Donut de 2 fatias; três blocos presos em «A carregar...» |
| Anomalias | 4 | Concordância «0 %» com 0 eventos; `ml_score.toFixed` rebenta com `null`; texto «modelo sintético» fixo |
| Models | 6 | Parágrafo duplicado; é possível declarar dados sintéticos como «reais» |
| Evaluation | 6 | Função duplicada; `colspan` errado; só texto onde um gráfico ajudava |
| Vaccines (Candidates) | 8 | Referência de qualidade; só falta paginação e ordenação |
| MTTD / MTTR | 6 | Janela fixa de 168 h; números com ponto decimal; sem distribuição |
| Detection Coverage | 5 | Faltam a matriz cenário × sensor e o gráfico que este tema pede |
| Detection Rate | 6 | Correto mas seco; a tabela por fonte devia ser um gráfico |
| Conformidade | 4 | Nunca mostra a justificação do veredito; janela cortada em silêncio |
| Sistema | 3 | Sem `try/catch`: sem banner, «A carregar...» eterno, barras verdes |

### Overview (`overview.js`, `app.js`)

- **Coerência.** A faixa de chips, os KPIs e a lista «Requer atenção» respondem às perguntas certas («está saudável?», «o que exige ação?», «quão bem detetamos?»), e a lista nunca diz «tudo em ordem» quando falta uma fonte. É o melhor ponto de partida do dashboard. Por baixo disso, porém, a página repete a v1: 6 KPIs de alertas, 3 gráficos e o cartão «Estado do Sistema». São duas páginas coladas uma à outra.
- **Estados.** Com o backend em baixo, os KPIs mostram «—» e «Fonte indisponível» (bom). Os chips mostram quatro «● —» vazios que não dizem nada. O banner fica «⚠️ Failed to fetch», em inglês e sem ação sugerida. Os gráficos ficam como retângulos cinzentos vazios. As barras de sistema ficam verdes e cheias (R1).
- **Hierarquia.** Os KPIs principais (Incidentes, MTTD, Taxa) têm o mesmo peso visual que os 6 KPIs de alertas logo abaixo. Os «—» dos KPIs de severidade aparecem coloridos (laranja, amarelo) mesmo sem dados.
- **Texto.** O subtítulo fixo «SentryLens — ligado ao Wazuh em tempo real» (`index.html:19`) contradiz o indicador quando não há ligação. A marca aparece três vezes seguidas: logo com nome, `h1` e subtítulo.
- **Gráficos.** Ver secção 6.

### Alertas (`app.js:337-416`)

- Ordena por severidade e mostra só os primeiros 100 (`app.js:361-366`), sem dizer «100 de N». Num SOC, o padrão é ordenar pelo mais recente; a severidade fica para um filtro.
- Só há filtro de severidade: não há pesquisa por agente, IP ou Event ID, nem ordenação por coluna. A coluna «Log completo» tem 10,5 px com scroll interno, o que é ilegível num projetor.
- O filtro de severidade muda também o gráfico temporal do Overview (porque usa a mesma lista), mas não os KPIs. É inconsistente.
- O painel de força bruta só aparece com suspeitas; numa falha fica escondido em silêncio (`app.js:393-397`), e o utilizador não distingue «sem suspeitas» de «não consegui ver».

### Incidentes (`incidents.js`)

- O ciclo de estados, a nota obrigatória para fechar um incidente novo e a timeline com o ator de cada evento estão bem pensados.
- **Bug:** «👤 Meus incidentes» (`index.html:1011`, `incidents.js:217-220`) depende de `CURRENT_USER`, que não existe; o filtro devolve tudo.
- A atribuição é texto livre (`index.html:1042`), quando já existe a lista de analistas da Equipa SOC. Gera nomes inconsistentes.
- Para saber se o incidente está em «NEW», o código lê uma classe do DOM (`incidents.js:271-272`). É frágil: deve ler o estado guardado do incidente selecionado.
- A secção de triagem JEV fica sempre visível (`incidents.js:167-175`, ambos os ramos põem `hidden = false`) mesmo com o JEV desligado. O utilizador só descobre ao clicar.
- `confirm()` nativo para repetir a triagem (`incidents.js:311`). A lógica de `force` também confunde: sem cache local, envia sempre `force=1`, o que ignora a cache do servidor.
- `refreshIncidentsTab` corre em **cada** evento de alerta (`incidents.js:296`), sem throttle, e a cada 30 s com qualquer aba aberta.
- O MTTD do KPI é uma média no período (nos outros sítios é a mediana) e `incFormatSeconds` não sabe formatar horas: 7200 s aparece como «120 min 0 s».

### Equipa SOC (`soc_team.js`, `index.html:1065-1336`)

- **Bloqueio.** Os modais ficam visíveis e por cima de tudo (R2). É o achado mais grave para uma demo: abrir esta aba prende o utilizador.
- **Segurança.** XSS através dos `onclick` inline (S1).
- **Funcionalidade falsa.** Apagar turno, apagar regra e editar turno ou regra não existem; editar o nome do analista não grava. Vai contra a regra «nunca dados inventados»: aqui são ações inventadas.
- **Bugs:**
  - O filtro «Estado: Todos» envia `active_only=true` (`soc_team.js:85`), por isso «Todos» mostra só os ativos.
  - O Resumo por Tier com «90 dias» dá 422 (`soc_team.js:471`; `main.py:1700`, `le=720`).
  - O `datetime-local` envia hora sem fuso, quando o modelo pede «ISO 8601 com timezone» (`main.py:1329`).
- **Código morto.** `stShowPanel` (`soc_team.js:11-16`) e as classes `.tier-badge-inline`, `.role-badge-inline` e `.status-badge` (`style.css:935-949`) não são usadas. Os badges de tier e de papel reaproveitam as classes de estado dos incidentes (`inc-status-NEW` para «Tier 1»), o que mistura semânticas.
- **Estrutura.** Há seis `section.panel` dentro de outro `section.panel` (cartão dentro de cartão), cabeçalhos `h3` sem `h2` por cima, e `<span style="color:#e74c3c">⚠️ ULTRAPASSADO</span>` com cor inline e maiúsculas.

### Red vs Blue (`redblue.js`)

- A lógica de tentativas antigas (excluídas e assinaladas, com linhas a itálico e um `title` explicativo) é honesta e bem feita.
- O texto fixo «a aplicação não regista ações de resposta (nem manuais)» (`redblue.js:247-249`) ficou desatualizado: os incidentes já têm estados, notas e atribuição.
- O KPI «Ataques no Log» conta todas as tentativas, mas os outros KPIs contam só as da janela. O aviso existe, mas o par de números confunde.
- Um 503 é sempre traduzido como «Modelo de ML ainda não foi treinado» (`redblue.js:119-121`, também em `app.js:1198`). O 503 pode ter outras causas: o registo recusar a versão ativa, por exemplo.
- `rbFormatSeconds` não formata horas.
- **Desempenho.** Cada mensagem de `/ws/network` chama `renderNetworkPanel()`, que reconstrói por `innerHTML` até 200 linhas de pacotes, mais todas as deteções (`redblue.js:392-410`), com a aba escondida ou não. `rbNetwork.detections` e `rbNetwork.history` crescem sem limite (`redblue.js:404-405`).
- Com o backend em baixo aparecem quatro banners «Failed to fetch» iguais e três tabelas em «A carregar...».
- Duplica conteúdo: o painel de rede repete as abas de rede, e o painel «Manager / Auditor» repete Agentes e Live SOC.

### Attack Library (`attack_library.js`)

- Um só pedido, filtros em memória, detalhe por teclado. Bom.
- **Bug:** um erro ao abrir o detalhe chama `renderPanelError` num painel que continua `hidden` (`attack_library.js:99-101`), e o erro não aparece.
- «Replayable» fica em inglês no meio de uma tabela em português.

### Attack Registry e Attack Timeline (`attack_registry.js`)

- O registo é dos melhores ficheiros: tem números de sequência contra respostas fora de ordem, validação da técnica MITRE, e o veredito «Desconhecido» em vez de «Não detetado» quando falta a correlação.
- Falta ordenação por coluna e paginação além de 500 linhas.
- A **Timeline** é uma `<ol>` com texto corrido. Não há eixo temporal, não se vê o intervalo entre o ataque e cada deteção, e os vereditos não são comparáveis de relance. Para um projeto Red vs Blue, este devia ser o gráfico assinatura (ver secção 6).

### Detections (`detections.js`)

- A mensagem de fonte indisponível está correta.
- O filtro de fonte filtra a tabela, mas os KPIs continuam a mostrar o total. Há mais um seletor de janela local, para além dos dois do cabeçalho.
- Em «Sem dados — Failed to fetch.», a mensagem de exceção do browser aparece em inglês.

### Live Traffic, Network Detections e PCAP / Evidence (`network_soc.js`)

- **Live Traffic** atualiza por polling a cada 30 s e não abre o WebSocket; o nome «Live» promete mais. Protocolos, top talkers e portas aparecem em tabelas de duas colunas onde uma barra horizontal por linha seria lida de relance.
- **Network Detections** mostra a coluna «Detalhe» como `JSON.stringify` cru (`network_soc.js:30-33`). O `formatTimestamp` entra sem `escapeHtml` (`network_soc.js:111`); não é explorável hoje, mas foge à regra do projeto.
- **PCAP / Evidence** diz bem na nota que não há PCAP. Mesmo assim, o nome da aba promete PCAP. O dia escreve-se num `input type=text` com `placeholder="hoje"`, quando devia ser `type=date`. O aviso «A carregar...» da nota fica preso quando o pedido falha.

### Agentes (`app.js:303-335`)

- É uma tabela simples e correta. Com erro, a mensagem crua («Failed to fetch» ou o `detail` em inglês) vai para dentro da tabela, sem banner.
- Os agentes aparecem em três sítios: esta aba, o Live SOC e o painel «Manager / Auditor» do Red vs Blue. Esta aba devia fundir-se com o Live SOC.

### Live SOC (`live_soc.js`)

- Reutiliza o WebSocket de `app.js` em vez de abrir outro (bom). Tem pausa com contador de alertas pendentes e um tique local para a idade do último alerta.
- Qualquer erro na saúde do SIEM aparece como «Backend inacessível: HTTP 401/502» (`live_soc.js:210`). Com um 401, o backend está acessível e o problema é a chave.
- O feed é uma tabela que se reescreve inteira; um alerta novo não tem nenhum realce. Respeitar `prefers-reduced-motion` aqui fazia sentido.

### Ciclo de Vida, Privilégios e Contas Admin (`app.js:872-1152`)

- Numa falha, o banner aparece, mas as tabelas e as listas de deteções ficam em «A carregar...» (verificado: 2, 2 e 3 ocorrências). Os KPIs mantêm o valor anterior, sem aviso de que estão desatualizados.
- No Ciclo de Vida, o gráfico tem 5 linhas sobre dados diários, com cores de estado (vermelho, laranja) usadas como categorias. O filtro de utilizador é um campo sem `<label>`.
- Em Privilégios, o gráfico «Grupos mais movimentados» usa barras verticais com nomes de grupo longos. Barras horizontais servem melhor.
- Em Contas Admin, o donut «administrativos vs normais» tem duas fatias: chega uma frase ou uma barra a 100 %. A «Última atividade» só olha para tarefas e processos (decisão documentada, mas não visível na UI).

### Anomalias (`app.js:1154-1204`)

- **Bug de honestidade:** com `total = 0`, a concordância aparece como «0%» (`app.js:1191`). É exatamente o erro que `ml_evaluation.js` documenta e evita («0 ÷ 0 não é concordância»).
- **Crash:** `r.ml_score.toFixed(4)` (`app.js:1174`) rebenta com um score `null` e a tabela inteira fica por desenhar.
- A nota «Modelo treinado sobre dados sintéticos» é fixa (`index.html:550`). Com o registo de modelos, pode estar errada; deve vir de `model_version` e da origem declarada.
- A classe `agreement-${r.agreement}` entra sem escape (`app.js:1176`).

### Models (`ml_models.js`)

- Tem camada pura testável, mensagens acionáveis e a distinção entre versão ativa e versão carregada. Muito bom.
- O mesmo parágrafo de 11 linhas aparece duas vezes seguidas (`index.html:608-615` e `626-633`).
- O formulário de treino arranca com «Export recente» + origem «dados reais» (`index.html:643`), e nada impede escolher «Gerador sintético» com origem «dados reais». A origem declarada é o garante de honestidade do R9; esta combinação devia ser impossível.
- Aparecem identificadores internos ao utilizador: «(D-01.2)» numa mensagem de erro, «(D-03)» num título.
- O texto passa duas vezes por escape: `mlmRenderTrainResult` mete `escapeHtml(texto)` em `textContent` (`ml_models.js:514`, `524-527`). Um «&» ou «<» aparecia como `&amp;`.
- «Erro inesperado ao ler o registo de modelos» aparece quando o backend está simplesmente desligado, o que engana. Falta o código `network_error` que `vaccines.js` já tem.

### Evaluation (`ml_evaluation.js`)

- `mleRenderEvaluation` está declarada duas vezes (`ml_evaluation.js:435` e `547`); vale a segunda. É código morto que engana quem lê.
- O estado vazio da comparação usa `colspan="7"` numa tabela de 8 colunas (`ml_evaluation.js:510`).
- Os números usam vírgula decimal pt-PT (bem), ao contrário do resto do dashboard (R12).
- Precisão, recall e F1 por versão estão em texto. Um gráfico de pontos por métrica, uma linha por versão, mostrava a evolução de uma vez.

### Vaccines (`vaccines.js`)

- É a referência do projeto: o erro nunca aparece como «sem dados», `network_error` tem frase própria, os textos são acionáveis em PT, o estado do gerador é explicado, há proteção contra respostas fora de ordem e a cadeia de substituições é visível.
- Falta: ordenação, paginação, e a tabela de Event IDs do detalhe não está dentro de `.table-scroll`.

### MTTD / MTTR, Detection Coverage e Detection Rate (`metrics.js`)

- A honestidade é boa: «sem dados» é diferente de «nenhuma lacuna», há aviso de amostra pequena e aviso de alertas truncados.
- Com o backend em baixo, o banner aparece, mas as notas e as listas ficam em «A carregar...».
- A janela é fixa em 168 h (`metrics.js:131`) e nenhum seletor a muda.
- Os números usam ponto decimal («12.5 s»); a Evaluation usa vírgula.
- As três abas leem o mesmo pedido e mostram pouco cada uma. Juntavam-se numa página «Métricas de deteção» com três secções.
- Faltam os gráficos que o tema pede: a distribuição do MTTD por cenário e a matriz de cobertura (secção 6).

### Conformidade (`app.js:1206-1259`)

- O motor devolve uma `justificacao` por regulamento, e o motor existe precisamente para nunca omitir um veredito. A UI deita a justificação fora e mostra «✅ Aplicável» ou «➖ N/A». Qualquer `estado` desconhecido ou em falta também aparece como «N/A» (`app.js:1217`).
- A janela é cortada a 7 dias sem aviso (secção 2).
- É uma tabela de alertas com três colunas de ✅. O valor do painel estaria em «quais obrigações estão a ser despoletadas e porquê», agrupado por regulamento.

### Sistema (`app.js:440-695`)

- `loadSystemPanel` não tem `try/catch`. Sem backend, a aba fica sem banner, com «—» e três «A carregar...» eternos, e com barras verdes cheias.
- `specs.cpu.usage_percent.toFixed(1)` (`app.js:567`) rebenta se o valor vier `null`.
- O botão «Medir agora» falha em silêncio: só escreve na consola (`app.js:689-691`).
- O gráfico tem 3 séries com área preenchida sobrepostas (`fill: true`), que dão manchas. A legenda «Histórico de uso (sessão atual)» contradiz o comentário do código, que diz que o histórico vem do backend e persiste entre recargas.
- É a máquina do analista, não o laboratório: o cartão no Overview mistura a saúde do PC com a saúde do SIEM.

---

## 4. Transversal

### 4.1 Navegação e arquitetura de informação

- **38 entradas é demasiado.** 12 delas (32 %) são promessas de roadmap com badge «R21» e afins. Para um recrutador numa demo de 3 minutos, um terço do menu diz «não implementado». A recomendação é tirar os itens planeados do menu e pô-los numa única página «Roadmap» (ou num interruptor «mostrar planeados» guardado em `localStorage`).
- **Os 13 grupos misturam critérios:** papel (Red Team, Blue Team), fonte (Wazuh, Network), domínio (IAM, ML) e artefacto (Relatórios). A mesma informação aparece em vários sítios:

  | Informação | Onde aparece |
  |---|---|
  | Agentes | 3 sítios |
  | Captura de rede | 4 sítios |
  | MTTD | 4 sítios (com 4 definições) |
  | Saúde do SIEM | 2 sítios |
- **Proposta** (de 38 entradas para 21, em 8 grupos):
  ```
  Visão geral       Overview
  Operações SOC     Ao vivo (Live SOC + Agentes) · Alertas · Incidentes · Deteções · Equipa
  Validação         Red vs Blue · Ataques (Registo ⇄ Linha temporal) · Biblioteca · Vaccines
  Rede              Tráfego · Deteções de rede · Evidência
  Identidade        Ciclo de vida · Privilégios · Contas admin
  ML                Anomalias · Modelos (Versões ⇄ Avaliação)
  Métricas          Métricas de deteção (MTTD/MTTR, Cobertura, Taxa)
  Relatórios        Conformidade · Sistema do analista · Roadmap
  ```
- **Língua.** O menu mistura PT e EN sem regra: «Alertas, Incidentes, Agentes» lado a lado com «Detections, Live Traffic, Attack Registry, Models, Evaluation, Candidates». Proposta de regra: interface em português, e termos da indústria sem tradução corrente ficam em inglês (MTTD, MITRE ATT&CK, PCAP, Red/Blue Team, SIEM). «Detections» passa a «Deteções», «Models» a «Modelos», «Candidates» a «Candidatas», «Live Traffic» a «Tráfego».
- **Emojis.** Há emojis repetidos com significados diferentes: 📡 em Live Traffic e Live SOC, 🎯 em Detections e Detection Rate, 📊 em Overview e Executive. Os títulos de painel também têm emojis, alguns diferentes do item de menu correspondente. Para um leitor de ecrã, cada emoji é lido («espadas cruzadas Red vs Blue»). Proposta: um conjunto de ícones SVG local (um sprite inline, sem CDN) usado só no menu, com `aria-hidden="true"`, e títulos sem emoji.
- **Dois seletores de tempo no cabeçalho** («Janela temporal» e «Período (novos painéis)»). O rótulo «novos painéis» é linguagem do processo de desenvolvimento, não do produto. Proposta: um só controlo de janela, e cada aba mostra a janela efetivamente aplicada («A mostrar: últimos 7 dias, o máximo desta fonte»).
- **Deep links.** `#aba` funciona (bom). `activateTab` monta um seletor CSS com o hash sem escape (`app.js:1344`): um hash com aspas lança `SyntaxError` e a navegação deixa de funcionar. Correção: `CSS.escape(tabName)`.

### 4.2 Sistema de design

- **Tokens.** O `:root` tem 6 cores e 3 fontes. O CSS tem 80 cores hexadecimais distintas e o JS mais 14, muitas da paleta «Flat UI» de 2014 (`#e74c3c`, `#f39c12`, `#27ae60`, `#3498db`, `#8e44ad`, `#16a085`), que não têm nada a ver com o navy e ciano do logo. Os botões de triagem e de atribuição usam o índigo e o violeta do Tailwind (`#6366f1`, `#8b5cf6`), uma terceira identidade.
- **Tipografia.** Space Grotesk, Inter e JetBrains Mono estão bem escolhidas e são coerentes com a marca, mas não há escala definida: aparecem 10, 10,5, 11, 12, 12,5, 13, 14, 16, 18, 22, 24 e 28 px, mais `0.8rem`, `0.85em` e `0.9em`. As maiúsculas com espaçamento entre letras são o padrão por omissão de todos os rótulos (KPI `h3`, `th`, `summary`, `chart-card h3`). Proposta: 5 tamanhos (12/14/16/20/28) e minúsculas com peso 600 nos rótulos.
- **Componentes.** Há pelo menos 9 badges com o mesmo formato (`severity-badge`, `inc-status`, `atk-verdict`, `alib-risk`, `vac-verdict`, `mlm-badge`, `mle-origin`, `agent-status`, `rb-badge`) e 4 estilos de botão (`.controls button`, `.inc-actions button`, `.ls-toolbar button`, `.btn-primary`). Um `.badge` com modificadores e um `.btn` com modificadores cobrem tudo.
- **Cartões.** Todos os blocos são cartões brancos com a mesma sombra `rgba(0,0,0,.08)` e o mesmo raio, há cartões dentro de cartões (Equipa SOC, KPIs dentro de painéis) e os KPIs estão centrados. É o «kit de cartões SaaS» genérico: nada diz «consola SOC».
- **Tema escuro.** Não existe. Num SOC, o tema escuro é a norma. Num projetor, o claro é mais seguro. Proposta: tokens semânticos (`--surface`, `--surface-raised`, `--text`, `--text-muted`, `--border`, `--sev-*`, `--accent`) redefinidos em `@media (prefers-color-scheme: dark)` e `[data-theme="dark"]`, com um botão de tema. Os gráficos têm de ler os tokens com `getComputedStyle`; hoje as cores estão fixas no JS (`app.js:780-938`).
- **Direção estética.** O cabeçalho e a sidebar já têm identidade (navy e ciano). O conteúdo regressa ao cinzento claro genérico. Proposta (segundo a skill frontend-design: ousar num sítio e ter disciplina no resto):

  | Elemento | Escolha |
  |---|---|
  | Fundo de conteúdo | `--navy-950` atenuado no escuro; `#f3f6f8` no claro, ligeiramente frio |
  | Superfícies | uma elevação só, contornos de 1 px em vez de sombras |
  | Acento | `--cyan-600` (claro) e `--cyan-400` (escuro), só para o que é interativo ou está selecionado |
  | Severidade | rampa própria, validada (ver 4.3) e sempre com ícone e texto |
  | Momento-assinatura | a «faixa de tempo do ataque»: para cada ataque lançado, a marca do lançamento e as marcas de deteção por sensor (regra, ML, rede), com o MTTD como intervalo visível. É o que este projeto tem e um SIEM genérico não. |
  | Mono | JetBrains Mono só em IPs, Event IDs, hashes e horas, como pedido. Hoje está bem aplicada nas tabelas novas, mas não em todas (`incidents.js:87`, `detections.js:64`). |

### 4.3 Acessibilidade

Medido com um script WCAG e com o validador da skill dataviz:

| Combinação | Contraste | Mínimo |
|---|---|---|
| Badge «Alto» (branco sobre `#f39c12`) | **2,19:1** | 4,5 (texto de 10 px) |
| Badge «Médio» (branco sobre `#d4ac0d`) | **2,16:1** | 4,5 |
| Badge «Baixo» (branco sobre `#27ae60`) | **2,87:1** | 4,5 |
| Badge «Info» (branco sobre `#3498db`) | **3,15:1** | 4,5 |
| Badge «Crítico» (branco sobre `#e74c3c`) | **3,82:1** | 4,5 |
| Rótulos `.card h3` e `th` (`#888` sobre branco) | **3,54:1** | 4,5 |
| `.empty-state` (`#999`) | **2,85:1** | 4,5 |
| Valores de KPI laranja e amarelo sobre branco | **2,19:1 / 2,16:1** | 3 (texto grande) |
| Âmbar dos avisos (`#b9770e` sobre `#fdebd0`) | **3,15:1** | 4,5 |
| `--cyan-600` sobre branco | 4,81:1 | OK |
| `--cyan-400` sobre `--navy-950` | 10,16:1 | OK |

- **Paleta de severidade** (validador da dataviz, modo claro): **FAIL**. Entre Médio e Alto, ΔE é 0,8 para deuteranopia e 6,2 com visão normal; abaixo de 15 conta como indistinguível. O donut de severidade depende só da cor.
- **Foco.** O `:focus-visible` existe no menu, nas linhas clicáveis e na lista de atenção. Os botões e selects dos painéis ficam com o anel por omissão do browser, que é visível no Chromium.
- **Modais.** Não têm `role="dialog"`, `aria-modal`, nem `aria-labelledby`. Não prendem o foco, não fecham com Esc e não devolvem o foco ao fechar.
- **Erros.** `renderPanelError` cria o banner sem `role="alert"`, por isso um leitor de ecrã não anuncia a falha. Em compensação, há 10 `role="status"` bem colocados.
- **Mudança de aba.** O foco não passa para o título da aba nova, e o leitor de ecrã não sabe que o conteúdo mudou.
- **Tabelas.** Não têm `<caption>`. As linhas clicáveis têm `tabindex="0"` e respondem a Enter e Espaço (bom), mas não dizem que são interativas (por exemplo, `aria-label="Abrir incidente 12"`).
- **Gráficos.** Os `<canvas>` não têm `role="img"`, `aria-label`, nem uma tabela alternativa.
- **Controlos sem `<label>`.** `#severity-filter`, `#lifecycle-type-filter` e `#lifecycle-user-filter` (este só tem placeholder).
- **Movimento.** Não há `prefers-reduced-motion`. As transições são poucas (barras de progresso), por isso o risco é baixo.

### 4.4 Responsividade

- **390 px.** Há 3 px de scroll horizontal (`scrollWidth` 378 contra 375). O cabeçalho ocupa 296 px de 900, um terço do ecrã antes de qualquer conteúdo. Os KPIs passam a uma coluna; o menu colapsa num botão «☰ Menu» (funciona).
- **1024 px.** Não há scroll horizontal. O cabeçalho quebra em duas linhas (155 px).
- **1920 px.** O `.app-shell` tem `max-width: 1600px` e o `.container` tem `max-width: 1300px`, por isso sobram faixas vazias dos dois lados. Num projetor de 1920 × 1080 o conteúdo útil fica estreito, e as tabelas de 9 a 10 colunas (Alertas, Attack Registry) continuam a precisar de scroll. Para modo projetor: largura total, letra base de 15-16 px, e um `?view=present` que esconde a sidebar.
- **Sidebar.** Tem `height: 100vh` e é sticky, por isso o menu longo obriga a fazer scroll dentro dele. Com os grupos todos abertos por omissão, os itens de baixo ficam fora da vista.

### 4.5 Desempenho

Pedidos com o Overview aberto e sem interação (contados no código):

| Origem | Pedidos | Quando | Respeita a aba escondida? |
|---|---|---|---|
| `app.js` `refreshNewPanels` | 5 (lifecycle, privileges, admin, ml-anomalies, compliance) | a cada 30 s | **Não** |
| `redblue.js` `refreshRedBlueTab` | 5 (metrics 168 h, health, agents, attack-log, network) | a cada 30 s | **Não** |
| `incidents.js` | 1 | a cada 30 s **e a cada alerta** | **Não** |
| `overview.js` | 4 | a cada 30 s | Sim |
| `app.js` `refreshDashboard` | 8 (stats, agents, alerts, brute-force e 4 de `/api/system/*`) | a cada alerta do WS, com intervalo mínimo de 15 s | **Não** |
| `/ws/network` | 1 render de até 200 linhas | a cada pacote | **Não** |

- No carregamento são cerca de **30 pedidos**. Em regime, são 15 pedidos a cada 30 s com o separador minimizado. `/api/redblue/metrics`, `/api/ml-anomalies` e `/api/compliance` vão ao Indexer buscar até 1000 alertas; com a VM do Wazuh em 1 vCPU, isto é carga contínua sem ninguém a olhar. Durante um ataque, cada alerta dispara ainda `/api/system/specs`, que é WMI/PowerShell na máquina local.
- **Correção.** Os 9 módulos novos já seguem o padrão `isActive()` (aba ativa e `document.visibilityState === "visible"`). Basta aplicá-lo a `app.js`, `redblue.js` e `incidents.js`. No `/ws/network`, acumular os pacotes e desenhar no máximo 1 vez por segundo com `requestAnimationFrame` e só com a aba visível. Os arrays `detections` e `history` devem ter teto.
- **DOM.** As tabelas são reescritas inteiras por `innerHTML` a cada refresh, e perdem o scroll e a seleção (os incidentes repõem `selected`; outras tabelas não).
- **Recursos externos.** Google Fonts e Chart.js vêm de CDN. O Chart.js tem SRI (bom). Num laboratório sem internet, ou numa demo com Wi-Fi fraco, as fontes caem para as do sistema e os gráficos não carregam (`Chart is not defined` rebenta o `app.js` inteiro, na linha 742). Proposta: copiar `chart.umd.min.js` e os `.woff2` para o repo e acrescentá-los à whitelist do `serve_frontend.py`.

### 4.6 Robustez

- **Doze funções de pedido com o mesmo formato:** `fetchJSON`, `ovwRequest`, `incRequest`, `stRequest`, `atkRequest`, `alibRequest`, `detRequest`, `metRequest`, `nsRequest`, `mlmRequest`, `mleRequest` e `vacRequest`, mais 3 `fetch` diretos (`live_soc.js:107,197`, `app.js:683,707`). Quatro tratamentos diferentes de erro:
  - `fetchJSON` aceita qualquer `detail`, e um 422 do FastAPI (onde `detail` é um array) dá «[object Object]»;
  - outras só aceitam `detail` se for string;
  - `mlm`, `mle` e `vac` usam códigos traduzidos;
  - `vac` tem `network_error` e é o único que distingue «backend desligado».
- **Não há timeout em nenhum pedido.** Um backend pendurado (por exemplo, o Indexer lento a 1 vCPU) deixa «A carregar...» para sempre. Proposta: `AbortSignal.timeout(15000)`.
- **Não há retry nem backoff** nos pedidos REST. O `/ws/alerts` tem um backoff decente (1-16 s, depois polling e nova tentativa a cada 30 s). O `/ws/network` desiste ao fim de 5 tentativas e só é reaberto pelo refresh de 30 s.
- **`alert()` e `confirm()` nativos** em `app.js:729`, `incidents.js:311` e `soc_team.js:197,301,394`. Bloqueiam a página e não seguem o estilo do dashboard.
- **`formatTimestamp`** (`app.js:198-205`) não corrige o fuso «+0000» do Wazuh. `overview.js`, `live_soc.js` e `soc_team.js` corrigem, cada um à sua maneira. No Firefox e no Safari, `new Date("...+0000")` pode dar «Invalid Date», em inglês, e o `catch` nunca dispara porque `toLocaleString` não lança erro.
- **Duplicação.** A formatação de segundos existe 6 vezes; três versões não sabem horas (`rbFormatSeconds`, `incFormatSeconds`, `atkFormatSeconds`).

### 4.7 Segurança

**S1. XSS no `onclick` inline. Crítico, confirmado.**

`soc_team.js:111` e `:112` constroem:

```js
`<button onclick="deactivateAnalyst('${escapeHtml(a.id)}', '${escapeHtml(a.name)}')">`
```

O `escapeHtml` protege o contexto HTML, mas o valor de um atributo é decodificado antes de ser executado como JavaScript: `&#39;` volta a ser `'`. O nome é texto livre até 128 caracteres (`main.py:1316`), e um analista com o nome `Ana'),document.title=('XSS-OK` executou código no teste. A página tem a API key em `window.SENTRYLENS_CONFIG.apiKey`, por isso o código injetado pode chamar qualquer rota: treinar modelos, mudar estados de incidentes, criar analistas. As linhas `:237` e `:333` metem `${s.id}` e `${r.id}` numéricos e sem escape no mesmo padrão; não são exploráveis hoje, mas são frágeis.

Correção: delegação de eventos com `data-*` e zero handlers inline.

```js
// render
`<button class="btn-sm btn-danger" data-action="deactivate" data-id="${escapeHtml(a.id)}">Desativar</button>`
// uma vez, no init
document.getElementById("analysts-body").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const analyst = stAnalystsCache.find((x) => x.id === btn.dataset.id);
  if (btn.dataset.action === "deactivate" && analyst) deactivateAnalyst(analyst.id, analyst.name);
  if (btn.dataset.action === "edit" && analyst) openAnalystModal("edit", analyst.id);
});
```

**S2. A API key no browser e nos logs. Crítico pelos logs; o resto é aceitável para um laboratório.**

O pedido parte de uma premissa já ultrapassada: a chave **já não está fixa no `app.js`**. Vem de `/config.js`, gerado pelo `serve_frontend.py` a partir do `.env` e servido só a pedidos same-origin (`Sec-Fetch-Site`, com o `Referer` como alternativa) e com `Host` de loopback. Para um dashboard local é uma solução razoável. Os riscos que sobram:

| Risco | Gravidade | Correção realista |
|---|---|---|
| A chave vai na query string do WebSocket e o uvicorn grava-a no access log (32 ocorrências encontradas) | Crítico | 1) **Rodar a chave já.** 2) Pôr `scripts/backend.log*` no `.gitignore`: hoje só `*.log` e `*.log.err` estão cobertos e o `backend.log-PC-Vicente.err` escapa. 3) Tirar a chave do URL: um endpoint `POST /api/ws-ticket` (com `X-API-Key`) devolve um token de uso único com validade de 30 s, e o WS usa `?ticket=`. Em alternativa, passar a chave em `Sec-WebSocket-Protocol`. 4) Ou um filtro de logging no uvicorn que apague `api_key=` dos caminhos. |
| Qualquer XSS lê a chave | Importante | Corrigir S1 e acrescentar CSP (S3). Uma chave de vida longa no `window` só é aceitável sem XSS. |
| Logs antigos do Playwright em `.playwright-mcp/` com a chave (8 ficheiros) | Menor (ignorados pelo git, mas sincronizados para o OneDrive) | Apagar os ficheiros depois de rodar a chave |
| A chave é a mesma para leitura e escrita | Menor | Mais tarde, uma chave só de leitura para o dashboard em modo demo |

**S3. Sem CSP e sem cabeçalhos de segurança. Importante.**

`serve_frontend.py:117-122` não envia CSP, `X-Frame-Options` nem `Referrer-Policy` para o `index.html` (só o `/config.js` leva `nosniff`). Depois de remover os `onclick` (S1), uma CSP sem `unsafe-inline` em `script-src` bloqueia toda esta classe de XSS:

```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com;
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com;
  connect-src http://localhost:8001 ws://localhost:8001; img-src 'self' data:;
  object-src 'none'; base-uri 'none'; frame-ancestors 'none'
```

O `style-src 'unsafe-inline'` é necessário enquanto existirem `style="width:..."` e o `cssText` do banner. Com os recursos locais (secção 4.5), os domínios de CDN saem da lista.

**S4. Auditoria dos `innerHTML`.** Há 143 usos de `innerHTML` e nenhum `insertAdjacentHTML` com HTML. Verifiquei os campos dinâmicos ficheiro a ficheiro. Fora do S1, o que entra sem `escapeHtml`:

- números da API (`s.id`, `r.id`, `d.total`, `d.open`, `b.n`, `by[k]`, `disk.usage_percent.toFixed`);
- enums do backend (`b.status` em `soc_team.js:460`, chaves de `by_status`/`by_severity` em `soc_team.js:489-490`, `level-${v.level}` em `app.js:653`, `agreement-${r.agreement}` em `app.js:1176`);
- `formatTimestamp` em `network_soc.js:111`.

Nenhum é explorável hoje, porque os valores são gerados pelo backend, mas todos quebram a regra «todo o conteúdo dinâmico passa por `escapeHtml()`». Proposta: uma função `html\`...\`` (tagged template) que escapa por omissão todas as interpolações, e um teste estático que falha se aparecer `innerHTML = \`` sem passar por ela.

**S5. Outros pontos.** Não há links externos (não há `target="_blank"` para auditar). Não há uso de `localStorage` nem `sessionStorage`. O Chart.js tem SRI e `crossorigin`. As fontes do Google não têm SRI (não é possível, o CSS é dinâmico); copiá-las para o repo resolve.

---

## 5. Verificação funcional: resultados

| Verificação | Resultado |
|---|---|
| O backend em baixo deixa alguma aba a rebentar com exceção JS? | **Não.** Houve 85 erros de consola, todos «Failed to fetch» já apanhados, e nenhum `pageerror`. |
| Estados de erro honestos com o backend em baixo | **Parcialmente.** Há banner em 20 de 26 abas. A aba **Sistema** não mostra banner nenhum, e **Agentes** e **Live SOC** mostram o erro só dentro do conteúdo. Ficam **38** «A carregar...» presos em 13 abas. A mensagem é a do browser («Failed to fetch»), em inglês, em 18 abas; só Vaccines diz «Sem ligação ao backend (localhost:8001)». |
| Cabeçalho com backend em baixo, 401 ou 502 | «● sem ligação» (correto, mas só porque `/api/system/*` também falha). |
| **Cabeçalho com o Wazuh em baixo e a máquina local OK** | **«● ligado ao Wazuh»** (errado: R5) |
| Barras de sistema sem dados | **Verdes e cheias** (errado: R1) |
| 401 | O texto do backend passa tal e qual em 7 abas. Models e Vaccines traduzem («API key inválida ou em falta — confirma SENTRYLENS_API_KEY»). Live SOC diz «Backend inacessível», o que é errado. |
| 502 | Mostrado corretamente na maioria das abas. Models diz «Erro inesperado ao ler o registo de modelos», o que engana. |
| Equipa SOC | **Modais visíveis e a bloquear os cliques** (R2) |
| XSS no nome do analista | **Confirmada** (S1) |
| 390 px | 3 px de scroll horizontal; cabeçalho de 296 px |
| Teclado | A ordem de foco é lógica (cabeçalho, depois `summary`, depois itens) e o foco é visível. O `summary` de cada grupo é um ponto de tab extra entre os itens. |

---

## 6. Dataviz

Diagnóstico gráfico a gráfico, segundo o procedimento da skill (forma → cor → validação → marcas → interação → acessibilidade):

| Gráfico | Problema | Proposta |
|---|---|---|
| Alertas ao longo do tempo (`app.js:758`) | O eixo é categórico (rótulos de texto) e só cria baldes onde há alertas: uma hora sem alertas **desaparece** em vez de valer 0, o que deforma o ritmo. `tension: 0.25` inventa curvas entre contagens discretas, e a área por baixo exagera. | Baldes contínuos (todas as horas ou dias da janela, com 0 nas vazias) e barras finas. Se for linha, sem `tension`. Tooltip com a hora completa e a contagem. |
| Distribuição por severidade (donut) | Cinco fatias em que Alto e Médio são indistinguíveis (validador: FAIL). Um donut não permite comparar magnitudes próximas e não tem estado vazio: sem dados, fica um retângulo em branco. | Barras horizontais na ordem fixa Crítico → Info, com o valor escrito em cada barra. Ou uma barra 100 % empilhada com rótulos diretos. Cor da rampa validada, mais ícone e texto. |
| Top Event IDs | Barras verticais com rótulos «#4625», sem nome; o nome só aparece no tooltip. | Barras horizontais com o rótulo «4625 · Logon falhado» (o número em mono). |
| Ciclo de vida (5 linhas) | Usa cores de estado como categorias (vermelho para «Eliminadas», laranja para «Desativadas»), viola a regra «as cores de estado são reservadas» e é esparguete em dados diários esparsos. | Barras empilhadas por dia, com as 5 categorias numa paleta categórica validada, ou pequenos múltiplos. |
| Contas Admin (donut de 2 fatias) | É um gráfico para dizer um número. | Um KPI («12 % dos eventos são de contas administrativas, 340 de 2 830»). |
| Grupos mais movimentados | Barras verticais com nomes longos | Barras horizontais |
| Uso do sistema (3 linhas com área) | Áreas sobrepostas dão manchas; o validador falha o croma de `#0b7d92` e a separação para daltonismo entre roxo e ciano (ΔE 5,9) | Linhas sem área, rótulo direto no fim de cada linha, linhas de referência nos limiares de aviso e crítico |
| KPIs | Rótulos em maiúsculas, valores centrados, e «—» pintado de laranja ou amarelo sem dados. Não indicam unidade, período ou variação. | Alinhar à esquerda, «—» sempre neutro, uma linha secundária com o período e a variação face ao período anterior (só se houver amostra) |
| Barras de sistema | Verde a 100 % sem dados (R1) | Faixa vazia e «Sem dados» |

**Gráficos que faltam** (onde o projeto ganha mais):

1. **Faixa ataque → deteção** (Attack Timeline e Red vs Blue). Uma linha por ataque, eixo temporal comum, um losango no lançamento e um ponto por sensor que detetou (regra, ML, rede), com a distância a mostrar o MTTD. Os ataques não detetados mostram só o losango, com «não detetado» escrito. É o gráfico que conta a história do projeto numa imagem.
2. **Matriz de cobertura** (Detection Coverage). Linhas: cenários ou técnicas MITRE. Colunas: regra, ML, rede. Células: esperado e alcançado (cheio), esperado e falhado (contorno), não esperado (vazio). Com tabela alternativa e texto em cada célula, sem depender só da cor.
3. **Distribuição do MTTD por cenário.** Um ponto por tentativa (strip plot) e a marca da mediana, em vez de média, mediana e p90 em três colunas de texto.
4. **Avaliação por versão.** Um gráfico de pontos (precisão, recall e F1 por versão), com ML e regras lado a lado.
5. **Live Traffic.** Barras inline nas tabelas de protocolos, origens e portas, sem precisar de biblioteca: uma `<div>` com largura proporcional.

**Regras transversais:**

- As cores dos gráficos saem de tokens CSS, não de literais no JS.
- Todos os gráficos têm estado vazio («Sem dados nesta janela»), `aria-label` e uma tabela «ver dados».
- Uma legenda sempre que há 2 ou mais séries, e rótulos diretos até 4 séries.
- Números em pt-PT (`toLocaleString("pt-PT")`: vírgula decimal, espaço nos milhares).
- Nunca dois eixos verticais.

Rampa de severidade sugerida como ponto de partida, a validar com `validate_palette.js` nos modos claro e escuro antes de adotar:

| Nível | Cor | Texto por cima |
|---|---|---|
| Crítico | `#b42318` | branco |
| Alto | `#c4320a` | branco |
| Médio | `#b54708` | branco |
| Baixo | `#3e7c5a` | branco |
| Info | `#475467` | branco |

Os pares adjacentes ficam próximos em tom, por isso esta rampa **tem de** ser acompanhada de ícone e texto. A severidade não é uma paleta categórica.

---

## 7. Catálogo de melhorias

Gravidade: **C** = crítico, **I** = importante, **M** = menor. Esforço: **S** até 2 h, **M** meio dia a 1 dia, **L** vários dias.

### 7.1 Correções rápidas

| ID | Grav. | Local | Problema | Correção | Esf. |
|---|---|---|---|---|---|
| R1 | C | `style.css:598-603`, `index.html:220-236,316-334` | Barras verdes a 100 % sem dados | `.progress-fill { width: 0; background: var(--border); }`; só ganha cor quando há valor | S |
| R2 | C | `style.css:892` | `.modal{display:flex}` anula o atributo `hidden` | `.modal[hidden]{display:none}` (ou `[hidden]{display:none !important}` global); mais `role="dialog"`, `aria-modal`, Esc e foco preso | S |
| R3 | C | `soc_team.js:111-112,237,333` | XSS por `onclick` inline | Delegação de eventos (exemplo em S1) | S |
| R4 | C | `.gitignore`; logs | A API key nos logs | Rodar a chave; `scripts/backend.log*` no `.gitignore`; apagar os logs antigos | S |
| R5 | C | `app.js:1284-1301` | O cabeçalho diz «ligado ao Wazuh» com o Wazuh em baixo | O indicador passa a ler `/api/siem/health` (já existe e diz ok/degraded/down), com 3 estados e texto: «Wazuh operacional», «Wazuh degradado», «Sem ligação ao backend». Tirar o subtítulo fixo de `index.html:19` | S |
| R6 | I | `app.js:198-205` | `formatTimestamp` sem a correção do «+0000»; «Invalid Date» em inglês | Uma `parseWazuhDate()` partilhada (a de `overview.js:69`) e «—» quando a data é inválida | S |
| R7 | I | `app.js:551-676` | Sistema sem `try/catch`; `toFixed` sobre `null` | `try/catch` com `renderPanelError`; uma função `fmtPct(v)` que devolve «—» | S |
| R8 | I | `app.js:1191,1174` | Concordância de 0 % sem amostra; `ml_score.toFixed` rebenta | «—» e «Sem eventos» quando `total === 0`; `mleNumero` para o score | S |
| R9 | I | `soc_team.js:300-304,393-397,259-262`; `index.html` | Botões falsos (apagar e editar turnos e regras) | Remover os botões até as rotas existirem. Para o nome: tirar o campo do modo de edição, ou acrescentar `name` ao `AnalystUpdate` | S |
| R10 | I | `incidents.js:217-220`; `index.html:1011` | «Meus incidentes» com `CURRENT_USER` inexistente | Remover a opção; quando houver analista atual, preencher a lista a partir de `/api/soc/analysts` | S |
| R11 | I | `soc_team.js:85` | «Todos» envia `active_only=true` | `if (active !== "") params.set("active_only", active === "1")` (confirmar a semântica do backend) | S |
| R12 | I | `soc_team.js:471` | 422 com «90 dias» | `Math.min(days*24, 720)` e mostrar «janela limitada a 30 dias» | S |
| R13 | I | `app.js:1217` | Conformidade colapsa estados e esconde a justificação | Mostrar o `estado` real e a `justificacao` (num `title` ou numa linha expandível); um estado desconhecido aparece como «Indeterminado», nunca «N/A» | S |
| R14 | I | `index.html:643`; `ml_models.js:92-97` | Permite declarar dados sintéticos como reais | Ao escolher «Gerador sintético», fixar a origem em «synthetic» e desativar o select; validar também no backend | S |
| R15 | I | `attack_library.js:99-101` | Erro do detalhe num painel escondido | Mostrar o painel antes de `renderPanelError` (como faz `vacRenderDetailError`) | S |
| R16 | M | `index.html:608-615` | Parágrafo duplicado | Apagar a primeira cópia | S |
| R17 | M | `ml_evaluation.js:435-438,510` | Função duplicada; `colspan` 7 em 8 colunas | Apagar a primeira declaração; `colspan="8"` | S |
| R18 | M | `ml_models.js:524-527` | Escape duplo em `textContent` | Tirar o `escapeHtml` antes do `textContent` | S |
| R19 | M | `app.js:1344` | Hash não escapado num seletor | `CSS.escape(tabName)` | S |
| R20 | M | `redblue.js:247-249` | Texto desatualizado sobre ações de resposta | Reescrever ou apontar para a aba Incidentes | S |
| R21 | M | `live_soc.js:210` | «Backend inacessível» para 401 e 502 | Mensagem por código (reaproveitar o mapa de `vaccines.js`) | S |
| R22 | M | `incidents.js:167-175` | A triagem JEV aparece sempre | Perguntar ao backend se o JEV está ativo (um campo em `/api/health`) e esconder a secção quando não está | S |
| R23 | M | `style.css:743,883,893,935-949`; `soc_team.js:11-16` | CSS e funções mortos | Remover | S |

### 7.2 UX e visual

| ID | Grav. | Local | Problema | Correção | Esf. |
|---|---|---|---|---|---|
| U1 | I | menu (`index.html:44-123`) | 38 entradas, 12 planeadas, 13 grupos | Arquitetura de informação da secção 4.1; os planeados passam para uma página «Roadmap» | M |
| U2 | I | todas as abas | Mistura de PT e EN | A regra de língua da secção 4.1; renomear 15 itens | S |
| U3 | I | cabeçalho | Dois seletores de tempo e limites silenciosos | Um seletor global, e cada aba mostra a janela efetiva | M |
| U4 | I | todos os módulos | «A carregar...» preso e «Failed to fetch» cru | Componente de estado único (W2) | M |
| U5 | I | MTTD em 4 sítios | Quatro definições | Uma definição (a mediana do `soc_metrics`) em todo o lado; o Incidentes mostra «MTTD (mediana)» vindo de `/api/metrics` | M |
| U6 | I | Alertas | Ordenação e corte silenciosos; sem pesquisa | Ordenar pelo mais recente; «a mostrar 100 de N»; pesquisa por agente, IP ou Event ID; cabeçalhos ordenáveis | M |
| U7 | I | Incidentes | Atribuição em texto livre | `<select>` alimentado pelos analistas ativos | S |
| U8 | M | `app.js:729`, `incidents.js:311`, `soc_team.js:197,301,394` | `alert()` e `confirm()` nativos | Uma mensagem dentro do painel; confirmação no próprio botão («Clica outra vez para confirmar») | S |
| U9 | M | Overview | Duas páginas coladas; marca repetida 3 vezes; 4 chips vazios | Overview em três faixas (saúde, ação, desempenho), com os alertas resumidos num só gráfico. Tirar o `h1` redundante e esconder os chips sem dados atrás de «SIEM: indisponível» | M |
| U10 | M | Equipa SOC | Cartões dentro de cartões; maiúsculas; cores inline | Uma secção por bloco com `h2`; badges próprios para tier e papel | S |
| U11 | M | PCAP/Evidence | Nome enganador; data em campo de texto | Renomear para «Evidência de rede»; `input type="date"` | S |
| U12 | M | 390 px | Cabeçalho de 296 px; 3 px de scroll horizontal | Compactar os controlos atrás de um botão «Filtros» em ecrãs pequenos; encontrar o elemento de 378 px | S |
| U13 | M | projetor | Largura máxima de 1300 px | Largura fluida até 1800 px; modo `?view=present` | S |

### 7.3 Dataviz

| ID | Grav. | Local | Problema | Correção | Esf. |
|---|---|---|---|---|---|
| D1 | I | `style.css:442-446,261-264`; `app.js:797` | Paleta de severidade sem contraste e sem separação | Rampa nova (secção 6), validada com o script; ícone e texto obrigatórios | M |
| D2 | I | `app.js:758-793` | Baldes em falta e curvas inventadas | Baldes contínuos, barras | S |
| D3 | I | `app.js:795-842` | Donut e Top Event IDs pouco legíveis | Barras horizontais com rótulos | S |
| D4 | I | `app.js:927-948`, `1063-1079`, `848-870` | Cores de estado usadas como categorias; donut de 2 fatias; áreas sobrepostas | Secção 6 | M |
| D5 | I | Attack Timeline | Lista em vez de linha temporal | Faixa ataque → deteção (gráfico novo: Chart.js scatter, ou SVG à mão) | L |
| D6 | I | Detection Coverage | Sem matriz | Matriz cenário × sensor | M |
| D7 | M | todos os gráficos | Sem estado vazio, sem `aria-label`, sem tabela alternativa | Uma função `renderChart` que trata disso | M |
| D8 | M | todos os números | Ponto decimal | `Intl.NumberFormat("pt-PT")` num `fmt.js` | S |

### 7.4 Refatorações estruturais

Sem passo de build: os browsers carregam `<script type="module">` nativamente, e o `serve_frontend.py` só precisa de ter os ficheiros novos na whitelist e o tipo MIME `.js` (já tem).

| ID | Grav. | Problema | Correção | Esf. |
|---|---|---|---|---|
| E1 | I | 12 funções de pedido, 4 contratos de erro, sem timeout | `api.js` com uma `apiRequest()` (ver em baixo) | M |
| E2 | I | 26 abas com 6 formas diferentes de ciclo de vida (observer, intervalos, interruptores `isActive`) | `router.js`: `registerTab({id, load, refreshMs})` trata da aba ativa e visível, do intervalo, do hash, do foco no título e do redimensionamento dos gráficos | M |
| E3 | I | `app.js` com 1393 linhas e 9 domínios | Partir em `overview-alerts.js`, `system.js`, `iam.js`, `ml-anomalies.js`, `compliance.js`, `realtime.js` (o WebSocket) e `shell.js` (navegação e cabeçalho) | L |
| E4 | I | 143 `innerHTML` com escape à mão | Uma `html\`\`` que escapa por omissão e `raw()` para HTML já seguro; mais um teste estático | M |
| E5 | M | Tabelas com o mesmo código em todo o lado | `table.js`: `renderTable(el, {columns, rows, empty, error, sortable, onSelect})` com ordenação, linhas selecionáveis por teclado e «a mostrar N de M» | M |
| E6 | M | KPIs repetidos | `kpi(el, {label, value, sub, level, unit})`, com «—» sempre neutro | S |
| E7 | M | 6 formatadores de tempo | `fmt.js`: `fmtDuration`, `fmtDate`, `fmtNumber`, `fmtPct` | S |

Esboço de E1:

```js
// api.js — único ponto que fala com o backend
const ERROR_TEXT = {
  network_error: "Sem ligação ao backend (localhost:8001) — confirma scripts/start-backend.ps1.",
  timeout: "O backend não respondeu em 15 s — o Wazuh Indexer pode estar lento.",
  unauthorized: "API key inválida ou em falta — confirma SENTRYLENS_API_KEY.",
  http_502: "O backend não conseguiu falar com o Wazuh.",
  http_503: "Serviço indisponível no backend — vê o backend.log.",
};
export class ApiError extends Error {
  constructor(code, status) { super(ERROR_TEXT[code] || `Erro inesperado (${code})`); this.code = code; this.status = status; }
}
export async function apiRequest(path, { method = "GET", body, timeoutMs = 15000 } = {}) {
  let res;
  try {
    res = await fetch(API_BASE + path, {
      method, signal: AbortSignal.timeout(timeoutMs),
      headers: { "X-API-Key": API_KEY, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    throw new ApiError(e.name === "TimeoutError" ? "timeout" : "network_error", 0);
  }
  if (res.ok) return res.json();
  if (res.status === 401) throw new ApiError("unauthorized", 401);
  const data = await res.json().catch(() => null);
  const code = typeof data?.detail === "string" && /^[a-z_]{1,64}$/.test(data.detail) ? data.detail : `http_${res.status}`;
  throw new ApiError(code, res.status);
}
```

### 7.5 Valor para o portefólio

Um avaliador técnico numa demo de 3 minutos quer ver três coisas: que entendes o ciclo de deteção (ataque → telemetria → deteção → resposta → métrica), que os números são verdadeiros, e que o produto aguenta falhas. O SentryLens tem as três no backend. No frontend, a história perde-se em 38 entradas de menu.

| ID | Grav. | Proposta | Esf. |
|---|---|---|---|
| P1 | I | **Guião de demo fixo** (`docs/DEMO.md`), 6 passos e 3 minutos. Overview (saúde verde) → lançar `brute_force` a partir da Kali → Live SOC (os alertas a chegar) → Incidentes (o incidente aberto sozinho, com a ligação ao ataque) → Attack Registry e a faixa ataque → deteção (o MTTD visível) → Vaccines (a proposta para o que escapou). Cada passo é uma aba. | S |
| P2 | I | **Gravar a demo** em GIF/MP4 no README, com dados reais de uma sessão e a data. Nunca um «modo demo» com dados inventados: isso violaria a regra do projeto e um avaliador atento nota. Para fazer a demo sem laboratório, o histórico real (`historico/`, `attack_log.jsonl`) pode alimentar o backend, desde que a UI diga «a reproduzir a sessão de 2026-10-XX». | M |
| P3 | I | **Zero itens «não implementado»** e zero abas a bloquear (R2) no caminho da demo | S |
| P4 | I | **Um MTTD só** e a mesma janela em todo o lado (U5): a primeira pergunta de um avaliador é «porque é que este número é diferente daquele?» | M |
| P5 | M | **A segurança do próprio dashboard como argumento.** Um parágrafo «Como protegi este dashboard» no README (CSP, sem handlers inline, chave fora do URL, escape por omissão, auditoria anterior). Depois de S1-S3 corrigidos, é material de entrevista para uma vaga de cibersegurança. | S |
| P6 | M | **Acessibilidade e tema escuro** visíveis na demo: um botão de tema, e navegar uma aba só com o teclado | M |

---

## 8. Plano em ondas

Cada onda é pequena, fecha com critérios verificáveis e parte-se em microtarefas com dono único (uma tarefa = um ficheiro ou uma função) e revisão independente. Os testes seguem o padrão do repositório: scripts standalone sem framework, que imprimem `[OK]`/`[FALHOU]` e terminam com `sys.exit(1)`. Os testes de lógica JS usam o padrão `node:vm` já usado em `test_ml_models_ui.cjs` e chamado a partir de Python; os testes de contrato estático seguem `test_vaccines_frontend.py`.

### Onda 0: higiene de segurança (antes de qualquer outra coisa)

- **W0.1** Rodar a `SENTRYLENS_API_KEY`. Acrescentar `scripts/backend.log*` ao `.gitignore`. Apagar `scripts/backend.log-PC-Vicente.err`, os `.err` antigos e os 8 logs de `.playwright-mcp/` com a chave.
- **W0.2** Remover os `onclick` de `soc_team.js` e substituí-los por delegação de eventos (R3).

**Critérios de saída:**
- `git status --short` não lista nenhum `backend.log*`;
- `grep -rc "api_key=" scripts/*.log*` dá 0 depois de um arranque e de uma ligação WS. Isto só é verdade depois da W5.4; até lá, o critério é a chave rodada;
- novo `test_frontend_no_inline_handlers.py`: falha se `onclick=`, `onchange=` ou `on[a-z]+=` aparecer em `*.js` ou `index.html`.

### Onda 1: honestidade e bloqueios (quick wins, todos S)

- **W1.1** R2: modais. **W1.2** R1: barras. **W1.3** R5: indicador do cabeçalho via `/api/siem/health`. **W1.4** R7: Sistema com `try/catch`.
- **W1.5** R8: concordância e `ml_score`. **W1.6** R9 e R10: botões e filtro falsos. **W1.7** R11 e R12: filtro «Todos» e 422 do tier.
- **W1.8** R13: justificação na Conformidade. **W1.9** R14: origem declarada coerente.

**Critérios de saída:**
- `test_frontend_states.cjs` (`node:vm` com um `document` mínimo e `fetch` a rejeitar) confirma que nenhuma aba deixa «A carregar...» depois de uma falha, e que nenhuma `.progress-fill` fica com largura sem dados;
- teste: com `/api/siem/health` a devolver `status: "down"`, o indicador não contém «ligado»;
- teste estático: `index.html` não contém `data-planned` dentro da área de demo, ou contém só a página Roadmap;
- verificação manual com o guião da secção 0 (Playwright com rotas intercetadas), anexando as capturas à revisão.

### Onda 2: um só cliente HTTP e um só componente de estado

- **W2.1** `api.js` (E1) com testes de mapeamento (rede, timeout, 401, 422 com array, 502, `detail` não seguro).
- **W2.2** `state.js`: `showLoading`, `showEmpty`, `showError` e `role="alert"` nos erros.
- **W2.3** a **W2.8**: migrar um módulo por tarefa (`metrics`, `network_soc`, `detections`, `attack_*`, `incidents`, `soc_team`, `redblue`, `app`). As abas que já fazem bem (Vaccines, ML) migram por último.

**Critérios de saída:**
- `grep -E "async function \w+Request" *.js` devolve só `apiRequest`;
- nenhum texto «Failed to fetch» chega ao DOM (teste `node:vm`);
- todas as mensagens de erro em PT, com uma ação sugerida.

### Onda 3: desempenho e ciclo de vida

- **W3.1** `router.js` (E2). **W3.2** Aplicar o padrão aba ativa e visível a `app.js`, `redblue.js` e `incidents.js`.
- **W3.3** `/ws/network`: lote com `requestAnimationFrame`, teto nos arrays, desenho só com a aba visível. **W3.4** Throttle no refresh dos incidentes por alerta.
- **W3.5** Chart.js e fontes locais, na whitelist do `serve_frontend.py`.

**Critérios de saída:**
- com timers falsos em `node:vm`: 0 pedidos em 120 s com `visibilityState = "hidden"`, e no máximo 4 por 30 s com o Overview visível;
- `test_serve_frontend.py` cobre os ficheiros novos;
- o dashboard abre sem internet (verificação manual com a rede cortada).

### Onda 4: sistema de design

- **W4.1** Tokens semânticos e tema escuro. **W4.2** Rampa de severidade validada (D1). **W4.3** Escala tipográfica e rótulos sem maiúsculas.
- **W4.4** `.badge` e `.btn` unificados. **W4.5** Ícones SVG locais com `aria-hidden`. **W4.6** `prefers-reduced-motion`. **W4.7** Modais acessíveis.

**Critérios de saída:**
- `validate_palette.js` passa nos modos claro e escuro para a paleta categórica dos gráficos;
- script de contraste com todos os pares texto/fundo dos tokens ≥ 4,5:1 (≥ 3:1 para texto grande);
- `grep -cE "#[0-9a-fA-F]{6}" style.css` ≤ 30, todos dentro de `:root` ou do bloco do tema escuro;
- nenhuma cor literal em `*.js`.

### Onda 5: arquitetura de informação e coerência

- **W5.1** Novo menu (U1) e página Roadmap. **W5.2** Regra de língua (U2). **W5.3** Seletor de janela único (U3).
- **W5.4** WS com ticket ou subprotocolo (S2), mais CSP no `serve_frontend.py` (S3). **W5.5** Um MTTD só (U5).

**Critérios de saída:**
- o menu tem no máximo 22 entradas e nenhuma com `is-planned`;
- `test_serve_frontend.py` verifica o cabeçalho CSP sem `unsafe-inline` em `script-src`;
- o access log de uma sessão com WS não contém `api_key=`;
- o MTTD do Overview, dos Incidentes, do Red vs Blue e das Métricas é o mesmo número para a mesma janela (teste de API mais teste `node:vm`).

### Onda 6: dataviz

- **W6.1** D2 e D3. **W6.2** D4. **W6.3** D7 e D8. **W6.4** D6: matriz de cobertura. **W6.5** D5: faixa ataque → deteção.

**Critérios de saída:**
- cada gráfico tem estado vazio, `aria-label` e tabela alternativa (teste estático sobre `renderChart`);
- verificação visual com captura em 1440 px e 390 px, nos temas claro e escuro.

### Onda 7: refatoração de `app.js` e componentes

- **W7.1** E4: `html\`\``. **W7.2** E5: `table.js`. **W7.3** E6 e E7.
- **W7.4** a **W7.8**: partir `app.js` (E3), um domínio por tarefa.

**Critérios de saída:**
- `app.js` com menos de 200 linhas (só arranque);
- `run_all_tests.py` verde;
- o teste estático de `innerHTML` sem `html\`\`` dá 0 ocorrências.

### Onda 8: portefólio

- **W8.1** P1: `docs/DEMO.md`. **W8.2** P2: gravação da sessão real. **W8.3** P5: secção de segurança no README. **W8.4** Ensaio da demo cronometrado (3 min) por outra pessoa.

**Critério de saída:** uma pessoa que não conhece o projeto percorre o guião sem ajuda e sem encontrar um ecrã vazio, preso ou «não implementado».

**Ordem recomendada:** 0 → 1 → 2 → 3 juntas formam o «mínimo para mostrar a alguém» (cerca de 3 a 4 dias de microtarefas). As ondas 4 a 6 dão o salto visual. A 7 pode correr em paralelo a partir da 3, porque reduz o custo de tudo o que vem a seguir.
