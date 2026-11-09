# SentryLens: arquitetura das fases 10 a 19

> Plano externo, 2026-11-09, Fernando Nuno Vieira. Colado na sessão do Claude Code e
> guardado aqui tal como veio (só as Fases 10 a 13 estavam no texto colado; as 14 a 19
> aparecem apenas no modelo de dados). Importado via `/gsd-import` — ver o relatório de
> conflitos em `.planning/` antes de tratar isto como plano aprovado.

## Visão geral

Com as fases 10 a 19, o SentryLens deixa de ser uma lista de alertas e passa a acompanhar o ciclo completo de um SOC: o alerta ganha contexto (técnica MITRE), junta-se a outros num incidente, vira um caso com dono e estado, e pode levar a uma resposta registada.

O desenho assenta em cinco regras que se mantêm em todas as fases.

- O FastAPI (pasta scripts/, porta 8001) continua a ser o único ponto de entrada. O frontend em HTML, CSS e JS simples nunca fala diretamente com o Wazuh nem com serviços externos.
- O Wazuh continua a ser a fonte dos eventos. O PostgreSQL guarda só o estado próprio do SentryLens (incidentes, casos, auditoria, resultados de enriquecimento) e referencia os alertas pelo id, sem os copiar inteiros.
- As regras e o ML correm em paralelo, como na Fase 6. A técnica MITRE vive no event_catalog.py; o Isolation Forest só acrescenta uma pontuação, não decide sozinho.
- Tudo o que altera um caso, uma conta ou um sistema fica no registo de auditoria, com utilizador e hora.
- Cada fase entrega algo que se vê no dashboard por si só, para que o projeto nunca fique a meio de uma dependência.

## Modelo de dados

O estado novo cabe em 13 tabelas no PostgreSQL, ligadas entre si por incident_id, case_id e user_id. A tabela de vulnerabilidades da Fase 9 (host, porta, vuln_id, severidade, data do scan) fica como está e é lida pelo score de risco.

| Tabela | Fase | Campos principais | Liga a |
|---|---|---|---|
| mitre_techniques | 10 | technique_id, nome, tática | event_catalog.py (o mapeamento evento para técnica fica no código) |
| caldera_runs | 10 | id, technique_id, host, executada_em, detetada, alert_id | mitre_techniques |
| incidents | 11 | id, host, aberto_em, fechado_em, severidade | incident_alerts, cases |
| incident_alerts | 11 | incident_id, wazuh_alert_id, timestamp, regra, technique_id | incidents |
| users | 12 | id, nome, hash_password, papel, ativo | audit_log, cases |
| audit_log | 12 | id, user_id, ação, alvo, detalhe, timestamp | users |
| cases | 13 | id, incident_id, estado, atribuído_a, aberto_em, fechado_em | incidents, users |
| case_notes | 13 | id, case_id, autor, texto, timestamp | cases |
| host_risk | 14 | host, score, componentes (JSON), calculado_em | lê alertas, incidentes e vulnerabilidades |
| ip_enrichment | 15 | ip, país, asn, reputação, consultado_em | usada em alertas e incidentes |
| notification_rules | 16 | id, condição, canal, silenciada_até | lê incidentes e alertas |
| response_actions | 17 | id, case_id, ação, alvo, pedido_por, estado, revertida_em | cases, users |
| replay_runs | 19 | id, dataset, iniciado_em, velocidade | só o modo demo |

O wazuh_alert_id guarda a referência ao alerta no Indexer em vez de uma cópia. Se o Wazuh for reconstruído, os incidentes antigos perdem o detalhe mas mantêm o resumo (regra, técnica, hora), e por isso incident_alerts guarda também esses três campos.

## Fase 10: MITRE ATT&CK

Esta fase etiqueta cada alerta com a técnica MITRE correspondente e mede quantas das técnicas lançadas pelo Caldera o Wazuh chegou a detetar. É a base das fases 11, 14 e 18, por isso vai primeiro.

- Catálogo: novo campo technique_id em cada entrada do event_catalog.py. O 4625 aponta para T1110 (força bruta) e o 4698 para T1053.005 (tarefa agendada). Um Event ID sem técnica clara fica vazio, não se força um mapeamento.
- Origem da técnica: os alertas do Wazuh trazem o campo rule.mitre quando a regra tem mapeamento. A ordem é usar esse campo primeiro e cair no catálogo quando estiver vazio. Falta confirmar no lab real que o campo vem preenchido para as regras que já disparam.
- Caldera: no fim de cada operação, o backend lê os resultados pela API do Caldera e grava uma linha em caldera_runs por técnica executada. A técnica conta como detetada se existir um alerta com essa técnica, nesse host, entre a execução e uma janela de N minutos depois.
- Endpoint: GET /api/mitre/coverage devolve, por técnica, os alertas vistos, as execuções do Caldera e quantas foram detetadas.
- Frontend: matriz com as táticas em colunas e as técnicas em células, em três estados (não executada, executada e detetada, executada e não detetada), com a percentagem de deteção por tática no topo.

Está pronta quando, depois de uma operação do Caldera, a matriz mostra que técnicas o Wazuh viu e quais passaram sem alerta.

## Fase 11: incidentes e timeline

Esta fase junta os alertas do mesmo host numa cadeia de ataque, para que uma operação do Caldera apareça como um incidente e não como dezenas de linhas soltas.

- Regra de agrupamento: alertas do mesmo host dentro de uma janela de 30 minutos (valor de partida, a ajustar) entram no mesmo incidente. Passada a janela sem atividade, o incidente fecha e o alerta seguinte abre outro.
- Severidade: a maior entre os alertas do incidente, subida um nível quando aparecem técnicas de duas ou mais táticas diferentes, que é o sinal de uma cadeia e não de um evento isolado.
- Execução: uma tarefa em segundo plano no FastAPI lê do Indexer os alertas novos desde o último timestamp processado, guardado como cursor, e cria ou atualiza incidentes. O frontend continua só a ler, com o refresh de 30 segundos que já tem.
- Reconhecimento: se existir um scan do Nikto ao mesmo host antes do primeiro alerta, entra como primeiro evento da timeline. Liga o que o atacante descobriu ao que depois tentou.
- Endpoints: GET /api/incidents e GET /api/incidents/{id}, este último com os alertas por ordem de tempo e a técnica de cada um.
- Frontend: lista de incidentes à esquerda e, ao abrir um, a timeline com as técnicas agrupadas por tática.

Está pronta quando uma operação completa do Caldera dá um único incidente, com a sequência de técnicas legível de cima para baixo.

## Fase 12: autenticação, perfis e auditoria

Esta fase põe login, perfis e registo de auditoria no próprio SentryLens. Vem antes dos casos e da resposta ativa porque ambos precisam de saber quem fez cada coisa.

- Perfis: analista Tier 1, Tier 2, Tier 3 e admin, alinhados com a aba da equipa SOC. Proposta de permissões: o Tier 1 vê alertas e incidentes e abre casos, o Tier 2 atribui e fecha casos, o Tier 3 pode pedir resposta ativa, o admin gere utilizadores.
- Autenticação: utilizador e palavra-passe, com hash argon2 ou bcrypt, e sessão por JWT de curta duração num cookie HttpOnly com SameSite. O HTTPS vem do nginx já previsto na Fase 9.
- Proteção do login: limite de tentativas por utilizador e por IP, com bloqueio temporário.
- Auditoria: um middleware do FastAPI grava em audit_log todas as escritas (POST, PUT, PATCH, DELETE) e todos os logins falhados, com utilizador, ação, alvo e hora.
- Opcional: escrever também o audit_log num ficheiro que o agente Wazuh leia, para o SentryLens ser monitorizado pelo próprio Wazuh.
- Endpoints: POST /api/auth/login, POST /api/auth/logout, GET /api/auth/me e um CRUD de /api/users só para admin.

Está pronta quando nenhum endpoint de /api responde sem sessão (exceto /api/health e o login) e o audit_log mostra quem fez cada escrita.

## Fase 13: gestão de casos

Cada incidente pode virar um caso com estado, dono e notas. É daqui que saem as métricas de tempo do SOC.

- Estados: novo, em análise, falso positivo e fechado. Um caso novo passa a em análise ao ser atribuído, e daí fecha ou é marcado como falso positivo. Reabrir fica reservado ao Tier 2 e acima.
- Criação: automática para incidentes de severidade alta ou crítica, manual para os restantes. Fica por decidir se este limiar é o certo.
- Dono e escalamento: o campo atribuído_a aponta para um utilizador. Quando o Tier 1 escala para o Tier 2 ou 3, a mudança de dono fica registada no audit_log e como nota do caso.
- Notas: case_notes só aceita acrescentos, sem editar nem apagar, para o historial do caso ser fiável.
- MTTD: tempo entre a execução da técnica no Caldera e o primeiro alerta. Só é calculável nas simulações, onde se sabe a hora do ataque.
- MTTR: tempo entre o primeiro alerta e o fecho do caso.
- Endpoints: GET e POST /api/cases, PATCH /api/cases/{id} para estado e dono, POST /api/cases/{id}/notes e GET /api/metrics/soc.
- Frontend: lista de casos com filtros por estado e dono, e um painel com MTTD e MTTR por simulação.

Está pronta quando um incidente do Caldera é aberto como caso, atribuído, fechado, e o painel mostra o MTTD e o MTTR dessa simulação.
