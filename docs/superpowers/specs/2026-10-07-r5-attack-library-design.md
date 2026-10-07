# R5 — Attack Library (design)

Data: 2026-10-07 · Branch: `roadmap-v2-r5-attack-library-spec` (a partir de
`roadmap-v2-r2-live-soc`) · Base: R0/R4.

## Objetivo

Hoje `scripts/attack_scenarios.py` tem `SCENARIOS` — um dict Python interno,
sem risco, sem sensores esperados explícitos, sem passos de limpeza — que
serve só para lançar ataques na Kali. A R5 extrai esse conhecimento para uma
**biblioteca de referência, só leitura**: um catálogo consultável de "que
ataques existem no laboratório, que técnica/ferramenta usam, que sensores
devem disparar, como reverter o estado da máquina alvo depois". É puro
metadata — nunca lança nada. Alimenta o campo `expected` da R4 (Attack
Registry) e dá contexto ao operador antes de lançar um cenário na Kali.

A R4 (nota: lido `git show roadmap-v2-r4-attack-registry:...`, commit
`0a0c7b6` já existe) já decidiu o contrato de "esperado": sem `expected` no
log, usa o default do cenário (`["rule","ml"]`), com `expected_source` a
dizer `log` ou `scenario_default`. A R5 tem de ser compatível com isso —
ver §3.

## Rulings (decididos, não em aberto)

1. **A biblioteca não executa nada.** Não existe nenhuma rota que lance um
   ataque a partir do dashboard/API. As duas rotas da R5 são `GET`. O único
   sítio que lança ataques continua a ser `attack_scenarios.py`, correndo
   manualmente na Kali (ver `scripts/README.md`) — isto não muda. Ver §2 para
   a justificação de segurança completa.
2. **Fonte de verdade = `scripts/attack_library.yaml`** (ficheiro versionado
   novo), não uma constante Python. Motivo: é dado de referência (descrição,
   risco, cleanup), editável por quem não lê Python, e dá para validar o
   schema no arranque/testes sem importar `attack_scenarios.py`. A chave de
   cada entrada é o mesmo `scenario_name` de `SCENARIOS`
   (`attack_scenarios.py` continua a ser a fonte de verdade para
   `event_ids`/`mitre_technique`/`tool` — ver §3, não há duplicação de dados
   que já existem lá).
3. **`id` da biblioteca = `scenario_name`** (string, igual à chave de
   `SCENARIOS`, ex. `brute_force_rdp`), não um número. É estável porque já é
   usado como `--scenario` na CLI e como `scenario` no `attack_log.jsonl` —
   inventar outro id duplicaria chaves para a mesma entidade.
4. **Risco = taxonomia curta e fixa**: `low | medium | high`. Critério: `low`
   = só gera ruído/leitura (ex. enumeração), `medium` = pode causar lockout de
   conta ou negação de serviço limitada, `high` = altera estado persistente
   na máquina alvo (cria tarefa, ficheiro, conta). Decidido no catálogo
   inicial por entrada, não calculado.
5. **Sensores esperados reaproveitam o vocabulário de `expected` da R4**:
   lista ⊂ `rule|ml|network`. A biblioteca é a origem do default por cenário
   que a R4 usa quando o log não tem `expected` próprio (`scenario_default`).
   Não inventa uma 4ª categoria.
6. **Replayable**: campo booleano + motivo em texto curto. `true` só para
   cenários cujo `build_command` não depende de estado que mude entre
   corridas (ex. `smb_enum`, `blank_password_check`); `false` com motivo
   explícito para os que exigem credenciais específicas ou que alteram
   estado que a corrida anterior já mudou (ex.
   `lateral_movement_schtasks` — a tarefa já lá está depois da 1ª vez;
   `account_lockout_spray` — pode já estar bloqueada). Isto informa o futuro
   Attack Replay Lab (R13); a R5 só regista o facto, não implementa replay.
7. **Cleanup = lista de passos em texto, não comandos executáveis.** Cada
   passo é uma frase descritiva (ex. "remover a tarefa agendada
   `SentryLensLab` via `schtasks /delete`") guardada como string no YAML — a
   biblioteca nunca contém um comando pronto para `subprocess.run`. Ver §2,
   ponto 3.
8. **Pré-requisitos** também em texto curto (ex. "requer `--user`/`--password`
   válidos pós-comprometimento"), espelhando o que já hoje faz
   `build_command` devolver `None` quando faltam argumentos.
9. **Duração estimada** é uma categoria (`seconds | minutes`), não um número
   de segundos preciso — o tempo real depende da wordlist/rede e um número
   fixo seria falso. Observação: `attack_scenarios.run_scenario` já regista
   `duration_seconds` real por execução no `attack_log.jsonl`; a biblioteca
   não duplica isso, só dá uma expectativa grosseira a priori.
10. **Validação de schema é fail-fast e síncrona no arranque do módulo**:
    `load_attack_library()` lê o YAML uma vez (cache em memória, sem
    recarregar a cada pedido — como `rbac.py` faz com o baseline), valida
    contra o schema (ver §4) e levanta `ValueError` com a lista de problemas
    se algo for inválido. `main.py` deixa essa excepção propagar no arranque
    (falha alto e claro) em vez de servir uma biblioteca corrompida; os
    testes cobrem o mesmo validador diretamente.

## 2. Segurança (ponto central)

A biblioteca é **catálogo**, nunca um executor. Isto não é só uma intenção —
é imposto estruturalmente:

1. **Sem rota de escrita.** As únicas rotas HTTP desta fase são
   `GET /api/attack-library` e `GET /api/attack-library/{id}`. Não existe
   `POST`/`PUT`/`DELETE` nesta fase nem está prevista — se algum dia houver
   execução a partir do dashboard (R13 Attack Replay Lab, ou uma eventual
   resposta automática do R21), é uma fase própria, com o seu próprio design
   de autorização, allowlist de alvos e auditoria; fica **fora de âmbito**
   aqui de propósito, para não misturar "consultar o catálogo" com "lançar
   ataques pela rede a partir de um backend acessível ao dashboard".
2. **Allowlist de alvos: decisão do roadmap ainda pendente.** Hoje
   `attack_scenarios.py --target` aceita qualquer valor — é convenção, não
   imposto em código (ver `docs/SECURITY.md`, linha sobre isto, e a nota de
   dívida já registada em R4: "allowlist de targets (R5)"). A R5 **não**
   resolve isto no backend (porque o backend não executa ataques — não há
   onde impor a allowlist do lado do servidor). O que a R5 faz é documentar
   no catálogo, por entrada, se o cenário é "seguro para qualquer alvo de
   laboratório" ou "só com credenciais/alvo específico pós-comprometimento"
   — e deixa explícito que impor a allowlist em código (ex. um ficheiro
   `allowed_targets.txt` lido por `attack_scenarios.py` antes de montar o
   comando) é trabalho da Kali-side, candidato a tarefa própria no plano de
   implementação (ver §5), não parte da API read-only.
3. **Separação metadados vs comandos de execução.** O YAML da biblioteca
   nunca contém uma `list[str]` pronta para `subprocess.run` nem um comando
   shell montado — só descrição em prosa (`cleanup_steps: list[str]` de
   frases, não de argv). Os comandos reais continuam só em
   `attack_scenarios.py::build_command` (que já redige passwords antes de
   logar, ver `_redact_command_for_log`) e em scripts manuais do operador em
   `kali-share/` (fora deste repo — confirmado por inspeção: `kali-share/`
   tem hoje `attack_scenarios.py` e um dump de notas, sem credenciais em
   texto nestes ficheiros). A API desta fase serve apenas o que está no YAML;
   não há caminho de código que leia `build_command` e o devolva ao cliente.
4. **Sem IPs/credenciais reais versionados.** Qualquer exemplo nesta spec,
   no YAML de exemplo e nos testes usa os blocos documentais
   `192.0.2.0/24`/`203.0.113.0/24` (RFC 5737), nunca os IPs reais do
   laboratório (`192.168.x.x`) que aparecem em `attack_log.jsonl` (gitignored)
   ou em `kali-share/`.
5. **Execução futura fica fora de âmbito, por desenho.** Se R13/R14/R21
   vierem a querer lançar replays a partir do backend, isso implica: uma
   rota de escrita nova, autenticação reforçada (a chave única de hoje não
   distingue "ver catálogo" de "lançar ataque"), allowlist de alvo imposta em
   código (não convenção), e um audit log dedicado — nenhuma dessas peças
   existe hoje nem é proposta aqui. Registar isto explicitamente evita que um
   plano de implementação futuro "estenda" a R5 para executar sem passar
   por esse desenho de segurança próprio.

## 3. Fonte de verdade e compatibilidade

`scripts/attack_library.yaml` (novo, versionado) — uma entrada por
`scenario_name` já existente em `attack_scenarios.SCENARIOS`:

```yaml
brute_force_rdp:
  name: "Força bruta de RDP"
  description: "Tentativas de autenticação RDP com dicionário de passwords."
  risk: medium
  prerequisites: "Alvo com RDP exposto; sem credenciais prévias."
  expected_sensors: [rule, ml]
  cleanup_steps:
    - "Desbloquear a conta se o lockout policy a tiver bloqueado."
    - "Limpar tentativas de login do histórico de eventos, se aplicável ao exercício."
  replayable: true
  replayable_reason: "Não altera estado persistente; cada corrida é independente."
  duration_estimate: minutes
```

- `attack_scenarios.SCENARIOS` continua a ser a única fonte de verdade para
  `event_ids`, `mitre_tactic`, `mitre_technique`, `tool`, `build_command` —
  o YAML **não** repete esses campos. `attack_library.py::load_attack_library()`
  junta as duas fontes em memória (merge por `scenario_name`) e expõe um
  único objeto combinado; se uma chave existir no YAML mas não em
  `SCENARIOS` (ou vice-versa), é um erro de validação (ver §4), não um
  "campo em falta" silencioso.
- Técnica/ferramenta reais: são as já existentes em `SCENARIOS`
  (`mitre_technique` tal como `T1110`/`T1110.003`, `tool` tal como
  `"hydra"`/`"netexec"`) — a R5 não inventa valores novos, só os expõe
  combinados com o novo metadata de risco/cleanup/replay.
- `attack_log.jsonl` e `attack_registry.py` (R4) não mudam de formato por
  causa da R5. A ligação é só de leitura: a R4 usa
  `attack_library.get_expected_sensors(scenario_name)` como a fonte do
  default do cenário em vez de reimplementar esse mapeamento — **a confirmar
  com quem implementar a R4**: se a R4 já tiver o seu próprio default
  embutido na altura em que a R5 for implementada, a integração é trocar
  esse default por uma chamada à biblioteca, sem mudar a resposta da API da
  R4 (mesmos valores, fonte única em vez de duplicada).

## 4. API, módulo, frontend, validação

**Módulo** `scripts/attack_library.py` (puro depois do primeiro load; sem
rede, sem subprocess):

- `load_attack_library(yaml_path=DEFAULT_PATH) -> dict[str, LibraryEntry]` —
  lê e valida; cache em memória (mesmo padrão de `rbac.load_rbac_baseline`);
  caminho configurável via `ATTACK_LIBRARY_PATH`, resolvido relativamente ao
  próprio ficheiro (nunca ao cwd, como o resto do projeto).
- `validate_entry(name, entry, known_scenarios) -> list[str]` — devolve a
  lista de problemas (vazia se válido): campos obrigatórios em falta
  (`risk`, `expected_sensors`, `cleanup_steps`, `replayable`,
  `duration_estimate`), `risk` fora de `low|medium|high`,
  `expected_sensors` com valor fora de `rule|ml|network`,
  `duration_estimate` fora de `seconds|minutes`, `scenario_name` sem par em
  `SCENARIOS` (e o inverso: cenário em `SCENARIOS` sem entrada na
  biblioteca — sinalizado como aviso, não erro, para não travar o arranque
  por um cenário novo ainda não documentado). Formato MITRE (herdado de
  `SCENARIOS`, não do YAML) validado com `^T\d{4}(\.\d{3})?$` — mesma regex
  da R4.
- `get_library_entry(scenario_name) -> dict | None`,
  `get_expected_sensors(scenario_name) -> list[str]` (usado pela R4).

**API** (`main.py`), ambas com `dependencies=_REQUIRE_API_KEY`:

| Rota | Parâmetros | Resposta |
|---|---|---|
| `GET /api/attack-library` | — | `{entries: [...], total}` — cada entrada: `id, name, description, mitre_technique, tool, risk, prerequisites, expected_sensors, cleanup_steps, replayable, replayable_reason, duration_estimate` |
| `GET /api/attack-library/{id}` | `id` validado por `^[a-z_]{1,64}$` (mesmo alfabeto de `scenario_name`) | uma entrada; `404` com código estável `entry_not_found` se `id` não existir; `422` se o formato do `id` for inválido |

Erro de ficheiro YAML ilegível/corrompido no arranque: o módulo levanta
`ValueError` na importação (ver ruling 10) — `main.py` não tenta servir uma
biblioteca inválida; isto é equivalente ao que a R4 já faz para o seu
próprio log ilegível, mas um nível mais estrito (falha no arranque, não por
pedido), porque aqui o conteúdo é estático e controlado pelo próprio projeto.

**Frontend** `attack_library.js` (padrão `incidents.js`/`live_soc.js`):
sidebar "📚 Attack Library" (grupo Red Team), `data-tab="attack-library"`.
Lista com filtro por risco/sensor esperado; detalhe mostra
descrição/pré-requisitos/cleanup/replayable com o motivo. `escapeHtml` em
todo o texto dinâmico (a descrição/cleanup vêm de um ficheiro que o próprio
projeto controla, mas a regra do projeto é sempre escapar). Estado vazio
("Sem dados") se a chamada falhar — nunca mostra um catálogo inventado no
cliente. `app.js` não é editado; `serve_frontend.py` ganha o ficheiro na
whitelist.

**Testes** `test_attack_library.py` (padrão standalone do projeto, sem
Wazuh): YAML válido carrega; campo obrigatório em falta é rejeitado com
mensagem a identificar o campo; `risk`/`duration_estimate` fora da
taxonomia rejeitados; técnica MITRE em formato inválido (herdada de
`SCENARIOS`) rejeitada; entrada em `SCENARIOS` sem par no YAML gera aviso
sem travar; entrada no YAML sem par em `SCENARIOS` é erro; rotas: 401 sem
API key, 404 em id inexistente (código estável), 422 em id malformado, 200
com a lista completa coincidindo em tamanho com `len(SCENARIOS)` depois do
catálogo inicial estar completo. Regressão: todos os `scripts/test_*.py`.

## 5. Fora de âmbito, riscos, dívida

**Fora de âmbito nesta fase**: execução de ataques a partir do
dashboard/API (ver §2.5); allowlist de alvos imposta em código do lado da
Kali (dívida registada, candidata a tarefa própria); edição da biblioteca
via API (é só leitura — editar é editar o YAML e re-commitar); replay real
(R13); UI para lançar um cenário (não existe e não vai existir nesta fase).

**Riscos**: (1) o YAML pode divergir de `SCENARIOS` ao longo do tempo se
alguém adicionar um cenário novo e esquecer a entrada da biblioteca — mitigado
pelo aviso não-bloqueante no arranque (ruling do módulo) e pelo critério de
aceitação abaixo; (2) taxonomia de risco (`low/medium/high`) é subjetiva e
decidida por quem escreve o YAML, não calculada — aceite para esta fase, sem
uma fórmula de risco automática.

**Dívida**: nenhuma automação liga `cleanup_steps` a uma execução real
(ficam só como checklist para o operador humano ler); sem versionamento de
schema do YAML (uma mudança incompatível de campo exige migrar o ficheiro à
mão).

**Critérios de aceitação**:
- [ ] Cada cenário de `attack_scenarios.SCENARIOS` tem uma entrada
      correspondente na biblioteca, ou aparece listado explicitamente como
      "sem entrada" nos testes/documentação (nunca omitido em silêncio).
- [ ] Cada ataque `launched` em `scripts/attack_log_round3.jsonl` (Round 3
      real) tem o seu `scenario` coberto por uma entrada da biblioteca, ou
      fica listado como "sem entrada" no relatório de verificação —
      confirmar isto com os dados reais do ficheiro ao implementar, não
      assumir.
- [ ] `GET /api/attack-library` nunca expõe um comando executável
      (`build_command`/argv) em nenhum campo da resposta.
- [ ] YAML inválido impede o arranque do backend com uma mensagem que
      identifica o(s) campo(s) em falta — nunca um 500 silencioso por pedido.
- [ ] Testes novos e os 18 ficheiros existentes passam; sem secrets; docs
      atualizadas (`API.md`, `DATA_MODEL.md`, `SECURITY.md`,
      `ROADMAP_STATUS.md`, README).

## 6. Tarefas sugeridas para o plano de implementação

1. Criar `scripts/attack_library.yaml` com as 5 entradas atuais de
   `SCENARIOS` (conteúdo real: descrição, risco, pré-requisitos, sensores
   esperados, cleanup, replayable, duração).
2. Implementar `scripts/attack_library.py` (load + validação + merge com
   `SCENARIOS` + cache em memória).
3. Escrever `test_attack_library.py` (validação do módulo, casos
   inválidos, verificação de cobertura face a `SCENARIOS`).
4. Adicionar as duas rotas `GET` em `main.py` (com `_REQUIRE_API_KEY`) e
   ligar o módulo; atualizar `test_attack_library.py` com os casos de API
   (401/404/422/200).
5. `attack_library.js` + entrada na sidebar + `serve_frontend.py` whitelist.
6. Alinhar `attack_registry.py` (R4, se já implementada nessa altura) para
   consumir `get_expected_sensors()` em vez do seu próprio default
   embutido, sem mudar a resposta observável da API da R4.
7. Atualizar `docs/API.md`, `docs/DATA_MODEL.md`, `docs/SECURITY.md`
   (allowlist de targets passa a estar documentada como dívida explícita
   da Kali-side, não resolvida aqui) e `docs/ROADMAP_STATUS.md` (R5 de
   🟡 para ✅ ou para o estado real alcançado).
8. Verificar cobertura contra `scripts/attack_log_round3.jsonl` (dados
   reais do Round 3) e documentar quaisquer cenários "sem entrada".

## Decisões em aberto para o utilizador

1. **Allowlist de alvos**: fica só documentada como convenção/dívida nesta
   fase, ou deve a R5 já propor um ficheiro de allowlist lido por
   `attack_scenarios.py` do lado da Kali (fora da API)? Isto muda se a
   tarefa 1 do roadmap-ready plan inclui ou não esse ficheiro.
2. **Risco automático vs manual**: a taxonomia `low/medium/high` fica
   decidida à mão por entrada (como proposto), ou deve derivar de uma regra
   (ex. de `replayable=false` → nunca `low`)? Muda o esforço de manter o
   YAML atualizado.
3. **Aviso vs erro para cenário sem entrada na biblioteca**: proposto como
   aviso não-bloqueante (arranque continua); se preferires fail-fast total
   (como o resto da validação), um cenário novo em `SCENARIOS` bloquearia o
   arranque até a biblioteca ser atualizada.
4. **Id da biblioteca**: proposto = `scenario_name` (string); se a R4 vier a
   usar outro identificador (ex. um id numérico próprio de execução), pode
   ser preciso um segundo campo de mapeamento — a confirmar quando a R4
   estiver implementada.
5. **Alcance dos `cleanup_steps`**: ficam só em texto descritivo (proposto),
   ou deves querer já aqui uma estrutura mais rica (ex. passos com
   categoria "manual"/"automatizável no futuro") para facilitar uma R13 que
   venha a semi-automatizar cleanup?
