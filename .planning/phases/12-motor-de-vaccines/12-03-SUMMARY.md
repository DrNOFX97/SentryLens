---
phase: 12-motor-de-vaccines
plan: 03
subsystem: backend
tags: [vaccines, attack-log, attack-id, max-plus-one, fail-closed, tracer, stdlib-only]

requires:
  - phase: 12-01
    provides: build_vaccine_candidates, vaccine_id (id determinístico vac-<sha256[:12]> de attack_id:sensores)
  - phase: 12-02
    provides: validate_vaccine, envelope de três estados
provides:
  - "scripts/attack_scenarios.py: MAX_ATTACK_ID, valid_attack_id, AttackIdUnavailable, next_attack_id, format_log_entry(..., attack_id=None) que grava id, run_scenario que atribui o id antes de tudo, main com código 2, _self_check que confirma ids 1 e 2"
  - "scripts/test_attack_log_ids.py: run_tracer (escritor real -> disco -> leitor -> registo -> motor -> vaccine validada) e run_ids (colisões, linhas hostis, sem backfill, partial, paridade, fail-closed, CLI)"
affects: [13 (store: o id da vaccine depende do attack_id agora gravado), 14 (docs do formato do attack log e contagem de testes)]

plan_head_before: ed910e2bc03c4063b8f14bc45b6d90a65767f9ba
plan_head_after: 58d4518aab5d3c437f317c1157d2fcccbf602bbd

actuals:
  tokens: 5200
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Id max+1 sobre o próprio log (nunca contagem+1), como model_registry.next_version_id"
    - "Regra duplicada de propósito (import circular) e coberta por teste de paridade com attack_registry.normalize_attack_id"
    - "Atribuição de id como primeira instrução de run_scenario: fail-closed antes da allowlist e do subprocess"

key-files:
  created:
    - scripts/test_attack_log_ids.py
  modified:
    - scripts/attack_scenarios.py

key-decisions:
  - "Esquema do id: int não-bool entre 1 e MAX_ATTACK_ID = 999_999_999 (mesmo teto de normalize_attack_id e da rota /api/attacks/{attack_id}), chave `id`, max+1 sobre ids válidos de qualquer status"
  - "Fail-closed: AttackIdUnavailable (log ilegível ou espaço de ids esgotado) antes de lançar e de escrever; mensagem só com o nome do ficheiro e o tipo da exceção, nunca o caminho completo; na CLI vira erro de argumentos (código 2)"
  - "Sem backfill: entradas antigas ficam byte a byte iguais e continuam em skipped.no_attack_id (D-04)"

requirements-completed: [VAC-03]

coverage:
  - id: D1
    description: "Uma entrada criada pelo escritor real tem id, é lida do disco pelo leitor real e gera a vaccine rastreável com origin.attack_id igual ao id gravado (not_detected -> vac-940811b93421; partial -> vac-d4586b217de9), ambas com validate_vaccine == []"
    requirement: VAC-03
    verification:
      - kind: unit
        ref: "scripts/test_attack_log_ids.py#run_tracer"
        status: pass
      - kind: unit
        ref: "scripts/test_attack_log_ids.py#run_ids"
        status: pass
    human_judgment: false
  - id: D2
    description: "Ids únicos em todos os caminhos de escrita (max+1, linhas hostis ignoradas, paridade com o leitor e o registo), sem backfill, e fail-closed com espaço esgotado, log ilegível e na CLI"
    requirement: VAC-03
    verification:
      - kind: unit
        ref: "scripts/test_attack_log_ids.py#run_ids"
        status: pass
    human_judgment: false

duration: 6min
completed: 2026-10-11
status: complete
---

# Phase 12 Plan 03: Escritor do attack log grava id Summary

**`attack_scenarios.run_scenario` passa a gravar um `id` inteiro (max+1 sobre os ids válidos do próprio log, teto 999_999_999, fail-closed antes de lançar nada) em todas as entradas novas, e um teste prova o caminho escritor real -> disco -> leitor real -> registo -> motor até à vaccine validada (VAC-03).**

## Performance

- **Duration:** ~6 min
- **Started:** 2026-10-11T23:02Z (aprox.)
- **Completed:** 2026-10-11T23:10Z
- **Tasks:** 2/2 (Task 1 tracer, Task 2 auto/tdd)
- **Files:** 2 (`scripts/attack_scenarios.py` alterado, `scripts/test_attack_log_ids.py` novo)

## Accomplishments

- **Esquema do id:** `valid_attack_id` (mesma regra de `attack_registry.normalize_attack_id`: bool -> None, int entre 1 e `MAX_ATTACK_ID`), `next_attack_id(log_path)` (max+1 de todos os ids válidos de qualquer status; parsing igual ao de `load_attack_log`; inexistente -> 1) e `format_log_entry(..., attack_id=None)` (grava `id` só quando dado; id inválido levanta `ValueError`, nunca se grava). O formato antigo sem `attack_id` não muda.
- **Atribuição antes de tudo:** `run_scenario` calcula `attack_id = next_attack_id(log_path)` como primeira instrução e põe-no em `meta`, que `_fmt` espalha em todos os seis caminhos de escrita (launched, timeout, failed por ferramenta ausente, failed por exceção, skipped por argumentos em falta, skipped por alvo fora da allowlist): ids [1..6] seguidos num log novo, todos aceites por `normalize_attack_id`.
- **Fail-closed (T-12-12/13):** espaço esgotado (id 999_999_999 no log) ou log ilegível (pasta, bytes não UTF-8) levantam `AttackIdUnavailable` sem chamar `subprocess.run` e sem escrever; a mensagem não traz o caminho completo; `main()` converte em `parser.error` (código 2, nada escrito na pasta, confirmado com subprocess verdadeiro).
- **Sem backfill (T-12-14):** conteúdo antigo é prefixo exato do novo após dois lançamentos; a linha 1 continua sem id; o sha256 do `scripts/attack_log.jsonl` real é igual no início e no fim do teste (`4e95fe63...`), e o ficheiro nunca é escrito.
- **VAC-03 com dados reais:** seed (ids 3 e 9 válidos, id ausente, `true`, `"11"`, linha crua) + lançamento real mockado dá id 10; o registo marca-o `not_detected` (`scenario_default`); o motor gera `vac-940811b93421` (`missing_sensors` [rule, ml]) validada; `skipped.no_attack_id == 3`, `considered.not_detected == 6`, total 3. Com um alerta de regra 5140 a 5 s do lançamento o ataque fica `partial` (achieved [rule]) e gera `vac-d4586b217de9` (`missing_sensors` [ml], evidência `matched_event_ids [5140]`). Alvo e ferramenta da entrada nova não entram na vaccine.
- **`_self_check`:** acrescenta a verificação de que as duas chamadas a `run_scenario` num log novo têm ids 1 e 2 (`[OK   ] run_scenario grava id max+1 em cada entrada nova`), útil também na VM Kali.
- `attack_scenarios.py` continua só com stdlib (nenhum import de registo, biblioteca, motor, feature_extractor nem yaml).

## Ids golden fixados

| Caso | Chave | `vaccine_id` |
|------|-------|--------------|
| ataque 10 `not_detected` (esperado rule, ml) | `10:rule,ml` | `vac-940811b93421` |
| ataque 10 `partial` (atingido rule) | `10:ml` | `vac-d4586b217de9` |

## Task Commits

1. **Task 1 (tracer):** `071ad4f` - feat(12-03): escritor do attack log grava id (tracer até à vaccine)
2. **Task 2:** `58d4518` - feat(12-03): ids sem colisão, fail-closed e verificação na CLI

## Verification

- `cd scripts && .venv/Scripts/python -X utf8 test_attack_log_ids.py`: 59 checks `[OK   ]`, 0 `[FALHOU]`, saída 0 (`run_tracer` + `run_ids`). Tracer gate: o teste e o `--self-check` verdes antes de expandir.
- `python attack_scenarios.py --self-check`: saída 0, com a linha `grava id`.
- `python run_all_tests.py`: 41 ficheiros, 40 PASS e 1 FAIL (`test_attack_registry.py`); ver "Issues Encountered". `PASS` em `test_attack_log_ids.py`, `test_attack_targets.py` e `test_vaccine_engine.py`.
- `test_attack_registry.py` passa (0 `[FALHOU]`, saída 0) com a minha alteração sobre os `main.py`/`incident_store.py` commitados (HEAD), numa cópia fora da árvore; as suas expectativas não foram alteradas. A verificação de formato antigo sem `attack_id` (`run_scenario_writer`) continua verde.
- `scripts/attack_log.jsonl` real: sha256 igual antes e depois (`4e95fe63197fdb527409f4f8d356ec33a9149181eb30a50badb80e3f2934210e`).
- Só `scripts/attack_scenarios.py` e `scripts/test_attack_log_ids.py` tocados; nenhuma eliminação de ficheiros; sem trailer de coautor; alterações alheias da árvore de trabalho intocadas e por stagiar.

## Deviations from Plan

None - plan executed exactly as written (código e testes). O único desvio de verificação é externo ao plano: ver "Issues Encountered".

## Issues Encountered

- **`test_attack_registry.py` falha na árvore de trabalho atual por alterações alheias por commitar** (2 checks: "lista: ataque 1 com incidente ligado" e "detalhe: 200 com esperado vs real e incidentes"; `run_all_tests.py` sai com 1). Não é causado por este plano: falha igual com o `attack_scenarios.py` de HEAD; passa com o meu código sobre `main.py`/`incident_store.py` de HEAD; o culpado é o diff não commitado de `scripts/incident_store.py` (insere `assigned_to` como parâmetro posicional antes de `limit` em `list_incidents`, o que desalinha a chamada posicional `list_incidents(None, None, None, 100000, 0)` de `main.py`). Fora do âmbito (SCOPE BOUNDARY): não foi corrigido nem staged; registado em `deferred-items.md`. O critério "suite completa verde" só se cumpre depois de esse trabalho alheio ser acertado.

## Known Stubs

None.

## Known follow-ups (fora do âmbito)

- Entradas antigas sem `id` continuam em `skipped.no_attack_id` (sem backfill, por decisão do utilizador); a próxima entrada escrita no log real fica com `id` 13.
- `incident_engine.py` (linhas 200-201) passa a ligar entradas novas a incidentes pelo id numérico em vez de `target@timestamp`; incidentes já gravados não mudam. Registar para a Phase 13/14.
- `packer/kali-attacker/scripts/03-configure-attack-tools.sh` (não rastreado) tem um escritor próprio do attack log que não grava `id`; fora do âmbito do VAC-03. Se for usado no lugar de `attack_scenarios.py`, as suas entradas caem em `skipped.no_attack_id`.
- Escritor único sem lock de ficheiro (T-12-15, aceite): dois processos em simultâneo podem colidir; o registo marca `duplicate_id` e o motor salta ambos.
- Um log sem newline final faria o append colar a nova linha à anterior (comportamento pré-existente de `append_attack_log`, não alterado).
- Política para a vaccine antiga quando o id evolui (partial para not_detected) e quem chama o motor: Phase 13.
- Docs (README, CLAUDE.md: formato do attack log com `id` e contagem de testes 41): Phase 14 (VAC-08).

## Threat Flags

None - nenhuma superfície de rede/auth nova; T-12-10 a T-12-14 mitigadas pelos testes acima, T-12-15 aceite.

## Next Phase Readiness

Phase 12 completa (3/3 planos): motor puro, contrato fechado e honestidade, e id gravado pelo escritor real. Pronta para a Phase 13 (store e API de vaccines), condicionada a acertar o trabalho alheio por commitar em `incident_store.py`/`main.py` para a suite voltar a ficar toda verde.

## Self-Check: PASSED

- FOUND: scripts/attack_scenarios.py (`def next_attack_id`, `class AttackIdUnavailable`), scripts/test_attack_log_ids.py (`vac-940811b93421`, `vac-d4586b217de9`)
- FOUND commits: 071ad4f, 58d4518
