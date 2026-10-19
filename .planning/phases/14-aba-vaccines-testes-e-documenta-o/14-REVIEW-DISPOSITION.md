---
phase: 14
review: 14-REVIEW.md
titles: json
findings:
  - id: WR-01
    severity: warning
    disposition: open
    title: "Código morto (`vacCodeFromResponse`/`VAC_CODE_RE`) mascara o caminho de erro real, e a guarda do contrato testa o código morto em vez do vivo"
  - id: WR-02
    severity: warning
    disposition: open
    title: "O estado de erro da tabela fica com uma caixa dupla, inconsistente com os estados vazio/a carregar da mesma tabela"
  - id: WR-03
    severity: warning
    disposition: open
    title: "README.md, CLAUDE.md e docs/ROADMAP_STATUS.md continuam a descrever o rótulo de menu \"💉 Candidates\", que já não existe no index.html servido"
  - id: IN-01
    severity: info
    disposition: open
    title: "Comentário de cabeçalho de vaccines.js desatualizado desde a própria Fase 14"
  - id: IN-02
    severity: info
    disposition: open
    title: "O regex de attack_id do frontend é mais estrito do que a validação do backend"
  - id: IN-03
    severity: info
    disposition: open
    title: "vaccines.js mantém o seu próprio ciclo de vida de aba (MutationObserver) em vez do router.js partilhado"
open: 6
total: 6
recorded: 2026-10-19T15:05:41.310Z
---

# Phase 14: Code Review Disposition

| Finding | Severity | Disposition | Source |
|---------|----------|-------------|--------|
| WR-01 | warning | open | - |
| WR-02 | warning | open | - |
| WR-03 | warning | open | - |
| IN-01 | info | open | - |
| IN-02 | info | open | - |
| IN-03 | info | open | - |

Dispositions: `open` (recorded, not yet triaged), `fixed`, `skipped`, `deferred`.
Set `deferred` by hand and put the reason in the Source cell; both are preserved. A `|` in the reason is kept as prose and escaped on the next run.
Re-running the gate keeps every row it can. A row the current review no longer reports is kept and its Source cell flagged, so a finding does not leave this record silently. ONE exception: when a finding id is REUSED by a different finding, the earlier decision cannot keep a row — the id is taken — and it is dropped. A RECORDED decision (anything but `open`) is named on the console when that happens; a row still at `open` is replaced silently, because `open` records no decision to lose.
