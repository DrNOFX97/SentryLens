# Phase 19: API de cobertura MITRE - Pattern Map

**Mapped:** 2026-11-10
**Files analyzed:** 4 (3 new, 1 modified)
**Analogs found:** 4 / 4

All analog paths verified git-tracked (`mitre_catalog.py`, `attack_registry.py`, `soc_metrics.py`, `test_metrics_api.py`; `main.py` is the tracked modified file).

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `scripts/mitre_coverage.py` (new) | service (pure report builder) | transform | `scripts/soc_metrics.py` | exact |
| `scripts/main.py` (modify: route `GET /api/mitre/coverage`) | route | request-response, isolated sources | `/api/attacks` (~1799) + `/api/metrics` (~1414) | exact |
| `scripts/test_mitre_coverage.py` (new, pure unit) | test | transform | `scripts/test_attack_registry.py` | role-match |
| `scripts/test_mitre_coverage_api.py` (new, route) | test | request-response | `scripts/test_metrics_api.py` | exact |

Not touched: `mitre_catalog.py`, `attack_registry.py` (read-only consumers). No new frontend file or `serve_frontend.py` change in this phase (Phase 20). No CORS change (GET only).

## Pattern Assignments

### `scripts/mitre_coverage.py` (pure `build_mitre_coverage_report`)

**Analog:** `scripts/soc_metrics.py`

**Module style** (lines 1-22): docstring explaining honesty rules (sem amostra = None, nunca 0; fonte em baixo -> `reason="source_unavailable"`), `from __future__ import annotations`, no I/O, stdlib + sibling imports only.
```python
from __future__ import annotations
from incident_engine import OPEN_STATUSES, parse_timestamp
```
For this module import: `from mitre_catalog import load_mitre_techniques, parent_of, tactics_for, resolve_alert_techniques, ENTERPRISE_TACTICS, SOURCE_WAZUH, SOURCE_CATALOG`.

**Source-down block shape** (`soc_metrics.py` ~76-78, 154, 229):
```python
block["reason"] = "source_unavailable"
return {"available": False, "reason": "source_unavailable", "n": 0, ...}
```
Reuse the shape for `sources = {"alerts": {"available", "reason"}, "attacks": {...}}`. Only stable codes, never exception text.

**Inputs from mitre_catalog** (`mitre_catalog.py`):
- `resolve_alert_techniques(raw, table=None) -> [{"id","source","tactics"}]` (line 275); source is `"wazuh"` or `"catalog"`; id returned exactly as received (`T1078.002` stays).
- `parent_of(tid)` (line 230): `'T1053.005'->'T1053'`, invalid -> `None`.
- `tactics_for(tid, table)` (line 238): own entry -> parent -> `[]`; always a new list.
- `load_mitre_techniques()` returns `{id: {"id","name","tactics": tuple}}` (lines 201-207). Pass the `table` in explicitly to the pure function so tests can inject.
- `ENTERPRISE_TACTICS` (line 49) is the ordered 14-tactic tuple for `tactics[]`.

**Inputs from attack_registry** (`attack_registry.py` 148-171): each attack has `mitre_technique`, `technique_source`, `actual.verdict` (`detected|partial|not_detected|unknown`). `summarize()` at 193-197 shows the counting idiom:
```python
counts = {v: 0 for v in VERDICTS}
for attack in attacks:
    counts[attack["actual"]["verdict"]] += 1
return {"total": len(attacks), **counts}
```

**Core logic to implement (from decisions):**
- Signature suggestion: `build_mitre_coverage_report(attacks, raw_alerts, table, hours, *, attacks_available, alerts_available, alerts_truncated)`; `attacks`/`raw_alerts` may be `None` when the source is down.
- Per-id rows (D-02, amended 2026-11-10): count exact ids; "detetado" is only the registry `detected` verdict counted on the attack's exact id (D-04), with no cross-matching by technique or by parent; `parent_of` is used only for tactic inheritance and the row's `parent` field; do not sum parent and child.
- `rate = detected / (detected+partial+not_detected)`, `None` if denominator 0 (D-05); `unknown` counted separately; `launched` includes unknown (D-06).
- Techniques with `tactics_for(...) == []` go to `unmapped[]` (D-03); table techniques with zero counts still appear in `techniques[]` (D-01).
- Multi-tactic technique counts in every tactic (D-10); also return unique totals.
- Alerts down -> alert counts `None` (D-08); attacks down -> attack counts `None`; never 0.
- Sort `techniques[]` by id.

---

### `scripts/main.py` — route `GET /api/mitre/coverage`

**Analog:** `/api/attacks` (lines 1799-1828), helpers at 1736-1796, and `/api/metrics` (1414-1461) for the isolated-source `try/except` style.

**Constants and helpers to reuse** (do not redefine):
```python
ATTACK_ALERTS_SIZE = 8000   # line 1736
ATTACK_MAX_HOURS = 720      # line 1737
_REQUIRE_API_KEY = [Depends(require_api_key)]  # line 226
async def _build_attack_registry(attack_log, hours) -> (registry, correlation, incidents_available)  # 1744
async def _read_attack_log() -> list   # 1791; raises HTTPException(500) on OSError
```

**Route signature/validation pattern** (1799-1806):
```python
@app.get("/api/attacks", dependencies=_REQUIRE_API_KEY)
async def list_attacks(
    hours: int = Query(168, ge=1, le=ATTACK_MAX_HOURS, description="Janela temporal ..."),
```
New route: `hours: int = Query(168, ge=1, le=ATTACK_MAX_HOURS)`. Place it after the `/api/attacks` block (~1855), before Attack Library.

**Window filter on attacks** (1810-1814):
```python
cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
in_window = [a for a in registry["attacks"]
    if (ts := incident_engine_parse(a["timestamp"])) is not None and ts >= cutoff]
```

**Isolated source pattern** (`/api/metrics` 1425-1452): wrap each source in `try/except Exception: logger.warning(..., exc_info=True)`, leave the variable `None`, and let the pure builder emit `reason: "source_unavailable"`. Never 500 for a down source; exception text only in the log.
```python
try:
    ...
except FileNotFoundError:
    logger.warning("GET /api/metrics: modelo ML em falta — ...")
except Exception:
    logger.warning("GET /api/metrics: falha na fonte Red vs Blue", exc_info=True)
```

**Source mapping (important):**
- `_build_attack_registry` swallows Indexer/ML failures itself and reports them in `correlation["error_code"]` (`indexer_unavailable`, `ml_model_unavailable`, `attack_outside_alert_window`) and `correlation["available"]`. It does NOT return raw alerts. For the alerts source (D-07) do a separate `await indexer_client.get_recent_alerts(hours=hours, size=ATTACK_ALERTS_SIZE, exclude_infra_noise=True)` in its own `try/except` (copy 1764-1768), with `alerts_truncated = len(raw_alerts) >= ATTACK_ALERTS_SIZE` (copy 1772). Registry-vs-alerts isolation takes priority over saving the request (D-09).
- `_read_attack_log()` raises `HTTPException(500)`; in this route catch it (and `HTTPException`) to turn into `attacks` source unavailable instead of 500.
- A registry with ML model missing still returns attacks with verdict `unknown` — attacks stay `available`.
- `incidents_available` is returned but irrelevant to counts; do not surface it as a source.

---

### `scripts/test_mitre_coverage_api.py` (route test)

**Analog:** `scripts/test_metrics_api.py` (lines 1-90)

**Header/boilerplate to copy verbatim** (lines 9-32):
```python
import os, sys, tempfile
from unittest.mock import AsyncMock, MagicMock
os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")  # BEFORE import main
from fastapi.testclient import TestClient
import main
main.app.router.on_startup.clear()
failures: list[str] = []
def check(label, condition):
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition: failures.append(label)
```

**Wiring/mocking pattern** (lines 64-80):
```python
main.indexer_client = MagicMock()
main.indexer_client.get_recent_alerts = AsyncMock(side_effect=RuntimeError("indexer em baixo"))  # or return_value=[...]
main.ml_anomalies.load_model = lambda _dir: (None, None)
main.ml_anomalies.build_ml_anomalies_report = lambda alerts, model, scaler: {"results": [...]}
main.load_attack_log = lambda _path: [RECENT_ATTACK, ...]
main.vm_ssh_client = None
```
Attack fixture: `{"timestamp": iso(-3600), "scenario": "brute_force_rdp", "target": ..., "tool": "hydra", "status": "launched", "details": {}}`. Also set `main.incident_store` to a temp `IncidentStore` (see `make_store`, lines 54-61) or mock it.

**Cases to cover:** no key -> 401; `hours=0` and `hours=721` -> 422; default 168; Indexer down -> alerts `available false/source_unavailable` + attack counts present with `unknown`; attack log unreadable -> attacks unavailable, alerts present; both ok; alerts `None` counts never 0; `alerts_truncated` at >= 8000; no exception text in body; PUT/POST -> 405; sub-technique vs parent crossing; multi-tactic counted in each tactic; `unmapped[]`; `rate` None on denominator 0. End with `sys.exit(1 if failures else 0)` (see tail of any `test_*_api.py`).

### `scripts/test_mitre_coverage.py` (pure unit)

**Analog:** `scripts/test_attack_registry.py` (standalone, same `check()` helper, no `TestClient`). Call `build_mitre_coverage_report` directly with injected `table` (as `load_mitre_techniques(..., scenarios=, catalog=)` allows injection) and hand-built attack dicts using the registry shape (`mitre_technique`, `actual.verdict`). Register automatically: `run_all_tests.py` globs `test_*.py`.

## Shared Patterns

### API key per route
**Source:** `scripts/main.py:226` and every route. **Apply to:** new route
```python
@app.get("/api/mitre/coverage", dependencies=_REQUIRE_API_KEY)
```

### Stable error codes, no exception text
**Source:** `main.py:1759-1768`, `soc_metrics.py` `source_unavailable`. Log with `logger.exception(...)`/`logger.warning(..., exc_info=True)`; response carries only `reason: "source_unavailable"`.

### Null instead of zero
**Source:** `soc_metrics.py` header contract; CLAUDE.md "Sem dados". Applies to every count/rate of an unavailable source and to rate with empty denominator.

### Truncation flag
**Source:** `main.py:1772` `alerts_truncated=len(raw_alerts) >= ATTACK_ALERTS_SIZE`.

### Standalone tests
No pytest; `[OK]`/`[FALHOU]`, `sys.exit(1)` on failure, `SENTRYLENS_API_KEY` set before `import main`, `main.app.router.on_startup.clear()`.

## No Analog Found

None. (The per-tactic/per-technique aggregation with multi-valued tactics has no existing analog; derive it from D-10/D-11 using `ENTERPRISE_TACTICS` ordering.)

## Metadata

**Analog search scope:** `scripts/main.py`, `mitre_catalog.py`, `attack_registry.py`, `soc_metrics.py`, `test_*api*.py`, `test_attack*.py`
**Pattern extraction date:** 2026-11-10
