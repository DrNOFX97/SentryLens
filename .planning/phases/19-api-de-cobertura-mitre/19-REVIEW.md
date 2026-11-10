---
phase: 19-api-de-cobertura-mitre
reviewed: 2026-11-10T00:00:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - scripts/mitre_coverage.py
  - scripts/main.py
  - scripts/test_mitre_coverage.py
  - scripts/test_mitre_coverage_api.py
findings:
  critical: 0
  warning: 2
  info: 3
  total: 5
status: issues_found
---

# Phase 19: Code Review Report

**Reviewed:** 2026-11-10
**Depth:** standard
**Files Reviewed:** 4
**Status:** issues_found

## Summary

Reviewed `mitre_coverage.py` (pure module), the `get_mitre_coverage` route and `import mitre_coverage` in `main.py` (diff `e72d14f..HEAD`), and the two standalone test files. Cross-referenced `attack_registry.py`, `mitre_catalog.py` and `_build_attack_registry` / `_read_attack_log` in `main.py`.

The CLAUDE.md constraints hold:
- The route carries `dependencies=_REQUIRE_API_KEY`, and a test checks it on the route object.
- It is GET-only, and a test checks that other methods return 405.
- No exception text reaches the body. The tests plant secrets in exceptions and assert they are absent.
- No-data cases give `null`, never 0.
- The module is pure, and an AST test enforces it.

I found no security vulnerabilities or crashing bugs on the normal path. The defects are data-integrity and consistency issues around free-text technique ids, the double Indexer fetch, and defensive gaps.

## Warnings

### WR-01: Technique id from the attack log reaches the response unvalidated and is not normalised

**File:** `scripts/mitre_coverage.py:150-158` (source of the value: `scripts/attack_registry.py:154`)
**Issue:** `attack["mitre_technique"]` is `clean_text(entry.get("technique")) or scenario.mitre_technique`. The `technique` field comes from the operator-written `attack_log.jsonl`. It is any string up to `MAX_FIELD_LEN`, with control characters stripped.

`build_mitre_coverage_report` uses it as a row key without checking the `Txxxx[.xxx]` format. Two consequences:
1. Free text such as `"Brute Force"` becomes `id` of an `unmapped[]` row. `test_mitre_coverage.py:108-111` asserts this behaviour on purpose. A consumer that renders `id` raw would be exposed, because the Phase 20 frontend must escape it. `/api/attacks` validates `technique` with `^T\d{4}(\.\d{3})?$`, but this route does not.
2. Case or whitespace variants such as `"t1110"` or `"T1110 "` (trailing space) are not folded into `T1110`. Coverage of the real technique is silently split, and `T1110` can look un-exercised, with `launched: 0`, while a stray row holds the attacks.

**Fix:** Normalise before counting. Keep non-conforming values visible without using them as an id:
```python
import re
_TID = re.compile(r"T\d{4}(\.\d{3})?")

tid = str(attack["mitre_technique"]).strip().upper()
if not _TID.fullmatch(tid):
    invalid_attacks += 1           # report as totals.attacks_without_valid_technique
    _add_attack(unique, verdict)   # still count in the unique total
    continue
```
Alternatively, reuse `mitre_catalog.TECHNIQUE_RE`. Either way, add a test with `"t1110"` and `"Brute Force"`, and update the existing test that blesses free-text ids.

### WR-02: Two independent Indexer fetches give contradictory truncation and availability in one response

**File:** `scripts/main.py:1865-1892` (route) with `scripts/main.py:1745-1790` (`_build_attack_registry`)
**Issue:** The route calls `indexer_client.get_recent_alerts(...)` itself. Then `_build_attack_registry` calls it again for the same window. These are two snapshots taken at different moments.

The response therefore carries two truncation flags: the top-level `alerts_truncated` from fetch A, and `sources.attacks.correlation.alerts_truncated` from fetch B. They can disagree, as can `sources.alerts.available` and `sources.attacks.correlation.available`. Example: the Indexer fails or returns a different count between the calls. The alert counts then come from one data set and the `detected/not_detected` verdicts from another.

The two fetches also double the Indexer load per request (2 x 8000 documents). D-09 allowed this trade-off. It did not ask for the inconsistency to be hidden, and nothing documents it.

**Fix:** Either reuse the fetch (changing `_build_attack_registry` to accept optional pre-fetched `raw_alerts`, while keeping the source-isolation behaviour), or document in the docstring and in `docs/API.md` that the two flags are independent snapshots. A test should cover the case where fetch A succeeds and fetch B fails (`side_effect=[alerts, RuntimeError]`). The current tests only cover "always fails" and "always succeeds".

## Info

### IN-01: `attack["mitre_technique"]` is indexed directly, outside the source-isolation `try`

**File:** `scripts/mitre_coverage.py:151`
**Issue:** `_verdict_of` is defensive (`isinstance`, `.get`), but `attack["mitre_technique"]` raises `KeyError` if a malformed attack dict arrives. `build_mitre_coverage_report` runs after both `try` blocks, so the failure would be an HTTP 500, contradicting "never 500 because of a source". Today `build_attack_registry` always sets the key, so the problem is latent.
**Fix:** Use `attack.get("mitre_technique")` and route non-str/missing values through the same path as WR-01.

### IN-02: Broad `except Exception` turns programming errors into `source_unavailable`; the exception is logged twice

**File:** `scripts/main.py:1873-1892`
**Issue:** The second `try` wraps `_read_attack_log`, `_build_attack_registry` and the window filter. A `TypeError` or `KeyError` bug in the registry is reported to clients as "attacks source unavailable", the same as a real outage. It is also logged only at `warning`. `_read_attack_log` already calls `logger.exception`, so the I/O failure case logs the traceback twice. The isolation is the intended design (D-07).
**Fix:** Log at `error` level for non-OSError types, or narrow the handler to `(HTTPException, OSError, sqlite3.Error)`. Drop the duplicate `exc_info`.

### IN-03: Hardcoded correlation reason codes duplicated from `main.py`, with no drift guard; window filter copy-pasted

**File:** `scripts/mitre_coverage.py:51`, `scripts/main.py:1883-1887`
**Issue:**
- `CORRELATION_REASONS` repeats the literals `indexer_unavailable`, `ml_model_unavailable` and `attack_outside_alert_window`, which `_build_attack_registry` sets in `main.py`. The tests only check each literal against the same literal. If `main.py` adds or renames a code, `mitre_coverage` silently maps it to `correlation_unavailable`, and no test fails.
- The cutoff and `incident_engine_parse(...) >= cutoff` filter is now repeated here and in `list_attacks` (`main.py:1812-1815`).

**Fix:** Define the codes once, for example in `attack_registry.py`, and import them in both places. Extract a helper `_attacks_in_window(registry, hours)` in `main.py`. Add a test that drives `_build_attack_registry` through each failure mode and asserts the reason is not `correlation_unavailable`.

---

_Reviewed: 2026-11-10_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
