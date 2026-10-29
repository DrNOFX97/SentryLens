# Phase 13: Store e API de leitura - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-10-12
**Phase:** 13-store-e-api-de-leitura
**Areas discussed:** Quem escreve e quando, Tecnologia do store, Id que evolui, Forma da API de leitura

---

## Quem escreve e quando

| Option | Description | Selected |
|--------|-------------|----------|
| Loop de background | Task no startup, GET só lê | ✓ |
| Uma vez no arranque | Ataques novos só após reinício | |
| Comando CLI manual | Escreve fora do processo | |

Cadência: intervalo fixo ~5 min ✓ (alternativas: após cada ataque novo; Claude decide).

---

## Tecnologia do store

| Option | Description | Selected |
|--------|-------------|----------|
| SQLite | PK + INSERT OR IGNORE + CHECK | ✓ |
| JSONL append-only | Dedup por varrimento | |

Caminho: `scripts/vaccines.sqlite3` + env ✓ (alternativa: dentro de `historico/`).

---

## Id que evolui

| Option | Description | Selected |
|--------|-------------|----------|
| Fica, com `superseded_by` | Metadado, estado continua proposed | ✓ |
| Fica, sem ligação | Duas independentes | |
| É apagada | Deixa de ser append-only | |

Ataque que passa a detected: vaccine mantém-se intacta ✓ (alternativa: flag `stale`).

---

## Forma da API de leitura

| Option | Description | Selected |
|--------|-------------|----------|
| limit/offset + filtros | attack_id, technique, include_superseded | ✓ |
| Só limit/offset | Filtros no frontend | |

Erros: 200 + `reason` estável para vazio, 503 `store_unavailable` ✓ (alternativas: tudo 200; 502).

---

## Claude's Discretion

Esquema de colunas, nomes de env/módulo, forma do estado do loop, regex do id.

## Deferred Ideas

Estados resolved/stale e aplicar no Wazuh (R12+); janela por cenário; aba Vaccines (Fase 14).
