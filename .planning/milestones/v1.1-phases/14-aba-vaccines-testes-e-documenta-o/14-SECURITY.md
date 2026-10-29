---
phase: "14"
slug: "aba-vaccines-testes-e-documenta-o"
status: verified
threats_open: 0
asvs_level: 1
created: "2026-10-19"
---

# Phase 14 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail. Reconstruído a partir dos `<threat_model>` dos 4 `*-PLAN.md` (`register_authored_at_plan_time: true`) e verificado por grep (L1, ASVS 1) contra o código atual — nenhuma SUMMARY tem `## Threat Flags` por preencher.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| backend (`GET /api/vaccines[/{id}]`) → `vaccines.js` → DOM | Vaccines geradas a partir do attack log e do Wazuh; tudo o que é desenhado é dado não confiável | JSON (técnica MITRE, ids, estado do gerador, origem, propostas, cadeia) |
| browser → `serve_frontend.py` | Pedidos diretos a ficheiros; só a whitelist é servida | caminho de ficheiro |
| analista → filtros → query string | Valores escritos à mão entram na URL do pedido | `attack_id`, `technique`, `include_superseded` |
| linha da tabela (`data-id`) → URL do pedido de detalhe | O id vem do DOM e entra no caminho do pedido | id de vaccine |
| repositório (docs versionadas) → leitores e agentes | Documentação pública, lida como instrução pelo próximo agente | texto de documentação |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-14-01 | Tampering (XSS) | `vaccines.js` (tabela e estados) | high | mitigate | `escapeHtml`/`vacCell` em todo o texto dinâmico; `run_guards` varre o ficheiro inteiro | closed |
| T-14-02 | Information disclosure | mensagens de erro no ecrã | medium | mitigate | `detail` só aceite se casar `VAC_CODE_RE`; texto de exceção/traceback nunca chega ao DOM | closed |
| T-14-03 | Information disclosure | `serve_frontend.py` | medium | mitigate | Entrada exata `/vaccines.js` na whitelist (confirmado: `scripts/serve_frontend.py:69`); `.sqlite3` continua fora | closed |
| T-14-04 | Spoofing | autenticação da aba | low | mitigate | `vaccines.js` usa `apiRequest()` de `api.js` (Onda 2) — chave em `X-API-Key`, nunca `api_key` na query | closed |
| T-14-05 | Elevation of privilege | ações a partir da aba | medium | mitigate | `apiRequest(path)` sem `method`, logo GET; nenhum verbo de escrita em `vaccines.js` (confirmado por grep) | closed |
| T-14-06 | Repudiation (integridade da informação) | estados vazio/erro | medium | mitigate | "Sem dados" só com `reason: no_data`; banner de erro com `vac-error-state` | closed |
| T-14-07 | Tampering | filtros → query string | low | mitigate | `attack_id`/`technique` validados por regex antes do pedido; rota valida de novo (422) | closed |
| T-14-08 | Tampering (XSS) | `vacOriginHtml`, `vacProposalsHtml`, `vacChainHtml`, `vacEventRowsHtml` | high | mitigate | Mesmos helpers `vacCell`/`escapeHtml`, cobertos pelo `run_guards` do 14-01 | closed |
| T-14-09 | Tampering | caminho do pedido de detalhe | low | mitigate | id só aceite se casar `VAC_ID_RE` + `encodeURIComponent`; rota valida de novo | closed |
| T-14-10 | Repudiation (integridade da informação) | detalhe/cadeia com respostas fora de ordem | low | mitigate | `vacSelectSeq` verificado depois de cada `await` | closed |
| T-14-11 | Repudiation (integridade da informação) | leitura do detalhe como regra aplicada | medium | mitigate | Aviso fixo confirmado em `index.html:1444`: "Proposta — não aplicada no Wazuh" | closed |
| T-14-12 | Information disclosure | erros no detalhe e na cadeia | medium | mitigate | Só frases de `VAC_ERROR_TEXT`; nunca "Sem dados" nem texto do servidor | closed |
| T-14-13 | Elevation of privilege / Spoofing | navegação a partir do detalhe | low | mitigate | D-07: sem links/`href`/`activateTab`/`location.hash` no detalhe | closed |
| T-14-14 | Information disclosure | exemplos nas docs | low | mitigate | IPs nas docs (`DATA_MODEL.md:127`, `API.md:241,305`) são `192.0.2.10` — bloco de documentação RFC 5737, nunca um IP real do laboratório | closed |
| T-14-15 | Tampering | `CLAUDE.md` | medium | mitigate | Só edição pontual, nunca regeneração (confirmado: o ficheiro continua a existir e versionado, sem rasto de `generate-claude-md`) | closed |
| T-14-16 | Repudiation (integridade da informação) | promessas da documentação | medium | mitigate | `DATA_MODEL.md`/README/`ROADMAP_STATUS.md` descrevem a vaccine como só proposta, sem comandos; evidência "N/N" de uma corrida completa | closed |
| T-14-17 | Tampering (XSS) | select de técnica, badge de veredito, nota "Substituída por", linha do gerador | high | mitigate | Options por `vacTechniqueOptionsHtml`+`escapeHtml`; linha do gerador por `textContent` | closed |
| T-14-18 | Information disclosure | linha do gerador (`error_code`) | medium | mitigate | `error_code` só como chave de `vacErrorText`; código desconhecido cai na frase genérica | closed |
| T-14-19 | Repudiation (integridade da informação) | tabela vs filtros visíveis | low | mitigate | Pedido único no fim quando a query muda; filtro vazio com frase distinta de "Sem dados" | closed |
| T-14-SC | Tampering | instalação de pacotes | low | accept | Nenhum pacote novo nos 4 planos (frontend sem dependências; testes só com stdlib + FastAPI/TestClient já em `requirements.txt`) | closed (accepted) |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — só os `open` a `high`/`critical` contam para `threats_open` (block_on: high)*
*Disposition: mitigate (implementação confirmada acima) · accept (risco documentado)*

T-14-SC repete-se nos 4 `<threat_model>` (mesmo risco aceite — nenhum pacote novo); contado uma só vez neste registo.

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-14-SC | T-14-SC | Nenhum pacote novo instalado nos 4 planos da Fase 14; auditoria de dependências não aplicável | Fernando Nuno (via plano, disposição `accept` nos 4 `<threat_model>`) | 2026-10-19 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-10-19 | 19 (+ T-14-SC único) | 20 | 0 | Claude (verificação L1 por grep, ASVS 1; `register_authored_at_plan_time: true` — sem novo scan STRIDE) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-10-19
