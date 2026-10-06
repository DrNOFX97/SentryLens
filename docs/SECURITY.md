# Segurança (estado em 2026-10-06)

Âmbito: laboratório local autorizado. Revisão completa prevista em R22.

## Em vigor

- Todas as rotas REST `/api/*` exigem `X-API-Key` (`SENTRYLENS_API_KEY`),
  fail-closed, aplicada **por rota** (uma rota nova tem de a incluir),
  comparação com `secrets.compare_digest`.
- WebSockets autenticam por query param `?api_key=` dentro do endpoint.
- CORS restrito a `localhost`/`127.0.0.1`; `/docs`, `/redoc`, `/openapi.json`
  desligados.
- Frontend servido por `serve_frontend.py` (whitelist fixa, só 127.0.0.1) — não
  usar `python -m http.server` na raiz (expõe `scripts/.env`).
- `API_KEY` no `app.js` está vazia no repositório; preenche-se localmente.
- `scripts/.env`, `models/`, `historico/`, `attack_log.jsonl` fora do git.
- `attack_scenarios.py` redige passwords nos logs de comando.
- Cada ataque lançado é registado com timestamp/target. **Não** está imposto em código que o target seja do laboratório (`--target` aceita qualquer valor): é convenção — allowlist de targets prevista em R4/R5.

## Riscos conhecidos

- API key na query string dos WebSockets pode aparecer em logs/histórico.
- Uma só chave global: sem papéis nem rate limiting.
- `joblib.load` (pickle) só é seguro com artefactos locais; reavaliar quando
  existir model registry/treino automático (R9–R10).
- Um segredo esteve no histórico git (removido): confirmar que a chave foi
  **rodada**; reescrever histórico não revoga uma chave já publicada.
- `WAZUH_VERIFY_SSL=false` por omissão (certificado autoassinado do lab).
- Credenciais da VM apareceram em texto em sessões anteriores: mudar e passar
  a autenticação por chave.
