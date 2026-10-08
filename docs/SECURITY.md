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
- A API key **não** está no `app.js`: o frontend lê-a de `/config.js`, gerado por
  `serve_frontend.py` a partir de `scripts/.env`. `/config.js` é fail-closed: só
  responde com `Sec-Fetch-Site: same-origin` ou, sem esse cabeçalho (browsers
  antigos), com `Referer` do mesmo origin — para uma página noutro separador
  não a ler via `<script src>` (ao estilo JSONP) — e todos
  os pedidos com `Host` fora de loopback levam 421 (DNS rebinding). Testes em
  `test_serve_frontend.py`.
- `scripts/.env`, `models/`, `historico/`, `attack_log.jsonl` fora do git.
- `attack_scenarios.py` redige passwords nos logs de comando.
- `/api/attacks*` (R4) é só leitura, sem path nem ficheiro vindos do cliente: `{id}` valida-se com `^[0-9]{1,9}$`, `technique` com regex, o log lê-se sempre de `ATTACK_LOG_PATH`; erros viram códigos estáveis (`indexer_unavailable`...) e o detalhe só vai para o log do servidor. `operator`/`source` são texto livre do log: o frontend escapa-os e a API limpa controlos e trunca a 64 caracteres. Não há rota POST: forjar ataques falsearia cobertura/MTTD.
- **Allowlist de alvos (R5), fail-closed, imposta em `attack_scenarios.py`**
  (único lugar que lança ataques — o backend nunca executa nada, ver abaixo):
  por omissão só loopback e os blocos de documentação RFC 5737/3849/4291
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) são
  aceites; qualquer outro alvo (ex. um IP real do laboratório `192.168.x.x`)
  é recusado com uma mensagem clara, sem lançar nada. Allowlist real via
  `ATTACK_TARGETS_PATH` (ou `scripts/attack_targets.json`, gitignored) a
  partir de `attack_targets.example.json` (só IPs de documentação); ficheiro
  configurado ilegível/inválido é erro, nunca ignorado em silêncio. Hostnames
  nunca são resolvidos (evita TOCTOU/DNS): só entram se constarem
  explicitamente em `allowed_hosts`. `--allow-any-target` é o override
  explícito para quem sabe que o alvo é do laboratório. **Compatibilidade**:
  isto é uma mudança de comportamento — qualquer fluxo anterior que já
  apontasse `--target` para um IP real do laboratório (`192.168.x.x`) passa a
  ser recusado por omissão a partir desta versão; usa
  `ATTACK_TARGETS_PATH`/`attack_targets.json` ou `--allow-any-target` para
  continuar a lançar contra esse alvo. Testes em `test_attack_targets.py`.
- **Attack Library (R5)**: catálogo de referência só-leitura
  (`scripts/attack_library.yaml`), nunca um executor — estruturalmente, não só
  por convenção: (1) só rotas `GET`, sem `POST`/`PUT`/`DELETE` nesta fase nem
  previstas (uma eventual execução a partir do dashboard é uma fase própria,
  com o seu próprio desenho de autorização/allowlist/auditoria, fora de
  âmbito aqui); (2) o YAML nunca contém uma `list[str]` pronta para
  `subprocess.run` nem um comando shell montado, só `cleanup_steps` em prosa —
  os comandos reais continuam só em `attack_scenarios.py::build_command`;
  (3) a API desta fase serve apenas o que está no YAML + os campos
  MITRE/ferramenta/Event IDs já existentes em `SCENARIOS`, nunca
  `build_command`/argv. `{id}` valida-se com `^[a-z_]{1,64}$`; 404 devolve o
  código estável `entry_not_found`. Sem IPs/credenciais reais no YAML
  (confirmado por inspeção: só texto descritivo). Validação de schema
  fail-fast e síncrona no arranque do backend: um YAML inválido/incoerente
  impede o processo de arrancar em vez de servir uma biblioteca corrompida.
- **Network SOC (R6)**: as 3 rotas novas (`/api/network/live-traffic`,
  `/api/network/detections`, `/api/network/evidence`) são `GET`, exigem
  `X-API-Key`, e não expõem nada que `/api/redblue/network` (Fase 11) já não
  expusesse — mesmos IPs/portas dos pacotes capturados, já públicos a quem
  tem a API key. `GET /api/network/evidence` nunca devolve mais de 500
  entradas: `limit` é validado por `Query(..., ge=1, le=500)` em `main.py` **e**
  capeado outra vez dentro de `history_store.read_network_detection_history`
  (não confia só no parâmetro HTTP) — impede um pedido de forçar a leitura
  de um ficheiro de evidência arbitrariamente grande. `date` é validado por
  regex (`^\d{4}-\d{2}-\d{2}$`) antes de tocar no filesystem, e
  `history_file_path`/`datetime.strptime` rejeitam datas malformadas sem
  construir um path fora do diretório esperado — sem risco de path
  traversal. A evidência persistida é só metadados (tipo/origem/destino/
  detalhe) — nunca payload, nunca um dump PCAP real (confirmado por leitura
  de `network_monitor._parse_fields_line`: só 11 campos de cabeçalho
  tshark); `payload_capture: false` é sempre explícito na resposta, nunca
  implícito.

- **Detection Engine (R7)**: `GET /api/detections` é `GET`, exige
  `X-API-Key`, e não expõe nada de novo — reaproveita exatamente os dados já
  servidos por `/api/alerts`, `/api/ml-anomalies` e
  `/api/network/detections`, só normalizados e combinados. `hours`
  (`Query(..., ge=1, le=168)`) e `limit` (`Query(..., ge=1, le=200)`) nunca
  ficam sem teto — sem paginação por cursor, pensado só para "vista recente",
  não para varrer histórico. O dado bruto de origem (`ref` em
  `DetectionEvent`) é explicitamente removido da resposta HTTP antes de
  devolver (`event.pop("ref", None)` em `main.py`) — nunca viaja para o
  cliente. Uma fonte em baixo (Indexer, modelo ML ausente, `VM_SSH_HOST` não
  configurado) nunca derruba as outras: `available: false` isolado por
  fonte, nunca 500 — superfície de erro mais previsível que
  `/api/ml-anomalies`/`/api/redblue/metrics` (fonte única, podem dar
  502/503). Sem painel frontend nesta fase (ver `docs/ROADMAP_STATUS.md`):
  menos superfície nova no cliente para esta rota, por agora.

## Riscos conhecidos

- API key na query string dos WebSockets pode aparecer em logs/histórico.
- Um processo local que forje `Referer`/`Host` (curl, extensão de browser)
  ainda obtém `/config.js`; aceitável num PC de laboratório de um só
  utilizador, onde esses processos já conseguem ler `scripts/.env`. Alternativa
  mais forte, não adotada: servir a chave como JSON e lê-la com `fetch()`
  (a política same-origin bloqueia a leitura cross-origin sem depender de
  cabeçalhos), o que obriga a tornar assíncrono o arranque de `app.js`/`redblue.js`.
- Uma só chave global: sem papéis nem rate limiting.
- `joblib.load` (pickle) só é seguro com artefactos locais; reavaliar quando
  existir model registry/treino automático (R9–R10).
- Um segredo esteve no histórico git (removido): confirmar que a chave foi
  **rodada**; reescrever histórico não revoga uma chave já publicada.
- `WAZUH_VERIFY_SSL=false` por omissão (certificado autoassinado do lab).
- Credenciais da VM apareceram em texto em sessões anteriores: mudar e passar
  a autenticação por chave.
