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
  502/503). O painel Detections (`detections.js`, botão `data-tab="detections"`
  sem `is-planned`) só consome esta rota — nenhuma superfície de rede nova
  para o browser.
- **Registo de modelo ML (R9 + R10)**: `/api/ml/models` continua `GET` e exige
  `X-API-Key`. A **escrita por HTTP existe desde o R10** e vive em duas rotas
  novas — `POST /api/ml/train` e `POST /api/ml/models/{version_id}/activate`
  —, não neste endpoint. As quatro protecções que fecham a superfície nova
  (D-01, ver `.planning/phases/10-ml-learning-loop/10-CONTEXT.md`):

  1. **Nenhum caminho vem do corpo**. O `dataset` é um `Literal` de um catálogo
     fechado que o servidor resolve (`ml_training.resolve_export_path`), e o
     registo é sempre o `ML_MODEL_DIR` lido a nível de módulo.
  2. **Um só treino (e uma só activação) a cada vez** — `ml_training._slot()`,
     que responde 409 a quem chega enquanto a outra corre.
  3. **Três tetos no corpo** (`contamination 0.01–0.5`, `random_state
     0–2³²−1`, `n_estimators 10–1000`), testados pelos dois lados.
  4. **`extra="forbid"`** no modelo Pydantic — sem isto, o Pydantic v2 ignora
     chaves extra e o utilizador acreditaria ter escolhido o sítio.

  O que **não** fecha: a chave continua a ser global e sem papéis. Quem a tem
  passa a poder escrever em `models/` — e o SHA-256 dos `.pkl` deixa de ser uma
  defesa e passa a ser um detector de corrupção. Isso é o risco residual que
  D-08 manda escrever aqui: **quem tem a API key passa a ter escrita em
  `models/`**, treinar, activar e recarregar a cache. HMAC/assinatura ficaram
  fora do âmbito do R10.

  O carregamento do `.pkl` só acontece depois da verificação de integridade:
  `resolve_active_artifacts` / `resolve_version_artifacts` devolvem os dois
  artefactos **juntos** ou nada, e `read_verified_bytes` lê cada ficheiro uma
  única vez, calcula o SHA-256 sobre esses mesmos bytes e devolve-os —
  `joblib.load` recebe exactamente os bytes verificados, logo não há janela
  TOCTOU entre verificar e carregar. Um `.pkl` em falta ou adulterado dá
  `hash_mismatch`/`artifact_missing` e a rota `/api/ml-anomalies` responde 503
  em vez de carregar. Um `ACTIVE` inválido é fail-closed: não cai para o
  legado. Todo o dado do disco é tratado como não confiável — o id de versão
  tem de casar com `v[0-9]{1,4}` **e** resolver para uma pasta filha direta de
  `models/`, os nomes dos artefactos vêm da constante `ARTIFACT_FILES` (nunca
  do `metadata.json`, logo nenhum caminho é construído a partir de dados do
  disco), `ACTIVE` tem teto de 64 bytes e é lido em binário, e o
  `metadata.json` tem teto de 64 KB. Os erros saem como códigos de uma lista
  fechada (`model_registry.ERROR_CODES`) — nunca texto de exceção nem caminhos,
  que só ficam no log. O `evaluation` é projectado por uma lista fechada de 14
  chaves com tipos validados e textos truncados, para que texto arbitrário de
  um ficheiro escrito à mão não chegue ao `detail` nem ao DOM.

  **Limite honesto desta verificação:** o SHA-256 deteta corrupção, troca
  acidental e ficheiros alheios sem metadados, mas **não autentica** quem
  escreveu — quem tem escrita em `models/` reescreve também o `metadata.json`,
  logo o hash é uma auto-atestação do próprio processo que gravou a versão.
  HMAC/assinatura ficaram fora do âmbito do R10.

## Riscos conhecidos

- API key na query string dos WebSockets pode aparecer em logs/histórico.
- Um processo local que forje `Referer`/`Host` (curl, extensão de browser)
  ainda obtém `/config.js`; aceitável num PC de laboratório de um só
  utilizador, onde esses processos já conseguem ler `scripts/.env`. Alternativa
  mais forte, não adotada: servir a chave como JSON e lê-la com `fetch()`
  (a política same-origin bloqueia a leitura cross-origin sem depender de
  cabeçalhos), o que obriga a tornar assíncrono o arranque de `app.js`/`redblue.js`.
- Uma só chave global: sem papéis nem rate limiting.
- `joblib.load` (pickle) só é seguro com artefactos locais, e o registo (R9)
  já verificou o SHA-256 antes de cada carga — mas isso não torna um `.pkl`
  alheio seguro, só torna a troca/corrupção visível (ver a entrada do R9 em
  "Em vigor"). O que fica por resolver é a automating do treino (R10) e,
  com ela, a origem do `.pkl`: nenhum `.pkl` de fora deve entrar em
  `models/` por descuido.
- Um segredo esteve no histórico git (removido): confirmar que a chave foi
  **rodada**; reescrever histórico não revoga uma chave já publicada.
- `WAZUH_VERIFY_SSL=false` por omissão (certificado autoassinado do lab).
- Credenciais da VM apareceram em texto em sessões anteriores: mudar e passar
  a autenticação por chave.
- **Triagem JEV (experimental)**: `POST /api/incidents/{id}/triage` é a **única** rota que envia dados a um serviço externo (`api.typesafe.ai`, EUA). Fail-closed: exige `SENTRYLENS_JEV_ENABLED=true` **e** `TYPESAFE_API_KEY`, senão 503 sem chamar a rede. Só corre a pedido, nunca em segundo plano. O `state` é agregado e anonimizado (`jev_client.build_state`: contagens, rótulos de evento, severidades, duração — nunca IPs, contas, hostnames nem payloads; coberto por teste). Erros devolvem códigos estáveis, nunca texto de exceção. O URL é constante no código (não configurável). Políticas da TypeSafe lidas a 2026-10-08: não treinam com o input; **sem prazo de retenção publicado** (MCA §4.1 permite guardar telemetria "in perpetuity"; zero retention só enterprise) — por isso apenas para o laboratório do CET, e nunca ligar com dados reais de uma organização sem zero retention contratado. A chave vive só em `scripts/.env` (gitignored).
