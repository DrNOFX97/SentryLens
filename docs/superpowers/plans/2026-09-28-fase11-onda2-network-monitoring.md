# Fase 11 (Onda 2) — Monitorização de Rede em Tempo Real (Wireshark) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Acrescentar a rede como um 3º método de deteção, independente do
Wazuh (regra+ML sobre Windows Event Log), capturando metadados de tráfego
na VM Wazuh via `tshark`, transportando-os por SSH até ao backend, e
expondo tentativas de ataque detetadas **só** pela rede — o "ponto cego"
que o Wazuh sozinho não veria — através de `build_redblue_report()`
estendido e de dois endpoints novos (`GET /api/redblue/network`,
`/ws/network`).

**Architecture:** Segue o padrão já estabelecido em `scripts/`: módulos de
domínio puros (`network_detections.py`) e um único ponto de I/O por
integração externa (`ssh_client.py`, espelhando `wazuh_client.py`), com
`network_monitor.py` a orquestrar o polling/parsing/broadcast (mesmo
desenho de `websocket_alerts.py`). `redblue_correlator.py` ganha um
parâmetro opcional e retrocompatível; `main.py` fica só a camada HTTP fina,
igual ao resto do projeto.

**Tech Stack:** Python stdlib (`datetime`, `collections.deque`) +
`asyncssh` (dependência nova, SSH assíncrono). Testes: scripts standalone
sem pytest, padrão `check()`/`[OK]`/`[FALHOU]`/`sys.exit(1)` já usado em
todo o projeto, com `unittest.mock.AsyncMock`/`MagicMock` para SSH e para
o `WazuhIndexerClient`.

**Spec:** `docs/superpowers/specs/2026-09-28-fase11-onda2-network-monitoring-design.md`
— este plano implementa essa spec, com um ajuste de formato assinalado no
Global Constraints (`-T fields`/CSV em vez de `-T ek`/NDJSON — ver nota).
Os executores devem ler os dois documentos.

## Global Constraints

- **Frontend está fora de escopo** deste plano (10ª aba + os 3 painéis
  Red/Blue/Manager-Auditor já adiados pela Onda 1) — Onda 3, só depois
  desta onda fechada e aprovada, com dados reais dos endpoints novos.
- **Ajuste de formato face à spec:** a spec descreve `tshark -T ek`
  (NDJSON). Este plano usa `tshark -T fields -E separator=, -E quote=n`
  (CSV de 9 campos fixos) em vez disso — `-T ek` produz pares de linhas
  ação+dados por pacote (formato bulk do Elasticsearch), desnecessariamente
  complexo para 7 campos escalares sem payload; CSV de campos fixos é
  trivial de parsear e igualmente robusto. O ficheiro de captura chama-se
  `network.csv`, não `network.jsonl`. Tudo o resto da spec (ponto de
  captura, filtro BPF, retenção, transporte SSH, isolamento do pipeline de
  alertas) mantém-se exatamente como decidido.
- **Sem payload, só metadados**: `timestamp`, `src_ip`, `dst_ip`,
  `src_port`, `dst_port`, `protocol`, `length` — nunca conteúdo de
  aplicação.
- **Deteção por regras fixas** (`network_detections.py`), nunca ML —
  limiares em `RULES`, ajustáveis sem tocar na lógica.
- **Isolamento do pipeline principal**: deteções de rede nunca entram em
  `history_store.py`, `compliance_evaluator.py` nem `/ws/alerts` — ficam
  contidas em `/api/redblue/network` e `/ws/network`.
- **`build_redblue_report()` continua uma função pura**, retrocompatível:
  `network_detections=None` (omitido) reproduz exatamente o comportamento
  já testado da Onda 1, byte a byte.
- **Funcionalidade opcional, fail-open (não fail-closed)**: sem
  `VM_SSH_HOST` no `.env`, `/api/redblue/network` e `/ws/network` devolvem
  `{"configured": false, ...}` com `200`, nunca `401`/`500` por causa
  disso — continuam a exigir `X-API-Key`/`api_key` normalmente, como
  qualquer outra rota. Isto é o oposto deliberado de `SENTRYLENS_API_KEY`
  (essa sim fail-closed para tudo).
- **Sem persistência no backend**: só o buffer efémero em memória
  (`collections.deque(maxlen=2000)`) — a VM é a única fonte de verdade
  para histórico de rede, com `logrotate` a manter 7 dias.
- Todos os endpoints REST `/api/*` exigem `dependencies=_REQUIRE_API_KEY`
  individualmente na rota (nunca a nível de app); `/ws/network` autentica
  por query param `api_key`, fora dessa dependency — mesmo padrão de
  `/ws/alerts` (ver `main.py:115-155` e `main.py:751-773`).
- Testes: `os.environ.setdefault("SENTRYLENS_API_KEY", ...)` **antes** de
  `import main`; `main.app.router.on_startup.clear()` logo a seguir. Sem
  pytest — script standalone com `check(label, condition)`, `sys.exit(1)`
  se `failures` não estiver vazio no fim.
- Caminhos/hosts configuráveis via variável de ambiente, todos opcionais
  para esta funcionalidade (`VM_SSH_HOST`, `VM_SSH_USER`,
  `VM_SSH_KEY_PATH`, `NETWORK_CAPTURE_REMOTE_PATH`).

## Review Focus

- **`VM_SSH_HOST` configurado mas a VM está inatingível em runtime** (rede
  em baixo, SSH recusa ligação) — `network_poll_loop` tem de sobreviver e
  continuar a tentar, nunca derrubar o backend inteiro. Testado na Task 4.
- **Uma deteção de rede não deve contar como cobertura de um ataque a que
  não pertence** — só porque existe *alguma* deteção de rede na janela de
  tempo não chega; o IP do alvo tem de aparecer como `src_ip` ou `dst_ip`
  dessa deteção específica. Testado na Task 2 (caso com IP que não bate).
- **Linha do `tshark` malformada** (campos a menos, `frame.time_epoch`
  vazio/inválido, IPs vazios — ex: pacotes ARP que escapem ao filtro BPF)
  nunca pode lançar exceção nem entrar no buffer como pacote inválido.
  Testado na Task 4.
- **`logrotate` com `copytruncate` a rodar o ficheiro entre duas iterações
  de poll** (o ficheiro fica mais pequeno do que o offset conhecido) tem
  de ser detetado e tratado como reinício de leitura, não como erro.
  Testado na Task 3; a janela de corrida residual *dentro* da mesma
  iteração (entre o `stat` e o `tail` na mesma ligação SSH) é um risco
  aceite e documentado em comentário — autocorrige-se no poll seguinte.
- **Retrocompatibilidade de `build_redblue_report()`** quando
  `network_detections` não é passado (omitido/`None`) — o comportamento e
  os 8 casos de teste já existentes da Onda 1 não podem mudar nem uma
  vírgula. Testado na Task 2 (caso 9).

---

## File Structure

| File | Task | Responsibility |
|---|---|---|
| `scripts/network_detections.py` | 1 | NOVO — função pura `detect_network_anomalies()`, regras fixas (port scan/brute force/volume spike). |
| `scripts/test_network_detections.py` | 1 | NOVO — testes da deteção pura. |
| `scripts/redblue_correlator.py` | 2 | Estende `build_redblue_report()` com o parâmetro opcional `network_detections`. |
| `scripts/test_redblue.py` | 2, 5 | Novos casos (Task 2: correlação pura; Task 5: endpoints HTTP). |
| `scripts/ssh_client.py` | 3 | NOVO — `VMSSHClient`, único ponto de SSH com a VM. |
| `scripts/test_ssh_client.py` | 3 | NOVO — testes com `asyncssh` mockado. |
| `scripts/requirements.txt` | 3 | Nova dependência `asyncssh`. |
| `scripts/network_monitor.py` | 4 | NOVO — parsing, buffer, poll loop, `NetworkConnectionManager`. |
| `scripts/test_network_monitor.py` | 4 | NOVO — testes com SSH fake. |
| `scripts/main.py` | 5 | Imports, env vars, `GET /api/redblue/network`, `/ws/network`, extensão de `GET /api/redblue/metrics`, `on_startup`. |
| `scripts/test_websocket_alerts.py` | 5 | Novo caso: autenticação de `/ws/network`. |
| `scripts/deploy/sentrylens-tshark.service` | 6 | NOVO — unidade `systemd` do `tshark` na VM. |
| `scripts/deploy/sentrylens-network.logrotate` | 6 | NOVO — rotação diária, 7 dias. |
| `docs/LAB_WAZUH_HYPERV.md` | 6 | Nova secção: setup manual do serviço de captura. |
| `CLAUDE.md` | 7 | Documenta os módulos/endpoints novos. |
| `README.md` | 7 | Tabela de testes + tabela de endpoints + árvore de ficheiros. |
| `docs/ML.md` | 7 | Estende a secção Red vs Blue com os campos de rede. |
| `docs/API.md` | 7 | Nova secção `/ws/network`. |
| `scripts/.env.example` | 7 | Documenta as 4 variáveis novas. |
| Notion (`page_id 3caa99e6-526b-8111-89be-db8b6ffe765b`) | 8 | Registo de execução da Onda 2. |

---

## Task 1: `network_detections.py` — deteção volumétrica (função pura)

**Files:**
- Create: `scripts/network_detections.py`
- Create: `scripts/test_network_detections.py`

**Interfaces:**
- Produces: `RULES: dict`, `detect_network_anomalies(packets: list[dict], rules: dict = RULES) -> list[dict]`
  — cada item devolvido: `{"type": "port_scan"|"brute_force"|"volume_spike", "src_ip": str, "dst_ip": str | None, "timestamp": str, "detail": dict}`.
  Consumido por `network_monitor.py` (Task 4) e por `redblue_correlator.py` (Task 2, via a mesma forma de dict).

- [ ] **Step 1: Escrever `scripts/test_network_detections.py` (vai falhar — o módulo ainda não existe)**

```python
"""
Testes de regressão de scripts/network_detections.py (Fase 11, Onda 2) —
deteção de padrões suspeitos (port scan, força bruta, pico de volume) a
partir só de metadados de pacotes. Funções puras, sem I/O.

Correr:
    python test_network_detections.py
"""

import sys
from datetime import datetime, timedelta, timezone

from network_detections import RULES, detect_network_anomalies

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


BASE = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)


def pkt(offset_seconds: float, src_ip: str, dst_ip: str, dst_port: int | None) -> dict:
    ts = BASE + timedelta(seconds=offset_seconds)
    return {
        "timestamp": ts.isoformat(), "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": 50000, "dst_port": dst_port, "protocol": "TCP", "length": 66,
    }


def run() -> None:
    # --- Caso 1: port scan (>= 15 portas distintas do mesmo par src/dst na janela) ---
    packets_scan = [pkt(i, "192.168.1.170", "192.168.1.20", 4000 + i) for i in range(16)]
    dets = detect_network_anomalies(packets_scan)
    check("port scan detetado com 16 portas distintas", any(d["type"] == "port_scan" for d in dets))
    scan_det = next(d for d in dets if d["type"] == "port_scan")
    check(
        "port scan regista src_ip/dst_ip corretos",
        scan_det["src_ip"] == "192.168.1.170" and scan_det["dst_ip"] == "192.168.1.20",
    )

    # --- Caso 2: abaixo do limiar -> sem deteção ---
    packets_ok = [pkt(i, "192.168.1.170", "192.168.1.20", 4000 + i) for i in range(5)]
    check("sem deteção abaixo do limiar de portas", detect_network_anomalies(packets_ok) == [])

    # --- Caso 3: brute force (>= 20 pacotes mesmo par src/dst/porta na janela) ---
    packets_bf = [pkt(i * 0.5, "192.168.1.170", "192.168.1.21", 3389) for i in range(20)]
    dets_bf = detect_network_anomalies(packets_bf)
    check("brute force detetado com 20 ligações à mesma porta", any(d["type"] == "brute_force" for d in dets_bf))

    # --- Caso 4: volume spike (>= 500 pacotes do mesmo src_ip na janela) ---
    packets_vol = [pkt(i * 0.01, "192.168.1.170", "192.168.1.22", 445) for i in range(500)]
    dets_vol = detect_network_anomalies(packets_vol)
    check("volume spike detetado com 500 pacotes", any(d["type"] == "volume_spike" for d in dets_vol))

    # --- Caso 5: pacotes fora da janela (demasiado antigos) não contam ---
    packets_old_and_new = (
        [pkt(i, "192.168.1.170", "192.168.1.23", 4000 + i) for i in range(16)]
        + [pkt(-3600 + i, "192.168.1.170", "192.168.1.23", 5000 + i) for i in range(20)]
    )
    dets_window = detect_network_anomalies(packets_old_and_new)
    scan_det_window = next(d for d in dets_window if d["type"] == "port_scan")
    check("pacotes fora da janela não contam para o limiar", scan_det_window["detail"]["distinct_ports"] == 16)

    # --- Caso 6: pacote malformado (sem src_ip) é ignorado sem rebentar ---
    packets_malformed = [{"timestamp": BASE.isoformat(), "dst_ip": "192.168.1.20", "dst_port": 80}]
    check("pacote sem src_ip é ignorado sem lançar exceção", detect_network_anomalies(packets_malformed) == [])

    # --- Caso 7: lista vazia -> [] ---
    check("lista vazia devolve []", detect_network_anomalies([]) == [])

    # --- Caso 8: limiares customizados via parâmetro rules ---
    custom_rules = {**RULES, "port_scan": {"distinct_ports": 3, "window_seconds": 30}}
    packets_small_scan = [pkt(i, "192.168.1.170", "192.168.1.24", 4000 + i) for i in range(4)]
    check(
        "limiar customizado deteta scan pequeno que o default ignoraria",
        any(d["type"] == "port_scan" for d in detect_network_anomalies(packets_small_scan, rules=custom_rules)),
    )

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
```

- [ ] **Step 2: Correr para confirmar que falha**

Run: `cd scripts && python test_network_detections.py`
Expected: `ModuleNotFoundError: No module named 'network_detections'`

- [ ] **Step 3: Implementar `scripts/network_detections.py`**

```python
"""
Deteção de padrões suspeitos em tráfego de rede (Fase 11, Onda 2), a partir
só de metadados de pacotes (sem payload) — port scan, força bruta e picos de
volume, com limiares fixos e explícitos (mesmo espírito de event_catalog.py:
regras simples, sem modelo a treinar).

Módulo puro: recebe a lista de pacotes já parseados por network_monitor.py
(cada um com timestamp/src_ip/dst_ip/src_port/dst_port/protocol/length) e
devolve as deteções encontradas na janela mais recente de cada regra. Nunca
lança exceção sobre dados malformados — pacotes sem os campos mínimos são
ignorados individualmente.

Limitação deliberada: sem rastreio de sessão/ligação TCP (só há pacotes
soltos), "brute_force" conta pacotes por (src_ip, dst_ip, dst_port) como
proxy de tentativas de ligação — impreciso para TCP real (uma única ligação
gera vários pacotes), mas suficiente para o objetivo de laboratório: expor
um padrão de repetição óbvio, não medir tentativas com precisão forense.
"""

from datetime import datetime, timedelta, timezone

RULES = {
    "port_scan": {"distinct_ports": 15, "window_seconds": 30},
    "brute_force": {"connections": 20, "window_seconds": 30},
    "volume_spike": {"packets": 500, "window_seconds": 10},
}


def _parse_timestamp(raw_timestamp: str | None) -> datetime | None:
    """Mesma convenção do resto do projeto (redblue_correlator.py/lifecycle.py):
    aceita o sufixo 'Z', assume UTC quando não há fuso indicado, devolve
    None em vez de lançar exceção para timestamps malformados."""
    if not raw_timestamp or not isinstance(raw_timestamp, str):
        return None
    normalized = raw_timestamp.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def detect_network_anomalies(packets: list[dict], rules: dict = RULES) -> list[dict]:
    """Analisa a lista de pacotes já parseados e devolve as deteções
    encontradas na janela mais recente de cada regra (a janela termina no
    timestamp mais recente presente em `packets`). Nunca lança exceção."""
    parsed: list[tuple[datetime, dict]] = []
    for p in packets or []:
        if not isinstance(p, dict):
            continue
        ts = _parse_timestamp(p.get("timestamp"))
        if ts is None or not p.get("src_ip") or not p.get("dst_ip"):
            continue
        parsed.append((ts, p))
    if not parsed:
        return []

    now = max(ts for ts, _ in parsed)
    detections: list[dict] = []

    # --- port_scan: mesmo par (src_ip, dst_ip), muitas portas de destino distintas ---
    cfg = rules["port_scan"]
    window_start = now - timedelta(seconds=cfg["window_seconds"])
    ports_by_pair: dict[tuple, set] = {}
    for ts, p in parsed:
        if ts < window_start or p.get("dst_port") is None:
            continue
        ports_by_pair.setdefault((p["src_ip"], p["dst_ip"]), set()).add(p["dst_port"])
    for (src_ip, dst_ip), ports in ports_by_pair.items():
        if len(ports) >= cfg["distinct_ports"]:
            detections.append({
                "type": "port_scan", "src_ip": src_ip, "dst_ip": dst_ip,
                "timestamp": now.isoformat(), "detail": {"distinct_ports": len(ports)},
            })

    # --- brute_force: mesmo trio (src_ip, dst_ip, dst_port), muitos pacotes ---
    cfg = rules["brute_force"]
    window_start = now - timedelta(seconds=cfg["window_seconds"])
    counts: dict[tuple, int] = {}
    for ts, p in parsed:
        if ts < window_start or p.get("dst_port") is None:
            continue
        key = (p["src_ip"], p["dst_ip"], p["dst_port"])
        counts[key] = counts.get(key, 0) + 1
    for (src_ip, dst_ip, dst_port), count in counts.items():
        if count >= cfg["connections"]:
            detections.append({
                "type": "brute_force", "src_ip": src_ip, "dst_ip": dst_ip,
                "timestamp": now.isoformat(), "detail": {"dst_port": dst_port, "connections": count},
            })

    # --- volume_spike: mesmo src_ip, muitos pacotes ---
    cfg = rules["volume_spike"]
    window_start = now - timedelta(seconds=cfg["window_seconds"])
    packet_counts: dict[str, int] = {}
    for ts, p in parsed:
        if ts < window_start:
            continue
        packet_counts[p["src_ip"]] = packet_counts.get(p["src_ip"], 0) + 1
    for src_ip, count in packet_counts.items():
        if count >= cfg["packets"]:
            detections.append({
                "type": "volume_spike", "src_ip": src_ip, "dst_ip": None,
                "timestamp": now.isoformat(), "detail": {"packets": count},
            })

    return detections
```

- [ ] **Step 4: Correr o teste, confirmar que passa**

Run: `cd scripts && python test_network_detections.py`
Expected: `[OK] Todos os testes passaram`, saída 0.

- [ ] **Step 5: Commit**

```bash
git add scripts/network_detections.py scripts/test_network_detections.py
git commit -m "feat: deteção de padrões suspeitos de rede - port scan/brute force/volume (Fase 11, Onda 2)"
```

---

## Task 2: `redblue_correlator.py` — rede como 3º método de deteção

**Files:**
- Modify: `scripts/redblue_correlator.py:38-43` (assinatura), `:89-94` (parsing), `:129-141` (loop de tentativas), `:143-163` (agregação por cenário), `:170-178` (agregação overall)
- Modify: `scripts/test_redblue.py` (novos casos, Parte 3)

**Interfaces:**
- Consumes: forma de dict de `network_detections.detect_network_anomalies()` (Task 1) — `{"type", "src_ip", "dst_ip", "timestamp", "detail"}`. Não importa o módulo, só assume a forma (função pura, desacoplada).
- Produces: `build_redblue_report(..., network_detections: list[dict] | None = None)` — cada item de `attempts` ganha `detected_by_network: bool`, `network_detection_types: list[str]`, `mttd_network_seconds: float | None`, `coverage_gap: bool`; `by_scenario[...]`/`overall` ganham `detected_by_network_only`, `detected_by_windows_only`, `detected_by_both_sources`, `detected_by_neither`. Consumido por `main.py` na Task 5.

- [ ] **Step 1: Escrever os casos de teste que falham, acrescentados a `scripts/test_redblue.py`**

Acrescentar ao ficheiro `scripts/test_redblue.py` existente (depois da
Parte 2 já existente — endpoint HTTP da Onda 1 — e antes do bloco final
`print()` / `if failures:` de `run()`):

```python
    # =========================================================================
    # Parte 3: dimensão de rede em build_redblue_report (Fase 11, Onda 2)
    # =========================================================================
    def net_det(det_type: str, src_ip: str, dst_ip: str | None, timestamp: str) -> dict:
        return {"type": det_type, "src_ip": src_ip, "dst_ip": dst_ip, "timestamp": timestamp, "detail": {}}

    # --- Caso 9: sem network_detections (None) -> retrocompatível ---
    attacks9 = [attack("smb_enum", "192.168.1.40", "2026-09-14T17:00:00+00:00")]
    report9 = build_redblue_report(attacks9, [], SCENARIOS)
    a9 = report9["attempts"][0]
    check("caso 9: sem network_detections -> detected_by_network=False", a9["detected_by_network"] is False)
    check("caso 9: sem network_detections -> coverage_gap=False", a9["coverage_gap"] is False)
    check("caso 9: overall.detected_by_network_only=0 por omissão", report9["overall"]["detected_by_network_only"] == 0)

    # --- Caso 10: deteção só de rede (Windows não viu nada) -> coverage_gap=True ---
    attacks10 = [attack("smb_enum", "192.168.1.41", "2026-09-14T18:00:00+00:00")]
    dets10 = [net_det("port_scan", "192.168.1.170", "192.168.1.41", "2026-09-14T18:00:05+00:00")]
    report10 = build_redblue_report(attacks10, [], SCENARIOS, network_detections=dets10)
    a10 = report10["attempts"][0]
    check("caso 10: detected_by_network=True", a10["detected_by_network"] is True)
    check("caso 10: detected_by (Windows) continua 'none'", a10["detected_by"] == "none")
    check("caso 10: coverage_gap=True (ponto cego exposto)", a10["coverage_gap"] is True)
    check("caso 10: mttd_network_seconds=5.0", a10["mttd_network_seconds"] == 5.0)
    check("caso 10: overall.detected_by_network_only == 1", report10["overall"]["detected_by_network_only"] == 1)

    # --- Caso 11: deteção por Windows e por rede -> both_sources, não coverage_gap ---
    attacks11 = [attack("brute_force_rdp", "192.168.1.42", "2026-09-14T19:00:00+00:00")]
    results11 = [ml_result("2026-09-14T19:00:03+00:00", "192.168.1.42", 4625, rule_flagged=True)]
    dets11 = [net_det("brute_force", "192.168.1.170", "192.168.1.42", "2026-09-14T19:00:04+00:00")]
    report11 = build_redblue_report(attacks11, results11, SCENARIOS, network_detections=dets11)
    a11 = report11["attempts"][0]
    check(
        "caso 11: detected_by_network=True e detected_by='rule'",
        a11["detected_by_network"] is True and a11["detected_by"] == "rule",
    )
    check("caso 11: coverage_gap=False (já detetado pelo Windows)", a11["coverage_gap"] is False)
    check("caso 11: overall.detected_by_both_sources == 1", report11["overall"]["detected_by_both_sources"] == 1)

    # --- Caso 12: alvo como src_ip da deteção (não só dst_ip) também conta ---
    attacks12 = [attack("smb_enum", "192.168.1.43", "2026-09-14T20:00:00+00:00")]
    dets12 = [net_det("volume_spike", "192.168.1.43", None, "2026-09-14T20:00:02+00:00")]
    report12 = build_redblue_report(attacks12, [], SCENARIOS, network_detections=dets12)
    check("caso 12: alvo como src_ip da deteção também conta", report12["attempts"][0]["detected_by_network"] is True)

    # --- Caso 13: deteção de rede para um IP diferente do alvo não conta (Review Focus) ---
    attacks13 = [attack("smb_enum", "192.168.1.44", "2026-09-14T21:00:00+00:00")]
    dets13 = [net_det("port_scan", "192.168.1.170", "10.0.0.99", "2026-09-14T21:00:05+00:00")]  # IP não relacionado
    report13 = build_redblue_report(attacks13, [], SCENARIOS, network_detections=dets13)
    check(
        "caso 13: deteção de rede para IP não relacionado não conta como cobertura",
        report13["attempts"][0]["detected_by_network"] is False,
    )
```

- [ ] **Step 2: Correr para confirmar que falha**

Run: `cd scripts && python test_redblue.py`
Expected: `TypeError: build_redblue_report() got an unexpected keyword argument 'network_detections'`

- [ ] **Step 3: Estender a assinatura (linhas 38-43)**

Em `scripts/redblue_correlator.py`, substituir:

```python
def build_redblue_report(
    attack_log: list[dict],
    ml_results: list[dict],
    scenarios: dict,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> dict:
```

por:

```python
def build_redblue_report(
    attack_log: list[dict],
    ml_results: list[dict],
    scenarios: dict,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    network_detections: list[dict] | None = None,
) -> dict:
```

- [ ] **Step 4: Parsear `network_detections` (a seguir ao bloco `parsed_alerts`, linhas 89-94)**

Substituir:

```python
    parsed_alerts: list[tuple[datetime, dict]] = []
    for result in ml_results or []:
        ts = _parse_timestamp(result.get("timestamp"))
        if ts is None:
            continue
        parsed_alerts.append((ts, result))
```

por:

```python
    parsed_alerts: list[tuple[datetime, dict]] = []
    for result in ml_results or []:
        ts = _parse_timestamp(result.get("timestamp"))
        if ts is None:
            continue
        parsed_alerts.append((ts, result))

    parsed_network: list[tuple[datetime, dict]] = []
    for det in network_detections or []:
        ts = _parse_timestamp(det.get("timestamp"))
        if ts is None:
            continue
        parsed_network.append((ts, det))
```

- [ ] **Step 5: Cruzar deteções de rede por tentativa (linhas 129-141)**

Substituir:

```python
        mttd_seconds = round((matches[0][0] - ts).total_seconds(), 2) if matches else None

        attempts.append({
            "scenario": scenario_name,
            "target": target,
            "timestamp": entry.get("timestamp"),
            "mitre_tactic": scenario.mitre_tactic,
            "mitre_technique": scenario.mitre_technique,
            "detected": detected,
            "detected_by": detected_by,
            "mttd_seconds": mttd_seconds,
            "matched_event_ids": sorted({result.get("windows_event_id") for _, result in matches}),
        })
```

por:

```python
        mttd_seconds = round((matches[0][0] - ts).total_seconds(), 2) if matches else None

        network_matches = [
            (net_ts, det)
            for net_ts, det in parsed_network
            if ts <= net_ts <= window_end and target in (det.get("src_ip"), det.get("dst_ip"))
        ]
        network_matches.sort(key=lambda item: item[0])
        detected_by_network = len(network_matches) > 0
        mttd_network_seconds = (
            round((network_matches[0][0] - ts).total_seconds(), 2) if network_matches else None
        )

        attempts.append({
            "scenario": scenario_name,
            "target": target,
            "timestamp": entry.get("timestamp"),
            "mitre_tactic": scenario.mitre_tactic,
            "mitre_technique": scenario.mitre_technique,
            "detected": detected,
            "detected_by": detected_by,
            "mttd_seconds": mttd_seconds,
            "matched_event_ids": sorted({result.get("windows_event_id") for _, result in matches}),
            "detected_by_network": detected_by_network,
            "network_detection_types": sorted({det.get("type") for _, det in network_matches}),
            "mttd_network_seconds": mttd_network_seconds,
            "coverage_gap": detected_by_network and detected_by == "none",
        })
```

- [ ] **Step 6: Estender a agregação por cenário (linhas 143-163)**

Substituir o bloco inteiro:

```python
    by_scenario: dict[str, dict] = {}
    for att in attempts:
        name = att["scenario"]
        bucket = by_scenario.setdefault(name, {
            "attempts": 0, "detected": 0,
            "detected_by_rule": 0, "detected_by_ml": 0, "detected_by_both": 0,
            "detected_by_none": 0,
            "_mttd_values": [],
        })
        bucket["attempts"] += 1
        if att["detected"]:
            bucket["detected"] += 1
            bucket["_mttd_values"].append(att["mttd_seconds"])
        if att["detected_by"] == "rule":
            bucket["detected_by_rule"] += 1
        elif att["detected_by"] == "ml":
            bucket["detected_by_ml"] += 1
        elif att["detected_by"] == "both":
            bucket["detected_by_both"] += 1
        else:
            bucket["detected_by_none"] += 1
```

por:

```python
    by_scenario: dict[str, dict] = {}
    for att in attempts:
        name = att["scenario"]
        bucket = by_scenario.setdefault(name, {
            "attempts": 0, "detected": 0,
            "detected_by_rule": 0, "detected_by_ml": 0, "detected_by_both": 0,
            "detected_by_none": 0,
            "detected_by_network_only": 0, "detected_by_windows_only": 0,
            "detected_by_both_sources": 0, "detected_by_neither": 0,
            "_mttd_values": [],
        })
        bucket["attempts"] += 1
        if att["detected"]:
            bucket["detected"] += 1
            bucket["_mttd_values"].append(att["mttd_seconds"])
        if att["detected_by"] == "rule":
            bucket["detected_by_rule"] += 1
        elif att["detected_by"] == "ml":
            bucket["detected_by_ml"] += 1
        elif att["detected_by"] == "both":
            bucket["detected_by_both"] += 1
        else:
            bucket["detected_by_none"] += 1

        windows_detected = att["detected_by"] != "none"
        network_detected = att["detected_by_network"]
        if windows_detected and network_detected:
            bucket["detected_by_both_sources"] += 1
        elif windows_detected:
            bucket["detected_by_windows_only"] += 1
        elif network_detected:
            bucket["detected_by_network_only"] += 1
        else:
            bucket["detected_by_neither"] += 1
```

- [ ] **Step 7: Estender a agregação overall (linhas 170-178)**

Substituir:

```python
    total_attempts = len(attempts)
    total_detected = sum(1 for a in attempts if a["detected"])
    all_mttd = [a["mttd_seconds"] for a in attempts if a["mttd_seconds"] is not None]
    overall = {
        "total_attempts": total_attempts,
        "detected": total_detected,
        "coverage_rate": round(total_detected / total_attempts, 4) if total_attempts else 0.0,
        "avg_mttd_seconds": round(sum(all_mttd) / len(all_mttd), 2) if all_mttd else None,
    }
```

por:

```python
    total_attempts = len(attempts)
    total_detected = sum(1 for a in attempts if a["detected"])
    all_mttd = [a["mttd_seconds"] for a in attempts if a["mttd_seconds"] is not None]
    overall = {
        "total_attempts": total_attempts,
        "detected": total_detected,
        "coverage_rate": round(total_detected / total_attempts, 4) if total_attempts else 0.0,
        "avg_mttd_seconds": round(sum(all_mttd) / len(all_mttd), 2) if all_mttd else None,
        "detected_by_network_only": sum(1 for a in attempts if a["coverage_gap"]),
        "detected_by_windows_only": sum(
            1 for a in attempts if a["detected_by"] != "none" and not a["detected_by_network"]
        ),
        "detected_by_both_sources": sum(
            1 for a in attempts if a["detected_by"] != "none" and a["detected_by_network"]
        ),
        "detected_by_neither": sum(
            1 for a in attempts if a["detected_by"] == "none" and not a["detected_by_network"]
        ),
    }
```

- [ ] **Step 8: Correr o teste, confirmar que passa**

Run: `cd scripts && python test_redblue.py`
Expected: `[OK] Todos os testes passaram`, saída 0.

- [ ] **Step 9: Commit**

```bash
git add scripts/redblue_correlator.py scripts/test_redblue.py
git commit -m "feat: rede como 3o metodo de deteccao independente em build_redblue_report (Fase 11, Onda 2)"
```

---

## Task 3: `ssh_client.py` — único ponto de SSH com a VM

**Files:**
- Create: `scripts/ssh_client.py`
- Create: `scripts/test_ssh_client.py`
- Modify: `scripts/requirements.txt`

**Interfaces:**
- Produces: `VMSSHClient(host, user, key_path=None)` com
  `async read_new_lines(remote_path: str, since_offset: int) -> tuple[str, int]`
  — consumido por `network_monitor.py` (Task 4) e por `main.py` (Task 5).

- [ ] **Step 1: Acrescentar a dependência a `scripts/requirements.txt`**

Adicionar no fim do ficheiro:

```
asyncssh==2.17.0
```

- [ ] **Step 2: Instalar e confirmar**

Run: `cd scripts && pip install -r requirements.txt`
Expected: instala sem erro. Se `asyncssh==2.17.0` já não existir no PyPI,
correr `pip index versions asyncssh` e usar a versão estável mais recente
disponível nesse momento.

- [ ] **Step 3: Escrever `scripts/test_ssh_client.py` (vai falhar — o módulo ainda não existe)**

```python
"""
Testes de regressão de scripts/ssh_client.py (Fase 11, Onda 2) —
VMSSHClient, o único ponto de contacto SSH com a VM Wazuh. Mocka
asyncssh.connect por completo, sem precisar de nenhuma VM real ligada.

Correr:
    python test_ssh_client.py
"""

import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

from ssh_client import VMSSHClient

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def _make_fake_conn(file_size: int, tail_output: str):
    """Fake de asyncssh.connect(...) como async context manager, com
    conn.run(...) a devolver stdout fixo consoante o comando (stat -c %s
    vs tail -c +N)."""
    fake_conn = MagicMock()

    async def _run(cmd: str, check: bool = True):
        result = MagicMock()
        result.stdout = f"{file_size}\n" if cmd.startswith("stat") else tail_output
        return result

    fake_conn.run = AsyncMock(side_effect=_run)

    fake_ctx = MagicMock()
    fake_ctx.__aenter__ = AsyncMock(return_value=fake_conn)
    fake_ctx.__aexit__ = AsyncMock(return_value=False)
    return fake_ctx


def run() -> None:
    async def _run_tests():
        client = VMSSHClient("192.168.1.100", "fernando", key_path=None)

        # --- Caso 1: ficheiro cresceu, offset avança, devolve só o conteúdo novo ---
        with patch("ssh_client.asyncssh.connect", return_value=_make_fake_conn(150, "linha nova 1\nlinha nova 2\n")):
            content, new_offset = await client.read_new_lines("/var/log/sentrylens/network.csv", since_offset=100)
        check("caso 1: devolve o conteúdo novo", content == "linha nova 1\nlinha nova 2\n")
        check("caso 1: novo offset == tamanho atual do ficheiro", new_offset == 150)

        # --- Caso 2: ficheiro mais pequeno que o offset conhecido (copytruncate rodou) -> reinício desde 0 ---
        with patch("ssh_client.asyncssh.connect", return_value=_make_fake_conn(50, "ficheiro inteiro\n")):
            content2, new_offset2 = await client.read_new_lines("/var/log/sentrylens/network.csv", since_offset=9999)
        check("caso 2: deteta rotação e lê desde offset 0", content2 == "ficheiro inteiro\n")
        check("caso 2: novo offset == tamanho do ficheiro rodado", new_offset2 == 50)

        # --- Caso 3: sem bytes novos (offset == tamanho atual) -> string vazia, offset inalterado ---
        with patch("ssh_client.asyncssh.connect", return_value=_make_fake_conn(200, "")):
            content3, new_offset3 = await client.read_new_lines("/var/log/sentrylens/network.csv", since_offset=200)
        check("caso 3: sem bytes novos devolve string vazia", content3 == "")
        check("caso 3: offset inalterado quando não há bytes novos", new_offset3 == 200)

    asyncio.run(_run_tests())

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
```

- [ ] **Step 4: Correr para confirmar que falha**

Run: `cd scripts && python test_ssh_client.py`
Expected: `ModuleNotFoundError: No module named 'ssh_client'`

- [ ] **Step 5: Implementar `scripts/ssh_client.py`**

```python
"""
Único ponto de contacto SSH com a VM Wazuh (Fase 11, Onda 2) — nenhum outro
módulo abre ligações SSH diretamente, mesmo papel que wazuh_client.py tem
para HTTP. Usado só por network_monitor.py, para ler o ficheiro de captura
de rede que o tshark vai escrevendo na VM (ver scripts/deploy/).
"""

import asyncssh


class VMSSHClient:
    """
    known_hosts=None desliga a verificação de host key SSH — mesma
    filosofia de WAZUH_VERIFY_SSL=false em wazuh_client.py: o laboratório
    usa infraestrutura própria sem PKI formal, decisão intencional, não um
    esquecimento.
    """

    def __init__(self, host: str, user: str, key_path: str | None = None) -> None:
        self._host = host
        self._user = user
        self._key_path = key_path

    async def read_new_lines(self, remote_path: str, since_offset: int) -> tuple[str, int]:
        """
        Lê só os bytes novos de remote_path a partir de since_offset. Se o
        ficheiro atual for mais pequeno que since_offset (logrotate com
        copytruncate rodou entre dois polls), trata como reinício: lê o
        ficheiro inteiro a partir de 0. Devolve (conteúdo_novo, novo_offset)
        — string vazia e o mesmo offset se não houver bytes novos.

        Risco aceite: se a rotação acontecer exatamente entre o `stat` e o
        `tail` desta mesma chamada (não entre polls), o `tail` pode ler a
        partir de um offset já inválido para o ficheiro truncado — o poll
        seguinte deteta o tamanho reduzido e autocorrige. Uma iteração
        perdida ocasional é aceitável para uma ferramenta de laboratório.
        """
        async with asyncssh.connect(
            self._host,
            username=self._user,
            client_keys=[self._key_path] if self._key_path else None,
            known_hosts=None,
        ) as conn:
            size_result = await conn.run(f"stat -c %s {remote_path}", check=True)
            current_size = int(size_result.stdout.strip())

            offset = since_offset if current_size >= since_offset else 0
            if current_size == offset:
                return "", offset

            result = await conn.run(f"tail -c +{offset + 1} {remote_path}", check=True)
            return result.stdout, current_size
```

- [ ] **Step 6: Correr o teste, confirmar que passa**

Run: `cd scripts && python test_ssh_client.py`
Expected: `[OK] Todos os testes passaram`, saída 0.

- [ ] **Step 7: Commit**

```bash
git add scripts/ssh_client.py scripts/test_ssh_client.py scripts/requirements.txt
git commit -m "feat: VMSSHClient - unico ponto de SSH com a VM Wazuh (Fase 11, Onda 2)"
```

---

## Task 4: `network_monitor.py` — parsing, buffer e poll loop

**Files:**
- Create: `scripts/network_monitor.py`
- Create: `scripts/test_network_monitor.py`

**Interfaces:**
- Consumes: `VMSSHClient.read_new_lines(remote_path, since_offset)` (Task 3, via qualquer objeto com essa assinatura — testado com um fake); `detect_network_anomalies(packets)` (Task 1).
- Produces: `NetworkConnectionManager`, `PACKET_BUFFER_MAX = 2000`,
  `_parse_fields_line(line) -> dict | None`,
  `async _poll_once(ssh_client, manager, packet_buffer, offset_state, seen_detections, remote_path) -> tuple[list[dict], list[dict]]`,
  `async network_poll_loop(ssh_client, manager, packet_buffer, remote_path, interval_seconds=5) -> None`
  — consumido por `main.py` na Task 5.

- [ ] **Step 1: Escrever `scripts/test_network_monitor.py` (vai falhar — o módulo ainda não existe)**

```python
"""
Testes de regressão de scripts/network_monitor.py (Fase 11, Onda 2) —
parsing das linhas do tshark, buffer e poll loop, sem VM nem SSH reais
(cliente SSH fake).

Correr:
    python test_network_monitor.py
"""

import asyncio
import sys
from collections import deque

from network_monitor import (
    NetworkConnectionManager,
    PACKET_BUFFER_MAX,
    _parse_fields_line,
    _poll_once,
    network_poll_loop,
)

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


class FakeSSHClient:
    """Fake simples: devolve os batches definidos em avanço, um por chamada."""

    def __init__(self, batches: list[tuple[str, int]]) -> None:
        self._batches = list(batches)

    async def read_new_lines(self, remote_path: str, since_offset: int) -> tuple[str, int]:
        return self._batches.pop(0)


def run_parse_tests() -> None:
    linha_tcp = "1758812760.123456,192.168.1.170,192.168.1.20,6,66,54321,3389,,"
    packet = _parse_fields_line(linha_tcp)
    check("linha TCP válida faz parse", packet is not None)
    check("src_ip correto", packet["src_ip"] == "192.168.1.170")
    check("dst_port vem de tcp.dstport (3389)", packet["dst_port"] == 3389)
    check("protocol resolvido para TCP", packet["protocol"] == "TCP")

    linha_udp = "1758812761.0,192.168.1.170,192.168.1.20,17,80,,,51820,53"
    packet_udp = _parse_fields_line(linha_udp)
    check("dst_port vem de udp.dstport quando tcp vazio", packet_udp["dst_port"] == 53)

    check("linha com campos a menos devolve None", _parse_fields_line("1,2,3") is None)
    check("linha sem ip.src devolve None", _parse_fields_line("1758812760.0,,192.168.1.20,6,66,,,,") is None)
    check("epoch inválido devolve None", _parse_fields_line("nao-e-um-numero,192.168.1.1,192.168.1.2,6,66,,,,") is None)


def run_poll_once_tests() -> None:
    async def _run() -> None:
        manager = NetworkConnectionManager()
        packet_buffer: deque = deque(maxlen=PACKET_BUFFER_MAX)
        offset_state = {"offset": 0}
        seen_detections: set = set()

        linhas = (
            "1758812760.0,192.168.1.170,192.168.1.20,6,66,54321,3389,,\n"
            "1758812761.0,192.168.1.170,192.168.1.20,6,66,54322,3390,,\n"
        )
        fake_ssh = FakeSSHClient([(linhas, 200)])
        new_packets, new_detections = await _poll_once(
            fake_ssh, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
        )
        check("_poll_once devolve os 2 pacotes novos", len(new_packets) == 2)
        check("offset_state atualizado para o novo offset", offset_state["offset"] == 200)
        check("buffer ficou com os 2 pacotes", len(packet_buffer) == 2)
        check("sem deteções ainda (só 2 pacotes, abaixo dos limiares)", new_detections == [])

        # --- Segunda chamada, sem linhas novas -> nada de novo, buffer inalterado ---
        fake_ssh_2 = FakeSSHClient([("", 200)])
        new_packets_2, _ = await _poll_once(
            fake_ssh_2, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
        )
        check("segunda chamada sem linhas novas devolve lista vazia", new_packets_2 == [])
        check("buffer continua com 2 pacotes", len(packet_buffer) == 2)

        # --- Terceira chamada: port scan (16 portas distintas do mesmo par src/dst) -> deteção nova ---
        linhas_scan = "".join(
            f"175881277{i}.0,192.168.1.170,192.168.1.21,6,66,50000,{4000 + i},,\n" for i in range(16)
        )
        fake_ssh_3 = FakeSSHClient([(linhas_scan, 400)])
        _, new_detections_3 = await _poll_once(
            fake_ssh_3, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
        )
        check("port scan detetado após 16 portas distintas", any(d["type"] == "port_scan" for d in new_detections_3))

        # --- Quarta chamada: mesmo padrão ainda ativo -> não repete a deteção (dedup) ---
        fake_ssh_4 = FakeSSHClient([("", 400)])
        _, new_detections_4 = await _poll_once(
            fake_ssh_4, manager, packet_buffer, offset_state, seen_detections, "/var/log/sentrylens/network.csv",
        )
        check("deteção repetida no mesmo minuto não é re-emitida", new_detections_4 == [])

    asyncio.run(_run())


def run_loop_survives_ssh_error() -> None:
    """Review Focus: VM_SSH_HOST configurado mas a VM fica inatingível —
    o loop não pode derrubar o backend, tem de continuar a tentar."""

    async def _run() -> None:
        class RaisingSSHClient:
            def __init__(self) -> None:
                self.calls = 0

            async def read_new_lines(self, remote_path: str, since_offset: int) -> tuple[str, int]:
                self.calls += 1
                if self.calls == 1:
                    raise ConnectionError("VM inatingível (simulado)")
                return "", since_offset

        manager = NetworkConnectionManager()
        packet_buffer: deque = deque(maxlen=PACKET_BUFFER_MAX)
        raising_client = RaisingSSHClient()
        task = asyncio.create_task(
            network_poll_loop(raising_client, manager, packet_buffer, "/x", interval_seconds=0.01)
        )
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        check("network_poll_loop sobrevive a uma falha SSH e continua a correr", raising_client.calls >= 2)

    asyncio.run(_run())


def run() -> None:
    run_parse_tests()
    run_poll_once_tests()
    run_loop_survives_ssh_error()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)


if __name__ == "__main__":
    run()
```

- [ ] **Step 2: Correr para confirmar que falha**

Run: `cd scripts && python test_network_monitor.py`
Expected: `ModuleNotFoundError: No module named 'network_monitor'`

- [ ] **Step 3: Implementar `scripts/network_monitor.py`**

```python
"""
Push de pacotes e deteções de rede novos via WebSocket (/ws/network),
Fase 11 (Onda 2). Mesmo padrão estrutural de websocket_alerts.py: lê a
fonte (aqui, o ficheiro de captura na VM via SSH em vez do Wazuh Indexer),
identifica o que é novo, difunde por WebSocket, devolve a lista para os
testes conseguirem verificar sem WebSockets reais.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from datetime import datetime, timezone

from fastapi import WebSocket

from network_detections import detect_network_anomalies

logger = logging.getLogger("sentrylens.network_monitor")

PACKET_BUFFER_MAX = 2000

_PROTO_NAMES = {"1": "ICMP", "6": "TCP", "17": "UDP"}


class NetworkConnectionManager:
    """Gere as ligações WebSocket ativas ao /ws/network."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        dead: list[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for connection in dead:
            self.disconnect(connection)


def _parse_fields_line(line: str) -> dict | None:
    """
    Faz parse de uma linha CSV produzida pelo tshark (-T fields -E
    separator=, -E quote=n, exatamente 9 campos, na ordem:
    frame.time_epoch,ip.src,ip.dst,ip.proto,frame.len,tcp.srcport,
    tcp.dstport,udp.srcport,udp.dstport — ver scripts/deploy/sentrylens-tshark.service).
    Devolve None (nunca lança) se a linha não tiver os 9 campos ou os
    campos obrigatórios (timestamp/src_ip/dst_ip) vierem vazios/inválidos.
    """
    fields = line.rstrip("\n").split(",")
    if len(fields) != 9:
        return None
    epoch, src_ip, dst_ip, proto, length, tcp_src, tcp_dst, udp_src, udp_dst = fields
    if not epoch or not src_ip or not dst_ip:
        return None
    try:
        ts = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    except ValueError:
        return None
    src_port = int(tcp_src) if tcp_src else (int(udp_src) if udp_src else None)
    dst_port = int(tcp_dst) if tcp_dst else (int(udp_dst) if udp_dst else None)
    return {
        "timestamp": ts.isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": _PROTO_NAMES.get(proto, proto or "?"),
        "length": int(length) if length else 0,
        "src_port": src_port,
        "dst_port": dst_port,
    }


async def _poll_once(
    ssh_client,
    manager: NetworkConnectionManager,
    packet_buffer: deque,
    offset_state: dict,
    seen_detections: set,
    remote_path: str,
) -> tuple[list[dict], list[dict]]:
    """
    Uma iteração do polling: lê as linhas novas do ficheiro de captura via
    SSH, faz parse de cada uma, acrescenta ao buffer, corre a deteção sobre
    o buffer atual, difunde pacotes e deteções novos por /ws/network, e
    devolve (pacotes_novos, deteções_novas) para os testes.

    Deduplicação de deteções por chave (tipo, src_ip, dst_ip, minuto) —
    evita repetir a mesma deteção a cada poll de 5s enquanto o padrão
    persiste, mesmo espírito do seen_ids em websocket_alerts.py.
    """
    raw_new, new_offset = await ssh_client.read_new_lines(remote_path, offset_state.get("offset", 0))
    offset_state["offset"] = new_offset

    new_packets: list[dict] = []
    for line in raw_new.splitlines():
        packet = _parse_fields_line(line)
        if packet is None:
            continue
        packet_buffer.append(packet)
        new_packets.append(packet)

    if new_packets and manager.active_connections:
        for packet in new_packets:
            await manager.broadcast({"type": "packet", "packet": packet})

    all_detections = detect_network_anomalies(list(packet_buffer))
    new_detections: list[dict] = []
    for det in all_detections:
        key = (det["type"], det["src_ip"], det["dst_ip"], det["timestamp"][:16])
        if key in seen_detections:
            continue
        seen_detections.add(key)
        new_detections.append(det)

    if len(seen_detections) > 5000:
        seen_detections.clear()

    if new_detections and manager.active_connections:
        for det in new_detections:
            await manager.broadcast({"type": "network_detection", "detection": det})

    return new_packets, new_detections


async def network_poll_loop(
    ssh_client,
    manager: NetworkConnectionManager,
    packet_buffer: deque,
    remote_path: str,
    interval_seconds: int = 5,
) -> None:
    """Mesmo padrão de alert_poll_loop: try/except por iteração, nunca mata o loop."""
    offset_state: dict = {"offset": 0}
    seen_detections: set = set()
    while True:
        try:
            await _poll_once(ssh_client, manager, packet_buffer, offset_state, seen_detections, remote_path)
        except Exception:
            logger.exception("Falha ao fazer polling de rede para o WebSocket")
        await asyncio.sleep(interval_seconds)
```

- [ ] **Step 4: Correr o teste, confirmar que passa**

Run: `cd scripts && python test_network_monitor.py`
Expected: `[OK] Todos os testes passaram`, saída 0.

- [ ] **Step 5: Commit**

```bash
git add scripts/network_monitor.py scripts/test_network_monitor.py
git commit -m "feat: network_monitor.py - parsing/buffer/poll loop de rede (Fase 11, Onda 2)"
```

---

## Task 5: `main.py` — endpoints, `/ws/network`, integração

**Files:**
- Modify: `scripts/main.py:22` (import `deque`), `:36-61` (imports de domínio), `:91-97` (env vars, a seguir a `ATTACK_LOG_PATH`), `:178` (managers/clientes globais), `:292-303` (`on_startup`), `:659-689` (`get_redblue_metrics`, estende), depois da linha 689 (novo endpoint), depois da linha 773 (`/ws/network`)
- Modify: `scripts/test_redblue.py` (Parte 4 — endpoints de rede)
- Modify: `scripts/test_websocket_alerts.py` (autenticação de `/ws/network`)

**Interfaces:**
- Consumes: `detect_network_anomalies` (Task 1), `build_redblue_report(..., network_detections=...)` (Task 2), `VMSSHClient` (Task 3), `NetworkConnectionManager`/`network_poll_loop`/`PACKET_BUFFER_MAX` (Task 4).
- Produces: `GET /api/redblue/network`, `/ws/network`, `GET /api/redblue/metrics` com os campos novos — endpoints HTTP.

- [ ] **Step 1: Escrever os testes que falham, acrescentados a `scripts/test_redblue.py`**

Acrescentar ao ficheiro `scripts/test_redblue.py` (depois da Parte 3
escrita na Task 2, antes do `print()` / `if failures:` final):

```python
    # =========================================================================
    # Parte 4: endpoints de rede (Fase 11, Onda 2)
    # =========================================================================
    from unittest.mock import MagicMock

    # --- VM_SSH_HOST não configurado (default nos testes) -> "não configurado", nunca 500 ---
    resp_net_unconf = client.get("/api/redblue/network")
    check("GET /api/redblue/network sem VM_SSH_HOST -> 200", resp_net_unconf.status_code == 200)
    check(
        "GET /api/redblue/network sem VM_SSH_HOST -> configured=False",
        resp_net_unconf.json()["configured"] is False,
    )

    resp_metrics_unconf = client.get("/api/redblue/metrics")
    check(
        "GET /api/redblue/metrics sem VM_SSH_HOST -> network_capture_configured=False",
        resp_metrics_unconf.json()["network_capture_configured"] is False,
    )

    # --- Com vm_ssh_client simulado e buffer com pacotes -> devolve pacotes/deteções ---
    main.vm_ssh_client = MagicMock()  # só precisa de não ser None para "configured"=True
    main.packet_buffer.append({
        "timestamp": "2026-09-14T21:00:00+00:00", "src_ip": "192.168.1.170", "dst_ip": "192.168.1.44",
        "src_port": 50000, "dst_port": 3389, "protocol": "TCP", "length": 66,
    })
    resp_net_conf = client.get("/api/redblue/network")
    check("GET /api/redblue/network configurado -> configured=True", resp_net_conf.json()["configured"] is True)
    check("GET /api/redblue/network devolve o pacote do buffer", len(resp_net_conf.json()["packets"]) == 1)

    # --- sem X-API-Key -> 401, igual às outras rotas /api/* ---
    resp_net_no_key = client_no_key.get("/api/redblue/network")
    check("GET /api/redblue/network sem X-API-Key devolve 401", resp_net_no_key.status_code == 401)

    main.vm_ssh_client = None
    main.packet_buffer.clear()
```

E acrescentar ao ficheiro `scripts/test_websocket_alerts.py`, dentro de
`run_connection_tests()` (a seguir ao último `check(...)` desse bloco,
antes do fecho da função):

```python
    # --- /ws/network (Fase 11, Onda 2): mesma autenticação de /ws/alerts ---
    r5 = _attempt_connect("/ws/network")
    check("Ligação a /ws/network sem api_key não fica aceite", not r5["connected"])

    r6 = _attempt_connect(f"/ws/network?api_key={api_key}")
    check(
        "Ligação a /ws/network com api_key correta é aceite"
        + (" -- FALHA REAL: bloqueia indefinidamente" if r6["hung"] else ""),
        r6["connected"] and not r6["hung"],
    )
```

- [ ] **Step 2: Correr para confirmar que falha**

Run: `cd scripts && python test_redblue.py`
Expected: `AttributeError: module 'main' has no attribute 'vm_ssh_client'` (ou 404 em `/api/redblue/network`).

- [ ] **Step 3: `deque` no import da stdlib (linha 22)**

Em `scripts/main.py`, substituir:

```python
from collections import Counter
```

por:

```python
from collections import Counter, deque
```

- [ ] **Step 4: Imports de domínio (linhas 36-61)**

Substituir o bloco inteiro:

```python
import ml_anomalies
from admin_activity import build_admin_activity_report
from attack_scenarios import SCENARIOS
from compliance_evaluator import evaluate_alert_compliance, load_compliance_rules
from event_catalog import classify_alert
from feature_extractor import load_attack_log
from history_index import index_alert, query_history_index, read_jsonl_at_offset
from history_store import append_alert_history, append_compliance_history
from lifecycle import build_lifecycle_report
from nis2_lookup import lookup_nis2_classification
from org_profile import get_org_profile
from rbac import build_privileges_report, load_rbac_baseline
from redblue_correlator import build_redblue_report
from report_generator import generate_html_report, render_compliance_section
from system_monitor import (
    THRESHOLDS,
    check_thresholds,
    get_history,
    get_last_network_speed,
    get_specs,
    get_usage_history,
    measure_network_speed,
    record_usage_sample,
)
from wazuh_client import WazuhIndexerClient, WazuhManagerClient
from websocket_alerts import ConnectionManager, alert_poll_loop
```

por:

```python
import ml_anomalies
from admin_activity import build_admin_activity_report
from attack_scenarios import SCENARIOS
from compliance_evaluator import evaluate_alert_compliance, load_compliance_rules
from event_catalog import classify_alert
from feature_extractor import load_attack_log
from history_index import index_alert, query_history_index, read_jsonl_at_offset
from history_store import append_alert_history, append_compliance_history
from lifecycle import build_lifecycle_report
from network_detections import detect_network_anomalies
from network_monitor import NetworkConnectionManager, PACKET_BUFFER_MAX, network_poll_loop
from nis2_lookup import lookup_nis2_classification
from org_profile import get_org_profile
from rbac import build_privileges_report, load_rbac_baseline
from redblue_correlator import build_redblue_report
from report_generator import generate_html_report, render_compliance_section
from ssh_client import VMSSHClient
from system_monitor import (
    THRESHOLDS,
    check_thresholds,
    get_history,
    get_last_network_speed,
    get_specs,
    get_usage_history,
    measure_network_speed,
    record_usage_sample,
)
from wazuh_client import WazuhIndexerClient, WazuhManagerClient
from websocket_alerts import ConnectionManager, alert_poll_loop
```

- [ ] **Step 5: Env vars novas (a seguir a `ATTACK_LOG_PATH`, linha 97)**

Em `scripts/main.py`, a seguir a:

```python
ATTACK_LOG_PATH = os.getenv("ATTACK_LOG_PATH", os.path.join(os.path.dirname(__file__), "attack_log.jsonl"))
```

acrescentar:

```python

# SSH para a VM Wazuh (Fase 11, Onda 2) — só usado pela captura de rede via
# tshark. Funcionalidade opcional: sem VM_SSH_HOST definido,
# /api/redblue/network e /ws/network ficam "não configurados" em vez de
# derrubarem o backend — ao contrário de SENTRYLENS_API_KEY, que é
# fail-closed para tudo.
VM_SSH_HOST = os.getenv("VM_SSH_HOST", "")
VM_SSH_USER = os.getenv("VM_SSH_USER", "")
VM_SSH_KEY_PATH = os.getenv("VM_SSH_KEY_PATH", "") or None
NETWORK_CAPTURE_REMOTE_PATH = os.getenv("NETWORK_CAPTURE_REMOTE_PATH", "/var/log/sentrylens/network.csv")
```

- [ ] **Step 6: Managers/cliente globais (linha 178)**

Em `scripts/main.py`, substituir:

```python
ws_manager = ConnectionManager()
```

por:

```python
ws_manager = ConnectionManager()
network_ws_manager = NetworkConnectionManager()
packet_buffer: deque = deque(maxlen=PACKET_BUFFER_MAX)
vm_ssh_client = VMSSHClient(VM_SSH_HOST, VM_SSH_USER, VM_SSH_KEY_PATH) if VM_SSH_HOST else None
```

- [ ] **Step 7: `on_startup` (linhas 292-303)**

Substituir:

```python
@app.on_event("startup")
async def _start_system_monitor() -> None:
    """Lança o loop de monitorização em background, sem bloquear o arranque do servidor."""
    app.state.system_monitor_task = asyncio.create_task(_system_monitor_loop())
    app.state.alert_ws_poll_task = asyncio.create_task(
        alert_poll_loop(
            indexer_client,
            ws_manager,
            _enrich_alert,
            on_new_alerts=_persist_new_alerts,
        )
    )
```

por:

```python
@app.on_event("startup")
async def _start_system_monitor() -> None:
    """Lança o loop de monitorização em background, sem bloquear o arranque do servidor."""
    app.state.system_monitor_task = asyncio.create_task(_system_monitor_loop())
    app.state.alert_ws_poll_task = asyncio.create_task(
        alert_poll_loop(
            indexer_client,
            ws_manager,
            _enrich_alert,
            on_new_alerts=_persist_new_alerts,
        )
    )
    if vm_ssh_client is not None:
        app.state.network_ws_poll_task = asyncio.create_task(
            network_poll_loop(vm_ssh_client, network_ws_manager, packet_buffer, NETWORK_CAPTURE_REMOTE_PATH)
        )
```

- [ ] **Step 8: Estender `get_redblue_metrics` e acrescentar `get_redblue_network` (linhas 659-689, antes de `export_report`)**

Substituir o endpoint existente:

```python
@app.get("/api/redblue/metrics", dependencies=_REQUIRE_API_KEY)
async def get_redblue_metrics(
    hours: int = Query(168, ge=1, le=168, description="Janela temporal em horas"),
    window_seconds: int = Query(300, ge=30, le=3600, description="Janela de correlação por ataque, em segundos"),
):
    """
    Motor de correlação Red vs Blue (Fase 11): cruza o log de ataques da
    VM Kali com os alertas já classificados por regra + ML, por cenário
    de ataque — cobertura, MTTD, e se foi detetado por regra, ML, ambos
    ou nenhum.
    """
    try:
        model, scaler = ml_anomalies.load_model(ML_MODEL_DIR)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))

    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=hours, size=1000)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")

    ml_report = ml_anomalies.build_ml_anomalies_report(raw_alerts, model, scaler)
    attack_log = load_attack_log(ATTACK_LOG_PATH)
    report = build_redblue_report(attack_log, ml_report["results"], SCENARIOS, window_seconds=window_seconds)
    report["window_hours"] = hours
    # O fetch de alertas está limitado a 1000 (newest-first): sinaliza-se se
    # esse teto foi atingido, para que uma cobertura subestimada por
    # truncagem não passe silenciosamente por deteção falhada.
    report["alerts_fetched"] = len(raw_alerts)
    report["alerts_truncated"] = len(raw_alerts) >= 1000
    return report
```

por:

```python
@app.get("/api/redblue/metrics", dependencies=_REQUIRE_API_KEY)
async def get_redblue_metrics(
    hours: int = Query(168, ge=1, le=168, description="Janela temporal em horas"),
    window_seconds: int = Query(300, ge=30, le=3600, description="Janela de correlação por ataque, em segundos"),
):
    """
    Motor de correlação Red vs Blue (Fase 11): cruza o log de ataques da
    VM Kali com os alertas já classificados por regra + ML, e (Onda 2) com
    as deteções de rede — por cenário de ataque: cobertura, MTTD, e se foi
    detetado por regra/ML/rede/combinação/nenhum.
    """
    try:
        model, scaler = ml_anomalies.load_model(ML_MODEL_DIR)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))

    try:
        raw_alerts = await indexer_client.get_recent_alerts(hours=hours, size=1000)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erro ao contactar Wazuh Indexer: {e}")

    ml_report = ml_anomalies.build_ml_anomalies_report(raw_alerts, model, scaler)
    attack_log = load_attack_log(ATTACK_LOG_PATH)
    network_dets = detect_network_anomalies(list(packet_buffer)) if vm_ssh_client is not None else None
    report = build_redblue_report(
        attack_log, ml_report["results"], SCENARIOS, window_seconds=window_seconds, network_detections=network_dets,
    )
    report["window_hours"] = hours
    # O fetch de alertas está limitado a 1000 (newest-first): sinaliza-se se
    # esse teto foi atingido, para que uma cobertura subestimada por
    # truncagem não passe silenciosamente por deteção falhada.
    report["alerts_fetched"] = len(raw_alerts)
    report["alerts_truncated"] = len(raw_alerts) >= 1000
    report["network_capture_configured"] = vm_ssh_client is not None
    return report


@app.get("/api/redblue/network", dependencies=_REQUIRE_API_KEY)
async def get_redblue_network():
    """
    Snapshot do buffer de rede ao vivo (Fase 11, Onda 2) — últimos pacotes
    capturados na VM + deteções de padrões suspeitos na janela mais
    recente. Devolve 200 com listas vazias e "configured": false se
    VM_SSH_HOST não estiver definido — nunca 500 por causa disso; continua
    a exigir X-API-Key como qualquer outra rota /api/*.
    """
    if vm_ssh_client is None:
        return {"configured": False, "packets": [], "detections": []}
    packets = list(packet_buffer)
    return {
        "configured": True,
        "packets": packets,
        "detections": detect_network_anomalies(packets),
    }
```

- [ ] **Step 9: `/ws/network` (depois de `/ws/alerts`, a seguir à linha 773)**

Em `scripts/main.py`, a seguir ao fim de `websocket_alerts_endpoint`,
acrescentar:

```python


@app.websocket("/ws/network")
async def websocket_network_endpoint(websocket: WebSocket) -> None:
    """
    Push de pacotes e deteções de rede novos (Fase 11, Onda 2). Mesma
    autenticação de /ws/alerts: query param api_key, secrets.compare_digest
    — ver o comentário junto a /ws/alerts para o porquê de não poder usar
    dependencies=[Depends(...)] aqui.
    """
    api_key = websocket.query_params.get("api_key", "")
    if not SENTRYLENS_API_KEY or not secrets.compare_digest(api_key, SENTRYLENS_API_KEY):
        await websocket.close(code=1008)
        return

    await network_ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        network_ws_manager.disconnect(websocket)
```

- [ ] **Step 10: Correr os testes, confirmar que passam**

Run: `cd scripts && python test_redblue.py`
Expected: `[OK] Todos os testes passaram`, saída 0.

Run: `cd scripts && python test_websocket_alerts.py`
Expected: `[OK] Todos os testes passaram`, saída 0.

- [ ] **Step 11: Correr toda a bateria de testes já existente, confirmar zero regressões**

Run:
```bash
cd scripts
python test_with_mock.py
python test_new_panels.py
python test_ml_anomalies.py
python test_auth.py
python test_websocket_alerts.py
python test_history_store.py
python test_report_generator.py
python test_system_monitor.py
python test_compliance.py
python test_redblue.py
python test_network_detections.py
python test_ssh_client.py
python test_network_monitor.py
```
Expected: todos terminam com `[OK] Todos os testes passaram` / saída 0.

- [ ] **Step 12: Commit**

```bash
git add scripts/main.py scripts/test_redblue.py scripts/test_websocket_alerts.py
git commit -m "feat: endpoints GET /api/redblue/network e /ws/network (Fase 11, Onda 2)"
```

---

## Task 6: Captura na VM — `systemd` + `logrotate` (setup manual)

**Files:**
- Create: `scripts/deploy/sentrylens-tshark.service`
- Create: `scripts/deploy/sentrylens-network.logrotate`
- Modify: `docs/LAB_WAZUH_HYPERV.md` (nova secção no fim, depois da linha 261)

**Interfaces:** nenhuma — ficheiros de configuração aplicados manualmente
na VM, sem dependência de código Python. `NETWORK_CAPTURE_REMOTE_PATH`
(Task 5) tem de apontar para o mesmo caminho usado aqui.

Esta task não tem testes automatizados (é infraestrutura da VM, não
código Python) — a verificação é manual, com os comandos do Step 4.

- [ ] **Step 1: Criar `scripts/deploy/sentrylens-tshark.service`**

```ini
[Unit]
Description=SentryLens - captura de metadados de rede (Fase 11, Onda 2)
After=network.target

[Service]
# Substituir <IFACE> pela interface ligada ao switch "Lab-Wazuh" (ver
# `ip addr` na VM) e a lista de IPs do filtro BPF pelos IPs reais do
# laboratório (Kali + alvos Windows) — específico de cada instalação,
# editado à mão, não passado dinamicamente pelo backend.
ExecStart=/usr/bin/tshark -i <IFACE> -l \
    -f "host <IP_KALI> or host <IP_ALVO1> or host <IP_ALVO2>" \
    -T fields -E separator=, -E quote=n \
    -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto -e frame.len \
    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport
StandardOutput=append:/var/log/sentrylens/network.csv
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Criar `scripts/deploy/sentrylens-network.logrotate`**

```
/var/log/sentrylens/network.csv {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
```

`copytruncate` é necessário porque o `tshark` mantém o ficheiro aberto
continuamente — uma rotação por `mv`/renomear quebraria a escrita até o
serviço ser reiniciado; `copytruncate` copia e esvazia o ficheiro no
lugar, sem sinalizar o processo.

- [ ] **Step 3: Acrescentar a secção de setup a `docs/LAB_WAZUH_HYPERV.md`**

No fim do ficheiro (depois da linha 261), acrescentar:

```markdown
## Fase 11 (Onda 2) — Captura de rede em tempo real

Passo manual, feito uma vez, depois do setup base do laboratório (SSH já
a funcionar — ver secção acima). Como os outros scripts desta pasta, não
é automatizado.

1. Instalar o `tshark` na VM (se ainda não estiver): `sudo apt install tshark`
   (aceitar "non-root users can capture packets" quando perguntado, ou
   correr o serviço como root — ver `sudo dpkg-reconfigure wireshark-common`).
2. Descobrir a interface ligada ao switch "Lab-Wazuh": `ip addr` (procurar
   a interface com o IP da VM usado pelo Manager/Indexer).
3. Copiar `scripts/deploy/sentrylens-tshark.service` para a VM, editar
   `<IFACE>` e a lista de IPs do filtro (Kali + alvos Windows reais deste
   laboratório):
   ```bash
   scp scripts/deploy/sentrylens-tshark.service fernando@<IP_DA_VM>:/tmp/
   ssh fernando@<IP_DA_VM>
   sudo mkdir -p /var/log/sentrylens
   sudo mv /tmp/sentrylens-tshark.service /etc/systemd/system/
   sudo nano /etc/systemd/system/sentrylens-tshark.service  # editar <IFACE>/IPs
   sudo systemctl daemon-reload
   sudo systemctl enable --now sentrylens-tshark.service
   ```
4. Copiar `scripts/deploy/sentrylens-network.logrotate`:
   ```bash
   scp scripts/deploy/sentrylens-network.logrotate fernando@<IP_DA_VM>:/tmp/
   ssh fernando@<IP_DA_VM> "sudo mv /tmp/sentrylens-network.logrotate /etc/logrotate.d/sentrylens-network"
   ```
5. Verificar que está a escrever:
   ```bash
   ssh fernando@<IP_DA_VM> "sudo systemctl status sentrylens-tshark.service"
   ssh fernando@<IP_DA_VM> "sudo tail -f /var/log/sentrylens/network.csv"
   ```
   Deve mostrar linhas novas a aparecer enquanto houver tráfego entre os
   IPs do filtro (ex: um `ping` do Kali a um alvo do laboratório).
6. No `.env` do backend, definir `VM_SSH_HOST`/`VM_SSH_USER`/
   `VM_SSH_KEY_PATH` (ver `scripts/.env.example`) para o backend conseguir
   ligar-se por SSH e começar a fazer polling deste ficheiro.
```

- [ ] **Step 4: Commit**

```bash
git add scripts/deploy/sentrylens-tshark.service scripts/deploy/sentrylens-network.logrotate docs/LAB_WAZUH_HYPERV.md
git commit -m "docs: setup manual da captura de rede na VM - systemd + logrotate (Fase 11, Onda 2)"
```

---

## Task 7: Documentação — `CLAUDE.md`, `README.md`, `docs/ML.md`, `docs/API.md`, `.env.example`

**Files:**
- Modify: `CLAUDE.md` (secção "Arquitetura do backend" + lista de testes)
- Modify: `README.md:128-131` (árvore de ficheiros), `:331` (tabela de testes), `:368-374` (tabela de endpoints)
- Modify: `docs/ML.md:176` (depois de `**Testes:** scripts/test_redblue.py.`)
- Modify: `docs/API.md:68` (depois de `**Testes:** scripts/test_websocket_alerts.py.`)
- Modify: `scripts/.env.example` (a seguir ao bloco `ATTACK_LOG_PATH`)

**Interfaces:** nenhuma — só documentação, sem código.

- [ ] **Step 1: `CLAUDE.md`**

Na secção "Arquitetura do backend (`scripts/`)", a seguir ao parágrafo
que descreve `redblue_correlator.py`, acrescentar:

```markdown
- `network_detections.py` — deteção de padrões suspeitos de rede (Fase 11,
  Onda 2), a partir só de metadados de pacotes: port scan, brute force,
  pico de volume, com limiares fixos em `RULES`. Função pura
  `detect_network_anomalies`.
- `ssh_client.py` — `VMSSHClient`, único ponto de SSH com a VM Wazuh
  (mesmo papel que `wazuh_client.py` tem para HTTP), usado só por
  `network_monitor.py` para ler o ficheiro de captura que o `tshark`
  escreve na VM.
- `network_monitor.py` — parsing das linhas do `tshark` (CSV de campos
  fixos), buffer efémero em memória (`deque(maxlen=2000)`, sem
  persistência própria) e o loop de polling/broadcast para `/ws/network`,
  mesmo padrão de `websocket_alerts.py`. `redblue_correlator.py` ganhou
  um parâmetro opcional `network_detections` — a rede passa a ser um 3º
  método de deteção, independente do Wazuh, expondo tentativas de ataque
  detetadas só pela rede (`detected_by_network_only`/`coverage_gap`).
  Deliberadamente isolado de `history_store.py`/`compliance_evaluator.py`/
  `/ws/alerts` — só alimenta `/api/redblue/network`, `/ws/network` e a
  análise de cobertura de `/api/redblue/metrics`. Captura na VM Wazuh via
  `tshark` (`scripts/deploy/`, setup manual — ver
  `docs/LAB_WAZUH_HYPERV.md`), filtrada por BPF, com `logrotate` a manter
  7 dias. Frontend (painel de rede na 10ª aba) ainda não implementado —
  Onda 3.
```

Na lista de comandos de teste, acrescentar as linhas:

```bash
python test_network_detections.py # deteção de padrões suspeitos de rede
python test_ssh_client.py         # VMSSHClient (SSH mockado)
python test_network_monitor.py    # parsing/buffer/poll loop de rede
```

- [ ] **Step 2: `README.md` — árvore de ficheiros (linhas 128-131)**

A seguir à linha
`│   ├── websocket_alerts.py      ← ConnectionManager + alert_poll_loop (/ws/alerts, 10s)`,
acrescentar:

```
│   ├── network_detections.py    ← deteção de padrões suspeitos de rede (port scan/brute force/volume)
│   ├── ssh_client.py            ← VMSSHClient, único ponto de SSH com a VM
│   ├── network_monitor.py       ← parsing/buffer/poll loop de rede (/ws/network, 5s)
```

- [ ] **Step 3: `README.md` — tabela de testes (linha 331)**

A seguir à linha
`python test_redblue.py           # correlação Red vs Blue + /api/redblue/metrics`,
acrescentar:

```
python test_network_detections.py # deteção de padrões suspeitos de rede
python test_ssh_client.py         # VMSSHClient (SSH mockado)
python test_network_monitor.py    # parsing/buffer/poll loop de rede + /ws/network
```

- [ ] **Step 4: `README.md` — tabela de endpoints (linhas 368-374)**

A seguir à linha
`| GET | \`/api/redblue/metrics\` | Correlação Red vs Blue (Fase 11) — cobertura/MTTD por cenário de ataque — ver [docs/ML.md](docs/ML.md#-correlação-red-vs-blue-getapiredbluemetrics-fase-11) |`,
acrescentar:

```
| GET | `/api/redblue/network` | Snapshot do buffer de rede ao vivo (Fase 11, Onda 2) — pacotes + deteções — ver [docs/ML.md](docs/ML.md#-correlação-red-vs-blue-getapiredbluemetrics-fase-11) |
```

E a seguir à linha
`| WS | \`/ws/alerts\` | Push de alertas novos em tempo real (auth por query param) |`,
acrescentar:

```
| WS | `/ws/network` | Push de pacotes e deteções de rede em tempo real (Fase 11, Onda 2, auth por query param) — ver [docs/API.md](docs/API.md#-websocket-de-rede-em-tempo-real-wsnetwork) |
```

- [ ] **Step 5: `docs/ML.md` — estender a secção Red vs Blue (depois da linha 176)**

A seguir a `**Testes:** \`scripts/test_redblue.py\`.`, acrescentar:

```markdown
### Rede como 3º método de deteção (Onda 2)

`build_redblue_report()` aceita agora um parâmetro opcional
`network_detections` (lista de deteções de
`network_detections.detect_network_anomalies()` — port scan/brute
force/pico de volume, a partir de metadados de pacotes capturados na VM
Wazuh via `tshark`, ver `docs/LAB_WAZUH_HYPERV.md`). Omitido/`None`,
`build_redblue_report()` comporta-se exatamente como na Onda 1.

Cada tentativa em `attempts` ganha:

```json
{
  "detected_by_network": true,
  "network_detection_types": ["port_scan"],
  "mttd_network_seconds": 4.8,
  "coverage_gap": true
}
```

`coverage_gap: true` significa: a rede detetou este ataque, mas o Wazuh
(regra + ML sobre Windows Event Log) não — é a métrica principal desta
onda. `by_scenario`/`overall` ganham `detected_by_network_only`,
`detected_by_windows_only`, `detected_by_both_sources`,
`detected_by_neither`.

`GET /api/redblue/metrics` ganha `"network_capture_configured": bool` no
topo da resposta.

### `GET /api/redblue/network` (Fase 11, Onda 2)

Snapshot do buffer de rede ao vivo (últimos ~2000 pacotes em memória, sem
persistência no backend — a VM é a fonte de verdade, com `logrotate` a
manter 7 dias):

```json
{
  "configured": true,
  "packets": [
    {"timestamp": "2026-09-28T14:00:00+00:00", "src_ip": "192.168.1.170", "dst_ip": "192.168.1.20", "src_port": 54321, "dst_port": 3389, "protocol": "TCP", "length": 66}
  ],
  "detections": [
    {"type": "port_scan", "src_ip": "192.168.1.170", "dst_ip": "192.168.1.20", "timestamp": "2026-09-28T14:00:30+00:00", "detail": {"distinct_ports": 16}}
  ]
}
```

`"configured": false` (com `packets`/`detections` vazios, sempre `200`)
quando `VM_SSH_HOST` não está definido no `.env` — funcionalidade
opcional, nunca fail-closed.

**Testes:** `scripts/test_network_detections.py`, `scripts/test_ssh_client.py`,
`scripts/test_network_monitor.py`, mais a Parte 3/4 de `scripts/test_redblue.py`.
```

- [ ] **Step 6: `docs/API.md` — nova secção `/ws/network` (depois da linha 68)**

A seguir a `**Testes:** \`scripts/test_websocket_alerts.py\`.` (fim da
secção `/ws/alerts`), acrescentar:

```markdown
## 🔌 WebSocket de rede em tempo real (`/ws/network`)

Fase 11 (Onda 2). O backend mantém um ciclo interno
(`network_poll_loop`) que lê por SSH o ficheiro de captura de metadados
de rede que o `tshark` escreve na VM Wazuh, a cada **5s**. Funcionalidade
opcional: só arranca se `VM_SSH_HOST` estiver definido no `.env`.

```
ws://localhost:8001/ws/network?api_key=<a mesma SENTRYLENS_API_KEY>
```

Mesma autenticação de `/ws/alerts` — query param `api_key`, fecha com
`1008` sem parâmetro ou com valor errado.

Duas mensagens possíveis:
- `{"type": "packet", "packet": {...}}` — um pacote novo (metadados só:
  `timestamp`/`src_ip`/`dst_ip`/`src_port`/`dst_port`/`protocol`/`length`,
  nunca payload).
- `{"type": "network_detection", "detection": {...}}` — uma deteção nova
  de `network_detections.py` (port scan/brute force/pico de volume),
  deduplicada por minuto enquanto o padrão persiste.

**Testes:** `scripts/test_network_monitor.py`, mais o caso de autenticação
em `scripts/test_websocket_alerts.py`.
```

- [ ] **Step 7: `scripts/.env.example`**

A seguir ao bloco `ATTACK_LOG_PATH`, acrescentar:

```
# SSH para a VM Wazuh (Fase 11, Onda 2) — só necessário para a captura de
# rede via tshark. Deixar vazio desliga a funcionalidade sem afetar o
# resto do backend (/api/redblue/network e /ws/network ficam "não
# configurados", nunca 401/500 por causa disso).
VM_SSH_HOST=
VM_SSH_USER=
VM_SSH_KEY_PATH=

# Caminho remoto (na VM) do ficheiro de captura que o tshark vai
# escrevendo (ver scripts/deploy/sentrylens-tshark.service).
NETWORK_CAPTURE_REMOTE_PATH=/var/log/sentrylens/network.csv
```

- [ ] **Step 8: Commit**

```bash
git add CLAUDE.md README.md docs/ML.md docs/API.md scripts/.env.example
git commit -m "docs: documenta a monitorizacao de rede em tempo real (Fase 11, Onda 2)"
```

---

## Task 8: Registo de execução no Notion

**Files:** nenhum ficheiro do repositório — só a página Notion.

**Interfaces:** nenhuma.

- [ ] **Step 1: Confirmar os commits das Tasks 1-7**

Run: `git log --oneline -8`
Expected: 8 commits desta onda, do mais recente (`docs: documenta a
monitorizacao de rede...`) até ao mais antigo (`feat: deteção de padrões
suspeitos de rede...`).

- [ ] **Step 2: Apendar uma nova secção à página Notion**

Usar a ferramenta MCP do Notion para apendar, no fim da página
`page_id: 3caa99e6-526b-8111-89be-db8b6ffe765b`, um bloco no mesmo
formato usado pelas fases anteriores ("Registo de execução"):

- Título: `# 📝 Registo de execução — Fase 11 (Onda 2)`
- Nome dos ficheiros criados/alterados por task, com o hash de cada
  commit (obtido no Step 1)
- Resumo do que foi validado pelos testes (8 casos de
  `network_detections`, 3 de `ssh_client`, ~8 de `network_monitor`, mais
  5 novos casos de correlação em `test_redblue.py` e 2 de autenticação em
  `test_websocket_alerts.py`)
- Nota explícita: "rede passa a ser um 3º método de deteção, independente
  do Wazuh — `detected_by_network_only`/`coverage_gap` expõe ataques que
  só a captura de rede apanhou. Frontend (painel de rede) fica para a
  Onda 3 — ainda não implementado."
- Atualizar a nota "Frontend (10ª aba) ainda não implementado — ver Onda 2"
  deixada pela Onda 1, para refletir que a Onda 2 (backend de rede) está
  feita e o frontend passou a ser Onda 3.

- [ ] **Step 3: Confirmar a atualização**

Reler a página Notion (`notion-fetch` com o mesmo `page_id`) e confirmar
que a nova secção aparece e que a nota da Onda 1 foi atualizada, não
duplicada.
