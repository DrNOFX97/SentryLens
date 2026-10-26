# Eventos do Defender via Wazuh — Plano de Implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Os eventos do canal Microsoft Defender Antivirus chegam ao Wazuh (configurado pelo `install-wazuh-agent.ps1`) e aparecem no dashboard classificados.

**Architecture:** Catálogo `DEFENDER_EVENTS` separado de `CRITICAL_EVENTS`, consultado só quando o canal do alerta é o do Defender; `classify_alert` ganha parâmetros opcionais e uma função nova extrai canal/eventdata do alerta bruto. O agente recolhe o canal por uma entrada `<localfile>` acrescentada ao `ossec.conf` pelo script de instalação.

**Tech Stack:** Python 3 (stdlib, testes standalone sem pytest), PowerShell 5.1, Wazuh eventchannel.

**Spec:** `docs/superpowers/specs/2026-10-26-defender-events-design.md`

## Global Constraints

- Testes standalone no estilo do repo: `check(label, cond)` a imprimir `[OK   ]`/`[FALHOU]`, `sys.exit(1)` se falhar; correm a partir de `scripts/` com o `.venv`. Os que importam `main` definem `SENTRYLENS_API_KEY` em `os.environ` antes do import e fazem `main.app.router.on_startup.clear()`.
- `CRITICAL_EVENTS` não pode receber nenhum ID novo (preserva `model_registry.catalog_sha256()`).
- `classify_alert(<só o ID>)` mantém exatamente o comportamento atual.
- Texto de UI e comentários em português; `.ps1` gravado com BOM UTF-8 (o ficheiro já tem).
- Sem `Co-Authored-By` nem "Generated with Claude Code" em commits (regra do CLAUDE.md).
- O canal é exatamente `Microsoft-Windows-Windows Defender/Operational`; os IDs recolhidos são 1116, 1117, 1118, 1119, 5001, 5007, 5008.

## Review Focus

1. Evento 1000/1001 do canal `Application` nunca é rotulado como Defender (e o ID do Defender sem canal fica "não catalogado").
2. 5007 de rotina (`WdConfigHash = 0x...`) fica `info`; `\Exclusions\` ou `DisableRealtimeMonitoring = 0x1` sobe a `high`; `= 0x0` não sobe.
3. Alerta sem `data.win`, sem `channel`, ou com `eventdata` que não é dict: sem exceção, resultado igual ao de hoje.
4. `ossec.conf` com dois blocos `<ossec_config>`, corrido duas vezes: exatamente uma entrada do Defender; ficheiro inexistente: erro claro e saída ≠ 0.
5. `CRITICAL_EVENTS` e `DEFENDER_EVENTS` disjuntos, para o hash do catálogo (e os modelos ML) não mudarem.

---

### Task 1: Catálogo do Defender e `classify_alert` com canal

**Files:**
- Modify: `scripts/event_catalog.py`
- Create: `scripts/test_defender_catalog.py`
- Modify: `README.md` (secção Testes: uma linha para o novo ficheiro)

**Interfaces:**
- Produces:
  - `DEFENDER_CHANNEL: str = "Microsoft-Windows-Windows Defender/Operational"`
  - `DEFENDER_EVENTS: dict[int, dict[str, str]]` (mesmas chaves `name`/`severity`/`category` de `CRITICAL_EVENTS`; categoria `protecao_endpoint`)
  - `classify_alert(win_event_id: int | None, channel: str | None = None, eventdata: dict | None = None) -> dict[str, str]` (mesmas 4 chaves de hoje)

- [ ] **Step 1: Escrever `test_defender_catalog.py` (falha primeiro)**
  Casos com `check()`:
  - `classify_alert(1116, DEFENDER_CHANNEL)` → `severity == "high"`, `category == "protecao_endpoint"`, `friendly_name == "Defender: Malware Detected"`.
  - Severidades por ID (1117 low, 1118 high, 1119 high, 5001 high, 5008 high) e que cada um tem recomendação não vazia, diferente do texto genérico "Investigar e tomar ação apropriada.".
  - `classify_alert(1116)` e `classify_alert(1116, "Application")` → `friendly_name == "Evento não catalogado"`; `classify_alert(1000, "Application")` e `classify_alert(1000, DEFENDER_CHANNEL)` → idem.
  - `classify_alert(4625)` e `classify_alert(4625, "Security")` iguais ao resultado atual (`friendly_name == "Failed Logon"`, `severity == "high"`).
  - 5007: `eventdata={"newValue": r"HKLM\SOFTWARE\Microsoft\Windows Defender\CoreService\WdConfigHash = 0xBCF68827"}` → `info`; `newValue` com `\Exclusions\Paths\C:\temp = 0x0` → `high`; `DisableRealtimeMonitoring = 0x1` → `high`; `DisableRealtimeMonitoring = 0x0` → `info`; `eventdata=None`, `{}`, `{"newValue": None}` e `eventdata="x"` → `info`, sem exceção.
  - `set(DEFENDER_EVENTS) & set(CRITICAL_EVENTS) == set()` (comentário: protege `catalog_sha256`).
  - Canal comparado sem distinguir maiúsculas (`DEFENDER_CHANNEL.upper()` também classifica).

- [ ] **Step 2: Correr e ver falhar**
  Run: `cd scripts && .venv/Scripts/python.exe test_defender_catalog.py`
  Expected: erro de import (`DEFENDER_CHANNEL` não existe).

- [ ] **Step 3: Implementar em `scripts/event_catalog.py`**
  Acrescentar `DEFENDER_CHANNEL`, `DEFENDER_EVENTS` (nomes em inglês com prefixo `Defender: `, severidades da spec; 5007 = `info` por omissão com nome `Defender: Configuration Changed`), `DEFENDER_RECOMMENDATIONS`, e o parâmetro `channel`/`eventdata` em `classify_alert`. Quando `channel` bate (casefold) com `DEFENDER_CHANNEL`, só `DEFENDER_EVENTS` é consultado; caso contrário o fluxo atual com `CRITICAL_EVENTS`. A regra do 5007 vive numa função privada `_defender_5007_is_tampering(eventdata) -> bool` com a lista de padrões da spec (`\Exclusions\` e os cinco `Disable…` a `0x1`), tolerante a qualquer tipo de entrada.

- [ ] **Step 4: Correr e ver passar**
  Run: `cd scripts && .venv/Scripts/python.exe test_defender_catalog.py && .venv/Scripts/python.exe test_model_registry.py`
  Expected: `[OK] Todos os testes passaram` nos dois (o segundo prova que o hash do catálogo não mexeu). Se o nome do teste do registo for outro, correr `python run_all_tests.py registry`.

- [ ] **Step 5: Commit**
  ```bash
  git add scripts/event_catalog.py scripts/test_defender_catalog.py README.md
  git commit -m "feat(catalog): catalogo de eventos do Defender, separado de CRITICAL_EVENTS"
  ```

---

### Task 2: Ligar a classificação aos alertas (API e deteções)

**Files:**
- Modify: `scripts/event_catalog.py`, `scripts/main.py` (`_enrich_alert`, descrição do parâmetro `category` em `/api/alerts`), `scripts/detection_event.py` (`from_rule_alert`)
- Create: `scripts/test_defender_alerts.py`

**Interfaces:**
- Consumes: `classify_alert`, `DEFENDER_CHANNEL` (Task 1).
- Produces: `classify_wazuh_alert(raw: dict) -> dict[str, str]` em `event_catalog.py`: lê `data.win.system.eventID` (int), `data.win.system.channel` e `data.win.eventdata`, devolve o mesmo dict de `classify_alert`; nunca levanta exceção para entrada malformada (devolve o resultado "não catalogado").

- [ ] **Step 1: Escrever `test_defender_alerts.py` (falha primeiro)**
  Define `SENTRYLENS_API_KEY` antes de `import main`. Fixture `defender_alert(event_id, event_data=None, channel=DEFENDER_CHANNEL)` com `@timestamp`, `agent.ip`, `rule.id`/`level`, `data.win.system.{eventID,channel}`, `data.win.eventdata`. Casos:
  - `main._enrich_alert(defender_alert(1116))` → `friendly_name == "Defender: Malware Detected"`, `severity == "high"`, `category == "protecao_endpoint"`, `windows_event_id == 1116`.
  - Mesmo alerta com `channel="Application"` → "Evento não catalogado" (o `windows_event_id` continua 1116).
  - `from_rule_alert(defender_alert(5001))` → `e["severity"] == "high"` e `e["label"] == "Defender: Real-Time Protection Disabled"` (usar o nome que o Task 1 deu ao 5001; ajustar a string a esse nome).
  - 5007 de rotina → `from_rule_alert(...)["severity"] == "info"`.
  - Alertas sem `data`, com `data.win` sem `system`, `eventdata` a `None`, e `eventID` não numérico: `classify_wazuh_alert` devolve "Evento não catalogado" sem exceção.
  - Alerta 4625 existente (sem canal) continua `high`/"Failed Logon" em `_enrich_alert` e `from_rule_alert`.

- [ ] **Step 2: Correr e ver falhar**
  Run: `cd scripts && .venv/Scripts/python.exe test_defender_alerts.py`
  Expected: FAIL/erro (`classify_wazuh_alert` não existe; classificação do Defender "não catalogado").

- [ ] **Step 3: Implementar**
  `classify_wazuh_alert` em `event_catalog.py`. Em `main._enrich_alert` e `detection_event.from_rule_alert` trocar `classify_alert(<id>)` por `classify_wazuh_alert(<alerta>)` (manter `_extract_windows_event_id`/`_windows_event_id` para o campo `windows_event_id`). Acrescentar `protecao_endpoint` à lista da descrição do parâmetro `category` de `/api/alerts`.

- [ ] **Step 4: Correr e ver passar, mais regressão**
  Run: `cd scripts && .venv/Scripts/python.exe test_defender_alerts.py && .venv/Scripts/python.exe run_all_tests.py`
  Expected: todos PASS (hoje 75/75, mais os 2 novos; `test_attack_log_ids.py`/`test_attack_targets.py` podem falhar por flake conhecido: repetir isolados).

- [ ] **Step 5: Commit**
  ```bash
  git add scripts/event_catalog.py scripts/main.py scripts/detection_event.py scripts/test_defender_alerts.py
  git commit -m "feat(alerts): classificar alertas do Defender por canal em main e detection_event"
  ```

---

### Task 3: `install-wazuh-agent.ps1` configura a recolha do canal

**Files:**
- Modify: `scripts/install-wazuh-agent.ps1` (manter o BOM UTF-8), `scripts/README.md` (descrever o parâmetro novo e o que não faz)
- Create: `scripts/test_install_agent_defender.py`

**Interfaces:**
- Produces: parâmetros novos do script `-ConfigureDefenderOnly` (switch), `-ConfPath` (string, default `C:\Program Files (x86)\ossec-agent\ossec.conf`), `-NoRestart` (switch); função `Add-DefenderCollection -ConfPath <string>`.

- [ ] **Step 1: Escrever `test_install_agent_defender.py` (falha primeiro)**
  Usa um `ossec.conf` de fixture numa pasta temporária (um com 1 bloco `<ossec_config>` e um com 2 blocos) e corre `powershell -NoProfile -ExecutionPolicy Bypass -File install-wazuh-agent.ps1 -ConfigureDefenderOnly -ConfPath <tmp> -NoRestart`. Sem `powershell` no PATH falha de propósito (como `node` nos testes do frontend). Casos:
  - Exit code 0; o ficheiro passa a ter exatamente 1 `<location>Microsoft-Windows-Windows Defender/Operational</location>`, o `<log_format>eventchannel</log_format>` e a `<query>` com os 7 IDs, tudo dentro de um bloco `<ossec_config>` (antes do último `</ossec_config>`).
  - Segunda execução: continua 1 entrada (idempotente) e o ficheiro fica byte a byte igual ao da 1ª execução.
  - Existe cópia `ossec.conf.bak-sentrylens` com o conteúdo original; uma 2ª execução não a sobrescreve.
  - O resto do ficheiro original está intacto (as `<localfile>` de Security/System continuam lá, sem BOM acrescentado).
  - `-ConfPath` para um ficheiro inexistente: exit code ≠ 0 e mensagem que contém o caminho.
  - O `.ps1` começa com os bytes `EF BB BF`.

- [ ] **Step 2: Correr e ver falhar**
  Run: `cd scripts && .venv/Scripts/python.exe test_install_agent_defender.py`
  Expected: FAIL (parâmetro `-ConfigureDefenderOnly` desconhecido, exit ≠ 0).

- [ ] **Step 3: Implementar em `install-wazuh-agent.ps1`**
  Acrescentar os 3 parâmetros ao `param(...)` e a função `Add-DefenderCollection` (marcador `<!-- SentryLens: Defender -->`, cópia de segurança, leitura/escrita UTF-8 sem BOM, inserção antes do último `</ossec_config>`). O modo `-ConfigureDefenderOnly` corre logo a seguir à verificação de administrador, que só se exige quando não há `-NoRestart`; chama a função, faz `Restart-Service WazuhSvc` (salvo `-NoRestart`) e termina sem descarregar nem instalar nada. No fluxo normal, chamar a função depois de o `msiexec` terminar com sucesso e antes de `Start-Service`. Nada disto muda regras de firewall nem o resto do script.

- [ ] **Step 4: Correr e ver passar**
  Run: `cd scripts && PYTHONIOENCODING=utf-8 .venv/Scripts/python.exe test_install_agent_defender.py`
  Expected: `[OK] Todos os testes passaram`.

- [ ] **Step 5: Commit**
  ```bash
  git add scripts/install-wazuh-agent.ps1 scripts/test_install_agent_defender.py scripts/README.md
  git commit -m "feat(agent): install-wazuh-agent recolhe o canal do Defender (-ConfigureDefenderOnly)"
  ```

---

### Task 4: Aplicar a este PC e verificar com dados reais (manual, com autorização)

**Files:** nenhum (só operação).

**Interfaces:** Consumes: Task 3. Passos que alteram o sistema ficam à espera de ordem do utilizador.

- [ ] **Step 1: O utilizador corre, num PowerShell como Administrador:**
  `.\scripts\install-wazuh-agent.ps1 -ConfigureDefenderOnly` (reinicia o serviço `WazuhSvc`). Confirmar que `ossec.conf` ganhou a entrada e `ossec.conf.bak-sentrylens` existe.

- [ ] **Step 2: Verificar a chegada de alertas (só leitura).**
  Esperar um 5007 natural (~1 por hora) e consultar `GET /api/alerts?hours=1&category=protecao_endpoint` com a API key. Expected: pelo menos um alerta com `windows_event_id == 5007`, `severity == "info"`, `friendly_name == "Defender: Configuration Changed"`.

- [ ] **Step 3 (só com autorização explícita): teste EICAR.**
  Criar numa pasta temporária um ficheiro com a string de teste EICAR; o Defender deve pô-lo em quarentena. Expected: alertas 1116 (`high`) e 1117 (`low`) no `/api/alerts`; apagar a pasta no fim. Se o utilizador preferir, este passo vira um cenário Red vs Blue à parte.
