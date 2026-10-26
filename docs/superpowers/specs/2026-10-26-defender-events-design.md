# Eventos do Microsoft Defender Antivirus via Wazuh — desenho

Data: 2026-10-26. Estado: aprovado em conversa (o utilizador escolheu o `install-wazuh-agent.ps1` para a configuração do agente).

## Porquê

Desativar ou contornar o Defender é um passo clássico de um atacante, e o SentryLens hoje não vê nada do Defender: o agente Wazuh só recolhe `Application`, `Security` e `System`. O canal `Microsoft-Windows-Windows Defender/Operational` tem os eventos que interessam (malware detetado, proteção desligada, configuração alterada).

## Factos verificados (2026-10-26)

- `C:\Program Files (x86)\ossec-agent\ossec.conf` só tem `<localfile>` de Application, Security, System e `active-responses.log`.
- O manager já tem as regras: `0600-win-wdefender_rules.xml`, ids 62107–62161, uma por Event ID. Níveis relevantes: 1116→62123 L12, 1117→62124 L3, 1118→62125 L8, 1119→62126 L14, 5001→62152 L5, 5007→62154 L5, 5008→62155 L12. Não há regras para 1121/1122 (ASR): fora do âmbito.
- Nesta máquina o 5007 aparece ~177 vezes por semana, todos registo de rotina (`WdConfigHash`, `ServiceStartStates`, `InitializingComponentProgress`). Campos do evento: `Product Name`, `Product Version`, `Old Value`, `New Value` (o Wazuh expõe-os como `data.win.eventdata.oldValue`/`newValue`).
- `feature_extractor._EVENT_ID_ORDER` e `model_registry.catalog_sha256()` derivam de `CRITICAL_EVENTS`. Acrescentar-lhe IDs desloca o `event_id_encoded` e invalida todos os modelos treinados.
- O Event ID não identifica o canal: 1000 e 1001 existem também no canal Application (crash de aplicação / WER).

## Objetivos

1. O agente recolhe só os IDs 1116, 1117, 1118, 1119, 5001, 5007 e 5008 do canal do Defender, configurado pelo `install-wazuh-agent.ps1`.
2. Esses alertas aparecem no dashboard com nome, severidade, categoria e recomendação próprios.

## Não-objetivos

- Sysmon, `Get-MpComputerStatus`, regras ASR (1121/1122), regras novas no Wazuh.
- ML, vaccines e conformidade: continuam a ver o Event ID sem canal (tratam-no como não catalogado, como hoje). Isto é uma limitação aceite.
- Alterar o `ossec.conf` desta máquina sem o utilizador correr o script como administrador.

## Decisões

- **Catálogo à parte.** `DEFENDER_EVENTS` em `event_catalog.py`, indexado só por ID mas consultado apenas quando o canal é o do Defender. `CRITICAL_EVENTS` não muda (preserva os modelos ML e evita a colisão 1000/1001).
- **`classify_alert(win_event_id, channel=None, eventdata=None)`.** Chamadas só com o ID ficam exatamente como estão. Nova função `classify_wazuh_alert(raw)` extrai ID, canal e eventdata de um alerta bruto; `main._enrich_alert` e `detection_event.from_rule_alert` passam a usá-la.
- **Severidades (decisão minha, ajustável):** 1116 high, 1117 low, 1118 high, 1119 high, 5001 high, 5008 high. O 5007 é `info`, e só sobe a `high` se `newValue` tocar em `\Exclusions\` ou puser `DisableRealtimeMonitoring`/`DisableAntiSpyware`/`DisableAntiVirus`/`DisableBehaviorMonitoring`/`DisableIOAVProtection` a `0x1`.
- **Categoria nova:** `protecao_endpoint`.
- **Script:** função `Add-DefenderCollection` no `install-wazuh-agent.ps1`, idempotente (marcador em comentário), com cópia de segurança do `ossec.conf`; mais o modo `-ConfigureDefenderOnly` (decisão minha) para um agente já instalado, sem voltar a correr o MSI.
- **Filtro no agente:** `<query>Event/System[EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=5001 or EventID=5007 or EventID=5008]</query>`.
