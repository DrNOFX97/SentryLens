# Guião de demo (3 minutos)

Seis passos, um por aba. Cada passo usa só abas que existem no menu lateral do `index.html`. A demo mostra o ciclo completo: **atacar, detetar, investigar, medir e propor uma correção para o que escapou**.

## Antes de começar (fora dos 3 minutos)

- Laboratório ligado: VM Wazuh e agente Windows a reportar (ver `README.md`, "Início rápido").
- `.\scripts\start-backend.ps1` e `.\scripts\start-frontend.ps1` (abre o dashboard em `http://127.0.0.1:5500`).
- Kali com `scripts/attack_scenarios.py` e o alvo (`--target`) na allowlist de alvos (`scripts/attack_targets.json`; por omissão só loopback e blocos de documentação são aceites).
- Comando do passo 2 já escrito num terminal da Kali, por executar:
  `python attack_scenarios.py --target <IP do agente> --scenario brute_force_rdp`
- Nota: o cenário chama-se `brute_force_rdp` (`python attack_scenarios.py --list` mostra todos).

## Os 6 passos

| # | Tempo | Aba (menu) | O que mostrar | O que dizer |
|---|-------|------------|---------------|-------------|
| 1 | 0:00 - 0:30 | **Overview** | O estado do SIEM no cabeçalho (vem de `/api/siem/health`) e os painéis de resumo. | "O dashboard lê o estado real do Wazuh. Se o SIEM falhar, o cabeçalho diz-o; não assume que está tudo bem." |
| 2 | 0:30 - 1:00 | (terminal da Kali) | Lançar `brute_force_rdp`. O ataque fica registado em `attack_log.jsonl`. | "O ataque é lançado a partir da Kali, contra o agente Windows. Fica registado com a técnica MITRE ATT&CK." |
| 3 | 1:00 - 1:30 | **Live SOC** | Os alertas a chegar em tempo real (WebSocket `/ws/alerts`; o rótulo da ligação mostra "Tempo real (WebSocket)"). | "O backend faz polling ao Wazuh Indexer e empurra cada alerta novo para o browser." |
| 4 | 1:30 - 2:00 | **Incidentes** | O incidente aberto automaticamente a partir dos alertas, com a ligação ao ataque na lista (`ataque #N`) e a timeline de eventos. | "Os alertas relacionados são agrupados num incidente, e o incidente fica ligado ao ataque que o provocou." |
| 5 | 2:00 - 2:30 | **Attack Registry** (e **Attack Timeline**) | O ataque lançado, o esperado contra o real (regra, ML, rede) e o veredito (detetado, parcial, não detetado, desconhecido), com o MTTD. | "Cada ataque tem sensores esperados. O registo compara o esperado com o que de facto detetou e mede o tempo até à deteção." |
| 6 | 2:30 - 3:00 | **Vaccines** (menu: Candidates) | A proposta gerada para um ataque `not_detected` ou `partial`, com o sensor em falta e a regra proposta. | "Para o que escapou, o sistema propõe uma regra. É só uma proposta: nunca é aplicada no Wazuh automaticamente." |

## Avisos para a demo correr bem

- **Vaccines demora.** Uma vaccine só aparece cerca de 10 minutos depois do ataque (tempo de estabilização), mais até 5 minutos do intervalo do gerador. Para o passo 6, lança um ataque **antes** da demo e mostra esse; só gera para ataques `not_detected` ou `partial`, nunca para `detected`.
- **O gerador de vaccines é em memória.** Depois de reiniciar o backend o estado volta a "nunca executado" até ao primeiro ciclo.
- **Se o ataque for totalmente detetado**, o passo 6 não tem vaccine para esse ataque. Tem à mão um ataque anterior que tenha escapado, ou diz que o veredito `detected` não gera proposta (é o comportamento correto).
- **Sem laboratório não há demo honesta.** Não existe um "modo demo" com dados inventados, e não deve ser criado. Os passos 3 a 6 dependem de alertas reais do Wazuh.
- **Evitar abas que mostrem "planeado".** No menu, as entradas com a etiqueta `R3`, `R12`, `R14`, `R16`, `R19` a `R22` ainda não estão implementadas; ficam fora do caminho da demo.

## Perguntas prováveis

- **"Porque é que o MTTD aparece em mais do que um sítio?"** O Attack Registry mostra o MTTD por ataque; as abas **MTTD / MTTR** e **Detection Rate** mostram agregados. Verifica a janela de cada uma antes da demo, porque os valores só são comparáveis na mesma janela.
- **"Isto aplica regras sozinho?"** Não. Uma vaccine é sempre uma proposta (estado `proposed`); o registo de modelos ML e as vaccines só se escrevem por processos controlados, nunca por pedido HTTP do frontend.
- **"E a segurança do próprio dashboard?"** Ver a secção "Segurança" do `README.md`.
