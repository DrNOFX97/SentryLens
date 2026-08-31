# SentryLens — CET

Projeto do CET (curso de cibersegurança) com duas fases:

- **Fase 1** — `scripts/` tem o backend FastAPI (`main.py`, `wazuh_client.py`,
  `event_catalog.py`) que liga às APIs do Wazuh (Manager API porta 55000,
  Indexer API porta 9200) e expõe dados prontos para o dashboard.
- **Frontend** — `index.html` (raiz) é o dashboard estático que consome esse
  backend.
- **Documentação** — `docs/README.md` explica a arquitetura backend/frontend
  em detalhe; `docs/LAB_WAZUH_HYPERV.md` é o guia completo do laboratório
  Wazuh usado como fonte de dados.

## Laboratório Wazuh

O backend em `scripts/` só tem dados reais para mostrar depois de o
laboratório Wazuh (VM Ubuntu em Hyper-V + agente no Windows) estar montado
e a correr. O guia passo-a-passo completo está em
[`docs/LAB_WAZUH_HYPERV.md`](docs/LAB_WAZUH_HYPERV.md) — lê esse ficheiro
antes de mexer no laboratório.

Existem 3 scripts em `scripts/` que automatizam o que é seguro automatizar
desse guia. Correm-se **manualmente, nesta ordem** (nunca automaticamente —
envolvem reiniciar o PC e mexer em virtualização):

| Ordem | Script | Onde corre | Automatiza |
|---|---|---|---|
| 1 | `scripts/setup-hyperv-lab.ps1` | Windows anfitrião (PowerShell, Admin) | Partes 1–2 do guia: ativa Hyper-V, cria o Virtual Switch `Lab-Wazuh` e a VM (Geração 2, 8 GB RAM, 4 vCPU, 60 GB disco dinâmico, Secure Boot desativado) |
| — | *(manual)* instalação do Ubuntu Server | Consola Hyper-V | Parte 2.4 — interativo, não automatizado de propósito |
| 2 | `scripts/install-wazuh.sh` | Dentro da VM Ubuntu (via SSH) | Parte 3: `apt update/upgrade`, instala Wazuh (`wazuh-install.sh -a`), mostra as passwords geradas e confirma que manager/indexer/dashboard estão `active (running)` |
| — | *(manual)* login no Dashboard | Browser do Windows | Parte 4 |
| 3 | `scripts/install-wazuh-agent.ps1` | Windows a monitorizar (PowerShell, Admin) | Parte 5: descarrega o MSI do agente, instala silenciosamente apontado para o IP do manager, arranca `WazuhSvc` e confirma `Running` |
| — | *(manual)* validação | Wazuh Dashboard | Parte 6 — confirmar agente `Active` e evento de teste (4625 / rule.id 60122) |

Passos que os scripts **não** tentam automatizar (BIOS/UEFI, instalador
interativo do Ubuntu, etc.) estão listados em
[`scripts/README.md`](scripts/README.md).

Todos os parâmetros (nomes de VM/switch, specs, versões, IP do manager)
estão configuráveis no topo de cada script — não é preciso editar o resto
do ficheiro para ajustar ao ambiente do utilizador.
