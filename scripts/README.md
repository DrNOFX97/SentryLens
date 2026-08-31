# Scripts do Laboratório Wazuh

Automatização das Partes 1, 2, 3 e 5 do guia [`docs/LAB_WAZUH_HYPERV.md`](../docs/LAB_WAZUH_HYPERV.md).

## Ordem de execução

| # | Script | Onde corre | O que faz | Parte do guia |
|---|--------|-----------|-----------|----------------|
| 1 | `setup-hyperv-lab.ps1` | Windows anfitrião (PowerShell, Admin) | Ativa Hyper-V, cria o Virtual Switch e a VM | Partes 1–2 |
| — | *instalação manual do Ubuntu* | Consola Hyper-V (vmconnect) | Instalador interativo do Ubuntu Server | Parte 2.4 |
| 2 | `install-wazuh.sh` | Dentro da VM Ubuntu (via SSH) | Instala Wazuh (Indexer + Manager + Dashboard) | Parte 3 |
| — | *acesso ao dashboard* | Browser do Windows | Login com `admin` + password gerada | Parte 4 |
| 3 | `install-wazuh-agent.ps1` | Windows a monitorizar (PowerShell, Admin) | Instala e regista o agente Wazuh | Parte 5 |
| — | *validação* | Wazuh Dashboard | Confirmar agente `Active` + evento de teste | Parte 6 |

Cada script tem parâmetros no topo (`param(...)`) para ajustar nomes, specs e versões sem editar o resto do ficheiro — ver `Get-Help .\setup-hyperv-lab.ps1 -Full` (ou o cabeçalho `<# .SYNOPSIS #>` de cada `.ps1`).

## Passos manuais que os scripts NÃO tentam automatizar

Estes passos ficam de propósito fora dos scripts, por serem interativos, dependerem de BIOS/UEFI, ou envolverem reiniciar a máquina — automatizá-los às cegas seria arriscado.

1. **Ativar a virtualização de hardware (Intel VT-x / AMD-V) na BIOS/UEFI do host.**
   O `Enable-WindowsOptionalFeature` liga a *feature* do Windows, mas se a virtualização estiver desativada ao nível do firmware, o Hyper-V não arranca nenhuma VM. Confirma em `msinfo32` → "Virtualização baseada em hardware" = Sim. Se não estiver, entra na BIOS/UEFI (tecla depende do fabricante, ex: F2/Del/F10) e ativa a opção equivalente a "Intel Virtualization Technology (VT-x)" ou "SVM Mode" (AMD).

2. **Reiniciar o PC depois de ativar o Hyper-V.**
   `setup-hyperv-lab.ps1` deteta este caso e para com um aviso — não força reinícios automáticos.

3. **Instalação interativa do Ubuntu Server (Parte 2.4).**
   Idioma/teclado, layout de disco, criar utilizador e password, e sobretudo marcar **"Install OpenSSH server"** — tudo isto é feito no instalador gráfico dentro da consola Hyper-V (vmconnect). Sem isto não há como fazer SSH para a VM depois.

4. **Anotar o IP da VM e a password do `admin` do Wazuh.**
   O IP aparece com `ip a` dentro da VM; a password do dashboard é gerada aleatoriamente pelo `wazuh-install.sh` e mostrada uma única vez no terminal (o `install-wazuh.sh` também a guarda em `~/wazuh-install/wazuh-passwords.txt` dentro da VM, mas continua a ser preciso ires lá buscá-la).

5. **Aceitar o certificado autoassinado no browser e fazer login no Dashboard (Parte 4).**

6. **Validação final no Dashboard (Parte 6):** confirmar o agente como `Active` em Management → Endpoints, gerar um evento de teste (ex: `runas` com password errada) e procurar `rule.id: 60122` / `4625` em Threat Hunting → Security Events.

7. **Regras de firewall entre a VM e o host**, se o Windows Defender Firewall bloquear as portas 1514/1515 — o `install-wazuh-agent.ps1` testa a conectividade e avisa, mas não altera regras de firewall automaticamente (é uma alteração de segurança do sistema que deve ser deliberada, não silenciosa).

## Pré-requisitos gerais

- Windows 10/11 Pro, Enterprise ou Education (Hyper-V não existe na edição Home).
- Virtualização de hardware ativa na BIOS (ver ponto 1 acima).
- ISO do Ubuntu Server 22.04 LTS descarregada (`ubuntu-22.04.x-live-server-amd64.iso`) — https://ubuntu.com/download/server
- Espaço em disco livre suficiente para o VHDX dinâmico (até 60 GB no pior caso).
