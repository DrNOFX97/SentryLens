# 🔬 Laboratório Wazuh — Guia Completo (VirtualBox ou Hyper-V)

**Projeto CET - Cibersegurança | Fase 3: Laboratório SIEM**

---

## Qual Hypervisor Usar

Só precisas de **um** dos dois — não instales/actives os dois ao mesmo tempo.

| | VirtualBox | Hyper-V |
|---|---|---|
| Já tens instalado | ✅ Sim | ❌ Precisa de ativar |
| Conflito | Nenhum, se Hyper-V estiver desligado | Toma conta exclusiva da CPU — pode degradar/quebrar VirtualBox |
| Recomendação para ti | **Usar este** | Só se precisares dele por outra razão específica (ex: containers Windows, WSL2 avançado) |

Antes de continuar, confirma que o Hyper-V está mesmo desativado:
```powershell
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
```
Se `State: Disabled` → segue a coluna **VirtualBox** abaixo e ignora a secção Hyper-V.

---

## O Que a VM Faz (e o que não faz)

Só a **VM Linux** é precisa para o **Wazuh Manager** (Indexer + Server + Dashboard) — esse software só existe para Linux.

O **agente Wazuh**, que recolhe os Event Logs, instala-se diretamente no teu Windows real — **não precisa de VM nenhuma**.

```
Teu PC Windows (máquina real)
  ├── Wazuh Agent (instalado direto) ──envia logs──► VM Linux
  │                                                     └── Wazuh Manager
  └── Browser ──consulta─────────────────────────────► Dashboard Wazuh
```

---

## PARTE 1A — Criar a VM com VirtualBox (recomendado no teu caso)

### 1A.1 Descarregar Ubuntu Server 22.04 LTS
https://ubuntu.com/download/server → `ubuntu-22.04.x-live-server-amd64.iso`

### 1A.2 Criar a VM

No VirtualBox Manager → **New**:

| Definição | Valor |
|---|---|
| Nome | `Wazuh-Manager` |
| Tipo | Linux / Ubuntu (64-bit) |
| Memória | **8192 MB** (mínimo) — 10-12 GB se tiveres disponível |
| Disco | **60 GB**, VDI, alocado dinamicamente |
| vCPU | 4 (Settings → System → Processor) |

### 1A.3 Ativar Virtualização Aninhada (se aplicável)

Se o teu CPU/BIOS já tem VT-x/AMD-V ativo (a maioria tem, por default), não precisas de fazer nada extra. Confirma em **Settings → System → Acceleration** que "Enable VT-x/AMD-V" está marcado.

### 1A.4 Configurar Rede

**Settings → Network → Adapter 1**:
- Attached to: **Bridged Adapter** (a VM fica na mesma sub-rede da tua rede local — mais simples para comunicar com o Windows real)
- Selecionar o teu adaptador de rede físico (Wi-Fi ou Ethernet, o que estiveres a usar)

> Nota: "Bridged" só funciona bem em ligações Wi-Fi se o driver da tua placa suportar modo promíscuo. Se tiveres problemas de conetividade depois, muda para **NAT Network** (criado em File → Tools → Network Manager) — mais configuração, mas mais fiável em Wi-Fi problemático.

### 1A.5 Montar a ISO e Instalar

**Settings → Storage** → clicar no ícone de disco vazio → selecionar a ISO do Ubuntu descarregada.

Arrancar a VM e seguir a instalação (ver Parte 2 — igual para ambos os hypervisors).

---

## PARTE 1B — Criar a VM com Hyper-V (alternativa)

Só seguir esta parte se tiveres uma razão específica para usar Hyper-V em vez de VirtualBox.

### 1B.1 Ativar Hyper-V
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```
Reiniciar o computador. **Nota:** isto pode degradar ou impedir o funcionamento do VirtualBox.

### 1B.2 Criar Virtual Switch
No **Hyper-V Manager** → **Virtual Switch Manager** → criar um switch **Externo**, ligado ao teu adaptador físico. Nome sugerido: `Lab-Wazuh`.

### 1B.3 Criar a VM

**New → Virtual Machine**:

| Definição | Valor |
|---|---|
| Geração | **Geração 2** |
| Memória | **8192 MB** (mínimo) |
| Rede | O switch `Lab-Wazuh` |
| Disco | **60 GB** (VHDX dinâmico) |
| vCPU | 4 (depois de criada, em Settings → Processor) |

### 1B.4 Desativar Secure Boot

Em **Settings → Security**: desativar Secure Boot (ou escolher template "Microsoft UEFI Certificate Authority"). Sem isto a VM não arranca a ISO.

### 1B.5 Montar a ISO e Instalar

Anexar a ISO do Ubuntu Server 22.04 nas definições da VM, arrancar, seguir a instalação (Parte 2 abaixo).

---

## PARTE 2 — Instalar Ubuntu Server (igual em ambos)

Arrancar a VM e seguir o instalador:
- Idioma / teclado: Português
- Rede: deixar em DHCP automático (**anota o IP** que aparece — vais precisar dele em todos os passos seguintes)
- Storage: usar disco inteiro (layout padrão)
- Utilizador: cria um (ex: `fernando`) — anota a password
- **"Install OpenSSH server"** → marcar **SIM** (para depois trabalhares via SSH a partir do Windows, em vez da consola da VM)
- Terminar, remover a ISO virtual, reiniciar

### Confirmar o IP da VM
Depois de reiniciar e fazer login na consola:
```bash
ip a
```
A partir daqui liga-te via SSH a partir do Windows:
```powershell
ssh fernando@<IP_DA_VM>
```

---

## PARTE 3 — Instalar o Wazuh (Quickstart Nó Único)

Já dentro da VM Ubuntu (via SSH):

```bash
sudo apt update && sudo apt upgrade -y

curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

> Nota: em versões antigas do instalador existia uma flag `--install-dependencies`.
> Na 4.14 já não existe (as dependências são tratadas automaticamente pelo `-a`) —
> se a passares, o script recusa com `Unknow option: --install-dependencies`.

Demora 10-15 minutos. No fim mostra:
```
User: admin
Password: <password gerada automaticamente>
```
**Guarda esta password imediatamente.**

Recuperar mais tarde, se precisares:
```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

Confirmar que os serviços estão ativos:
```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```
Todos devem mostrar `active (running)`.

---

## PARTE 4 — Aceder ao Dashboard

No browser do teu Windows:
```
https://<IP_DA_VM>
```
Aviso de certificado autoassinado → Avançado → Continuar. Login: `admin` / password do passo anterior.

---

## PARTE 5 — Instalar o Agente Wazuh no Windows

No teu Windows real, **PowerShell como Administrador**:

```powershell
$installer = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi" -OutFile $installer

Start-Process msiexec.exe -Wait -ArgumentList @(
  "/i", $installer,
  "/q",
  "WAZUH_MANAGER=<IP_DA_VM>",
  "WAZUH_AGENT_NAME=$env:COMPUTERNAME"
)

NET START WazuhSvc
```

Confirmar:
```powershell
Get-Service *wazuh*
```
Deve mostrar `Running`.

### Portas necessárias
- **1514/TCP** — envio de logs
- **1515/TCP** — registo inicial

Se usaste **Bridged** (VirtualBox) ou **switch Externo** (Hyper-V), a VM e o Windows estão na mesma sub-rede e normalmente não há bloqueios extra a configurar — só confirma que a Windows Defender Firewall não está a bloquear tráfego de saída nessas portas.

---

## PARTE 6 — Validar

**Dashboard → Management → Endpoints** → o teu Windows deve aparecer como `Active`.

Gerar um evento de teste (logon falhado de propósito):
```powershell
runas /user:administrador cmd
```
(introduzir password errada)

**Dashboard → Threat Hunting → Security Events** → pesquisar `4625` → deve aparecer em segundos.

---

## 🐛 Troubleshooting

**VirtualBox: VM sem rede / não obtém IP**
→ Confirma modo Bridged e o adaptador físico certo selecionado
→ Se estiveres em Wi-Fi e continuar sem rede, muda para NAT Network (ver nota na Parte 1A.4)

**Hyper-V: VM não arranca da ISO**
→ Confirma que Secure Boot está desativado (Parte 1B.4)

**`wazuh-install.sh` falha por falta de RAM**
→ Sobe a VM para pelo menos 8GB — com menos, o Indexer (OpenSearch) não arranca de forma fiável

**Agente Windows instala mas não aparece "Active" no Dashboard**
→ Confirma o IP do `WAZUH_MANAGER`
→ Testa conectividade: `Test-NetConnection <IP_DA_VM> -Port 1514`
→ Reinicia o serviço: `Restart-Service WazuhSvc`

---

## 📋 Checklist de Progresso

- [ ] Confirmado qual hypervisor vou usar (VirtualBox recomendado)
- [ ] VM Ubuntu Server 22.04 criada e a correr
- [ ] SSH a funcionar a partir do Windows
- [ ] Wazuh instalado (`wazuh-install.sh -a`)
- [ ] Dashboard acessível via browser
- [ ] Agente Windows instalado
- [ ] Agente aparece "Active" no Dashboard
- [ ] Evento de teste (4625) visível no Threat Hunting

---

## 🚀 Próximo Passo

Depois do checklist completo, o laboratório está pronto para o backend FastAPI (Fase 2, `wazuh-dashboard/`) consultar dados reais em vez de mocks.
