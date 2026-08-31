# 🛡️ Checklist de Hardening — Windows & Linux

**Projeto CET - Cibersegurança**
Checklist prática de configuração segura de sistemas, baseada nos **CIS Benchmarks** e nas recomendações da **Microsoft Security Baseline**.

---

## 📋 Como Usar

- Marca `[x]` cada item à medida que o aplicas/verificas.
- Coluna **Prioridade**: 🔴 Crítica · 🟠 Alta · 🟡 Média · 🟢 Baixa
- Usa esta checklist em conjunto com o `log_analyzer.py` deste projeto: muitos dos Event IDs monitorizados (4720, 4728, 4672, 4719...) correspondem diretamente a alterações nas configurações abaixo.

---

## 🪟 Windows Hardening

### 1. Contas e Autenticação

- [ ] 🔴 Desativar a conta `Administrator` local incorporada (ou renomear + palavra-passe forte)
- [ ] 🔴 Impor política de palavra-passe: mínimo 14 caracteres, complexidade ativa, histórico de 24
- [ ] 🔴 Ativar bloqueio de conta após 5 tentativas falhadas (Event ID 4625) — janela de 15 min
- [ ] 🔴 Ativar MFA para todas as contas com privilégios administrativos
- [ ] 🟠 Remover utilizadores desnecessários do grupo `Administrators`
- [ ] 🟠 Implementar princípio de menor privilégio (contas separadas para admin vs uso diário)
- [ ] 🟡 Configurar expiração de palavra-passe (ex: 90 dias) exceto para contas de serviço com gestão dedicada
- [ ] 🟡 Desativar contas de convidado (`Guest`)

### 2. Política de Auditoria e Logging

- [ ] 🔴 Ativar auditoria de: Logon/Logoff, Gestão de Contas, Alterações de Política, Uso de Privilégios
- [ ] 🔴 Aumentar tamanho máximo do Security Log (mín. 1 GB) para evitar rotação prematura
- [ ] 🟠 Encaminhar logs para um coletor central (Wazuh, Sentinel, Syslog) — ver `log_analyzer.py` para análise offline
- [ ] 🟡 Ativar auditoria de acesso a objetos (PowerShell, ficheiros sensíveis)
- [ ] 🟡 Ativar Windows Defender Application Control (WDAC) ou AppLocker logging

### 3. Rede e Firewall

- [ ] 🔴 Ativar Windows Firewall nos 3 perfis (Domain, Private, Public)
- [ ] 🔴 Bloquear SMBv1 (`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`)
- [ ] 🟠 Desativar NetBIOS e LLMNR (mitigar poisoning/relay attacks)
- [ ] 🟠 Restringir RDP: MFA, Network Level Authentication (NLA) obrigatório, IP allowlisting
- [ ] 🟡 Desativar serviços de rede não usados (Telnet, FTP, SNMP v1/v2)

### 4. Atualizações e Patch Management

- [ ] 🔴 Windows Update automático ativo (ou WSUS/Intune com SLA definido, ex: patches críticos em 72h)
- [ ] 🟠 Manter inventário de software instalado e remover software não autorizado/obsoleto
- [ ] 🟡 Validar que drivers e firmware também estão atualizados

### 5. Proteção de Endpoint

- [ ] 🔴 Windows Defender (ou EDR equivalente) ativo com proteção em tempo real
- [ ] 🔴 Ativar BitLocker em todos os discos (proteção contra roubo/perda física)
- [ ] 🟠 Ativar Controlled Folder Access (proteção anti-ransomware)
- [ ] 🟠 Desativar macros do Office por defeito / bloquear macros de origem externa
- [ ] 🟡 Ativar Attack Surface Reduction (ASR) rules

### 6. Tarefas Agendadas e Scripts

- [ ] 🔴 Restringir criação de tarefas agendadas a administradores (Event ID 4698)
- [ ] 🟠 Ativar logging de execução do PowerShell (Script Block Logging + Transcription)
- [ ] 🟠 Restringir Execution Policy do PowerShell (`AllSigned` ou `RemoteSigned`)
- [ ] 🟡 Auditar tarefas agendadas existentes contra whitelist conhecida

---

## 🐧 Linux Hardening

### 1. Contas e Autenticação

- [ ] 🔴 Desativar login root direto (`PermitRootLogin no` no sshd_config)
- [ ] 🔴 Impor política de password forte via `pam_pwquality` (mín. 14 caracteres)
- [ ] 🔴 Configurar MFA (ex: `pam_google_authenticator`) para acessos SSH/sudo
- [ ] 🟠 Bloquear conta após tentativas falhadas (`pam_faillock` / `fail2ban`)
- [ ] 🟠 Remover/bloquear contas de utilizador não usadas
- [ ] 🟡 Configurar `sudo` com logging completo (`Defaults log_output`)

### 2. SSH Hardening

- [ ] 🔴 Autenticação por chave pública apenas (`PasswordAuthentication no`)
- [ ] 🔴 Alterar porta padrão do SSH (mitigação, não substitui outras medidas)
- [ ] 🟠 Restringir acesso SSH por IP (`AllowUsers`, firewall, ou bastion host)
- [ ] 🟠 Desativar `X11Forwarding` e `AllowTcpForwarding` se não usados
- [ ] 🟡 Definir `ClientAliveInterval` para terminar sessões inativas

### 3. Firewall e Rede

- [ ] 🔴 Ativar `ufw`/`firewalld`/`iptables` com política default-deny inbound
- [ ] 🟠 Fechar todas as portas exceto as estritamente necessárias
- [ ] 🟠 Desativar IPv6 se não usado (reduz superfície de ataque)
- [ ] 🟡 Configurar `fail2ban` para SSH, web server e outros serviços expostos

### 4. Atualizações e Patch Management

- [ ] 🔴 Atualizações automáticas de segurança ativas (`unattended-upgrades` no Debian/Ubuntu, `dnf-automatic` no RHEL)
- [ ] 🟠 Auditar pacotes instalados e remover software desnecessário
- [ ] 🟡 Subscrever avisos de segurança da distro (CVE feeds)

### 5. Logging e Auditoria

- [ ] 🔴 Ativar `auditd` com regras para: alterações de utilizadores/grupos, uso de `sudo`, alterações em `/etc/passwd`, `/etc/shadow`
- [ ] 🟠 Centralizar logs (`rsyslog`/`journald` → SIEM, ex: Wazuh)
- [ ] 🟠 Proteger logs contra alteração (`chattr +a` em ficheiros de log críticos)
- [ ] 🟡 Configurar rotação de logs (`logrotate`) com retenção adequada (mín. 90 dias)

### 6. Sistema de Ficheiros e Permissões

- [ ] 🔴 Permissões restritas em ficheiros sensíveis (`/etc/shadow` 600, `/etc/passwd` 644)
- [ ] 🟠 Montar partições sensíveis (`/tmp`, `/var`) com `noexec`, `nosuid`, `nodev`
- [ ] 🟠 Remover binários SUID/SGID desnecessários (`find / -perm -4000`)
- [ ] 🟡 Ativar SELinux (enforcing) ou AppArmor

### 7. Serviços e Kernel

- [ ] 🔴 Desativar serviços não usados (`systemctl list-unit-files --state=enabled`)
- [ ] 🟠 Aplicar hardening de kernel via `sysctl` (ex: `net.ipv4.tcp_syncookies=1`, desativar IP forwarding se não necessário)
- [ ] 🟡 Restringir acesso ao compilador/ferramentas de desenvolvimento em produção

---

## ✅ Validação e Ferramentas de Apoio

| Ferramenta | Uso |
|---|---|
| **Microsoft Security Compliance Toolkit** | Aplicar/validar baseline oficial Windows via GPO |
| **CIS-CAT Lite** | Scan automático de conformidade CIS Benchmark (Windows e Linux) |
| **Lynis** | Auditoria de hardening para Linux (`lynis audit system`) |
| **OpenSCAP** | Verificação de compliance (SCAP/CIS) em Linux |
| **`log_analyzer.py`** (este projeto) | Validar, via logs, se as políticas de auditoria configuradas aqui estão a gerar os Event IDs esperados |

---

## 📚 Referências

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [NIST SP 800-123 — Guide to General Server Security](https://csrc.nist.gov/publications/detail/sp/800-123/final)
- [OWASP Docker/Linux Security Cheat Sheets](https://cheatsheetseries.owasp.org/)

---

**Projeto CET - Cibersegurança — FaroForma**
