#!/usr/bin/env bash
#
# install-wazuh.sh
#
# Automatiza a Parte 3 do guia docs/LAB_WAZUH_HYPERV.md — corre DENTRO
# da VM Ubuntu Server, depois de o SO já estar instalado (Parte 2.4/2.5)
# e de teres ligado via SSH.
#
# O que faz:
#   1. Atualiza o sistema (apt update && apt upgrade)
#   2. Descarrega e corre o wazuh-install.sh oficial (quickstart -a)
#   3. Extrai e mostra as passwords geradas (wazuh-passwords.txt)
#   4. Confirma que os 3 serviços (manager, indexer, dashboard) estão
#      "active (running)"
#
# Uso:
#   chmod +x install-wazuh.sh
#   ./install-wazuh.sh
#
# Variáveis opcionais (podes exportar antes de correr, ou editar aqui):
#   WAZUH_VERSION   - versão do Wazuh a instalar (default: 4.14)
#   SKIP_APT_UPGRADE - se "1", salta o "apt upgrade" (só faz update)
#
# NOTA: precisa de sudo. Vai pedir a password da conta criada na
# instalação do Ubuntu (Parte 2.4 do guia).

set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.14}"
SKIP_APT_UPGRADE="${SKIP_APT_UPGRADE:-0}"

WORKDIR="$HOME/wazuh-install"
INSTALL_SCRIPT="wazuh-install.sh"
PASSWORDS_ARCHIVE="wazuh-install-files.tar"
PASSWORDS_ENTRY="wazuh-install-files/wazuh-passwords.txt"

# --- cores para output (sem dependências externas) ---
c_cyan()   { printf '\033[36m%s\033[0m\n' "$1"; }
c_green()  { printf '\033[32m%s\033[0m\n' "$1"; }
c_yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
c_red()    { printf '\033[31m%s\033[0m\n' "$1"; }

step() { echo; c_cyan "==> $1"; }
ok()   { c_green "OK  $1"; }
warn() { c_yellow "!!  $1"; }
err()  { c_red "XX  $1"; }

if [ "$(id -u)" -eq 0 ]; then
    warn "Estás a correr como root diretamente. O script já usa 'sudo' onde"
    warn "precisa — não é preciso (nem recomendado) correr tudo como root."
fi

echo "========================================================="
echo " Instalação do Wazuh (quickstart nó único) - Parte 3"
echo " Versão alvo: ${WAZUH_VERSION}"
echo "========================================================="

# ---------------------------------------------------------------------
# 3.1 — Atualizar o sistema
# ---------------------------------------------------------------------
step "A atualizar a lista de pacotes (apt update)..."
sudo apt update -y

if [ "$SKIP_APT_UPGRADE" != "1" ]; then
    step "A atualizar pacotes instalados (apt upgrade)... isto pode demorar alguns minutos"
    sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y
    ok "Sistema atualizado."
else
    warn "SKIP_APT_UPGRADE=1 — a saltar 'apt upgrade'."
fi

# ---------------------------------------------------------------------
# 3.2 — Descarregar e correr o instalador assistido do Wazuh
# ---------------------------------------------------------------------
mkdir -p "$WORKDIR"
cd "$WORKDIR"

step "A descarregar wazuh-install.sh (versão ${WAZUH_VERSION})..."
curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"

if [ ! -s "$INSTALL_SCRIPT" ]; then
    err "Falha ao descarregar $INSTALL_SCRIPT — confirma a ligação à internet e a versão."
    exit 1
fi
ok "Download concluído: $WORKDIR/$INSTALL_SCRIPT"

step "A correr o instalador (-a)... demora normalmente 10-15 minutos"
echo "    (Indexer + Manager/Server + Dashboard, tudo neste único host)"
# Nota: versões atuais do wazuh-install.sh (4.x) já não aceitam
# --install-dependencies — as dependências são tratadas automaticamente
# pelo -a. Passar essa flag causa "Unknow option" e o script aborta.
sudo bash "./$INSTALL_SCRIPT" -a

ok "wazuh-install.sh terminado."

# ---------------------------------------------------------------------
# 3.3 — Extrair e mostrar as passwords
# ---------------------------------------------------------------------
step "A extrair as passwords geradas de $PASSWORDS_ARCHIVE..."

if [ ! -f "$PASSWORDS_ARCHIVE" ]; then
    err "Não encontrei $WORKDIR/$PASSWORDS_ARCHIVE — a instalação pode ter falhado."
    exit 1
fi

PASSWORDS_OUTPUT=$(sudo tar -O -xvf "$PASSWORDS_ARCHIVE" "$PASSWORDS_ENTRY" 2>/dev/null)

echo
echo "========================================================="
c_yellow " PASSWORDS GERADAS — guarda-as já num sítio seguro!"
echo "========================================================="
echo "$PASSWORDS_OUTPUT"
echo "========================================================="
echo

# Guarda também uma cópia local legível apenas pelo dono, para
# recuperares mais tarde com 'cat ~/wazuh-install/wazuh-passwords.txt'
echo "$PASSWORDS_OUTPUT" > "$WORKDIR/wazuh-passwords.txt"
chmod 600 "$WORKDIR/wazuh-passwords.txt"
ok "Cópia guardada em $WORKDIR/wazuh-passwords.txt (chmod 600)."

# ---------------------------------------------------------------------
# 3.4 — Confirmar que os serviços estão ativos
# ---------------------------------------------------------------------
step "A confirmar o estado dos serviços..."

SERVICES=(wazuh-manager wazuh-indexer wazuh-dashboard)
ALL_RUNNING=1

for svc in "${SERVICES[@]}"; do
    STATE=$(systemctl is-active "$svc" 2>/dev/null || true)
    if [ "$STATE" = "active" ]; then
        ok "$svc: active (running)"
    else
        err "$svc: estado atual = '${STATE:-desconhecido}' (esperado: active)"
        ALL_RUNNING=0
    fi
done

echo
if [ "$ALL_RUNNING" -eq 1 ]; then
    ok "Todos os 3 serviços estão active (running)."
else
    warn "Nem todos os serviços estão ativos. Corre 'sudo systemctl status <serviço>'"
    warn "para diagnosticar (ver secção Troubleshooting do guia)."
fi

IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}')

echo
echo "========================================================="
ok "Instalação concluída."
echo "========================================================="
echo
echo "Próximos passos manuais (Parte 4 do guia):"
echo "  1. No browser do Windows, acede a: https://${IP_ADDR:-<IP_DA_VM>}"
echo "  2. Aceita o aviso de certificado autoassinado (Avançado -> Continuar)"
echo "  3. Login: admin / password mostrada acima"
echo
echo "Recuperar as passwords mais tarde, se precisares:"
echo "  sudo tar -O -xvf $WORKDIR/$PASSWORDS_ARCHIVE $PASSWORDS_ENTRY"
echo "  (ou: cat $WORKDIR/wazuh-passwords.txt)"
echo
