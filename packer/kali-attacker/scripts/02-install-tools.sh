#!/usr/bin/env bash
#
# 02-install-tools.sh - Install additional attack tools for SentryLens Red Team

set -euo pipefail

SSH_USERNAME="${SSH_USERNAME:-kali}"
SSH_PASSWORD="${SSH_PASSWORD:-kali}"

log() { echo -e "\033[36m==>\033[0m $*"; }
ok()   { echo -e "\033[32mOK\033[0m  $*"; }
warn() { echo -e "\033[33m!!\033[0m  $*"; }
err()  { echo -e "\033[31mXX\033[0m  $*"; }

log "Installing additional attack tools..."

# Install Python packages for attack scripts
log "Installing Python packages..."
sudo -u ${SSH_USERNAME} pip3 install --user --break-system-packages \
    requests \
    paramiko \
    scapy \
    netaddr \
    python-nmap \
    ldap3 \
    dnspython \
    impacket \
    bloodhound \
    pypykatz \
    certipy \
    mitm6 \
    kerberos \
    gssapi 2>/dev/null || warn "Some Python packages failed to install"

# Install Go tools (for newer attack tools)
log "Installing Go..."
if ! command -v go &> /dev/null; then
    GO_VERSION="1.22.5"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
    rm /tmp/go.tar.gz
    ok "Go ${GO_VERSION} installed"
else
    ok "Go already installed: $(go version)"
fi

export PATH=$PATH:/usr/local/go/bin
export GOPATH=/home/${SSH_USERNAME}/go
mkdir -p ${GOPATH}/bin
chown -R ${SSH_USERNAME}:${SSH_USERNAME} /home/${SSH_USERNAME}/go

# Install Go-based tools
log "Installing Go-based attack tools..."
sudo -u ${SSH_USERNAME} bash -c '
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=/home/kali/go
    
    # Versões fixas (não @latest, para a imagem ser reprodutível e não
    # trocar de código sem aviso); verificadas contra a última release de
    # cada repositório em 2026-10-19 — atualizar à mão de vez em quando.

    # Subdomain enumeration
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0 2>/dev/null || true

    # HTTP probing
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0 2>/dev/null || true

    # DNS resolution
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1 2>/dev/null || true

    # Port scanning
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 2>/dev/null || true

    # Vulnerability scanning
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1 2>/dev/null || true

    # Cloud enumeration (nota: cloud_enum é um script Python, não um módulo
    # Go — este "go install" nunca funcionou; falha sempre, por isso o
    # "|| true" no fim do bloco. Fora do âmbito desta correção de segurança.)
    go install -v github.com/initstring/cloud_enum@latest 2>/dev/null || true
' 2>/dev/null || warn "Some Go tools failed to install"

# Add Go bin to PATH
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /home/${SSH_USERNAME}/.bashrc

# Install Nuclei templates
log "Updating Nuclei templates..."
sudo -u ${SSH_USERNAME} bash -c '
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    nuclei -update-templates 2>/dev/null || true
' 2>/dev/null || warn "Nuclei template update failed"

# Install additional wordlists
log "Installing wordlists..."
apt-get install -y \
    wordlists \
    seclists 2>/dev/null || true

# Create symlinks for common wordlists
ln -sf /usr/share/wordlists/rockyou.txt.gz /usr/share/wordlists/rockyou.txt 2>/dev/null || true
gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Install Docker for containerized tools
log "Installing Docker..."
if ! command -v docker &> /dev/null; then
    # get.docker.com não é versionado (serve sempre o script mais recente),
    # por isso descarrega-se para ficheiro e verifica-se o checksum antes de
    # executar, em vez de "curl | bash" direto. O hash abaixo foi capturado
    # em 2026-10-19; se o Docker mudar o script, esta verificação falha de
    # propósito (fail-closed) e pede atualização manual, em vez de correr
    # código não revisto.
    GET_DOCKER_SHA256="7f966774378d94acf1817eb1aba213c21b576d01d1ee2f0656fe36e75ffa1258"
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    echo "${GET_DOCKER_SHA256}  /tmp/get-docker.sh" | sha256sum -c -
    bash /tmp/get-docker.sh
    rm -f /tmp/get-docker.sh
    usermod -aG docker ${SSH_USERNAME}
    ok "Docker installed"
else
    ok "Docker already installed"
fi

# Pull useful attack containers, fixos por digest em vez de "latest" (uma
# tag pode mudar de conteúdo sem aviso). Digests resolvidos em 2026-10-19;
# o Empire não pôde ser verificado (pull anónimo ao ghcr.io negado nessa
# data) — fica por tag, documentado, para o operador decidir.
log "Pulling attack containers..."
docker pull kalilinux/kali-rolling@sha256:4be87f78671419c13dcf4f207ead1cfc0de178ea281b3f69c0f49b69ba4e79b1 2>/dev/null || warn "Failed to pull kali-rolling"
docker pull ghcr.io/bc-security/empire:latest 2>/dev/null || warn "Failed to pull Empire (tag, não digest — ver comentário acima)"
docker pull mcr.microsoft.com/azure-cli@sha256:933eb8dcb81aecb6f77e03c5b8660f0a1dfa9e1d16525763a27f86ff3b83a044 2>/dev/null || warn "Failed to pull Azure CLI"

# Install BloodHound dependencies
log "Setting up BloodHound..."
systemctl enable neo4j 2>/dev/null || true
systemctl start neo4j 2>/dev/null || true

# Wait for Neo4j to start
sleep 5

# Set Neo4j password
cypher-shell -u neo4j -p neo4j "ALTER CURRENT USER SET PASSWORD FROM 'neo4j' TO 'bloodhound';" 2>/dev/null || true

ok "Attack tools installation completed"