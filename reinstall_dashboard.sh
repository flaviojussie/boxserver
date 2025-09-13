#!/bin/bash

# =============================================================================
# BoxServer Dashboard Reinstaller v1.0
# =============================================================================
# Autor: Gemini
# Descrição: Reinstala e corrige uma instalação quebrada do dashboard,
#            baixando as versões mais recentes e configurando-as corretamente.
# =============================================================================

set -euo pipefail

# --- Configurações ---
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly GITHUB_REPO="https://github.com/flaviojussie/boxserver.git"
readonly CONFIG_FILE="/etc/boxserver/config.conf"

# --- Cores ---
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script deve ser executado como root. Use: sudo $0"
        exit 1
    fi
}

# 1. Parar o serviço antigo
stop_service() {
    log_info "Parando o serviço do dashboard existente..."
    systemctl stop dashboard-api.service 2>/dev/null || true
}

# 2. Instalar dependências
install_deps() {
    log_info "Garantindo a instalação das dependências (requests, psutil)..."
    apt-get update
    apt-get install -y python3-requests python3-psutil git
}

# 3. Baixar os arquivos mais recentes
fetch_files() {
    log_info "Baixando arquivos mais recentes do repositório GitHub..."
    local temp_dir="/tmp/dashboard-fix-$"$$
    
    if git clone --depth 1 "$GITHUB_REPO" "$temp_dir"; then
        cp "$temp_dir/dashboard.html" "$SCRIPT_DIR/"
        cp "$temp_dir/dashboard-api.py" "$SCRIPT_DIR/"
        rm -rf "$temp_dir"
        log_info "Arquivos do dashboard baixados com sucesso."
    else
        log_error "Falha ao clonar o repositório. Verifique a conexão com a internet."
        exit 1
    fi
}

# 4. Corrigir o arquivo da API
patch_api_file() {
    log_info "Personalizando o arquivo da API com o IP do servidor..."
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Arquivo de configuração $CONFIG_FILE não encontrado. Não é possível determinar o IP do servidor."
        exit 1
    fi
    
    source "$CONFIG_FILE"
    local server_ip="$SERVER_IP"
    local api_file="$SCRIPT_DIR/dashboard-api.py"
    local placeholder="{{BOXSERVER_IP}}"

    if [[ -z "$server_ip" ]]; then
        log_error "A variável SERVER_IP não está definida em $CONFIG_FILE."
        exit 1
    fi

    sed -i "s|${placeholder}|${server_ip}|g" "$api_file"
    log_info "API configurada para o IP: $server_ip"
}

# 5. Reinstalar o Dashboard
deploy_dashboard() {
    log_info "Instalando os novos arquivos do dashboard..."
    
    # Copiar frontend e backend
    cp "$SCRIPT_DIR/dashboard.html" /var/www/html/index.html
    cp "$SCRIPT_DIR/dashboard-api.py" /var/www/html/dashboard-api.py
    
    # Definir permissões
    chown www-data:www-data /var/www/html/index.html
    chown www-data:www-data /var/www/html/dashboard-api.py
    chmod 644 /var/www/html/index.html
    chmod +x /var/www/html/dashboard-api.py

    log_info "Recriando e habilitando o serviço systemd..."
    cat > /etc/systemd/system/dashboard-api.service << 'EOF'
[Unit]
Description=BoxServer Dashboard API
After=network.target
[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/html
ExecStart=/usr/bin/python3 /var/www/html/dashboard-api.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
MemoryMax=100M
CPUQuota=30%
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dashboard-api.service
    log_info "Serviço configurado."
}

# 6. Iniciar e Verificar
start_and_verify() {
    log_info "Iniciando e verificando o novo serviço do dashboard..."
    systemctl restart dashboard-api.service
    
    sleep 5 # Dar um tempo para o serviço iniciar

    if systemctl is-active --quiet dashboard-api.service; then
        log_info "Serviço da API está ATIVO."
        # Teste final de saúde da API
        if curl -s http://localhost:8081/api/health | grep -q '"status": "healthy"'; then
            log_info "✅ Teste de saúde da API passou com sucesso!"
            echo -e "\n${GREEN}O dashboard foi reinstalado e corrigido com sucesso!${NC}"
            echo "Acesse o dashboard em: http://$(source $CONFIG_FILE && echo $SERVER_IP)/"
        else
            log_error "O serviço está ativo, mas a API não respondeu corretamente ao teste de saúde."
            log_warning "Verifique os logs com: journalctl -u dashboard-api.service"
        fi
    else
        log_error "Falha ao iniciar o serviço da API do dashboard."
        log_warning "Verifique os logs com: journalctl -u dashboard-api.service"
    fi
}

# --- Fluxo Principal ---
main() {
    echo "=================================================="
    echo "    Reinstalador do Dashboard do BoxServer        "
    echo "=================================================="
    check_root
    stop_service
    install_deps
    fetch_files
    patch_api_file
    deploy_dashboard
    start_and_verify
    echo "=================================================="
}

main
