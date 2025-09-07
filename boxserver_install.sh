#!/bin/bash
set -euo pipefail

# =========================
# Configurações
# =========================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/boxserver_install.log"
PIHOLE_SETUPVARS="/etc/pihole/setupVars.conf"
WG_DIR="/etc/wireguard"
KEYS_DIR="$WG_DIR/keys"
CONF_FILE="$WG_DIR/wg0.conf"
SERVER_IP="10.200.200.1"
NETWORK="10.200.200.0/24"

# =========================
# Funções auxiliares
# =========================
msg() {
    echo "🤖 $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

error() {
    echo "❌ ERRO: $1" >&2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERRO: $1" >> "$LOG_FILE"
    exit 1
}

success() {
    echo "✅ $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCESSO: $1" >> "$LOG_FILE"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Este script precisa ser executado como root. Use: sudo bash $0"
    fi
}

install_dependencies() {
    msg "Instalando dependências do sistema..."
    apt update >> "$LOG_FILE" 2>&1
    apt install -y curl git wget net-tools dnsutils resolvconf qrencode >> "$LOG_FILE" 2>&1
    success "Dependências instaladas"
}

install_pihole() {
    msg "Instalando Pi-hole..."

    # Verificar se Pi-hole já está instalado
    if command -v pihole &> /dev/null; then
        msg "Pi-hole já está instalado. Atualizando..."
        pihole -up >> "$LOG_FILE" 2>&1
        success "Pi-hole atualizado"
        return 0
    fi

    # Instalar Pi-hole
    curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended >> "$LOG_FILE" 2>&1

    # Verificar se a instalação foi bem-sucedida
    if [ ! -f "$PIHOLE_SETUPVARS" ]; then
        error "Pi-hole instalado mas setupVars.conf não encontrado. Execute manualmente: pihole -r"
    fi

    success "Pi-hole instalado com sucesso"

    # Configurar Pi-hole como DNS para WireGuard
    if [ -f "$PIHOLE_SETUPVARS" ]; then
        msg "Configurando Pi-hole no setupVars.conf..."
        sed -i "s|^PIHOLE_DNS_.*=.*|# Removido configurações antigas|" "$PIHOLE_SETUPVARS"
        echo "PIHOLE_DNS_1=9.9.9.9" >> "$PIHOLE_SETUPVARS"
        echo "PIHOLE_DNS_2=1.1.1.1" >> "$PIHOLE_SETUPVARS"
        echo "DNSMASQ_LISTENING=all" >> "$PIHOLE_SETUPVARS"
    fi

    success "Pi-hole configurado"
}

install_wireguard() {
    msg "Instalando WireGuard..."

    # Verificar se WireGuard já está instalado
    if command -v wg &> /dev/null; then
        msg "WireGuard já está instalado"
        return 0
    fi

    # Instalar WireGuard
    apt install -y wireguard wireguard-tools >> "$LOG_FILE" 2>&1

    # Habilitar IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p >> "$LOG_FILE" 2>&1

    success "WireGuard instalado"
}

setup_wireguard_server() {
    msg "Configurando servidor WireGuard..."

    # Criar diretório de chaves
    mkdir -p "$KEYS_DIR"
    chmod 700 "$KEYS_DIR"

    # Gerar chaves do servidor
    umask 077
    wg genkey | tee "${KEYS_DIR}/privatekey" | wg pubkey > "${KEYS_DIR}/publickey"

    # Criar configuração do servidor
    cat > "$CONF_FILE" <<EOF
[Interface]
Address = $SERVER_IP/24
ListenPort = 51820
PrivateKey = $(cat "${KEYS_DIR}/privatekey")
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
DNS = $SERVER_IP
EOF

    chmod 600 "$CONF_FILE"

    # Habilitar e iniciar serviço
    systemctl enable wg-quick@wg0 >> "$LOG_FILE" 2>&1
    systemctl start wg-quick@wg0 >> "$LOG_FILE" 2>&1

    success "Servidor WireGuard configurado"
}

configure_firewall() {
    msg "Configurando firewall..."

    # Instalar UFW se não estiver instalado
    if ! command -v ufw &> /dev/null; then
        apt install -y ufw >> "$LOG_FILE" 2>&1
    fi

    # Configurar UFW
    ufw allow 22/tcp comment 'SSH' >> "$LOG_FILE" 2>&1
    ufw allow 51820/udp comment 'WireGuard' >> "$LOG_FILE" 2>&1
    ufw allow 53/tcp comment 'DNS TCP' >> "$LOG_FILE" 2>&1
    ufw allow 53/udp comment 'DNS UDP' >> "$LOG_FILE" 2>&1
    ufw allow 80/tcp comment 'HTTP' >> "$LOG_FILE" 2>&1
    ufw allow 443/tcp comment 'HTTPS' >> "$LOG_FILE" 2>&1

    echo "y" | ufw enable >> "$LOG_FILE" 2>&1

    success "Firewall configurado"
}

setup_dns_resolution() {
    msg "Configurando resolução DNS..."

    # Configurar resolv.conf para usar Pi-hole
    cat > /etc/resolv.conf <<EOF
nameserver 127.0.0.1
nameserver 9.9.9.9
nameserver 1.1.1.1
EOF

    # Prevenir sobrescrita do resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null || true

    success "DNS configurado"
}

create_admin_user() {
    msg "Criando usuário administrador..."

    # Verificar se o usuário já existe
    if id "boxadmin" &>/dev/null; then
        msg "Usuário boxadmin já existe"
        return 0
    fi

    # Criar usuário
    useradd -m -s /bin/bash boxadmin
    echo "boxadmin:BoxServer123!" | chpasswd
    usermod -aG sudo boxadmin

    success "Usuário boxadmin criado (senha: BoxServer123!)"
}

install_monitoring_tools() {
    msg "Instalando ferramentas de monitoramento..."

    apt install -y htop iftop iotop nethogs >> "$LOG_FILE" 2>&1

    success "Ferramentas de monitoramento instaladas"
}

create_backup_script() {
    msg "Criando script de backup..."

    cat > "${SCRIPT_DIR}/backup_boxserver.sh" <<'EOF'
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/backup/boxserver"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup do Pi-hole
tar -czf "${BACKUP_DIR}/pihole_${TIMESTAMP}.tar.gz" /etc/pihole /var/log/pihole* 2>/dev/null || true

# Backup do WireGuard
tar -czf "${BACKUP_DIR}/wireguard_${TIMESTAMP}.tar.gz" /etc/wireguard 2>/dev/null || true

# Backup das configurações do sistema
tar -czf "${BACKUP_DIR}/system_${TIMESTAMP}.tar.gz" /etc/resolv.conf /etc/sysctl.conf 2>/dev/null || true

echo "Backup completo criado em: ${BACKUP_DIR}"
EOF

    chmod +x "${SCRIPT_DIR}/backup_boxserver.sh"

    success "Script de backup criado"
}

show_installation_summary() {
    echo ""
    echo "🎉 INSTALAÇÃO DO BOXSERVER CONCLUÍDA!"
    echo "======================================"
    echo ""
    echo "📊 RESUMO DA INSTALAÇÃO:"
    echo "   ✅ Pi-hole instalado como bloqueador de anúncios e DNS"
    echo "   ✅ WireGuard configurado como VPN server"
    echo "   ✅ Firewall (UFW) configurado e ativado"
    echo "   ✅ Usuário administrador 'boxadmin' criado"
    echo "   ✅ Ferramentas de monitoramento instaladas"
    echo "   ✅ Script de backup criado"
    echo ""
    echo "🔧 INFORMAÇÕES IMPORTANTES:"
    echo "   📍 IP do Servidor: $SERVER_IP"
    echo "   📍 Porta WireGuard: 51820/udp"
    echo "   📍 Interface WireGuard: wg0"
    echo "   📍 Diretório de chaves: $KEYS_DIR"
    echo ""
    echo "🚀 PRÓXIMOS PASSOS:"
    echo "   1. Acesse o painel do Pi-hole: http://$(hostname -I | awk '{print $1}')/admin"
    echo "   2. Use o script wireguard-manager.sh para gerenciar peers VPN"
    echo "   3. Configure seus dispositivos com os arquivos .conf gerados"
    echo ""
    echo "📋 Log completo da instalação: $LOG_FILE"
    echo ""
}

# =========================
# Fluxo principal
# =========================
main() {
    check_root

    msg "Iniciando instalação do BoxServer..."
    echo "Log da instalação: $LOG_FILE"
    echo ""

    # Criar arquivo de log
    > "$LOG_FILE"

    install_dependencies
    install_pihole
    install_wireguard
    setup_wireguard_server
    configure_firewall
    setup_dns_resolution
    create_admin_user
    install_monitoring_tools
    create_backup_script

    show_installation_summary
}

# Executar apenas se chamado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
