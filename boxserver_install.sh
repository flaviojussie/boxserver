#!/bin/bash

###############################################################################
# BOXSERVER AUTO-INSTALLER v2.0
# Script Automatizado com TUI para Configuração Completa
#
# Componentes: Pi-hole + Unbound + WireGuard + RNG-tools + Otimizações
# Otimizado para: ARM RK322x, Debian/Ubuntu, Armbian
# Hardware Mínimo: 1GB RAM, 8GB Storage
#
# Autor: BOXSERVER Project
# Data: $(date +%Y-%m-%d)
###############################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

readonly SCRIPT_VERSION="2.0"
readonly SCRIPT_NAME="BOXSERVER Auto-Installer"
readonly LOG_FILE="/var/log/boxserver-installer.log"
readonly CONFIG_DIR="/etc/boxserver"
readonly BACKUP_DIR="/tmp/boxserver-backup"

# Cores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Variáveis globais dinâmicas
NETWORK_INTERFACE=""
SYSTEM_IP=""
GATEWAY_IP=""
DNS_SERVERS=""
TOTAL_RAM=""
AVAILABLE_STORAGE=""
CPU_ARCHITECTURE=""
INSTALL_MODE=""

# ============================================================================
# FUNÇÕES DE UTILIDADE E LOGGING
# ============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_success() { log "SUCCESS" "$@"; }

show_message() {
    local type="$1"
    local title="$2"
    local message="$3"

    case "$type" in
        "info")
            dialog --title "$title" --msgbox "$message" 10 60
            ;;
        "error")
            dialog --title "❌ $title" --msgbox "$message" 10 60
            log_error "$title: $message"
            ;;
        "success")
            dialog --title "✅ $title" --msgbox "$message" 10 60
            log_success "$title: $message"
            ;;
        "warning")
            dialog --title "⚠️ $title" --msgbox "$message" 10 60
            log_warn "$title: $message"
            ;;
    esac
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

run_with_progress() {
    local title="$1"
    local cmd="$2"

    (
        echo "0"
        eval "$cmd" &>/dev/null
        echo "100"
    ) | dialog --title "$title" --gauge "Executando..." 6 60 0

    if [ $? -eq 0 ]; then
        log_success "$title concluído"
        return 0
    else
        log_error "$title falhou"
        return 1
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        show_message "error" "Privilégios Insuficientes" "Este script deve ser executado como root.\nUse: sudo $0"
        exit 1
    fi
}

check_dependencies() {
    local deps=("curl" "wget" "dig" "iptables" "systemctl")
    local missing_deps=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_warn "Instalando dependências faltantes: ${missing_deps[*]}"
        apt update &>/dev/null
        apt install -y "${missing_deps[@]}" dialog &>/dev/null || {
            show_message "error" "Erro de Dependências" "Falha ao instalar: ${missing_deps[*]}"
            exit 1
        }
    fi
}

# ============================================================================
# FUNÇÕES DE DETECÇÃO DE SISTEMA
# ============================================================================

detect_system_info() {
    log_info "Detectando informações do sistema..."

    # Detectar interface de rede principal
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$NETWORK_INTERFACE" ]]; then
        NETWORK_INTERFACE=$(ip link show | grep -E "^[0-9].*state UP" | head -1 | awk -F': ' '{print $2}')
    fi

    # IP do sistema
    SYSTEM_IP=$(ip route get 8.8.8.8 | grep -oP 'src \K\S+' | head -1)

    # Gateway
    GATEWAY_IP=$(ip route | grep default | awk '{print $3}' | head -1)

    # RAM total
    TOTAL_RAM=$(free -m | awk 'NR==2{print $2}')

    # Armazenamento disponível
    AVAILABLE_STORAGE=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')

    # Arquitetura
    CPU_ARCHITECTURE=$(uname -m)

    # DNS atual
    DNS_SERVERS=$(grep -E "^nameserver" /etc/resolv.conf | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')

    log_info "Sistema detectado:"
    log_info "  Interface: $NETWORK_INTERFACE"
    log_info "  IP: $SYSTEM_IP"
    log_info "  Gateway: $GATEWAY_IP"
    log_info "  RAM: ${TOTAL_RAM}MB"
    log_info "  Storage: ${AVAILABLE_STORAGE}GB"
    log_info "  Arquitetura: $CPU_ARCHITECTURE"
}

validate_system_requirements() {
    local errors=()

    # Verificar RAM mínima
    if [[ $TOTAL_RAM -lt 512 ]]; then
        errors+=("RAM insuficiente: ${TOTAL_RAM}MB (mínimo 512MB)")
    fi

    # Verificar storage
    if [[ $AVAILABLE_STORAGE -lt 4 ]]; then
        errors+=("Storage insuficiente: ${AVAILABLE_STORAGE}GB (mínimo 4GB)")
    fi

    # Verificar interface de rede
    if [[ -z "$NETWORK_INTERFACE" ]]; then
        errors+=("Interface de rede não detectada")
    fi

    # Verificar conectividade
    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        errors+=("Sem conectividade com a internet")
    fi

    if [[ ${#errors[@]} -gt 0 ]]; then
        local error_msg=""
        for error in "${errors[@]}"; do
            error_msg+="• $error\n"
        done
        show_message "error" "Requisitos Não Atendidos" "$error_msg"
        exit 1
    fi

    log_success "Requisitos do sistema validados"
}

# ============================================================================
# FUNÇÕES DE BACKUP E ROLLBACK
# ============================================================================

create_backup() {
    log_info "Criando backup das configurações atuais..."

    mkdir -p "$BACKUP_DIR"

    # Backup de arquivos de configuração importantes
    local config_files=(
        "/etc/resolv.conf"
        "/etc/systemd/resolved.conf"
        "/etc/pihole"
        "/etc/unbound"
        "/etc/wireguard"
        "/etc/default/rng-tools"
        "/etc/sysctl.conf"
    )

    for config in "${config_files[@]}"; do
        if [[ -e "$config" ]]; then
            cp -r "$config" "$BACKUP_DIR/" 2>/dev/null || true
        fi
    done

    # Salvar lista de pacotes instalados
    dpkg --get-selections > "$BACKUP_DIR/installed-packages.txt"

    log_success "Backup criado em $BACKUP_DIR"
}

rollback_changes() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        show_message "warning" "Rollback" "Backup não encontrado. Rollback não disponível."
        return 1
    fi

    if dialog --title "⚠️ Confirmar Rollback" --yesno "Deseja realmente desfazer todas as alterações?\nIsso irá restaurar as configurações originais." 8 60; then
        log_info "Iniciando rollback..."

        # Parar serviços
        systemctl stop pihole-FTL unbound wg-quick@wg0 rng-tools 2>/dev/null || true

        # Restaurar configurações
        cp -r "$BACKUP_DIR"/* / 2>/dev/null || true

        # Remover pacotes instalados (básico)
        apt remove -y pihole unbound wireguard rng-tools 2>/dev/null || true
        apt autoremove -y 2>/dev/null || true

        show_message "success" "Rollback Concluído" "Configurações originais restauradas.\nReinicie o sistema para aplicar completamente."

        log_success "Rollback concluído"
    fi
}

# ============================================================================
# FUNÇÕES DE INSTALAÇÃO - PI-HOLE
# ============================================================================

install_pihole() {
    log_info "Iniciando instalação do Pi-hole..."

    # Pré-configurar variáveis do Pi-hole
    cat > /tmp/pihole-setupvars.conf <<EOF
WEBPASSWORD=
PIHOLE_INTERFACE=$NETWORK_INTERFACE
IPV4_ADDRESS=$SYSTEM_IP/24
IPV6_ADDRESS=
PIHOLE_DNS_1=127.0.0.1#5335
PIHOLE_DNS_2=
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSSEC=true
TEMPERATUREUNIT=C
WEBUIBOXEDLAYOUT=boxed
API_EXCLUDE_DOMAINS=
API_EXCLUDE_CLIENTS=
API_QUERY_LOG_SHOW=permittedonly
API_PRIVACY_MODE=false
EOF

    # Instalar Pi-hole
    if ! run_with_progress "Instalação Pi-hole" "curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended"; then
        show_message "error" "Erro Pi-hole" "Falha na instalação do Pi-hole"
        return 1
    fi

    # Aplicar configurações personalizadas
    if [[ -f /etc/pihole/setupVars.conf ]]; then
        cp /tmp/pihole-setupvars.conf /etc/pihole/setupVars.conf
        pihole reconfigure --unattended &>/dev/null
    fi

    # Configurar password do admin
    local admin_password
    admin_password=$(dialog --title "Configuração Pi-hole" --passwordbox "Digite a senha do administrador Pi-hole:" 8 50 3>&1 1>&2 2>&3) || admin_password="admin123"

    if [[ -n "$admin_password" ]]; then
        pihole -a -p "$admin_password" &>/dev/null
    fi

    # Habilitar e iniciar serviço
    systemctl enable pihole-FTL &>/dev/null
    systemctl start pihole-FTL &>/dev/null

    log_success "Pi-hole instalado e configurado"
    return 0
}

configure_pihole_optimizations() {
    log_info "Aplicando otimizações do Pi-hole para ARM..."

    # Configurações otimizadas para ARM com pouca RAM
    cat >> /etc/pihole/pihole-FTL.conf <<EOF
# Otimizações para ARM RK322x
MAXDBDAYS=30
DBINTERVAL=60.0
MAXLOGAGE=7
PRIVACYLEVEL=0
IGNORE_LOCALHOST=no
AAAA_QUERY_ANALYSIS=yes
ANALYZE_ONLY_A_AND_AAAA=false
DBFILE=/etc/pihole/pihole-FTL.db
LOGFILE=/var/log/pihole-FTL.log
PIDFILE=/var/run/pihole-FTL.pid
SOCKETFILE=/var/run/pihole/FTL.sock
MACVENDORDB=/etc/pihole/macvendor.db
GRAVITYDB=/etc/pihole/gravity.db

# Configurações de memória para sistemas limitados
FTLCHUNKSIZE=4096
MAXNETAGE=365
MAXDBDAYS=30

# Configurações de rede otimizadas
SOCKET_LISTENING=localonly
FTLPORT=4711
RESOLVE_IPV6=no
RESOLVE_IPV4=yes
EOF

    # Reiniciar serviço para aplicar configurações
    systemctl restart pihole-FTL &>/dev/null

    log_success "Otimizações do Pi-hole aplicadas"
}

# ============================================================================
# FUNÇÕES DE INSTALAÇÃO - UNBOUND
# ============================================================================

install_unbound() {
    log_info "Iniciando instalação do Unbound..."

    # Instalar Unbound
    if ! run_with_progress "Instalação Unbound" "apt update && apt install -y unbound"; then
        show_message "error" "Erro Unbound" "Falha na instalação do Unbound"
        return 1
    fi

    # Criar configuração otimizada para ARM
    cat > /etc/unbound/unbound.conf.d/pi-hole.conf <<EOF
server:
    # Configurações básicas
    verbosity: 1
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    prefer-ip6: no

    # Configurações de rede
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    edns-buffer-size: 1232
    prefetch: yes
    prefetch-key: yes

    # Otimizações para ARM/baixa RAM (${TOTAL_RAM}MB)
    num-threads: 1
    msg-cache-slabs: 1
    rrset-cache-slabs: 1
    infra-cache-slabs: 1
    key-cache-slabs: 1

    # Configurações de cache otimizadas
    rrset-cache-size: 32m
    msg-cache-size: 16m
    so-rcvbuf: 512k
    so-sndbuf: 512k

    # Configurações de privacidade
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
    hide-identity: yes
    hide-version: yes

    # Configurações de segurança
    harden-short-bufsize: yes
    harden-large-queries: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes

    # Trust anchor e root hints
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    root-hints: "/var/lib/unbound/root.hints"

    # Configurações de tempo
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    serve-expired: yes
    serve-expired-ttl: 3600
EOF

    # Configurar trust anchor e root hints
    setup_unbound_security

    # Habilitar e iniciar serviço
    systemctl enable unbound &>/dev/null

    # Testar configuração antes de iniciar
    if unbound-checkconf &>/dev/null; then
        systemctl start unbound &>/dev/null
        log_success "Unbound instalado e configurado"
        return 0
    else
        show_message "error" "Erro Unbound" "Configuração inválida do Unbound"
        return 1
    fi
}

setup_unbound_security() {
    log_info "Configurando segurança do Unbound..."

    # Criar diretório se necessário
    mkdir -p /var/lib/unbound

    # Baixar root hints
    if ! wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root &>/dev/null; then
        log_warn "Falha ao baixar root.hints online, usando configuração local"
        # Fallback para configuração básica
        echo ". 518400 IN NS a.root-servers.net." > /var/lib/unbound/root.hints
    fi

    # Configurar trust anchor automático
    if ! unbound-anchor -a /var/lib/unbound/root.key &>/dev/null; then
        log_warn "Falha no trust anchor automático, configurando manualmente"
        # Trust anchor manual (última versão conhecida)
        cat > /var/lib/unbound/root.key <<EOF
. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
EOF
    fi

    # Configurar permissões
    chown unbound:unbound /var/lib/unbound/root.key /var/lib/unbound/root.hints 2>/dev/null || true
    chmod 644 /var/lib/unbound/root.key /var/lib/unbound/root.hints

    log_success "Segurança do Unbound configurada"
}

test_unbound_dns() {
    log_info "Testando resolução DNS do Unbound..."

    # Aguardar serviço inicializar
    sleep 3

    # Teste básico
    if dig @127.0.0.1 -p 5335 google.com +short &>/dev/null; then
        log_success "Unbound DNS funcionando"
        return 0
    else
        log_error "Unbound DNS não está funcionando"
        return 1
    fi
}

# ============================================================================
# FUNÇÕES DE INSTALAÇÃO - WIREGUARD
# ============================================================================

install_wireguard() {
    log_info "Iniciando instalação do WireGuard..."

    # Instalar WireGuard
    if ! run_with_progress "Instalação WireGuard" "apt update && apt install -y wireguard wireguard-tools"; then
        show_message "error" "Erro WireGuard" "Falha na instalação do WireGuard"
        return 1
    fi

    # Configurar geração de chaves e configuração
    setup_wireguard_config

    # Configurar firewall e forwarding
    setup_wireguard_network

    log_success "WireGuard instalado e configurado"
    return 0
}

setup_wireguard_config() {
    log_info "Configurando WireGuard..."

    # Criar diretório de chaves
    mkdir -p /etc/wireguard/keys
    cd /etc/wireguard/keys

    # Gerar chaves com permissões corretas
    umask 077
    wg genkey | tee privatekey | wg pubkey > publickey

    # Obter chaves
    local private_key=$(cat privatekey)
    local public_key=$(cat publickey)

    # Configurar VPN subnet
    local vpn_subnet="10.200.200.0/24"
    local vpn_server_ip="10.200.200.1"

    # Criar configuração do servidor
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
# Configuração do Servidor WireGuard
PrivateKey = $private_key
Address = $vpn_server_ip/24
ListenPort = 51820

# Configurações de NAT e forwarding
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE

# Configurações DNS para clientes
DNS = $SYSTEM_IP

# Exemplo de peer - Configure clientes aqui
# [Peer]
# PublicKey = <CHAVE_PUBLICA_DO_CLIENTE>
# AllowedIPs = 10.200.200.2/32

EOF

    # Salvar informações para configuração de clientes
    cat > /etc/wireguard/client-template.conf <<EOF
# Configuração do Cliente WireGuard
# Substitua <PRIVATE_KEY_CLIENT> pela chave privada do cliente
# Configure no servidor a chave pública correspondente

[Interface]
PrivateKey = <PRIVATE_KEY_CLIENT>
Address = 10.200.200.X/24  # X = 2,3,4... para cada cliente
DNS = $SYSTEM_IP

[Peer]
PublicKey = $public_key
Endpoint = $SYSTEM_IP:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # Mostrar informações para configuração manual
    dialog --title "🔐 Configuração WireGuard" --msgbox "Chave Pública do Servidor:\n$public_key\n\nTemplate de cliente salvo em:\n/etc/wireguard/client-template.conf\n\nConfigure os clientes manualmente editando:\n/etc/wireguard/wg0.conf" 15 70

    log_info "Chave pública do servidor: $public_key"
}

setup_wireguard_network() {
    log_info "Configurando rede para WireGuard..."

    # Habilitar IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=1 &>/dev/null

    # Configurar UFW se estiver instalado
    if command -v ufw &>/dev/null; then
        # Configurar UFW para WireGuard
        ufw allow 51820/udp comment "WireGuard" &>/dev/null || true
        ufw allow 22/tcp comment "SSH" &>/dev/null || true
        ufw --force enable &>/dev/null || true
    else
        # Configurar iptables básico
        iptables -A INPUT -p udp --dport 51820 -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT

        # Salvar regras do iptables
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    fi

    # Habilitar e testar WireGuard
    systemctl enable wg-quick@wg0 &>/dev/null

    if systemctl start wg-quick@wg0 &>/dev/null; then
        log_success "WireGuard network configurado e ativo"
        return 0
    else
        log_error "Falha ao iniciar WireGuard"
        return 1
    fi
}

# ============================================================================
# FUNÇÕES DE INSTALAÇÃO - RNG-TOOLS
# ============================================================================

install_rng_tools() {
    log_info "Iniciando instalação do RNG-tools..."

    # Instalar rng-tools
    if ! run_with_progress "Instalação RNG-tools" "apt update && apt install -y rng-tools"; then
        show_message "error" "Erro RNG-tools" "Falha na instalação do RNG-tools"
        return 1
    fi

    # Configurar para hardware específico
    setup_rng_optimization

    # Verificar alternativas se necessário
    setup_entropy_alternatives

    log_success "RNG-tools instalado e configurado"
    return 0
}

setup_rng_optimization() {
    log_info "Configurando RNG para hardware ARM..."

    # Detectar dispositivos de entropia disponíveis
    local rng_device="/dev/urandom"  # Fallback seguro

    if [[ -e "/dev/hwrng" ]]; then
        rng_device="/dev/hwrng"
        log_info "Hardware RNG detectado: /dev/hwrng"
    elif [[ -e "/dev/random" ]]; then
        rng_device="/dev/random"
        log_info "Usando /dev/random como fonte de entropia"
    fi

    # Configurar rng-tools
    cat > /etc/default/rng-tools <<EOF
# Configuração RNG-tools otimizada para ARM RK322x

# Dispositivo de entropia
HRNGDEVICE="$rng_device"

# Opções otimizadas para ARM com pouca RAM
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10 --random-step=64"

# Configurações específicas para RK322x
RNGD_OPTS="-f -r $rng_device -W 2048"

# Enable para inicialização automática
RNGD_ENABLED=1
EOF

    # Habilitar e iniciar serviço
    systemctl enable rng-tools &>/dev/null
    systemctl start rng-tools &>/dev/null

    # Verificar nível de entropia
    sleep 2
    local entropy_level=$(cat /proc/sys/kernel/random/entropy_avail)
    log_info "Nível de entropia atual: $entropy_level"

    if [[ $entropy_level -lt 1000 ]]; then
        log_warn "Entropia baixa ($entropy_level), configurando alternativas..."
        return 1
    fi

    return 0
}

setup_entropy_alternatives() {
    local current_entropy=$(cat /proc/sys/kernel/random/entropy_avail)

    if [[ $current_entropy -lt 1000 ]]; then
        log_info "Configurando haveged como alternativa..."

        if apt install -y haveged &>/dev/null; then
            systemctl enable haveged &>/dev/null
            systemctl start haveged &>/dev/null

            # Aguardar e verificar novamente
            sleep 3
            local new_entropy=$(cat /proc/sys/kernel/random/entropy_avail)

            if [[ $new_entropy -gt $current_entropy ]]; then
                log_success "Haveged instalado, entropia melhorada: $new_entropy"
            fi
        fi
    fi
}

# ============================================================================
# FUNÇÕES DE OTIMIZAÇÃO DO SISTEMA
# ============================================================================

apply_system_optimizations() {
    log_info "Aplicando otimizações do sistema para ARM..."

    # Otimizações de memória para ARM
    cat >> /etc/sysctl.conf <<EOF

# Otimizações BOXSERVER para ARM RK322x
# Configurações de memória
vm.swappiness=10
vm.vfs_cache_pressure=50
vm.dirty_background_ratio=5
vm.dirty_ratio=10

# Configurações de rede
net.core.rmem_default=262144
net.core.wmem_default=262144
net.core.rmem_max=16777216
net.core.wmem_max=16777216

# Otimizações DNS
net.core.netdev_max_backlog=5000
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3

# Segurança de rede
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1
EOF

    # Aplicar configurações
    sysctl -p &>/dev/null

    # Configurar chrony para sincronização de tempo
    setup_time_sync

    # Configurar logrotate
    setup_log_rotation

    # Configurar limpeza automática
    setup_automated_cleanup

    log_success "Otimizações do sistema aplicadas"
}

setup_time_sync() {
    log_info "Configurando sincronização de tempo..."

    if apt install -y chrony &>/dev/null; then
        # Configurar servidores NTP brasileiros
        cat >> /etc/chrony/chrony.conf <<EOF

# Servidores NTP brasileiros - BOXSERVER
server a.st1.ntp.br iburst
server b.st1.ntp.br iburst
server c.st1.ntp.br iburst
server d.st1.ntp.br iburst
EOF

        systemctl enable chrony &>/dev/null
        systemctl start chrony &>/dev/null

        log_success "Sincronização de tempo configurada"
    else
        log_warn "Falha ao instalar chrony"
    fi
}

setup_log_rotation() {
    log_info "Configurando rotação de logs..."

    # Configuração para Pi-hole
    cat > /etc/logrotate.d/boxserver <<EOF
/var/log/pihole.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 pihole pihole
    postrotate
        systemctl reload pihole-FTL > /dev/null 2>&1 || true
    endscript
}

/var/log/boxserver-installer.log {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
    create 644 root root
}

/var/log/unbound.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 unbound unbound
    postrotate
        systemctl reload unbound > /dev/null 2>&1 || true
    endscript
}
EOF

    log_success "Rotação de logs configurada"
}

setup_automated_cleanup() {
    log_info "Configurando limpeza automática..."

    # Script de limpeza semanal
    cat > /etc/cron.weekly/boxserver-cleanup <<'EOF'
#!/bin/bash
# Script de limpeza automática do BOXSERVER

LOG_FILE="/var/log/boxserver-cleanup.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

log "Iniciando limpeza automática..."

# Limpeza de pacotes
apt autoremove --purge -y >> "$LOG_FILE" 2>&1
apt autoclean >> "$LOG_FILE" 2>&1

# Limpeza de logs (manter últimos 7 dias)
journalctl --vacuum-time=7d >> "$LOG_FILE" 2>&1

# Limpeza de logs do Pi-hole (manter últimos 30 dias)
find /var/log -name "pihole*.log*" -mtime +30 -delete 2>/dev/null

# Limpeza de cache DNS
if systemctl is-active --quiet unbound; then
    unbound-control flush_zone . >> "$LOG_FILE" 2>&1 || true
fi

# Verificar espaço em disco
DISK_USAGE=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
log "Uso do disco: ${DISK_USAGE}%"

if [ "$DISK_USAGE" -gt 90 ]; then
    log "ALERTA: Uso de disco alto (${DISK_USAGE}%)"
fi

# Verificar entropia
ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail)
log "Entropia atual: $ENTROPY"

if [ "$ENTROPY" -lt 1000 ]; then
    log "ALERTA: Entropia baixa ($ENTROPY)"
    systemctl restart rng-tools >> "$LOG_FILE" 2>&1 || true
fi

log "Limpeza automática concluída"
EOF

    chmod +x /etc/cron.weekly/boxserver-cleanup

    log_success "Limpeza automática configurada"
}

# ============================================================================
# FUNÇÕES DE TESTE E VALIDAÇÃO
# ============================================================================

run_system_tests() {
    log_info "Executando testes do sistema..."

    local test_results=()
    local total_tests=0
    local passed_tests=0

    # Teste 1: Serviços ativos
    log_info "Testando serviços..."
    local services=("pihole-FTL" "unbound" "wg-quick@wg0" "rng-tools" "chrony")

    for service in "${services[@]}"; do
        ((total_tests++))
        if systemctl is-active --quiet "$service"; then
            test_results+=("✅ Serviço $service: ATIVO")
            ((passed_tests++))
        else
            test_results+=("❌ Serviço $service: INATIVO")
        fi
    done

    # Teste 2: DNS Pi-hole
    ((total_tests++))
    if timeout 5 dig @127.0.0.1 google.com +short &>/dev/null; then
        test_results+=("✅ DNS Pi-hole: FUNCIONANDO")
        ((passed_tests++))
    else
        test_results+=("❌ DNS Pi-hole: FALHOU")
    fi

    # Teste 3: DNS Unbound
    ((total_tests++))
    if timeout 5 dig @127.0.0.1 -p 5335 google.com +short &>/dev/null; then
        test_results+=("✅ DNS Unbound: FUNCIONANDO")
        ((passed_tests++))
    else
        test_results+=("❌ DNS Unbound: FALHOU")
    fi

    # Teste 4: Conectividade externa
    ((total_tests++))
    if timeout 5 ping -c 1 8.8.8.8 &>/dev/null; then
        test_results+=("✅ Conectividade externa: OK")
        ((passed_tests++))
    else
        test_results+=("❌ Conectividade externa: FALHOU")
    fi

    # Teste 5: WireGuard interface
    ((total_tests++))
    if ip link show wg0 &>/dev/null; then
        test_results+=("✅ Interface WireGuard: ATIVA")
        ((passed_tests++))
    else
        test_results+=("❌ Interface WireGuard: INATIVA")
    fi

    # Teste 6: Entropia
    ((total_tests++))
    local entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    if [[ $entropy -gt 1000 ]]; then
        test_results+=("✅ Entropia: ADEQUADA ($entropy)")
        ((passed_tests++))
    else
        test_results+=("⚠️  Entropia: BAIXA ($entropy)")
    fi

    # Mostrar resultados
    local result_text=""
    for result in "${test_results[@]}"; do
        result_text+="$result\n"
    done
    result_text+="\nResultado: $passed_tests/$total_tests testes aprovados"

    if [[ $passed_tests -eq $total_tests ]]; then
        show_message "success" "Testes Concluídos" "$result_text"
        log_success "Todos os testes passaram ($passed_tests/$total_tests)"
        return 0
    else
        show_message "warning" "Testes com Problemas" "$result_text"
        log_warn "Alguns testes falharam ($passed_tests/$total_tests)"
        return 1
    fi
}

show_system_status() {
    log_info "Coletando status do sistema..."

    # Informações do sistema
    local uptime_info=$(uptime -p)
    local memory_info=$(free -h | awk 'NR==2{printf "%.1f%% (%s/%s)", $3*100/$2, $3, $2}')
    local disk_info=$(df -h / | awk 'NR==2{printf "%s usado de %s (%s)", $3, $2, $5}')
    local entropy_info=$(cat /proc/sys/kernel/random/entropy_avail)

    # Temperatura (se disponível)
    local temp_info="N/A"
    if [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
        temp_info="$(($(cat /sys/class/thermal/thermal_zone0/temp)/1000))°C"
    fi

    # Status dos serviços
    local service_status=""
    local services=("pihole-FTL" "unbound" "wg-quick@wg0" "rng-tools" "chrony")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            service_status+="✅ $service: ATIVO\n"
        else
            service_status+="❌ $service: INATIVO\n"
        fi
    done

    # Informações de rede
    local vpn_clients="0"
    if systemctl is-active --quiet wg-quick@wg0; then
        vpn_clients=$(wg show wg0 peers 2>/dev/null | wc -l)
    fi

    # Testes rápidos de DNS
    local pihole_dns="❌"
    local unbound_dns="❌"

    if timeout 3 dig @127.0.0.1 google.com +short &>/dev/null; then
        pihole_dns="✅"
    fi

    if timeout 3 dig @127.0.0.1 -p 5335 google.com +short &>/dev/null; then
        unbound_dns="✅"
    fi

    # Montar mensagem de status
    local status_msg="=== INFORMAÇÕES DO SISTEMA ===
Uptime: $uptime_info
Memória: $memory_info
Disco: $disk_info
Temperatura: $temp_info
Entropia: $entropy_info

=== STATUS DOS SERVIÇOS ===
$service_status
=== CONECTIVIDADE ===
$pihole_dns Pi-hole DNS
$unbound_dns Unbound DNS
VPN Clientes conectados: $vpn_clients

=== CONFIGURAÇÃO DE REDE ===
Interface: $NETWORK_INTERFACE
IP do sistema: $SYSTEM_IP
Gateway: $GATEWAY_IP"

    dialog --title "📊 Status do BOXSERVER" --msgbox "$status_msg" 25 80
}

# ============================================================================
# INTERFACE TUI - MENUS
# ============================================================================

show_main_menu() {
    while true; do
        local choice
        choice=$(dialog --clear --title "🚀 BOXSERVER Auto-Installer v$SCRIPT_VERSION" \
            --menu "Escolha uma opção:" 20 70 12 \
            "1" "🔧 Instalação Completa Automática" \
            "2" "📦 Instalação Individual por Componente" \
            "3" "🔍 Verificar Requisitos do Sistema" \
            "4" "🧪 Executar Testes do Sistema" \
            "5" "📊 Mostrar Status Atual" \
            "6" "🔧 Otimizações do Sistema" \
            "7" "📋 Configurar Cliente WireGuard" \
            "8" "🗂️  Criar Backup das Configurações" \
            "9" "↩️  Rollback (Desfazer Alterações)" \
            "10" "📖 Mostrar Logs do Sistema" \
            "11" "ℹ️  Sobre" \
            "0" "🚪 Sair" \
            3>&1 1>&2 2>&3) || exit 0

        case $choice in
            1) full_installation ;;
            2) component_installation_menu ;;
            3) system_requirements_check ;;
            4) run_system_tests ;;
            5) show_system_status ;;
            6) apply_system_optimizations ;;
            7) configure_wireguard_client ;;
            8) create_backup ;;
            9) rollback_changes ;;
            10) show_logs_menu ;;
            11) show_about ;;
            0) exit 0 ;;
            *) show_message "error" "Opção Inválida" "Por favor, selecione uma opção válida." ;;
        esac
    done
}

component_installation_menu() {
    while true; do
        local choice
        choice=$(dialog --clear --title "📦 Instalação Individual" \
            --menu "Escolha o componente:" 15 60 8 \
            "1" "🛡️  Pi-hole (DNS + Ad-block)" \
            "2" "🔒 Unbound (DNS Recursivo)" \
            "3" "🌐 WireGuard (VPN)" \
            "4" "🎲 RNG-tools (Entropia)" \
            "5" "⚡ Otimizações do Sistema" \
            "6" "🧪 Testar Componentes" \
            "0" "↩️  Voltar ao Menu Principal" \
            3>&1 1>&2 2>&3) || break

        case $choice in
            1)
                if install_pihole && configure_pihole_optimizations; then
                    show_message "success" "Pi-hole" "Pi-hole instalado com sucesso!"
                fi
                ;;
            2)
                if install_unbound && test_unbound_dns; then
                    show_message "success" "Unbound" "Unbound instalado com sucesso!"
                fi
                ;;
            3)
                if install_wireguard; then
                    show_message "success" "WireGuard" "WireGuard instalado com sucesso!"
                fi
                ;;
            4)
                if install_rng_tools; then
                    show_message "success" "RNG-tools" "RNG-tools instalado com sucesso!"
                fi
                ;;
            5)
                if apply_system_optimizations; then
                    show_message "success" "Otimizações" "Otimizações aplicadas com sucesso!"
                fi
                ;;
            6) run_system_tests ;;
            0) break ;;
        esac
    done
}

full_installation() {
    if dialog --title "⚠️ Confirmação" --yesno "Deseja executar a instalação completa?\n\nIsso irá instalar e configurar:\n• Pi-hole\n• Unbound\n• WireGuard\n• RNG-tools\n• Otimizações do sistema\n\nContinuar?" 12 60; then

        log_info "Iniciando instalação completa..."

        # Criar backup
        create_backup

        # Executar instalações sequencialmente
        local components=("Pi-hole" "Unbound" "WireGuard" "RNG-tools" "Otimizações")
        local functions=("install_pihole && configure_pihole_optimizations"
                        "install_unbound && test_unbound_dns"
                        "install_wireguard"
                        "install_rng_tools"
                        "apply_system_optimizations")

        local failed_components=()

        for i in "${!components[@]}"; do
            local component="${components[i]}"
            local func="${functions[i]}"

            log_info "Instalando: $component"

            (
                echo "25"
                eval "$func" &>/dev/null
                echo "100"
            ) | dialog --title "Instalando $component" --gauge "Por favor, aguarde..." 6 60 0

            if [ $? -ne 0 ]; then
                failed_components+=("$component")
                log_error "Falha na instalação: $component"
            else
                log_success "Instalação concluída: $component"
            fi
        done

        # Mostrar resultado final
        if [ ${#failed_components[@]} -eq 0 ]; then
            show_message "success" "Instalação Completa" "Todos os componentes foram instalados com sucesso!\n\nExecute os testes do sistema para verificar o funcionamento."

            # Executar testes automáticos
            if dialog --title "Testes Automáticos" --yesno "Deseja executar os testes do sistema agora?" 8 50; then
                run_system_tests
            fi
        else
            local failed_list=""
            for comp in "${failed_components[@]}"; do
                failed_list+="• $comp\n"
            done
            show_message "warning" "Instalação Parcial" "Alguns componentes falharam:\n$failed_list\nConsulte os logs para mais detalhes."
        fi
    fi
}

configure_wireguard_client() {
    if ! systemctl is-active --quiet wg-quick@wg0; then
        show_message "error" "WireGuard Inativo" "WireGuard não está instalado ou ativo.\nInstale o WireGuard primeiro."
        return 1
    fi

    # Obter próximo IP disponível
    local next_ip=2
    while grep -q "10.200.200.$next_ip" /etc/wireguard/wg0.conf; do
        ((next_ip++))
        if [[ $next_ip -gt 254 ]]; then
            show_message "error" "Limite Atingido" "Máximo de clientes VPN atingido (254)."
            return 1
        fi
    done

    # Solicitar nome do cliente
    local client_name
    client_name=$(dialog --title "Configuração Cliente VPN" --inputbox "Digite o nome do cliente:" 8 40 "cliente$next_ip" 3>&1 1>&2 2>&3) || return

    if [[ -z "$client_name" ]]; then
        show_message "error" "Nome Inválido" "Nome do cliente não pode estar vazio."
        return 1
    fi

    # Gerar chaves do cliente
    local client_dir="/etc/wireguard/clients/$client_name"
    mkdir -p "$client_dir"
    cd "$client_dir"

    wg genkey | tee private.key | wg pubkey > public.key
    local client_private_key=$(cat private.key)
    local client_public_key=$(cat public.key)
    local server_public_key=$(cat /etc/wireguard/keys/publickey)

    # Adicionar peer ao servidor
    cat >> /etc/wireguard/wg0.conf <<EOF

# Cliente: $client_name
[Peer]
PublicKey = $client_public_key
AllowedIPs = 10.200.200.$next_ip/32
EOF

    # Criar configuração do cliente
    cat > "$client_dir/$client_name.conf" <<EOF
[Interface]
PrivateKey = $client_private_key
Address = 10.200.200.$next_ip/24
DNS = $SYSTEM_IP

[Peer]
PublicKey = $server_public_key
Endpoint = $SYSTEM_IP:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # Gerar QR Code se possível
    if command -v qrencode &>/dev/null; then
        qrencode -t ansiutf8 < "$client_dir/$client_name.conf" > "$client_dir/$client_name.qr"
    fi

    # Reiniciar WireGuard
    systemctl restart wg-quick@wg0

    # Mostrar informações
    local config_content=$(cat "$client_dir/$client_name.conf")
    dialog --title "✅ Cliente VPN Configurado" --msgbox "Cliente '$client_name' configurado com sucesso!\n\nIP: 10.200.200.$next_ip\n\nArquivo de configuração salvo em:\n$client_dir/$client_name.conf\n\nImporte esta configuração no aplicativo WireGuard do cliente." 15 70

    log_success "Cliente VPN '$client_name' configurado com IP 10.200.200.$next_ip"
}

system_requirements_check() {
    log_info "Verificando requisitos do sistema..."

    detect_system_info

    local req_msg="=== REQUISITOS DO SISTEMA ===

Hardware Detectado:
• Arquitetura: $CPU_ARCHITECTURE
• RAM Total: ${TOTAL_RAM}MB
• Storage Disponível: ${AVAILABLE_STORAGE}GB
• Interface de Rede: $NETWORK_INTERFACE

Configurações de Rede:
• IP do Sistema: $SYSTEM_IP
• Gateway: $GATEWAY_IP
• DNS Atual: $DNS_SERVERS

Requisitos Mínimos:
✓ RAM: 512MB (Recomendado: 1GB)
✓ Storage: 4GB (Recomendado: 8GB)
✓ Conectividade com Internet
✓ Interface de Rede Ativa"

    # Validar requisitos
    local warnings=""

    if [[ $TOTAL_RAM -lt 1024 ]]; then
        warnings+="⚠️  RAM abaixo do recomendado (${TOTAL_RAM}MB < 1GB)\n"
    fi

    if [[ $AVAILABLE_STORAGE -lt 8 ]]; then
        warnings+="⚠️  Storage abaixo do recomendado (${AVAILABLE_STORAGE}GB < 8GB)\n"
    fi

    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        warnings+="❌ Sem conectividade com a internet\n"
    fi

    if [[ -n "$warnings" ]]; then
        req_msg+="\n\n=== AVISOS ===\n$warnings"
    fi

    dialog --title "🔍 Verificação de Requisitos" --msgbox "$req_msg" 25 80

    # Validação automática
    validate_system_requirements
}

show_logs_menu() {
    while true; do
        local choice
        choice=$(dialog --clear --title "📖 Logs do Sistema" \
            --menu "Escolha o log:" 15 60 8 \
            "1" "📋 Log do Installer" \
            "2" "🛡️  Log do Pi-hole" \
            "3" "🔒 Log do Unbound" \
            "4" "🌐 Log do WireGuard" \
            "5" "🎲 Log do RNG-tools" \
            "6" "⚙️  Log do Sistema (journalctl)" \
            "7" "🧹 Log de Limpeza" \
            "0" "↩️  Voltar" \
            3>&1 1>&2 2>&3) || break

        case $choice in
            1) show_log_file "$LOG_FILE" ;;
            2) show_log_file "/var/log/pihole.log" ;;
            3) show_journal_log "unbound" ;;
            4) show_journal_log "wg-quick@wg0" ;;
            5) show_journal_log "rng-tools" ;;
            6) show_journal_log "" ;;
            7) show_log_file "/var/log/boxserver-cleanup.log" ;;
            0) break ;;
        esac
    done
}

show_log_file() {
    local log_file="$1"
    if [[ -f "$log_file" ]]; then
        dialog --title "📖 $log_file" --textbox "$log_file" 20 80
    else
        show_message "error" "Log não encontrado" "Arquivo de log não existe: $log_file"
    fi
}

show_journal_log() {
    local service="$1"
    local temp_log="/tmp/boxserver-journal.log"

    if [[ -n "$service" ]]; then
        journalctl -u "$service" -n 50 --no-pager > "$temp_log"
    else
        journalctl -n 50 --no-pager > "$temp_log"
    fi

    dialog --title "📖 Journal Log${service:+ - $service}" --textbox "$temp_log" 20 80
    rm -f "$temp_log"
}

show_about() {
    dialog --title "ℹ️ Sobre o BOXSERVER" --msgbox "
🚀 BOXSERVER Auto-Installer v$SCRIPT_VERSION

Instalador automatizado para configuração completa de:
• Pi-hole (DNS + Bloqueio de anúncios)
• Unbound (DNS recursivo local)
• WireGuard (VPN segura)
• RNG-tools (Gerador de entropia)
• Otimizações para ARM RK322x

📋 Características:
✓ Interface TUI amigável
✓ Detecção automática de hardware
✓ Configurações otimizadas para ARM
✓ Sistema de backup e rollback
✓ Testes automáticos de validação
✓ Monitoramento integrado

🎯 Otimizado para:
• Sistemas ARM RK322x
• Debian/Ubuntu/Armbian
• Hardware com recursos limitados

📧 Projeto: BOXSERVER
📅 Data: $(date +%Y-%m-%d)
" 25 70
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

main() {
    # Configurar logging
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$CONFIG_DIR"

    # Verificações iniciais
    check_root
    check_dependencies

    # Detectar informações do sistema
    detect_system_info

    log_info "=== BOXSERVER Auto-Installer v$SCRIPT_VERSION iniciado ==="
    log_info "Sistema: $CPU_ARCHITECTURE, RAM: ${TOTAL_RAM}MB, Interface: $NETWORK_INTERFACE"

    # Mostrar tela de boas-vindas
    dialog --title "🚀 Bem-vindo ao BOXSERVER" --msgbox "
BOXSERVER Auto-Installer v$SCRIPT_VERSION

Este script irá configurar automaticamente:
• Pi-hole (DNS + Ad-block)
• Unbound (DNS recursivo)
• WireGuard (VPN)
• RNG-tools (Entropia)
• Otimizações do sistema

Sistema detectado:
• Arquitetura: $CPU_ARCHITECTURE
• RAM: ${TOTAL_RAM}MB
• Interface: $NETWORK_INTERFACE
• IP: $SYSTEM_IP

Pressione OK para continuar...
" 20 60

    # Iniciar menu principal
    show_main_menu

    log_info "=== BOXSERVER Auto-Installer finalizado ==="
}

# ============================================================================
# TRATAMENTO DE SINAIS E LIMPEZA
# ============================================================================

cleanup() {
    log_info "Limpeza em andamento..."
    clear
    echo "👋 Obrigado por usar o BOXSERVER Auto-Installer!"
    echo "📋 Logs salvos em: $LOG_FILE"
    echo "🔧 Configurações em: $CONFIG_DIR"
    exit 0
}

trap cleanup EXIT INT TERM

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

# Verificar se foi executado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
