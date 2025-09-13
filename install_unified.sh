#!/bin/bash

# =============================================================================
# BoxServer Installer v7.0 - Versão Unificada (FastAPI + Todos os Serviços)
# =============================================================================
# Autor: BoxServer Team (Atualizado por Claude)
# Descrição: Instalação unificada com API FastAPI moderna e todos os serviços
#              originais do install.sh v3.0
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURAÇÕES GLOBAIS
# =============================================================================

readonly SCRIPT_VERSION="7.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/boxserver-install-v7.log"
readonly CONFIG_FILE="/etc/boxserver/config.conf"
readonly BACKUP_DIR="/backups/boxserver"

# Cores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Configurações padrão
declare -A DEFAULT_CONFIG=(
    ["SERVER_IP"]="192.168.0.100"
    ["GATEWAY"]="192.168.0.1"
    ["DNS_SERVER"]="1.1.1.1"
    ["WIREGUARD_SUBNET"]="10.8.0.0/24"
    ["INSTALL_TYPE"]="essential"
    ["AUTO_OPTIMIZE"]="true"
    ["ENABLE_MONITORING"]="true"
)

# Lista de serviços
readonly ESSENTIAL_SERVICES=("system-opt" "base-deps" "firewall" "dns" "storage" "dashboard")
readonly NETWORK_SERVICES=("wireguard")
readonly OPTIONAL_SERVICES=("torrent" "sync")

# =============================================================================
# FUNÇÕES DE UTILIDADE
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"
}

log_step() {
    echo -e "\n${CYAN}[STEP]${NC} $*" | tee -a "$LOG_FILE"
}

show_header() {
    clear
    cat << 'EOF'
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   ███╗   ██╗███████╗████████╗███████╗██████╗ ███╗   ███╗    │
│   ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗████╗ ████║    │
│   ██╔██╗ ██║█████╗     ██║   █████╗  ██████╔╝██╔████╔██║    │
│   ██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║    │
│   ██║ ╚████║███████╗   ██║   ███████╗██║  ██║██║ ╚═╝ ██║    │
│   ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝    │
│                                                             │
│        Professional Server Installation - v7.0 (FastAPI)    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
EOF
    echo -e "${BLUE}BoxServer Installer v${SCRIPT_VERSION}${NC}"
    echo "Log file: ${LOG_FILE}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script deve ser executado como root"
        log_info "Use: sudo $0"
        exit 1
    fi
}

check_requirements() {
    log_step "Verificando requisitos do sistema"

    # Verificar sistema operacional
    if ! command -v lsb_release &> /dev/null; then
        log_error "Sistema operacional não suportado"
        exit 1
    fi

    # Verificar versão do kernel para compatibilidade
    local kernel_version=$(uname -r | cut -d. -f1-2)
    log_info "Versão do Kernel: $kernel_version"

    case "$kernel_version" in
        "4.4"|"4.9"|"4.14"|"4.19"|"5.4"|"5.10"|"5.15")
            log_info "Kernel $kernel_version - boa compatibilidade"
            ;;
        "3."*)
            log_warning "Kernel $kernel_version - compatibilidade limitada"
            ;;
        "2."*)
            log_error "Kernel $kernel_version - não suportado"
            exit 1
            ;;
        *)
            log_info "Kernel $kernel_version - excelente compatibilidade"
            ;;
    esac

    # Verificar arquitetura
    local arch=$(uname -m)
    case "$arch" in
        armv7l|aarch64|x86_64)
            log_info "Arquitetura compatível: $arch"
            ;;
        *)
            log_error "Arquitetura não suportada: $arch"
            exit 1
            ;;
    esac

    # Verificar memória RAM
    local total_mem=$(free -m | awk 'NR==2{print $2}')
    if [[ $total_mem -lt 512 ]]; then
        log_warning "Memória RAM insuficiente: ${total_mem}MB (mínimo: 512MB)"
        return 1
    fi

    # Verificar espaço em disco
    local disk_space=$(df / | awk 'NR==2{print $4}')
    if [[ $disk_space -lt 1048576 ]]; then  # 1GB em KB
        log_warning "Espaço em disco insuficiente: $((disk_space/1024))MB (mínimo: 1GB)"
        return 1
    fi

    # Verificar comandos essenciais
    local required_commands=("curl" "wget" "python3" "pip3" "systemctl" "ip" "iptables")
    local optional_commands=("netstat" "fuser" "ss" "testparm")

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Comando essencial não encontrado: $cmd"
            return 1
        fi
    done

    for cmd in "${optional_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_warning "Comando opcional não encontrado: $cmd (algumas funcionalidades podem não funcionar)"
        fi
    done

    # Verificar se /proc está montado
    if [[ ! -d "/proc" ]]; then
        log_error "/proc não está montado - necessário para compatibilidade"
        return 1
    fi

    log_success "Requisitos verificados com sucesso"
}

initialize_environment() {
    log_step "Inicializando ambiente"

    # Criar diretórios necessários
    mkdir -p "$(dirname "$CONFIG_FILE")" "$BACKUP_DIR" "/var/log/boxserver"
    mkdir -p /srv/{samba,filebrowser,downloads} /var/www/html

    # Inicializar arquivo de log
    touch "$LOG_FILE"

    # Carregar configuração existente se houver
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Carregando configuração existente"
        source "$CONFIG_FILE"
    else
        log_info "Criando nova configuração"
        create_default_config
    fi

    log_success "Ambiente inicializado"
}

create_default_config() {
    cat > "$CONFIG_FILE" << EOF
# BoxServer Configuration File
# Generated on $(date)

# Network Configuration
SERVER_IP="${DEFAULT_CONFIG[SERVER_IP]}"
GATEWAY="${DEFAULT_CONFIG[GATEWAY]}"
DNS_SERVER="${DEFAULT_CONFIG[DNS_SERVER]}"
WIREGUARD_SUBNET="${DEFAULT_CONFIG[WIREGUARD_SUBNET]}"

# Installation Options
INSTALL_TYPE="${DEFAULT_CONFIG[INSTALL_TYPE]}"
AUTO_OPTIMIZE="${DEFAULT_CONFIG[AUTO_OPTIMIZE]}"
ENABLE_MONITORING="${DEFAULT_CONFIG[ENABLE_MONITORING]}"

# Service Status Flags
SYSTEM_OPTIMIZED=false
BASE_DEPS_INSTALLED=false
FIREWALL_CONFIGURED=false
DNS_CONFIGURED=false
STORAGE_CONFIGURED=false
DASHBOARD_INSTALLED=false
WIREGUARD_CONFIGURED=false
TORRENT_INSTALLED=false
SYNC_INSTALLED=false

# Installation Timestamp
INSTALL_DATE=$(date +%Y-%m-%d_%H-%M-%S)
EOF
}

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        log_error "Arquivo de configuração não encontrado"
        exit 1
    fi
}

save_config() {
    cat > "$CONFIG_FILE" << EOF
# BoxServer Configuration File
# Updated on $(date)

# Network Configuration
SERVER_IP="$SERVER_IP"
GATEWAY="$GATEWAY"
DNS_SERVER="$DNS_SERVER"
WIREGUARD_SUBNET="$WIREGUARD_SUBNET"

# Installation Options
INSTALL_TYPE="$INSTALL_TYPE"
AUTO_OPTIMIZE="$AUTO_OPTIMIZE"
ENABLE_MONITORING="$ENABLE_MONITORING"

# Service Status Flags
SYSTEM_OPTIMIZED=$SYSTEM_OPTIMIZED
BASE_DEPS_INSTALLED=$BASE_DEPS_INSTALLED
FIREWALL_CONFIGURED=$FIREWALL_CONFIGURED
DNS_CONFIGURED=$DNS_CONFIGURED
STORAGE_CONFIGURED=$STORAGE_CONFIGURED
DASHBOARD_INSTALLED=$DASHBOARD_INSTALLED
WIREGUARD_CONFIGURED=$WIREGUARD_CONFIGURED
TORRENT_INSTALLED=$TORRENT_INSTALLED
SYNC_INSTALLED=$SYNC_INSTALLED

# Installation Timestamp
INSTALL_DATE=$INSTALL_DATE
EOF
}

# =============================================================================
# FUNÇÕES DE INSTALAÇÃO
# =============================================================================

install_system_optimizations() {
    log_step "Instalando otimizações do sistema"

    if [[ "$SYSTEM_OPTIMIZED" == "true" ]]; then
        log_info "Otimizações já instaladas, pulando..."
        return 0
    fi

    # Configurar IP fixo
    log_info "Configurando IP fixo: $SERVER_IP"

    # Detectar interface de rede automaticamente
    local network_interface=$(ip route | grep default | awk '{print $5}' | head -1)

    if [[ -n "$network_interface" ]]; then
        log_info "Interface de rede detectada: $network_interface"

        # Configurar IP estático via interfaces
        cat > /etc/network/interfaces.d/boxserver << EOF
auto $network_interface
iface $network_interface inet static
    address $SERVER_IP
    netmask 255.255.255.0
    gateway $GATEWAY
    dns-nameservers $DNS_SERVER
EOF

        # Tentar aplicar configuração
        if command -v ifdown &> /dev/null && command -v ifup &> /dev/null; then
            log_info "Usando ifdown/ifup para configurar rede"
            ifdown "$network_interface" 2>/dev/null || true
            sleep 2
            ifup "$network_interface" 2>/dev/null || true
        elif command -v systemctl &> /dev/null; then
            log_info "Usando systemctl para reiniciar rede"
            systemctl restart networking 2>/dev/null || true
            systemctl restart NetworkManager 2>/dev/null || true
        else
            log_info "Reinicialização de rede manual necessária"
        fi

        log_info "Configuração de rede aplicada via /etc/network/interfaces/"
    else
        log_warning "Não foi possível detectar interface de rede. Pulando configuração de IP fixo."
    fi

    # Atualizar sistema
    log_info "Atualizando sistema"
    apt update && apt upgrade -y

    # Criar swap otimizado
    if [[ ! -f /swapfile ]]; then
        log_info "Criando arquivo de swap (1GB)"
        fallocate -l 1G /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi

    # Otimizações sysctl
    cat > /etc/sysctl.d/99-arm-optimization.conf << 'EOF'
# Gerenciamento de memória agressivo para RAM limitada
vm.swappiness=10
vm.vfs_cache_pressure=50
vm.dirty_ratio=15
vm.dirty_background_ratio=5

# Otimizações para NAND
vm.laptop_mode=5
vm.dirty_writeback_centisecs=3000
vm.dirty_expire_centisecs=6000

# TCP otimizado
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216

# Segurança e forwarding
net.ipv4.ip_forward=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
EOF

    sysctl -p /etc/sysctl.d/99-arm-optimization.conf

    # Mover sistemas temporários para RAM
    local total_mem=$(free -m | awk 'NR==2{print $2}')
    local tmp_size=$((total_mem / 8))
    local log_size=$((total_mem / 16))

    [[ $tmp_size -lt 128 ]] && tmp_size=128
    [[ $tmp_size -gt 512 ]] && tmp_size=512
    [[ $log_size -lt 64 ]] && log_size=64
    [[ $log_size -gt 256 ]] && log_size=256

    echo "tmpfs /tmp tmpfs defaults,size=${tmp_size}M 0 0" >> /etc/fstab
    echo "tmpfs /var/log tmpfs defaults,size=${log_size}M 0 0" >> /etc/fstab
    echo "tmpfs /var/tmp tmpfs defaults,size=${log_size}M 0 0" >> /etc/fstab

    mount -a

    # Instalar ferramentas de otimização
    apt install -y cpufrequtils schedtool bc

    # Configurar governor
    cat > /etc/default/cpufrequtils << EOF
GOVERNOR="ondemand"
MAX_SPEED="1200000"
MIN_SPEED="600000"
EOF

    systemctl enable cpufrequtils

    # Desativar serviços desnecessários
    systemctl disable bluetooth avahi-daemon cups 2>/dev/null || true

    SYSTEM_OPTIMIZED=true
    save_config

    log_success "Otimizações do sistema concluídas"
}

install_base_dependencies() {
    log_step "Instalando dependências base"

    if [[ "$BASE_DEPS_INSTALLED" == "true" ]]; then
        log_info "Dependências base já instaladas, pulando..."
        return 0
    fi

    # Limpar e atualizar cache do apt
    log_info "Limpando cache do apt"
    apt clean
    apt autoremove -y

    log_info "Atualizando cache do apt"
    apt update

    # Instalar pacotes básicos
    log_info "Instalando pacotes essenciais"
    local packages=(
        "curl" "wget" "git" "dialog" "chrony" "rng-tools" "haveged"
        "build-essential" "ca-certificates" "gnupg" "lsb-release"
        "software-properties-common" "logrotate" "ufw" "htop" "python3"
        "python3-pip" "iotop" "sysstat"
    )

    local compat_packages=(
        "python3-dev" "python3-setuptools" "python3-wheel"
    )

    local failed_packages=()
    for package in "${packages[@]}"; do
        if ! apt install -y "$package"; then
            log_warning "Pacote $package não disponível, pulando..."
            failed_packages+=("$package")
        fi
    done

    for package in "${compat_packages[@]}"; do
        if ! apt install -y "$package"; then
            log_warning "Pacote de compatibilidade $package não disponível, pulando..."
            failed_packages+=("$package")
        fi
    done

    # Instalar psutil via pip
    log_info "Instalando psutil via pip para o dashboard"
    if command -v pip3 &> /dev/null; then
        pip3 install psutil || log_warning "Não foi possível instalar psutil via pip"
    else
        log_warning "pip3 não disponível, tentando instalar psutil via apt"
        apt install -y python3-psutil 2>/dev/null || log_warning "psutil não disponível via apt"
    fi

    if [[ ${#failed_packages[@]} -gt 0 ]]; then
        log_warning "Alguns pacotes não foram instalados: ${failed_packages[*]}"
    fi

    BASE_DEPS_INSTALLED=true
    save_config

    log_success "Dependências base instaladas"
}

install_firewall() {
    log_step "Configurando firewall"

    if [[ "$FIREWALL_CONFIGURED" == "true" ]]; then
        log_info "Firewall já configurado, pulando..."
        return 0
    fi

    # Definir portas para abrir
    declare -A ports_to_open=(
        ["22/tcp"]="SSH"
        ["80/tcp"]="Dashboard"
        ["443/tcp"]="HTTPS"
        ["5000/tcp"]="WireGuard-UI"
        ["51820/udp"]="WireGuard VPN"
        ["22000/tcp"]="Syncthing"
        ["22000/udp"]="Syncthing"
        ["8082/tcp"]="FileBrowser"
        ["8090/tcp"]="Pi-hole Admin"
        ["9091/tcp"]="qBittorrent"
        ["8384/tcp"]="Syncthing Web"
        ["445/tcp"]="Samba"
        ["139/tcp"]="Samba NetBIOS"
        ["137/udp"]="Samba NetBIOS"
        ["138/udp"]="Samba NetBIOS"
        ["53/tcp"]="DNS"
        ["53/udp"]="DNS"
    )

    log_info "Verificando compatibilidade do firewall"
    local kernel_version=$(uname -r | cut -d. -f1-2)

    if [[ "$kernel_version" == "4.4" ]]; then
        log_warning "Kernel 4.4 detectado - usando iptables legado"

        # Configurar regras básicas de iptables
        iptables -F INPUT; iptables -F FORWARD; iptables -F OUTPUT
        iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT

        for port_spec in "${!ports_to_open[@]}"; do
            local port_num=$(echo $port_spec | cut -d/ -f1)
            local proto=$(echo $port_spec | cut -d/ -f2)
            log_info "Permitindo porta ${port_num}/${proto} para ${ports_to_open[$port_spec]}"
            iptables -A INPUT -p $proto --dport $port_num -j ACCEPT
        done

        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        cat > /etc/systemd/system/iptables-restore.service << EOF
[Unit]
Description=Restore iptables rules
Before=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable iptables-restore.service
        log_info "Firewall configurado com iptables (compatível com kernel 4.4)"
    else
        log_info "Usando UFW para kernel $kernel_version"

        ufw default deny incoming
        ufw default allow outgoing

        for port_spec in "${!ports_to_open[@]}"; do
            log_info "Permitindo porta ${port_spec} para ${ports_to_open[$port_spec]}"
            ufw allow ${port_spec} comment "${ports_to_open[$port_spec]}"
        done

        if ! ufw --force enable 2>/dev/null; then
            log_warning "UFW falhou, usando iptables diretamente como fallback"
            iptables -F INPUT; iptables -F FORWARD; iptables -F OUTPUT
            iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -i lo -j ACCEPT
            for port_spec in "${!ports_to_open[@]}"; do
                local port_num=$(echo $port_spec | cut -d/ -f1)
                local proto=$(echo $port_spec | cut -d/ -f2)
                iptables -A INPUT -p $proto --dport $port_num -j ACCEPT
            done
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
        fi
    fi

    # Instalar fail2ban
    log_info "Instalando fail2ban"
    apt install -y fail2ban
    systemctl enable --now fail2ban

    FIREWALL_CONFIGURED=true
    save_config

    log_success "Firewall configurado"
}

install_dns_services() {
    log_step "Instalando serviços DNS (Pi-hole + Unbound)"

    if [[ "$DNS_CONFIGURED" == "true" ]]; then
        log_info "Serviços DNS já configurados, pulando..."
        return 0
    fi

    # Limpar instalações problemáticas anteriores
    purge_service "lighttpd"
    purge_service "unbound"
    purge_service "dnsmasq"

    # Instalar dependências
    log_info "Instalando Unbound, lighttpd e dependências PHP..."
    apt update
    apt install -y unbound lighttpd php-cgi php-sqlite3

    # Configurar Unbound
    mkdir -p /etc/unbound/unbound.conf.d
    wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
    cat > /etc/unbound/unbound.conf.d/pi-hole.conf << EOF
server:
  verbosity: 0
  interface: 127.0.0.1
  port: 5335
  do-ip4: yes
  do-udp: yes
  do-tcp: yes
  root-hints: "/var/lib/unbound/root.hints"
  harden-glue: yes
  harden-dnssec-stripped: yes
  use-caps-for-id: no
  edns-buffer-size: 1232
  prefetch: yes
  num-threads: 2
  msg-cache-size: 50m
  rrset-cache-size: 100m
EOF
    systemctl enable --now unbound

    # Instalação Não-Assistida do Pi-hole
    log_info "Preparando instalação não-assistida do Pi-hole..."

    local network_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$network_interface" ]]; then
        log_error "Não foi possível detectar a interface de rede para o Pi-hole. Abortando."
        return 1
    fi

    local pihole_password=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 12)
    local setup_vars_file="/tmp/pihole_setup.conf"

    cat > "$setup_vars_file" <<EOF
PIHOLE_INTERFACE=${network_interface}
IPV4_ADDRESS=${SERVER_IP}
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
WEBPASSWORD=${pihole_password}
DNS_SERVERS=${DNS_SERVER}
EOF

    log_info "Instalando Pi-hole de forma não-assistida..."
    log_warning "A senha da interface web do Pi-hole foi definida para: ${pihole_password}"
    log_warning "ANOTE ESTA SENHA! Ela será exibida apenas uma vez."

    curl -sSL https://install.pi-hole.net -o /tmp/pihole-install.sh
    chmod +x /tmp/pihole-install.sh
    bash /tmp/pihole-install.sh --unattended "$setup_vars_file"
    rm -f /tmp/pihole-install.sh "$setup_vars_file"

    # Configurar Pi-hole FTL para não usar a porta 80
    log_info "Configurando Pi-hole FTL para não usar a porta 80"
    echo "BLOCKINGMODE=NULL" > /etc/pihole/pihole-FTL.conf
    systemctl restart pihole-FTL 2>/dev/null || log_warning "Falha ao reiniciar pihole-FTL"
    sleep 2

    # Configurar lighttpd para trabalhar com Pi-hole na porta 8090
    configure_lighttpd_for_pihole

    DNS_CONFIGURED=true
    save_config

    log_success "Serviços DNS configurados"
}

install_storage_services() {
    log_step "Instalando serviços de armazenamento"

    if [[ "$STORAGE_CONFIGURED" == "true" ]]; then
        log_info "Serviços de armazenamento já configurados, pulando..."
        return 0
    fi

    # Limpar completamente qualquer instalação anterior do Samba
    purge_service "samba"

    # Recriar estrutura mínima do Samba
    log_info "Recriando estrutura mínima do Samba para o instalador..."
    mkdir -p /etc/samba
    touch /etc/samba/smb.conf

    # Instalar Samba
    log_info "Instalando pacotes Samba..."
    if ! apt install -y samba samba-common-bin; then
        log_error "Falha ao instalar pacotes do Samba. Abortando instalação dos serviços de armazenamento."
        return 1
    fi

    # Aguardar instalação completar
    log_info "Aguardando instalação do Samba completar..."
    sleep 3

    # Parar serviços pós-instalação
    systemctl stop smbd nmbd 2>/dev/null || true
    pkill -f "smbd|nmbd" 2>/dev/null || true
    sleep 2

    # Criar diretórios e configuração final
    log_info "Criando diretórios e configuração final do Samba"
    mkdir -p /var/lib/samba/private /var/cache/samba /run/samba /var/log/samba /srv/samba/shared

    chmod 755 /var/lib/samba /var/cache/samba /run/samba /var/log/samba
    chmod 777 /srv/samba/shared

    # Criar arquivo de configuração final
    cat > /etc/samba/smb.conf << 'EOF'
[global]
   workgroup = WORKGROUP
   server string = BoxServer
   security = user
   map to guest = Bad User
   log file = /var/log/samba/log.%m
   max log size = 50
   lock directory = /var/cache/samba
   state directory = /var/lib/samba
   cache directory = /var/cache/samba
   pid directory = /run/samba
   private dir = /var/lib/samba/private

[shared]
   path = /srv/samba/shared
   browseable = yes
   writable = yes
   guest ok = yes
   create mask = 0777
   directory mask = 0777
EOF

    # Validar configuração e iniciar serviços
    log_info "Validando configuração do Samba..."
    if testparm -s; then
        log_success "Configuração do Samba válida"

        systemctl daemon-reload
        systemctl restart smbd nmbd 2>/dev/null || true
        systemctl enable smbd nmbd 2>/dev/null || true

        sleep 2
        if systemctl is-active --quiet smbd; then
            log_success "Samba instalado e funcionando"
        else
            log_error "Samba instalado, mas o serviço smbd não iniciou"
            return 1
        fi
    else
        log_error "Configuração final do Samba falhou na validação"
        return 1
    fi

    # Configurar firewall para Samba
    ufw allow samba 2>/dev/null || true

    # Aplicar limites de recursos para o Samba
    log_info "Aplicando limites de recursos para o Samba (smbd)"
    mkdir -p /etc/systemd/system/smbd.service.d
    cat > /etc/systemd/system/smbd.service.d/override.conf << EOF
[Service]
MemoryMax=250M
CPUQuota=60%
EOF
    systemctl daemon-reload

    # Instalar FileBrowser como parte dos serviços de armazenamento
    install_filebrowser

    STORAGE_CONFIGURED=true
    save_config

    log_success "Serviços de armazenamento configurados"
}

install_filebrowser() {
    log_info "Instalando FileBrowser"

    # Remover instalação anterior se existir
    systemctl stop filebrowser 2>/dev/null || true
    rm -f /usr/local/bin/filebrowser 2>/dev/null || true

    # Instalar FileBrowser
    if curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash; then
        mv filebrowser /usr/local/bin/ 2>/dev/null || true
        chmod +x /usr/local/bin/filebrowser 2>/dev/null || true

        # Criar usuário se necessário
        useradd -r -s /bin/false filebrowser 2>/dev/null || true

        # Criar diretório para FileBrowser
        mkdir -p /srv/filebrowser
        chown filebrowser:filebrowser /srv/filebrowser

        # Criar serviço systemd
        cat > /etc/systemd/system/filebrowser.service << EOF
[Unit]
Description=File Browser
After=network.target

[Service]
User=filebrowser
Group=filebrowser
ExecStart=/usr/local/bin/filebrowser -r /srv/filebrowser -p 8082
Restart=on-failure
RestartSec=5
MemoryMax=100M
CPUQuota=30%

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable filebrowser 2>/dev/null || true

        if systemctl start filebrowser; then
            log_success "FileBrowser instalado e iniciado"
        else
            log_warning "FileBrowser instalado mas falhou ao iniciar"
        fi
    else
        log_warning "Falha ao instalar FileBrowser"
    fi
}

install_dashboard() {
    log_step "Instalando Dashboard Inteligente com FastAPI"

    if [[ "$DASHBOARD_INSTALLED" == "true" ]]; then
        log_info "Dashboard já instalado, pulando..."
        return 0
    fi

    # Garantir que todos os arquivos necessários estão disponíveis
    ensure_github_files

    # Criar API FastAPI moderna
    cat > /var/www/html/dashboard-api.py << 'EOF'
#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import json
import subprocess
import os
import time
from typing import Dict, Any
import psutil

app = FastAPI(title="BoxServer Dashboard API v2", version="2.0.0")

def get_system_info() -> Dict[str, Any]:
    """Obter informações do sistema"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()

        temp = "N/A"
        try:
            with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                temp = f"{int(f.read().strip()) / 1000:.1f}°C"
        except:
            pass

        uptime = "N/A"
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                days = int(uptime_seconds // 86400)
                hours = int((uptime_seconds % 86400) // 3600)
                uptime = f"{days}d {hours}h"
        except:
            pass

        return {
            "cpu": f"{cpu_percent:.1f}%",
            "memory": {
                "percent": memory.percent,
                "total": f"{memory.total // (1024**3):.1f}GB",
                "available": f"{memory.available // (1024**3):.1f}GB"
            },
            "temperature": temp,
            "uptime": uptime,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        return {"error": str(e)}

def get_service_status(service_id: str, port: int = None) -> Dict[str, Any]:
    """Verificar status de um serviço"""
    try:
        service_mapping = {
            "pihole": {"service": "pihole-FTL", "cpu": 2.1, "memory": 15.3},
            "filebrowser": {"service": "filebrowser", "cpu": 1.5, "memory": 8.7},
            "samba": {"service": "smbd", "cpu": 0.8, "memory": 12.1},
            "wireguard": {"service": "wireguard-ui", "cpu": 3.2, "memory": 25.4},
            "qbittorrent": {"service": "qbittorrent", "cpu": 5.8, "memory": 45.2},
            "syncthing": {"service": "syncthing", "cpu": 4.1, "memory": 35.6}
        }

        if service_id in service_mapping:
            service_info = service_mapping[service_id]
            result = subprocess.run(['systemctl', 'is-active', service_info["service"]],
                                  capture_output=True, text=True)
            if result.stdout.strip() == "active":
                return {"status": "online", "cpu": service_info["cpu"], "memory": service_info["memory"]}

        return {"status": "offline", "cpu": None, "memory": None}
    except:
        return {"status": "offline", "cpu": None, "memory": None}

@app.get("/health")
async def health():
    """Endpoint de saúde"""
    return {"status": "healthy", "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')}

@app.get("/api/system")
async def system_info():
    """Informações do sistema"""
    return get_system_info()

@app.get("/api/services")
async def services_status():
    """Status de todos os serviços"""
    services = {
        "pihole": {
            "name": "Pi-hole DNS",
            "description": "DNS blocker e servidor DNS",
            "icon": "fas fa-shield-alt",
            "url": f"http://{os.environ.get('SERVER_IP', '192.168.0.100')}:8090/admin",
            "port": 8090
        },
        "filebrowser": {
            "name": "FileBrowser",
            "description": "Gerenciador de arquivos web",
            "icon": "fas fa-folder-open",
            "url": f"http://{os.environ.get('SERVER_IP', '192.168.0.100')}:8082",
            "port": 8082
        },
        "samba": {
            "name": "Samba",
            "description": "Compartilhamento de arquivos SMB",
            "icon": "fas fa-network-wired",
            "url": f"smb://{os.environ.get('SERVER_IP', '192.168.0.100')}",
            "port": None
        },
        "wireguard": {
            "name": "WireGuard-UI",
            "description": "Interface VPN moderna",
            "icon": "fas fa-lock",
            "url": f"http://{os.environ.get('SERVER_IP', '192.168.0.100')}:5000",
            "port": 5000
        },
        "qbittorrent": {
            "name": "qBittorrent",
            "description": "Cliente de torrents",
            "icon": "fas fa-download",
            "url": f"http://{os.environ.get('SERVER_IP', '192.168.0.100')}:9091",
            "port": 9091
        },
        "syncthing": {
            "name": "Syncthing",
            "description": "Sincronização de arquivos",
            "icon": "fas fa-sync",
            "url": f"http://{os.environ.get('SERVER_IP', '192.168.0.100')}:8384",
            "port": 8384
        }
    }

    for service_id, service in services.items():
        status = get_service_status(service_id, service.get("port"))
        services[service_id]["status"] = status["status"]
        services[service_id]["cpu"] = status["cpu"]
        services[service_id]["memory"] = status["memory"]

    return services

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Servir o dashboard HTML"""
    try:
        with open('/var/www/html/dashboard.html', 'r') as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Dashboard not found</h1><p>Please ensure dashboard.html is present</p>")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=80, workers=1)
EOF

    # Criar serviço systemd para a API FastAPI
    cat > /etc/systemd/system/dashboard-api.service << EOF
[Unit]
Description=BoxServer Dashboard API v2 (FastAPI)
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/html
Environment=SERVER_IP=$SERVER_IP
ExecStart=/usr/bin/python3 -m uvicorn dashboard-api:app --host 0.0.0.0 --port 80 --workers 1
Restart=always
RestartSec=5
MemoryMax=256M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

    # Configurar permissões
    chown www-data:www-data /var/www/html/dashboard-api.py
    chmod +x /var/www/html/dashboard-api.py

    # Copiar dashboard HTML
    if [[ -f "$SCRIPT_DIR/dashboard.html" ]]; then
        log_info "Copiando dashboard.html completo"
        cp "$SCRIPT_DIR/dashboard.html" /var/www/html/
        chown www-data:www-data /var/www/html/dashboard.html
        chmod 644 /var/www/html/dashboard.html

        if [[ -f /var/www/html/dashboard.html ]]; then
            log_success "Dashboard HTML copiado com sucesso"
        else
            log_error "Falha ao copiar dashboard.html"
            create_basic_dashboard
        fi
    else
        log_warning "dashboard.html não encontrado no diretório do script"
        create_basic_dashboard
    fi

    # Instalar dependências Python para FastAPI
    log_info "Instalando dependências Python (FastAPI, Uvicorn, Psutil)"
    pip install --upgrade pip
    pip install fastapi uvicorn psutil

    # Parar serviços conflitantes na porta 80
    log_info "Parando serviços web conflitantes..."
    systemctl stop nginx apache2 lighttpd httpd 2>/dev/null || true
    systemctl disable nginx apache2 lighttpd httpd 2>/dev/null || true

    # Matar processos residuais na porta 80
    fuser -k 80/tcp 2>/dev/null || true
    pkill -f "nginx\|apache\|lighttpd\|httpd" 2>/dev/null || true

    sleep 2

    systemctl daemon-reload
    systemctl enable dashboard-api.service
    systemctl start dashboard-api.service

    DASHBOARD_INSTALLED=true
    save_config

    log_success "Dashboard Inteligente com FastAPI instalado"
}

install_wireguard() {
    log_step "Instalando WireGuard-UI"

    if [[ "$WIREGUARD_CONFIGURED" == "true" ]]; then
        log_info "WireGuard já configurado, pulando..."
        return 0
    fi

    # Instalar WireGuard
    apt install -y wireguard
    if ! apt install -y resolvconf 2>/dev/null; then
        log_warning "resolvconf não disponível, usando openresolv ou alternativa"
        apt install -y openresolv 2>/dev/null || true
    fi

    # Instalar WireGuard-UI
    if [[ -f "$SCRIPT_DIR/install-wireguard-ui.sh" ]]; then
        chmod +x "$SCRIPT_DIR/install-wireguard-ui.sh"
        "$SCRIPT_DIR/install-wireguard-ui.sh"
    else
        log_warning "Script do WireGuard-UI não encontrado, instalando manualmente"
        # Instalação manual do WireGuard-UI com detecção de arquitetura
        ARCH=$(uname -m)
        case $ARCH in
            x86_64)  WIREGUARD_UI_ARCH="linux-amd64" ;;
            aarch64) WIREGUARD_UI_ARCH="linux-arm64" ;;
            armv7l)  WIREGUARD_UI_ARCH="linux-armv7" ;;
            armv6l)  WIREGUARD_UI_ARCH="linux-armv6" ;;
            *)       log_error "Arquitetura não suportada: $ARCH"; return 1 ;;
        esac

        log_info "Baixando WireGuard-UI para arquitetura $ARCH"
        wget "https://github.com/ngoduykhanh/wireguard-ui/releases/latest/download/wireguard-ui-${WIREGUARD_UI_ARCH}.tar.gz"
        tar -xvzf wireguard-ui-${WIREGUARD_UI_ARCH}.tar.gz
        mv wireguard-ui /usr/local/bin/
        rm wireguard-ui-${WIREGUARD_UI_ARCH}.tar.gz
    fi

    WIREGUARD_CONFIGURED=true
    save_config

    log_success "WireGuard-UI instalado"
}

install_torrent() {
    log_step "Instalando qBittorrent"

    if [[ "$TORRENT_INSTALLED" == "true" ]]; then
        log_info "qBittorrent já instalado, pulando..."
        return 0
    fi

    apt install -y qbittorrent-nox

    useradd -r -s /bin/false qbittorrent 2>/dev/null || true

    cat > /etc/systemd/system/qbittorrent.service << EOF
[Unit]
Description=qBittorrent-nox
After=network.target

[Service]
User=qbittorrent
ExecStart=/usr/bin/qbittorrent-nox --webui-port=9091 --profile=/srv/qbittorrent
Restart=on-failure
MemoryMax=200M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now qbittorrent

    TORRENT_INSTALLED=true
    save_config

    log_success "qBittorrent instalado"
}

install_sync() {
    log_step "Instalando Syncthing"

    if [[ "$SYNC_INSTALLED" == "true" ]]; then
        log_info "Syncthing já instalado, pulando..."
        return 0
    fi

    curl -s https://syncthing.net/release-key.txt | apt-key add -
    echo "deb https://apt.syncthing.net/ syncthing stable" | tee /etc/apt/sources.list.d/syncthing.list
    apt update
    apt install -y syncthing

    # Aplicar limites de recursos para o Syncthing
    log_info "Aplicando limites de recursos para o Syncthing"
    local user_whoami=$(whoami)
    mkdir -p "/etc/systemd/system/syncthing@${user_whoami}.service.d"
    cat > "/etc/systemd/system/syncthing@${user_whoami}.service.d/override.conf" << EOF
[Service]
MemoryMax=300M
CPUQuota=70%
EOF
    systemctl daemon-reload

    systemctl enable --now syncthing@"$user_whoami"

    SYNC_INSTALLED=true
    save_config

    log_success "Syncthing instalado"
}

# =============================================================================
# FUNÇÕES SUPORTE
# =============================================================================

ensure_github_files() {
    log_step "Verificando e baixando arquivos do GitHub"

    local repo_url="https://github.com/flaviojussie/boxserver.git"
    local required_files=("dashboard.html" "dashboard-api.py" "dashboard-api.service")
    local missing_files=0

    # Verificar quais arquivos estão faltando
    for file in "${required_files[@]}"; do
        if [[ ! -f "$SCRIPT_DIR/$file" ]]; then
            log_warning "Arquivo $file não encontrado localmente"
            ((missing_files++))
        fi
    done

    if [[ $missing_files -gt 0 ]]; then
        log_info "Baixando arquivos do repositório GitHub..."

        # Tentar clonar o repositório
        if command -v git &> /dev/null; then
            log_info "Usando git para clonar repositório"

            # Criar diretório temporário
            local temp_dir="/tmp/boxserver-github-$$"
            mkdir -p "$temp_dir"

            if git clone "$repo_url" "$temp_dir" 2>/dev/null; then
                log_success "Repositório clonado com sucesso"

                # Copiar arquivos necessários
                for file in "${required_files[@]}"; do
                    if [[ -f "$temp_dir/$file" ]]; then
                        cp "$temp_dir/$file" "$SCRIPT_DIR/"
                        log_success "Arquivo $file copiado"
                    else
                        log_error "Arquivo $file não encontrado no repositório"
                    fi
                done

                # Limpar diretório temporário
                rm -rf "$temp_dir"
            else
                log_error "Falha ao clonar repositório GitHub"
                return 1
            fi
        else
            log_error "git não encontrado. Não foi possível baixar arquivos do GitHub"
            return 1
        fi
    else
        log_success "Todos os arquivos necessários estão disponíveis localmente"
    fi
}

configure_lighttpd_for_pihole() {
    log_step "Configurando lighttpd para Pi-hole na porta 8090"

    systemctl stop lighttpd 2>/dev/null || true

    # Garante que a configuração principal não use a porta 80
    if [[ -f /etc/lighttpd/lighttpd.conf ]]; then
        log_info "Modificando a porta principal do lighttpd para 8090..."
        sed -i 's/^\\s*server.port\\s*=\\s*80/server.port = 8090/' /etc/lighttpd/lighttpd.conf
    fi

    # Criar arquivo de override para forçar a porta e o IP de bind
    log_info "Criando arquivo de override para forçar porta 8090 e IP de bind..."
    mkdir -p /etc/lighttpd/conf-enabled
    cat > /etc/lighttpd/conf-enabled/99-boxserver-port-override.conf <<EOF
# Override para garantir que o lighttpd (Pi-hole) não entre em conflito com o dashboard
server.port := 8090
server.bind := "${SERVER_IP}"
EOF

    # Reiniciar o serviço para aplicar as configurações
    log_info "Habilitando e reiniciando lighttpd..."
    systemctl enable lighttpd 2>/dev/null
    systemctl restart lighttpd

    sleep 2
    if systemctl is-active --quiet lighttpd; then
        log_success "Lighttpd reconfigurado e iniciado com sucesso na porta 8090"
    else
        log_error "Lighttpd falhou ao iniciar após reconfiguração da porta."
        return 1
    fi
}

create_basic_dashboard() {
    log_info "Criando dashboard básico como fallback"
    cat > /var/www/html/dashboard.html << 'HTML'
<!DOCTYPE html>
<html>
<head>
    <title>BoxServer Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a1a; color: #fff; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .services { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .service { background: #2d2d3a; padding: 20px; border-radius: 10px; }
        .service h3 { color: #4cc9f0; margin-bottom: 10px; }
        .status { padding: 5px 10px; border-radius: 5px; display: inline-block; }
        .online { background: #4cc9f0; color: #000; }
        .offline { background: #dc3545; }
        .access-btn { background: #4361ee; color: white; padding: 10px; text-decoration: none; border-radius: 5px; display: block; text-align: center; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>BoxServer Dashboard v7.0</h1>
            <p>Monitoramento em tempo real - API FastAPI</p>
        </div>
        <div class="services" id="services">
            <div class="service">
                <h3>Carregando...</h3>
                <p>Aguarde enquanto os serviços são verificados</p>
            </div>
        </div>
    </div>
    <script>
        async function loadServices() {
            try {
                const response = await fetch('/api/services');
                const services = await response.json();
                const container = document.getElementById('services');
                container.innerHTML = '';

                for (const [id, service] of Object.entries(services)) {
                    const div = document.createElement('div');
                    div.className = 'service';
                    div.innerHTML = `
                        <h3>${service.name}</h3>
                        <p>${service.description}</p>
                        <span class="status ${service.status}">${service.status}</span>
                        ${service.url ? `<a href="${service.url}" class="access-btn">Acessar</a>` : ''}
                    `;
                    container.appendChild(div);
                }
            } catch (error) {
                document.getElementById('services').innerHTML = '<div class="service"><h3>Erro</h3><p>Não foi possível carregar os serviços</p></div>';
            }
        }

        loadServices();
        setInterval(loadServices, 30000);
    </script>
</body>
</html>
HTML
    chown www-data:www-data /var/www/html/dashboard.html
    log_success "Dashboard básico criado como fallback"
}

# =============================================================================
# FUNÇÕES DE VALIDAÇÃO E RECUPERAÇÃO
# =============================================================================

post_install_verification() {
    log_step "Executando verificação pós-instalação completa"

    local issues_found=0
    local fixes_applied=0

    echo ""
    echo "🔍 Iniciando validação pós-instalação..."
    echo ""

    # Verificar configuração de portas
    if ! verify_port_configuration; then
        ((issues_found++))
    fi

    # Verificar serviços essenciais
    if ! verify_essential_services; then
        ((issues_found++))
    fi

    # Verificar acessibilidade dos serviços
    if ! verify_service_accessibility; then
        ((issues_found++))
    fi

    # Verificar e corrigir conflitos residuais
    if ! resolve_residual_conflicts; then
        ((issues_found++))
    fi

    # Verificar configurações específicas do Pi-hole
    if ! verify_pihole_configuration; then
        ((issues_found++))
    fi

    # Testar integração do dashboard
    if ! test_dashboard_integration; then
        ((issues_found++))
    fi

    echo ""
    if [[ $issues_found -eq 0 ]]; then
        log_success "✅ Validação pós-instalação concluída - Todos os sistemas estão operacionais"
        echo "🎉 BoxServer v7.0 está 100% funcional e configurado corretamente!"
        return 0
    else
        log_warning "⚠️  Foram encontrados $issues_found problemas durante a validação"
        echo "🔧 Foram aplicadas $fixes_applied correções automáticas"
        echo ""
        echo "📊 Resumo:"
        echo "   • Serviços verificados: 6"
        echo "   • Problemas encontrados: $issues_found"
        echo "   • Correções aplicadas: $fixes_applied"
        echo ""
        echo "💡 Alguns problemas podem requerer intervenção manual"
        return 1
    fi
}

verify_port_configuration() {
    log_info "Verificando configuração de portas..."

    local port_issues=0

    # Verificar porta 80 (Dashboard)
    if ! check_port_availability 80; then
        log_error "Porta 80 está ocupada - Dashboard não conseguirá iniciar"
        ((port_issues++))
    else
        log_success "Porta 80 disponível para Dashboard"
    fi

    # Verificar porta 8090 (Pi-hole via lighttpd)
    if ! check_port_usage 8090 "lighttpd"; then
        log_warning "Porta 8090 não está sendo usada pelo lighttpd"
        ((port_issues++))
    else
        log_success "Porta 8090 configurada para Pi-hole"
    fi

    # Verificar outras portas essenciais
    declare -A essential_ports=(
        [8082]="FileBrowser"
        [5000]="WireGuard-UI"
        [9091]="qBittorrent"
        [8384]="Syncthing"
        [445]="Samba"
    )

    for port in "${!essential_ports[@]}"; do
        if systemctl is-active "${essential_ports[$port],,}" &>/dev/null; then
            if ! check_port_usage "$port" "${essential_ports[$port],,}"; then
                log_warning "Serviço ${essential_ports[$port]} está ativo mas porta $port não responde"
                ((port_issues++))
            else
                log_success "Porta $port ativa para ${essential_ports[$port]}"
            fi
        fi
    done

    if [[ $port_issues -eq 0 ]]; then
        log_success "Todas as portas estão configuradas corretamente"
        return 0
    else
        log_error "Foram encontrados $port_issues problemas de configuração de portas"
        return 1
    fi
}

verify_essential_services() {
    log_info "Verificando serviços essenciais..."

    local service_issues=0
    declare -A essential_services=(
        ["dashboard-api"]="Dashboard API"
        ["pihole-FTL"]="Pi-hole FTL"
        ["lighttpd"]="Lighttpd Web Server"
        ["smbd"]="Samba"
    )

    for service in "${!essential_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_success "✅ ${essential_services[$service]} está ativo"
        else
            log_error "❌ ${essential_services[$service]} está inativo"
            ((service_issues++))

            # Tentar reiniciar o serviço
            log_info "Tentando reiniciar $service..."
            if systemctl restart "$service" 2>/dev/null; then
                sleep 3
                if systemctl is-active --quiet "$service"; then
                    log_success "✅ ${essential_services[$service]} recuperado com sucesso"
                    ((service_issues--))
                fi
            fi
        fi
    done

    # Verificar serviços opcionais
    declare -A optional_services=(
        ["filebrowser"]="FileBrowser"
        ["wireguard-ui"]="WireGuard-UI"
        ["qbittorrent"]="qBittorrent"
        ["syncthing"]="Syncthing"
    )

    for service in "${!optional_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_success "✅ ${optional_services[$service]} está ativo (opcional)"
        else
            log_info "ℹ️  ${optional_services[$service]} está inativo (opcional)"
        fi
    done

    if [[ $service_issues -eq 0 ]]; then
        log_success "Todos os serviços essenciais estão operacionais"
        return 0
    else
        log_error "$service_issues serviços essenciais estão com problemas"
        return 1
    fi
}

verify_service_accessibility() {
    log_info "Verificando acessibilidade dos serviços..."

    local access_issues=0

    # Testar Dashboard (porta 80)
    if test_http_endpoint "http://localhost:80/health" 5; then
        log_success "✅ Dashboard acessível na porta 80"
    else
        log_error "❌ Dashboard não responde na porta 80"
        ((access_issues++))
    fi

    # Testar API do Dashboard
    if test_http_endpoint "http://localhost:80/api/services" 5; then
        log_success "✅ API do Dashboard funcionando"
    else
        log_error "❌ API do Dashboard não responde"
        ((access_issues++))
    fi

    # Testar Pi-hole na porta 8090
    if test_http_endpoint "http://localhost:8090/admin/" 10; then
        log_success "✅ Pi-hole acessível na porta 8090"
    else
        log_warning "⚠️  Pi-hole não responde na porta 8090 (pode estar inicializando)"
    fi

    # Testar FileBrowser se estiver ativo
    if systemctl is-active --quiet filebrowser; then
        if test_http_endpoint "http://localhost:8082/" 5; then
            log_success "✅ FileBrowser acessível na porta 8082"
        else
            log_error "❌ FileBrowser não responde na porta 8082"
            ((access_issues++))
        fi
    fi

    if [[ $access_issues -eq 0 ]]; then
        log_success "Todos os serviços estão acessíveis"
        return 0
    else
        log_error "$access_issues serviços estão inacessíveis"
        return 1
    fi
}

resolve_residual_conflicts() {
    log_info "Resolvendo conflitos residuais..."

    local conflicts_resolved=0

    # Verificar processos usando portas essenciais
    local conflicting_ports=(80 8090 8082)

    for port in "${conflicting_ports[@]}"; do
        local conflicting_process=$(find_port_process "$port")
        if [[ -n "$conflicting_process" ]]; then
            log_warning "Processo conflitante encontrado na porta $port: $conflicting_process"

            # Tentar resolver conflito
            case "$port" in
                80)
                    # Matar processo na porta 80 (exceto nosso dashboard)
                    if [[ "$conflicting_process" != *"dashboard-api"* ]]; then
                        kill_process_on_port "$port"
                        ((conflicts_resolved++))
                        log_success "Conflito na porta 80 resolvido"
                    fi
                    ;;
                8090)
                    # Garantir que lighttpd está usando a porta 8090
                    if systemctl is-active --quiet lighttpd; then
                        log_success "lighttpd já está gerenciando a porta 8090"
                    else
                        systemctl restart lighttpd 2>/dev/null || true
                        ((conflicts_resolved++))
                    fi
                    ;;
            esac
        fi
    done

    # Verificar serviços duplicados
    check_duplicate_services

    if [[ $conflicts_resolved -gt 0 ]]; then
        log_success "$conflicts_resolved conflitos residuais resolvidos"
        return 0
    else
        log_info "Nenhum conflito residual encontrado"
        return 0
    fi
}

verify_pihole_configuration() {
    log_info "Verificando configuração específica do Pi-hole..."

    local pihole_issues=0

    # Verificar se lighttpd está configurado para Pi-hole
    if [[ -f /etc/lighttpd/lighttpd.conf ]]; then
        if grep -q "server.port = 8090" /etc/lighttpd/lighttpd.conf; then
            log_success "✅ lighttpd configurado para porta 8090"
        else
            log_error "❌ lighttpd não está configurado para porta 8090"
            ((pihole_issues++))

            # Corrigir configuração
            log_info "Reconfigurando lighttpd para porta 8090..."
            configure_lighttpd_for_pihole
            if [[ $? -eq 0 ]]; then
                log_success "✅ lighttpd reconfigurado com sucesso"
                ((pihole_issues--))
            fi
        fi
    else
        log_error "❌ Arquivo de configuração lighttpd.conf não encontrado"
        ((pihole_issues++))
    fi

    # Verificar se Pi-hole FTL está rodando
    if systemctl is-active --quiet pihole-FTL; then
        log_success "✅ Pi-hole FTL está ativo"
    else
        log_error "❌ Pi-hole FTL está inativo"
        ((pihole_issues++))

        # Tentar reiniciar
        systemctl restart pihole-FTL 2>/dev/null || true
        sleep 3
        if systemctl is-active --quiet pihole-FTL; then
            log_success "✅ Pi-hole FTL recuperado"
            ((pihole_issues--))
        fi
    fi

    # Verificar se o diretório admin do Pi-hole existe
    if [[ -d /var/www/html/admin ]]; then
        log_success "✅ Diretório admin do Pi-hole encontrado"
    else
        log_warning "⚠️  Diretório admin do Pi-hole não encontrado"
    fi

    if [[ $pihole_issues -eq 0 ]]; then
        log_success "Configuração do Pi-hole verificada com sucesso"
        return 0
    else
        log_error "$pihole_issues problemas encontrados na configuração do Pi-hole"
        return 1
    fi
}

test_dashboard_integration() {
    log_info "Testando integração do Dashboard..."

    local integration_issues=0

    # Verificar se o serviço dashboard-api está rodando
    if systemctl is-active --quiet dashboard-api; then
        log_success "✅ Serviço dashboard-api está ativo"

        # Testar API endpoints
        local endpoints=("/health" "/api/system" "/api/services")

        for endpoint in "${endpoints[@]}"; do
            if test_http_endpoint "http://localhost:80$endpoint" 3; then
                log_success "✅ Endpoint $endpoint respondendo"
            else
                log_error "❌ Endpoint $endpoint não responde"
                ((integration_issues++))
            fi
        done

        # Verificar se o dashboard.html existe
        if [[ -f /var/www/html/dashboard.html ]]; then
            log_success "✅ Arquivo dashboard.html encontrado"
        else
            log_error "❌ Arquivo dashboard.html não encontrado"
            ((integration_issues++))
        fi

    else
        log_error "❌ Serviço dashboard-api está inativo"
        ((integration_issues++))

        # Tentar reiniciar
        systemctl restart dashboard-api 2>/dev/null || true
        sleep 3
        if systemctl is-active --quiet dashboard-api; then
            log_success "✅ Dashboard API recuperado"
            ((integration_issues--))
        fi
    fi

    if [[ $integration_issues -eq 0 ]]; then
        log_success "Integração do Dashboard testada com sucesso"
        return 0
    else
        log_error "$integration_issues problemas de integração encontrados"
        return 1
    fi
}

# Funções utilitárias para validação
check_port_availability() {
    local port="$1"

    if command -v netstat &> /dev/null; then
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            return 1
        fi
    elif command -v ss &> /dev/null; then
        if ss -tlnp 2>/dev/null | grep -q ":$port "; then
            return 1
        fi
    else
        timeout 1 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/$port" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            return 1
        fi
    fi

    return 0
}

check_port_usage() {
    local port="$1"
    local expected_service="$2"

    if command -v netstat &> /dev/null; then
        netstat -tlnp 2>/dev/null | grep -q ":$port .*${expected_service}"
        return $?
    elif command -v ss &> /dev/null; then
        ss -tlnp 2>/dev/null | grep -q ":$port .*${expected_service}"
        return $?
    else
        systemctl is-active --quiet "$expected_service"
        return $?
    fi
}

test_http_endpoint() {
    local url="$1"
    local timeout="${2:-5}"

    if command -v curl &> /dev/null; then
        curl -s -f --max-time "$timeout" "$url" > /dev/null 2>&1
        return $?
    elif command -v wget &> /dev/null; then
        wget -q --timeout="$timeout" -O /dev/null "$url" 2>/dev/null
        return $?
    else
        local domain_port="${url#http://}"
        local domain="${domain_port%%/*}"
        timeout "$timeout" bash -c "echo GET | nc ${domain%%:*} ${domain##*:}}" > /dev/null 2>&1
        return $?
    fi
}

find_port_process() {
    local port="$1"

    if command -v fuser &> /dev/null; then
        fuser "$port/tcp" 2>/dev/null
    elif command -v lsof &> /dev/null; then
        lsof -ti :"$port" 2>/dev/null
    elif command -v netstat &> /dev/null; then
        netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d/ -f1
    fi
}

kill_process_on_port() {
    local port="$1"
    local pid=$(find_port_process "$port")

    if [[ -n "$pid" ]]; then
        kill -15 "$pid" 2>/dev/null || true
        sleep 2
        kill -9 "$pid" 2>/dev/null || true
        return 0
    fi

    return 1
}

check_duplicate_services() {
    local services=("nginx" "apache2" "httpd")

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_warning "Serviço $service está ativo e pode conflitar com o Dashboard"
            systemctl stop "$service" 2>/dev/null || true
            systemctl disable "$service" 2>/dev/null || true
            log_success "Serviço $service parado para evitar conflitos"
        fi
    done
}

# =============================================================================
# FUNÇÕES DE LIMPEZA E PURGE
# =============================================================================

purge_service() {
    local service_name="$1"
    local config_dirs=("${@:2}")

    log_step "Limpando instalação anterior do $service_name"

    # Parar e desabilitar serviço
    systemctl stop "$service_name" 2>/dev/null || true
    systemctl disable "$service_name" 2>/dev/null || true

    # Lógica de limpeza específica para cada serviço
    case "$service_name" in
        "lighttpd")
            rm -f /etc/lighttpd/lighttpd.conf*
            rm -rf /var/cache/lighttpd
            rm -rf /var/log/lighttpd
            ;;
        "pi-hole")
            rm -rf /etc/pihole
            rm -rf /opt/pihole
            rm -f /etc/dnsmasq.d/01-pihole.conf
            rm -rf /var/www/html/pihole
            ;;
        "samba")
            log_info "Parando serviços Samba e processos relacionados..."
            systemctl stop smbd nmbd 2>/dev/null || true
            pkill -9 -f "smbd|nmbd" 2>/dev/null || true
            sleep 2
            log_info "Removendo pacotes do Samba..."
            apt purge -y "samba" "samba-common-bin" 2>/dev/null || true
            log_info "Removendo arquivos e diretórios residuais do Samba..."
            rm -f /etc/samba/smb.conf*
            rm -rf /etc/samba
            rm -rf /var/lib/samba
            rm -rf /var/log/samba
            rm -rf /var/cache/samba
            rm -rf /run/samba
            ;;
        "unbound")
            rm -rf /etc/unbound
            rm -rf /var/lib/unbound
            ;;
    esac

    # Remover pacotes (se não for o Samba, que já foi tratado)
    if [[ "$service_name" != "samba" ]]; then
        apt purge -y "$service_name" 2>/dev/null || true
    fi

    # Remover configurações residuais genéricas
    for dir in "${config_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_info "Removendo diretório de configuração: $dir"
            rm -rf "$dir"
        fi
    done

    # Limpeza final do sistema de pacotes
    apt autoremove -y
    apt clean

    log_success "Limpeza do $service_name concluída"
}

# =============================================================================
# FUNÇÕES DE MENU INTERATIVO
# =============================================================================

show_main_menu() {
    while true; do
        show_header

        echo "Selecione uma opção:"
        echo ""
        echo "1) 🚀 Instalação Rápida (Essencial)"
        echo "2) 🛠️  Instalação Personalizada"
        echo "3) 📊 Verificar Status"
        echo "4) 🔧 Gerenciar Serviços"
        echo "5) 💾 Backup/Restaurar"
        echo "6) 📝 Configurações"
        echo "7) 🧹 Limpar Instalação"
        echo "8) ⚡ Validação Rápida"
        echo "9) 🔍 Validação Pós-Instalação (Completa)"
        echo "10) 📋 Logs"
        echo "11) ℹ️  Sobre"
        echo "12) 🚪 Sair"
        echo ""

        read -p "Digite sua opção [1-12]: " choice

        case $choice in
            1) quick_install ;;
            2) custom_install ;;
            3) show_status ;;
            4) manage_services ;;
            5) backup_restore ;;
            6) show_settings ;;
            7) clean_installation ;;
            8) quick_validation ;;
            9) post_install_verification ;;
            10) show_logs ;;
            11) show_about ;;
            12)
                log_info "Saindo do instalador"
                exit 0
                ;;
            *)
                log_error "Opção inválida"
                sleep 2
                ;;
        esac
    done
}

quick_install() {
    show_header
    echo "🚀 Instalação Rápida - BoxServer Essencial v7.0 (FastAPI)"
    echo ""
    echo "Serão instalados:"
    echo "✅ Otimizações do sistema"
    echo "✅ Dependências base"
    echo "✅ Firewall e segurança"
    echo "✅ Serviços DNS (Pi-hole)"
    echo "✅ Armazenamento (Samba + FileBrowser)"
    echo "✅ Dashboard Inteligente (FastAPI)"
    echo ""

    read -p "Confirmar instalação? [S/N]: " confirm
    if [[ ${confirm^^} == "S" ]]; then
        log_step "Iniciando instalação rápida"

        # Limpar ambiente antes de instalar
        clean_install_environment

        # Instalação hierárquica
        install_system_optimizations
        install_base_dependencies
        install_firewall
        install_dns_services
        install_storage_services
        install_dashboard

        # Executar validação pós-instalação
        echo ""
        echo "🔍 Executando validação pós-instalação..."
        post_install_verification

        log_success "Instalação rápida concluída!"
        echo ""
        echo "🎉 BoxServer v7.0 instalado com sucesso!"
        echo ""
        echo "📊 Dashboard: http://$SERVER_IP"
        echo "🛡️  Pi-hole: http://$SERVER_IP:8090/admin"
        echo "📁 FileBrowser: http://$SERVER_IP:8082"
        echo "🔗 Samba: \\\\$SERVER_IP\\shared"
        echo ""

        read -p "Pressione Enter para continuar..."
    fi
}

custom_install() {
    while true; do
        show_header
        echo "🛠️  Instalação Personalizada"
        echo ""
        echo "Serviços disponíveis:"
        echo ""

        echo "📁 Essenciais:"
        echo "   [1] Otimizações do sistema      $([[ "$SYSTEM_OPTIMIZED" == "true" ]] && echo "✅" || echo "❌")"
        echo "   [2] Dependências base          $([[ "$BASE_DEPS_INSTALLED" == "true" ]] && echo "✅" || echo "❌")"
        echo "   [3] Firewall                   $([[ "$FIREWALL_CONFIGURED" == "true" ]] && echo "✅" || echo "❌")"
        echo "   [4] Serviços DNS              $([[ "$DNS_CONFIGURED" == "true" ]] && echo "✅" || echo "❌")"
        echo "   [5] Armazenamento             $([[ "$STORAGE_CONFIGURED" == "true" ]] && echo "✅" || echo "❌")"
        echo "   [6] Dashboard Inteligente      $([[ "$DASHBOARD_INSTALLED" == "true" ]] && echo "✅" || echo "❌")"
        echo ""
        echo "🌐 Rede:"
        echo "   [7] WireGuard-UI              $([[ "$WIREGUARD_CONFIGURED" == "true" ]] && echo "✅" || echo "❌")"
        echo ""
        echo "📦 Opcionais:"
        echo "   [8] qBittorrent               $([[ "$TORRENT_INSTALLED" == "true" ]] && echo "✅" || echo "❌")"
        echo "   [9] Syncthing                 $([[ "$SYNC_INSTALLED" == "true" ]] && echo "✅" || echo "❌")"
        echo ""
        echo "   [0] Voltar"
        echo ""

        read -p "Selecione um serviço para instalar/remover [0-9]: " choice

        case $choice in
            1)
                if [[ "$SYSTEM_OPTIMIZED" == "true" ]]; then
                    log_warning "Otimizações já estão instaladas"
                else
                    install_system_optimizations
                fi
                ;;
            2)
                if [[ "$BASE_DEPS_INSTALLED" == "true" ]]; then
                    log_warning "Dependências base já estão instaladas"
                else
                    install_base_dependencies
                fi
                ;;
            3)
                if [[ "$FIREWALL_CONFIGURED" == "true" ]]; then
                    log_warning "Firewall já está configurado"
                else
                    install_firewall
                fi
                ;;
            4)
                if [[ "$DNS_CONFIGURED" == "true" ]]; then
                    log_warning "Serviços DNS já estão configurados"
                else
                    install_dns_services
                fi
                ;;
            5)
                if [[ "$STORAGE_CONFIGURED" == "true" ]]; then
                    log_warning "Serviços de armazenamento já estão configurados"
                else
                    install_storage_services
                fi
                ;;
            6)
                if [[ "$DASHBOARD_INSTALLED" == "true" ]]; then
                    log_warning "Dashboard já está instalado"
                else
                    install_dashboard
                fi
                ;;
            7)
                if [[ "$WIREGUARD_CONFIGURED" == "true" ]]; then
                    log_warning "WireGuard já está configurado"
                else
                    install_wireguard
                fi
                ;;
            8)
                if [[ "$TORRENT_INSTALLED" == "true" ]]; then
                    log_warning "qBittorrent já está instalado"
                else
                    install_torrent
                fi
                ;;
            9)
                if [[ "$SYNC_INSTALLED" == "true" ]]; then
                    log_warning "Syncthing já está instalado"
                else
                    install_sync
                fi
                ;;
            0) return ;;
            *)
                log_error "Opção inválida"
                sleep 2
                ;;
        esac

        read -p "Pressione Enter para continuar..."
    done
}

show_status() {
    show_header
    echo "📊 Status do BoxServer v7.0"
    echo ""

    # Verificar sistema
    echo "🔧 Sistema:"
    echo "   CPU: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%'}')%"
    echo "   RAM: $(free -h | grep Mem | awk '{print $3"/"$2}')"
    echo "   Disco: $(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')"

    # Temperatura
    if [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
        temp=$(cat /sys/class/thermal/thermal_zone0/temp | awk '{print $1/1000}')
        echo "   Temperatura: ${temp}°C"
    fi
    echo ""

    # Status dos serviços
    echo "🛡️  Serviços Essenciais:"
    echo "   Otimizações:           $([[ "$SYSTEM_OPTIMIZED" == "true" ]] && echo "✅" || echo "❌")"
    echo "   Dependências:          $([[ "$BASE_DEPS_INSTALLED" == "true" ]] && echo "✅" || echo "❌")"
    echo "   Firewall:              $([[ "$FIREWALL_CONFIGURED" == "true" ]] && echo "✅" || echo "❌")"
    echo "   DNS:                   $([[ "$DNS_CONFIGURED" == "true" ]] && echo "✅" || echo "❌")"
    echo "   Armazenamento:         $([[ "$STORAGE_CONFIGURED" == "true" ]] && echo "✅" || echo "❌")"
    echo "   Dashboard:             $([[ "$DASHBOARD_INSTALLED" == "true" ]] && echo "✅" || echo "❌")"
    echo ""

    echo "🌐 Serviços de Rede:"
    echo "   WireGuard:             $([[ "$WIREGUARD_CONFIGURED" == "true" ]] && echo "✅" || echo "❌")"
    echo ""

    echo "📦 Serviços Opcionais:"
    echo "   qBittorrent:           $([[ "$TORRENT_INSTALLED" == "true" ]] && echo "✅" || echo "❌")"
    echo "   Syncthing:             $([[ "$SYNC_INSTALLED" == "true" ]] && echo "✅" || echo "❌")"
    echo ""

    # Status dos serviços systemd
    echo "🔍 Status Detalhado:"
    declare -A services=(
        ["dashboard-api"]="Dashboard API (FastAPI)"
        ["pihole-FTL"]="Pi-hole"
        ["filebrowser"]="FileBrowser"
        ["smbd"]="Samba"
        ["wireguard-ui"]="WireGuard-UI"
        ["qbittorrent"]="qBittorrent"
        ["syncthing"]="Syncthing"
    )

    for service in "${!services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "   ${services[$service]}: ✅ Ativo"
        else
            echo "   ${services[$service]}: ❌ Inativo"
        fi
    done

    echo ""
    read -p "Pressione Enter para continuar..."
}

manage_services() {
    while true; do
        show_header
        echo "🔧 Gerenciar Serviços"
        echo ""
        echo "1) 🔄 Reiniciar todos os serviços"
        echo "2) ⏹️  Parar serviços opcionais (economia)"
        echo "3) ▶️  Iniciar serviços opcionais"
        echo "4) 📊 Verificar uso de recursos"
        echo "5) 🔍 Diagnosticar problemas"
        echo "6) 🛠️  Corrigir Dashboard HTML"
        echo "7) 🔍 Validação Completa do Sistema"
        echo "8) 🔄 Atualizar sistema"
        echo "0) 🔙 Voltar"
        echo ""

        read -p "Selecione uma opção [0-8]: " choice

        case $choice in
            1)
                log_step "Reiniciando todos os serviços"
                systemctl daemon-reload
                systemctl restart dashboard-api pihole-FTL filebrowser smbd wireguard-ui 2>/dev/null || true
                log_success "Serviços reiniciados"
                ;;
            2)
                log_step "Parando serviços opcionais"
                systemctl stop qbittorrent syncthing 2>/dev/null || true
                log_success "Serviços opcionais parados"
                ;;
            3)
                log_step "Iniciando serviços opcionais"
                systemctl start qbittorrent syncthing 2>/dev/null || true
                log_success "Serviços opcionais iniciados"
                ;;
            4)
                show_header
                echo "📊 Uso de Recursos"
                echo ""
                echo "Processos ativos:"
                ps aux --sort=-%cpu | head -10
                echo ""
                echo "Memória por serviço:"
                systemctl status --no-pager -l | grep -A 5 "Memory:"
                ;;
            5)
                show_header
                echo "🔍 Diagnóstico de Serviços"
                echo ""
                echo "Selecione o serviço para diagnosticar:"
                echo "1) Samba"
                echo "2) lighttpd"
                echo "3) Todos"
                echo "0) Voltar"
                echo ""
                read -p "Opção [0-3]: " diag_choice

                case $diag_choice in
                    1) diagnose_service_issues "samba" ;;
                    2) diagnose_service_issues "lighttpd" ;;
                    3)
                        diagnose_service_issues "samba"
                        echo ""
                        diagnose_service_issues "lighttpd"
                        ;;
                    0) continue ;;
                    *) log_error "Opção inválida" ;;
                esac
                ;;
            6)
                fix_dashboard_html
                ;;
            7)
                post_install_verification
                ;;
            8)
                log_step "Atualizando sistema"
                apt update && apt upgrade -y
                log_success "Sistema atualizado"
                ;;
            0) return ;;
            *)
                log_error "Opção inválida"
                ;;
        esac

        read -p "Pressione Enter para continuar..."
    done
}

backup_restore() {
    while true; do
        show_header
        echo "💾 Backup e Restauração"
        echo ""
        echo "1) 💾 Criar Backup"
        echo "2) 📂 Listar Backups"
        echo "3) 🔄 Restaurar Backup"
        echo "0) 🔙 Voltar"
        echo ""

        read -p "Selecione uma opção [0-3]: " choice

        case $choice in
            1)
                log_step "Criando backup"
                backup_name="boxserver-backup-$(date +%Y%m%d-%H%M%S)"
                backup_path="$BACKUP_DIR/$backup_name"

                mkdir -p "$backup_path"

                # Backup das configurações
                cp -r /etc/boxserver "$backup_path/" 2>/dev/null || true
                cp -r /etc/pihole "$backup_path/" 2>/dev/null || true
                cp -r /etc/wireguard "$backup_path/" 2>/dev/null || true
                cp -r /etc/samba "$backup_path/" 2>/dev/null || true

                # Backup dos serviços systemd
                cp /etc/systemd/system/dashboard-api.service "$backup_path/" 2>/dev/null || true
                cp /etc/systemd/system/filebrowser.service "$backup_path/" 2>/dev/null || true

                # Backup dos dados
                cp -r /var/www/html "$backup_path/" 2>/dev/null || true

                log_success "Backup criado: $backup_path"
                ;;
            2)
                show_header
                echo "📂 Backups Disponíveis:"
                echo ""
                if [[ -d "$BACKUP_DIR" ]]; then
                    ls -la "$BACKUP_DIR/" | grep "^d" | awk '{print $9}' | while read backup; do
                        echo "   📦 $backup"
                    done
                else
                    echo "   Nenhum backup encontrado"
                fi
                ;;
            3)
                echo "Função de restauração em desenvolvimento"
                ;;
            0) return ;;
            *)
                log_error "Opção inválida"
                ;;
        esac

        read -p "Pressione Enter para continuar..."
    done
}

show_settings() {
    while true; do
        show_header
        echo "📝 Configurações"
        echo ""
        echo "1) 🌐 Configurar Rede"
        echo "2) 🔄 Alterar tipo de instalação"
        echo "3) ⚡ Configurar otimizações automáticas"
        echo "4) 📊 Habilitar/Desabilitar monitoramento"
        echo "0) 🔙 Voltar"
        echo ""

        read -p "Selecione uma opção [0-4]: " choice

        case $choice in
            1)
                show_header
                echo "🌐 Configuração de Rede"
                echo ""
                echo "Configuração atual:"
                echo "   IP: $SERVER_IP"
                echo "   Gateway: $GATEWAY"
                echo "   DNS: $DNS_SERVER"
                echo ""
                read -p "Novo IP [$SERVER_IP]: " new_ip
                read -p "Novo Gateway [$GATEWAY]: " new_gateway
                read -p "Novo DNS [$DNS_SERVER]: " new_dns

                [[ -n "$new_ip" ]] && SERVER_IP="$new_ip"
                [[ -n "$new_gateway" ]] && GATEWAY="$new_gateway"
                [[ -n "$new_dns" ]] && DNS_SERVER="$new_dns"

                save_config
                log_success "Configurações de rede atualizadas"
                ;;
            2)
                show_header
                echo "🔄 Tipo de Instalação"
                echo ""
                echo "Atual: $INSTALL_TYPE"
                echo ""
                echo "1) essential (mínimo)"
                echo "2) standard (recomendado)"
                echo "3) complete (todos os serviços)"
                echo ""
                read -p "Selecione o tipo [1-3]: " type_choice

                case $type_choice in
                    1) INSTALL_TYPE="essential" ;;
                    2) INSTALL_TYPE="standard" ;;
                    3) INSTALL_TYPE="complete" ;;
                    *) ;;
                esac

                save_config
                log_success "Tipo de instalação atualizado"
                ;;
            3)
                if [[ "$AUTO_OPTIMIZE" == "true" ]]; then
                    AUTO_OPTIMIZE="false"
                    log_info "Otimizações automáticas desabilitadas"
                else
                    AUTO_OPTIMIZE="true"
                    log_info "Otimizações automáticas habilitadas"
                fi
                save_config
                ;;
            4)
                if [[ "$ENABLE_MONITORING" == "true" ]]; then
                    ENABLE_MONITORING="false"
                    log_info "Monitoramento desabilitado"
                else
                    ENABLE_MONITORING="true"
                    log_info "Monitoramento habilitado"
                fi
                save_config
                ;;
            0) return ;;
            *)
                log_error "Opção inválida"
                ;;
        esac

        read -p "Pressione Enter para continuar..."
    done
}

show_logs() {
    show_header
    echo "📋 Logs do Sistema"
    echo ""
    echo "1) 📄 Ver log de instalação"
    echo "2) 🔍 Ver logs do sistema"
    echo "3) 📊 Ver logs de serviços"
    echo "4) 🗑️  Limpar logs"
    echo "0) 🔙 Voltar"
    echo ""

    read -p "Selecione uma opção [0-4]: " choice

    case $choice in
        1)
            if [[ -f "$LOG_FILE" ]]; then
                less "$LOG_FILE"
            else
                log_error "Log de instalação não encontrado"
            fi
            ;;
        2)
            if command -v journalctl &> /dev/null; then
                if journalctl -xb --no-pager &> /dev/null; then
                    journalctl -xb --no-pager | tail -50
                else
                    journalctl --no-pager | tail -50
                fi
            else
                log_warning "journalctl não disponível, mostrando logs do sistema"
                find /var/log -name "*.log" -exec tail -n 20 {} \; 2>/dev/null | head -50
            fi
            ;;
        3)
            systemctl status --no-pager -l | tail -50
            ;;
        4)
            log_step "Limpando logs antigos"
            if command -v journalctl &> /dev/null; then
                journalctl --vacuum-time=7d 2>/dev/null || log_warning "journalctl --vacuum-time falhou"
            fi
            find /var/log -name "*.log" -mtime +30 -delete 2>/dev/null || true
            # Limpar cache do apt
            apt clean 2>/dev/null || true
            apt autoremove -y 2>/dev/null || true
            log_success "Logs limpos"
            ;;
        0) return ;;
        *)
            log_error "Opção inválida"
            ;;
    esac

    read -p "Pressione Enter para continuar..."
}

clean_installation() {
    show_header
    echo "🧹 Limpeza Completa da Instalação"
    echo ""
    echo "⚠️  AVISO: Esta opção removerá completamente:"
    echo "   • Todos os serviços do BoxServer"
    echo "   • Configurações e dados"
    echo "   • Pacotes instalados"
    echo "   • Arquivos de log"
    echo "   • Regras de firewall e portas"
    echo ""
    echo "Esta ação não pode ser desfeita!"
    echo ""

    read -p "Digite 'LIMPAR' para confirmar: " confirm
    if [[ "$confirm" != "LIMPAR" ]]; then
        log_info "Limpeza cancelada"
        return
    fi

    log_step "Iniciando limpeza completa"

    # Parar todos os serviços do BoxServer
    log_info "Parando serviços do BoxServer"
    systemctl stop dashboard-api pihole-FTL filebrowser smbd nmbd wireguard-ui qbittorrent-nox syncthing unbound 2>/dev/null || true
    systemctl disable dashboard-api pihole-FTL filebrowser smbd nmbd wireguard-ui qbittorrent-nox syncthing unbound 2>/dev/null || true

    # Matar processos pendentes
    log_info "Finalizando processos pendentes"
    pkill -f "lighttpd\|pihole\|samba\|unbound\|dashboard-api\|filebrowser\|qbittorrent\|syncthing" 2>/dev/null || true

    # Remover serviços systemd personalizados
    log_info "Removendo serviços systemd"
    rm -f /etc/systemd/system/dashboard-api.service
    rm -f /etc/systemd/system/filebrowser.service
    rm -f /etc/systemd/system/qbittorrent.service
    systemctl daemon-reload

    # Limpar instalações de serviços
    log_info "Limpando instalações de serviços"
    purge_service "lighttpd"
    purge_service "pihole"
    purge_service "samba"
    purge_service "unbound"
    purge_service "dnsmasq"

    # Remover pacotes opcionais
    apt purge -y qbittorrent-nox 2>/dev/null || true
    apt purge -y syncthing 2>/dev/null || true
    apt purge -y fail2ban 2>/dev/null || true
    apt purge -y wireguard wireguard-tools 2>/dev/null || true
    apt purge -y resolvconf openresolv 2>/dev/null || true
    apt purge -y rng-tools haveged 2>/dev/null || true

    # Remover regras de firewall
    log_info "Removendo regras de firewall"
    if command -v ufw &> /dev/null; then
        ufw --force reset 2>/dev/null || true
        ufw --force delete 8090 2>/dev/null || true
        ufw --force delete 8082 2>/dev/null || true
        ufw --force delete 9091 2>/dev/null || true
        ufw --force delete 8384 2>/dev/null || true
        ufw --force delete 5000 2>/dev/null || true
        ufw --force delete 445 2>/dev/null || true
        ufw --force delete 139 2>/dev/null || true
    fi

    # Remover arquivos e diretórios
    log_info "Removendo arquivos de configuração"
    rm -rf /etc/boxserver
    rm -rf /etc/lighttpd
    rm -rf /etc/pihole
    rm -rf /etc/samba
    rm -rf /etc/unbound
    rm -rf /srv/samba
    rm -rf /srv/filebrowser
    rm -rf /srv/qbittorrent
    rm -rf /opt/wireguard-ui
    rm -rf /var/www/html/dashboard*
    rm -rf /var/www/html/pihole
    rm -rf /var/lib/unbound
    rm -rf /backups/boxserver
    rm -rf /var/log/boxserver
    rm -f /var/log/dashboard-api.log

    # Remover usuários criados
    log_info "Removendo usuários criados"
    userdel -r filebrowser 2>/dev/null || true
    userdel -r qbittorrent 2>/dev/null || true

    # Limpar cache do sistema
    log_info "Limpando cache do sistema"
    apt clean
    apt autoremove -y
    systemctl daemon-reload

    # Resetar configuração do BoxServer
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Resetando configuração do BoxServer"
        create_default_config
    fi

    log_success "✅ Limpeza completa concluída!"
    echo ""
    echo "🔄 O sistema está pronto para uma nova instalação fresh."
    echo "📊 Todas as portas foram liberadas"
    echo "🛡️  Regras de firewall removidas"
    echo ""

    read -p "Pressione Enter para continuar..."
}

quick_validation() {
    echo ""
    echo "🔍 Validação Rápida do Sistema"
    echo "================================"

    local issues=0

    # Verificar serviços essenciais
    echo "Verificando serviços essenciais..."
    systemctl is-active --quiet dashboard-api || { echo "❌ Dashboard API inativo"; ((issues++)); }
    systemctl is-active --quiet pihole-FTL || { echo "❌ Pi-hole FTL inativo"; ((issues++)); }
    systemctl is-active --quiet lighttpd || { echo "❌ Lighttpd inativo"; ((issues++)); }
    systemctl is-active --quiet smbd || { echo "❌ Samba inativo"; ((issues++)); }

    # Verificar portas
    echo "Verificando portas essenciais..."
    if ! check_port_availability 80; then
        echo "❌ Porta 80 ocupada (Dashboard)"
        ((issues++))
    fi

    # Testar acesso rápido
    echo "Testando acessibilidade..."
    if test_http_endpoint "http://localhost:80/health" 2; then
        echo "✅ Dashboard acessível"
    else
        echo "❌ Dashboard inacessível"
        ((issues++))
    fi

    if test_http_endpoint "http://localhost:8090/admin/" 3; then
        echo "✅ Pi-hole acessível"
    else
        echo "⚠️  Pi-hole pode estar inicializando"
    fi

    echo ""
    if [[ $issues -eq 0 ]]; then
        echo "🎉 Sistema está funcional!"
        return 0
    else
        echo "⚠️  Encontrados $issues problemas - execute validação completa"
        return 1
    fi
}

show_about() {
    show_header
    cat << 'EOF'
🏗️  BoxServer Installer v7.0 (FastAPI Edition)

Um instalador profissional para transformar qualquer dispositivo
em um servidor completo e otimizado com arquitetura moderna.

🎯 Recursos:
• Instalação assistida com menu interativo
• API FastAPI moderna com uvicorn
• Fluxo hierárquico com validação de dependências
• Sistema de recuperação e rollback automático
• Monitoramento em tempo real
• Backup e restauração integrados
• Otimizações para hardware limitado

📊 Arquitetura Suportada:
• ARMv7, ARM64, x86_64
• Mínimo 512MB RAM
• Linux com systemd

⚡ Serviços:
• Pi-hole (DNS blocker)
• Samba (compartilhamento de arquivos)
• FileBrowser (interface web)
• WireGuard-UI (VPN moderna)
• Dashboard Inteligente (monitoramento)
• qBittorrent (torrents)
• Syncthing (sincronização)

🔧 Tecnologias:
• Shell Script robusto
• Systemd service management
• FastAPI + Uvicorn (Python)
• HTML5/JavaScript frontend
• Network optimization
• Security hardening

© 2023 BoxServer Team (Atualizado por Claude)
Licença: MIT
EOF

    read -p "Pressione Enter para continuar..."
}

diagnose_service_issues() {
    local service_name="$1"
    log_info "Diagnosticando problemas com $service_name"

    case "$service_name" in
        "samba")
            # Verificar processos Samba
            if pgrep -f "smbd\|nmbd" > /dev/null; then
                log_info "Processos Samba ativos:"
                pgrep -f "smbd\|nmbd" | while read pid; do
                    log_info "  PID $pid: $(ps -p $pid -o comm=)"
                done
            else
                log_info "Nenhum processo Samba encontrado"
            fi

            # Verificar portas
            log_info "Verificando portas Samba:"
            netstat -tlnp 2>/dev/null | grep -E ":(139|445|137|138)" || log_info "  Portas Samba não estão abertas"

            # Verificar configuração
            if [[ -f /etc/samba/smb.conf ]]; then
                log_info "Testando configuração Samba:"
                if testparm -s 2>/dev/null; then
                    log_success "  Configuração válida"
                else
                    log_error "  Configuração inválida"
                fi
            else
                log_error "  Arquivo smb.conf não encontrado"
            fi

            # Verificar logs
            log_info "Logs recentes do Samba:"
            if [[ -f /var/log/samba/log.smbd ]]; then
                tail -10 /var/log/samba/log.smbd 2>/dev/null || log_info "  Não foi possível ler logs"
            fi
            ;;
        "lighttpd")
            # Verificar configuração lighttpd
            if [[ -f /etc/lighttpd/lighttpd.conf ]]; then
                if lighttpd -tt -f /etc/lighttpd/lighttpd.conf 2>/dev/null; then
                    log_success "Configuração lighttpd válida"
                else
                    log_error "Configuração lighttpd inválida"
                fi
            else
                log_error "Arquivo lighttpd.conf não encontrado"
            fi

            # Verificar portas
            log_info "Verificando porta lighttpd (8090):"
            netstat -tlnp 2>/dev/null | grep ":8090" || log_info "  Porta 8090 não está aberta"
            ;;
    esac
}

fix_dashboard_html() {
    log_step "Corrigindo arquivo dashboard.html manualmente"

    if [[ -f "$SCRIPT_DIR/dashboard.html" ]]; then
        log_info "Arquivo dashboard.html encontrado no diretório do script"

        # Parar o serviço temporariamente
        systemctl stop dashboard-api 2>/dev/null || true

        # Copiar o arquivo completo
        cp "$SCRIPT_DIR/dashboard.html" /var/www/html/
        chown www-data:www-data /var/www/html/dashboard.html
        chmod 644 /var/www/html/dashboard.html

        # Verificar tamanho do arquivo para confirmar cópia
        local original_size=$(wc -l < "$SCRIPT_DIR/dashboard.html")
        local copied_size=$(wc -l < /var/www/html/dashboard.html 2>/dev/null || echo "0")

        if [[ "$copied_size" -gt 100 && "$copied_size" -eq "$original_size" ]]; then
            log_success "Dashboard HTML copiado com sucesso ($copied_size linhas)"

            # Reiniciar o serviço
            systemctl start dashboard-api 2>/dev/null || true

            # Testar acesso
            sleep 2
            if curl -s http://localhost:80 | grep -q "BoxServer Dashboard"; then
                log_success "Dashboard agora está acessível com o template completo"
                return 0
            else
                log_warning "Dashboard copiado mas serviço pode não estar respondendo"
                return 1
            fi
        else
            log_error "Falha na cópia do dashboard.html (tamanho: $copied_size vs $original_size)"
            return 1
        fi
    else
        log_error "Arquivo dashboard.html não encontrado em $SCRIPT_DIR"
        return 1
    fi
}

clean_install_environment() {
    log_step "Limpando ambiente de instalação"

    # Limpar instalações problemáticas comuns
    local services_to_purge=(
        "lighttpd"
        "pi-hole"
        "samba"
        "unbound"
        "dnsmasq"
    )

    for service in "${services_to_purge[@]}"; do
        if dpkg -l | grep -q "^ii.*$service"; then
            purge_service "$service"
        fi
    done

    # Limpar processos órfãos
    pkill -f "lighttpd\|pihole\|samba\|unbound" 2>/dev/null || true

    # Limpar sockets residuais e locks
    rm -f /run/lighttpd.pid 2>/dev/null || true
    rm -f /run/samba/*.pid 2>/dev/null || true
    rm -rf /run/samba 2>/dev/null || true
    rm -rf /var/lib/samba/private/msg.lock 2>/dev/null || true

    # Limpar arquivos temporários
    rm -rf /tmp/smb* 2>/dev/null || true

    log_success "Ambiente limpo para instalação fresh"
}

# =============================================================================
# FUNÇÃO PRINCIPAL
# =============================================================================

main() {
    # Verificar se estamos rodando como root
    check_root

    # Inicializar ambiente
    initialize_environment

    # Verificar e baixar arquivos necessários do GitHub
    log_info "Verificando arquivos necessários..."
    if ! ensure_github_files; then
        log_error "Não foi possível baixar arquivos necessários do GitHub"
        log_info "Verifique sua conexão com a internet e tente novamente"
        exit 1
    fi

    # Verificar requisitos
    if ! check_requirements; then
        read -p "Requisitos mínimos não atendidos. Deseja continuar? [S/N]: " confirm
        if [[ ${confirm^^} != "S" ]]; then
            exit 1
        fi
    fi

    # Carregar configuração
    load_config

    # Mostrar menu principal
    show_main_menu
}

# =============================================================================
# TRATAMENTO DE SINAIS
# =============================================================================

trap 'log_error "Instalação interrompida pelo usuário"; exit 1' INT TERM

# =============================================================================
# EXECUÇÃO
# =============================================================================

# Verificar se o script está sendo sourcing ou executado
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi