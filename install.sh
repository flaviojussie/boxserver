#!/bin/bash

# =============================================================================
# BoxServer Installer v3.0 - Instalação Assistida e Robusta
# =============================================================================
# Autor: BoxServer Team
# Descrição: Instalação unificada com fluxo hierárquico e validações
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURAÇÕES GLOBAIS
# =============================================================================

readonly SCRIPT_VERSION="3.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/boxserver-install.log"
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
│                 Professional Server Installation           │
│                         Version 3.0                        │
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

    # Verificar comandos essenciais para Kernel 4.4
    local required_commands=("curl" "wget" "python3" "pip3" "systemctl" "ip" "iptables")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Comando essencial não encontrado: $cmd"
            return 1
        fi
    done

    # Verificar se /proc está montado (essencial para métodos legacy)
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
# FUNÇÕES DE LIMPEZA E PURGE
# =============================================================================

purge_service() {
    local service_name="$1"
    local config_dirs=("${@:2}")
    
    log_step "Limpando instalação anterior do $service_name"
    
    # Parar serviços
    systemctl stop "$service_name" 2>/dev/null || true
    systemctl disable "$service_name" 2>/dev/null || true
    
    # Remover pacotes completamente
    apt purge -y "$service_name" 2>/dev/null || true
    apt autoremove -y
    
    # Remover configurações residuais
    for dir in "${config_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_info "Removendo diretório de configuração: $dir"
            rm -rf "$dir"
        fi
    done
    
    # Remover arquivos de configuração específicos
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
    
    # Limpar cache do apt
    apt clean
    
    log_success "Limpeza do $service_name concluída"
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

fix_samba_issues() {
    log_step "Tentando corrigir problemas do Samba"
    
    # Parar serviços forçadamente
    systemctl stop smbd nmbd 2>/dev/null || true
    pkill -f "smbd\|nmbd" 2>/dev/null || true
    
    # Remover locks e arquivos problemáticos
    rm -rf /var/lib/samba/private/msg.lock 2>/dev/null || true
    rm -rf /run/samba 2>/dev/null || true
    rm -f /etc/samba/smb.conf 2>/dev/null || true
    
    # Recrear todos os diretórios necessários com permissões corretas
    log_info "Recriando estrutura de diretórios Samba"
    mkdir -p /etc/samba
    mkdir -p /var/lib/samba/private
    mkdir -p /var/log/samba
    mkdir -p /run/samba
    mkdir -p /srv/samba/{shared,private}
    
    # Definir permissões corretas
    chown root:root /etc/samba
    chown root:root /var/lib/samba/private
    chown root:users /srv/samba/shared
    chown root:users /srv/samba/private
    chmod 755 /etc/samba
    chmod 700 /var/lib/samba/private
    chmod 777 /srv/samba/shared
    chmod 750 /srv/samba/private
    
    # Resetar configuração para básica (mínima e compatível)
    cat > /etc/samba/smb.conf << 'EOF'
[global]
   workgroup = WORKGROUP
   server string = BoxServer Samba
   security = user
   map to guest = Bad User
   guest account = nobody
   
[shared]
   comment = Compartilhamento Público
   path = /srv/samba/shared
   browseable = yes
   writable = yes
   guest ok = yes
   guest only = yes
   read only = no
   create mask = 0777
   directory mask = 0777
   force create mode = 0777
   force directory mode = 0777
EOF
    
    # Testar configuração (mas não falhar se testparm retornar erro)
    log_info "Testando configuração básica do Samba"
    if testparm -s 2>/dev/null; then
        log_success "Configuração básica do Samba válida"
    else
        log_warning "testparm reportou problemas, mas tentando iniciar mesmo assim"
    fi
    
    # Tentar iniciar serviços individualmente
    systemctl daemon-reload
    
    # Parar serviços completamente antes de iniciar
    systemctl stop smbd nmbd 2>/dev/null || true
    sleep 2
    
    # Tentar iniciar smbd primeiro
    if systemctl start smbd; then
        log_success "Serviço smbd iniciado com sucesso"
        
        # Tentar iniciar nmbd (opcional para compartilhamento básico)
        if systemctl start nmbd; then
            log_success "Serviço nmbd iniciado com sucesso"
        else
            log_warning "Serviço nmbd falhou - continuando sem resolução de nomes NetBIOS"
        fi
        
        # Verificar se smbd continua ativo após alguns segundos
        sleep 3
        if systemctl is-active --quiet smbd; then
            log_success "Samba corrigido e funcionando"
            return 0
        else
            log_error "smbd parou após iniciar"
            return 1
        fi
    else
        log_error "Não foi possível iniciar smbd mesmo com configuração básica"
        
        # Última tentativa: verificar logs do sistema
        log_info "Verificando logs do sistema para mais detalhes:"
        journalctl -u smbd --no-pager -n 10 2>/dev/null || log_info "Não foi possível acessar logs"
        
        return 1
    fi
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

        # Configurar IP estático via interfaces (compatível com sistemas legados)
        cat > /etc/network/interfaces.d/boxserver << EOF
auto $network_interface
iface $network_interface inet static
    address $SERVER_IP
    netmask 255.255.255.0
    gateway $GATEWAY
    dns-nameservers $DNS_SERVER
EOF

        # Tentar aplicar configuração (métodos alternativos)
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

# TCP otimizado (BBR pode não estar disponível em kernels antigos)
# net.ipv4.tcp_congestion_control=bbr
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
    echo "tmpfs /tmp tmpfs defaults,size=256M 0 0" >> /etc/fstab
    echo "tmpfs /var/log tmpfs defaults,size=128M 0 0" >> /etc/fstab
    echo "tmpfs /var/tmp tmpfs defaults,size=128M 0 0" >> /etc/fstab

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

    # Limpar e atualizar cache do apt antes de instalar
    log_info "Limpando cache do apt"
    apt clean
    apt autoremove -y

    log_info "Atualizando cache do apt"
    apt update

    # Instalar pacotes básicos (individualmente para pular pacotes não disponíveis)
    log_info "Instalando pacotes essenciais"
    local packages=(
        "curl" "wget" "git" "dialog" "chrony" "unbound" "rng-tools" "haveged"
        "build-essential" "ca-certificates" "gnupg" "lsb-release"
        "software-properties-common" "logrotate" "ufw" "htop" "python3"
        "python3-pip" "iotop" "sysstat"
    )

    # Pacotes adicionais para compatibilidade
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

    # Instalar pacotes de compatibilidade
    log_info "Instalando pacotes de compatibilidade"
    for package in "${compat_packages[@]}"; do
        if ! apt install -y "$package"; then
            log_warning "Pacote de compatibilidade $package não disponível, pulando..."
            failed_packages+=("$package")
        fi
    done

    # Instalar psutil via pip (necessário para o dashboard)
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

    # Verificar instalação bem-sucedida
    if [[ $? -eq 0 ]]; then
        BASE_DEPS_INSTALLED=true
        save_config
        log_success "Dependências base instaladas"
    else
        log_error "Falha ao instalar dependências base"
        return 1
    fi
}

install_firewall() {
    log_step "Configurando firewall"

    if [[ "$FIREWALL_CONFIGURED" == "true" ]]; then
        log_info "Firewall já configurado, pulando..."
        return 0
    fi

    # Verificar compatibilidade do UFW com kernel antigo
    log_info "Verificando compatibilidade do firewall"
    local kernel_version=$(uname -r | cut -d. -f1-2)

    if [[ "$kernel_version" == "4.4" ]]; then
        log_warning "Kernel 4.4 detectado - usando iptables legado"

        # Para kernel 4.4, usar iptables diretamente em vez de UFW
        # Configurar regras básicas de iptables
        iptables -F INPUT
        iptables -F FORWARD
        iptables -F OUTPUT
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT

        # Permitir tráfego estabelecido e relacionado
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

        # Permitir loopback
        iptables -A INPUT -i lo -j ACCEPT

        # Permitir portas essenciais
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT    # SSH
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # Dashboard
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # HTTPS
        iptables -A INPUT -p tcp --dport 5000 -j ACCEPT  # WireGuard-UI
        iptables -A INPUT -p udp --dport 51820 -j ACCEPT # WireGuard VPN

        # Salvar regras
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4

        # Criar serviço para persistência das regras
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
        # Para kernels mais recentes, usar UFW normalmente
        log_info "Usando UFW para kernel $kernel_version"

        # Configurar UFW
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp comment "SSH"
        ufw allow 80/tcp comment "Dashboard"
        ufw allow 443/tcp comment "HTTPS"
        ufw allow 5000/tcp comment "WireGuard-UI"
        ufw allow 51820/udp comment "WireGuard VPN"

        # Tentar habilitar UFW com tratamento de erro
        if ! ufw --force enable 2>/dev/null; then
            log_warning "UFW falhou, usando iptables diretamente"
            # Fallback para iptables
            iptables -F INPUT
            iptables -F FORWARD
            iptables -F OUTPUT
            iptables -P INPUT DROP
            iptables -P FORWARD DROP
            iptables -P OUTPUT ACCEPT
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A INPUT -p tcp --dport 22 -j ACCEPT
            iptables -A INPUT -p tcp --dport 80 -j ACCEPT
            iptables -A INPUT -p tcp --dport 443 -j ACCEPT
            iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
            iptables -A INPUT -p udp --dport 51820 -j ACCEPT

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

    # Instalar Unbound e lighttpd com versões frescas
    log_info "Instalando Unbound e lighttpd (fresh install)"
    apt update
    apt install -y unbound lighttpd
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

    # Instalar Pi-hole
    log_info "Instalando Pi-hole (interativo)"
    curl -sSL https://install.pi-hole.net | bash

    # Configurar lighttpd para trabalhar com Pi-hole na porta 8090 (alternativa)
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

    # Limpar instalações anteriores do Samba completamente
    purge_service "samba"
    
    # Parar serviços residuais e remover processos
    systemctl stop smbd nmbd 2>/dev/null || true
    pkill -f "smbd\|nmbd" 2>/dev/null || true
    
    # Remover completamente diretórios residuais
    rm -rf /etc/samba 2>/dev/null || true
    rm -rf /var/lib/samba 2>/dev/null || true
    rm -rf /var/cache/samba 2>/dev/null || true
    rm -rf /run/samba 2>/dev/null || true
    
    # Aguardar sistema liberar recursos completamente
    log_info "Aguardando serviços pararem completamente..."
    for i in {1..10}; do
        if ! systemctl is-active --quiet smbd && ! systemctl is-active --quiet nmbd; then
            log_success "Serviços parados após $i segundos"
            break
        fi
        sleep 1
        if [[ $i -eq 10 ]]; then
            log_warning "Serviços não pararam completamente, forçando parada"
            pkill -9 -f "smbd\|nmbd" 2>/dev/null || true
            sleep 2
        fi
    done
    
    # Instalar Samba de forma simples
    log_info "Instalando Samba"
    apt update
    apt install -y samba samba-common-bin
    
    # Aguardar instalação completar e serviços estabilizarem
    log_info "Aguardando instalação completar..."
    sleep 5
    
    # Garantir que serviços estão parados antes de criar configuração
    log_info "Parando serviços pós-instalação..."
    systemctl stop smbd nmbd 2>/dev/null || true
    pkill -f "smbd\|nmbd" 2>/dev/null || true
    sleep 3
    
    # Criar configuração básica depois que tudo estiver estabilizado
    log_info "Criando configuração básica"
    mkdir -p /etc/samba
    
    # Criar TODOS os diretórios necessários para o Samba funcionar
    log_info "Criando diretórios necessários para o Samba"
    mkdir -p /var/lib/samba
    mkdir -p /var/cache/samba
    mkdir -p /run/samba
    mkdir -p /var/log/samba
    mkdir -p /srv/samba/shared
    
    # Definir permissões corretas
    chmod 755 /var/lib/samba
    chmod 755 /var/cache/samba
    chmod 755 /run/samba
    chmod 755 /var/log/samba
    chmod 777 /srv/samba/shared
    
    # Criar arquivo de configuração
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

    # Aguardar configuração ser completamente escrita
    sleep 2
    
    # Testar configuração simples com diagnóstico detalhado
    log_info "Validando configuração do Samba..."
    
    # Mostrar conteúdo do arquivo para diagnóstico
    log_info "Conteúdo do /etc/samba/smb.conf:"
    cat /etc/samba/smb.conf
    
    # Testar configuração e mostrar erros
    if testparm -s; then
        log_success "Configuração do Samba válida"
        
        # Reiniciar serviços
        systemctl restart smbd nmbd 2>/dev/null || true
        systemctl enable smbd nmbd 2>/dev/null || true
        
        # Verificar se está funcionando
        if systemctl is-active --quiet smbd; then
            log_success "Samba instalado e funcionando"
        else
            log_warning "Samba instalado mas serviço não iniciado - tentando manualmente"
            systemctl daemon-reload
            systemctl start smbd || true
        fi
    else
        log_error "Configuração básica falhou na validação"
        log_info "=== SAÍDA COMPLETA DO TESTPARM PARA DIAGNÓSTICO ==="
        testparm -s 2>&1 || true
        log_info "=== FIM DO DIAGNÓSTICO ==="
        return 1
    fi

    # Configurar firewall
    ufw allow samba 2>/dev/null || true

    # Instalar FileBrowser
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
    log_step "Instalando Dashboard Inteligente"

    if [[ "$DASHBOARD_INSTALLED" == "true" ]]; then
        log_info "Dashboard já instalado, pulando..."
        return 0
    fi

    # Criar API Python
    cat > /var/www/html/dashboard-api.py << 'EOF'
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import subprocess
import os
import time
from urllib.parse import urlparse, parse_qs

# Tentar importar psutil com fallback
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class DashboardAPI(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        # CORS headers
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

        if path == '/health':
            response = {"status": "healthy", "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')}
        elif path == '/api/system':
            response = self.get_system_info()
        elif path == '/api/services':
            response = self.get_services_status()
        else:
            # Serve dashboard.html for root path
            if path == '/' or path == '':
                try:
                    with open('/var/www/html/dashboard.html', 'r') as f:
                        content = f.read()
                    self.wfile.write(content.encode())
                    return
                except FileNotFoundError:
                    response = {"error": "Dashboard not found"}
            else:
                response = {"error": "Endpoint not found"}

        self.wfile.write(json.dumps(response, indent=2).encode())

    def get_system_info(self):
        # Obter uso de CPU com ou sem psutil
        if PSUTIL_AVAILABLE:
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
            except:
                cpu_percent = self.get_cpu_usage_legacy()
        else:
            cpu_percent = self.get_cpu_usage_legacy()

        # Obter uso de memória com ou sem psutil
        if PSUTIL_AVAILABLE:
            try:
                memory = psutil.virtual_memory()
                memory_info = {
                    "percent": memory.percent,
                    "total": f"{memory.total // (1024**3):.1f}GB",
                    "available": f"{memory.available // (1024**3):.1f}GB"
                }
            except:
                memory_info = self.get_memory_usage_legacy()
        else:
            memory_info = self.get_memory_usage_legacy()

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
            "memory": memory_info,
            "temperature": temp,
            "uptime": uptime,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "psutil_available": PSUTIL_AVAILABLE
        }

    def get_cpu_usage_legacy(self):
        """Método alternativo para obter uso de CPU sem psutil"""
        try:
            # Usar /proc/stat para calcular uso de CPU
            with open('/proc/stat', 'r') as f:
                lines = f.readlines()

            for line in lines:
                if line.startswith('cpu '):
                    values = line.split()[1:8]
                    user, nice, system, idle, iowait, irq, softirq = map(int, values)
                    total = user + nice + system + idle + iowait + irq + softirq
                    used = total - idle
                    return (used / total * 100) if total > 0 else 0.0
        except:
            pass
        return 0.0

    def get_memory_usage_legacy(self):
        """Método alternativo para obter uso de memória sem psutil"""
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()

            meminfo = {}
            for line in lines:
                if line.strip():
                    key, value = line.split(':')[:2]
                    meminfo[key.strip()] = int(value.strip().split()[0])

            total = meminfo.get('MemTotal', 0)
            available = meminfo.get('MemAvailable', meminfo.get('MemFree', 0))
            used = total - available

            return {
                "percent": (used / total * 100) if total > 0 else 0,
                "total": f"{total // 1024:.1f}GB",
                "available": f"{available // 1024:.1f}GB"
            }
        except:
            return {
                "percent": 0,
                "total": "N/A",
                "available": "N/A"
            }

    def get_services_status(self):
        services = {
            "pihole": {
                "name": "Pi-hole DNS",
                "description": "DNS blocker e servidor DNS",
                "icon": "fas fa-shield-alt",
                "url": "http://192.168.0.100:8090/admin",
                "port": 8090
            },
            "filebrowser": {
                "name": "FileBrowser",
                "description": "Gerenciador de arquivos web",
                "icon": "fas fa-folder-open",
                "url": "http://192.168.0.100:8082",
                "port": 8082
            },
            "samba": {
                "name": "Samba",
                "description": "Compartilhamento de arquivos SMB",
                "icon": "fas fa-network-wired",
                "url": "smb://192.168.0.100",
                "port": None
            },
            "wireguard": {
                "name": "WireGuard-UI",
                "description": "Interface VPN moderna",
                "icon": "fas fa-lock",
                "url": "http://192.168.0.100:5000",
                "port": 5000
            },
            "qbittorrent": {
                "name": "qBittorrent",
                "description": "Cliente de torrents",
                "icon": "fas fa-download",
                "url": "http://192.168.0.100:9091",
                "port": 9091
            },
            "syncthing": {
                "name": "Syncthing",
                "description": "Sincronização de arquivos",
                "icon": "fas fa-sync",
                "url": "http://192.168.0.100:8384",
                "port": 8384
            }
        }

        for service_id, service in services.items():
            status = self.check_service_status(service_id, service["port"])
            services[service_id]["status"] = status["status"]
            services[service_id]["cpu"] = status["cpu"]
            services[service_id]["memory"] = status["memory"]

        return services

    def check_service_status(self, service_id, port):
        try:
            # Check systemd service
            if service_id == "pihole":
                result = subprocess.run(['systemctl', 'is-active', 'pihole-FTL'], capture_output=True, text=True)
                if result.stdout.strip() == "active":
                    return {"status": "online", "cpu": 2.1, "memory": 15.3}
            elif service_id == "filebrowser":
                result = subprocess.run(['systemctl', 'is-active', 'filebrowser'], capture_output=True, text=True)
                if result.stdout.strip() == "active":
                    return {"status": "online", "cpu": 1.5, "memory": 8.7}
            elif service_id == "samba":
                result = subprocess.run(['systemctl', 'is-active', 'smbd'], capture_output=True, text=True)
                if result.stdout.strip() == "active":
                    return {"status": "online", "cpu": 0.8, "memory": 12.1}
            elif service_id == "wireguard":
                result = subprocess.run(['systemctl', 'is-active', 'wireguard-ui'], capture_output=True, text=True)
                if result.stdout.strip() == "active":
                    return {"status": "online", "cpu": 3.2, "memory": 25.4}
            elif service_id == "qbittorrent":
                result = subprocess.run(['systemctl', 'is-active', 'qbittorrent'], capture_output=True, text=True)
                if result.stdout.strip() == "active":
                    return {"status": "online", "cpu": 5.8, "memory": 45.2}
            elif service_id == "syncthing":
                result = subprocess.run(['systemctl', 'is-active', 'syncthing'], capture_output=True, text=True)
                if result.stdout.strip() == "active":
                    return {"status": "online", "cpu": 4.1, "memory": 35.6}
        except:
            pass

        return {"status": "offline", "cpu": None, "memory": None}

if __name__ == '__main__':
    server_address = ('', 80)
    httpd = HTTPServer(server_address, DashboardAPI)
    print("Dashboard API running on port 80")
    httpd.serve_forever()
EOF

    # Criar serviço systemd
    cat > /etc/systemd/system/dashboard-api.service << EOF
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

# Limites de recursos
MemoryMax=100M
CPUQuota=30%

# Segurança
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/www/html /var/log
ProtectHome=true
RemoveIPC=true

[Install]
WantedBy=multi-user.target
EOF

    # Configurar permissões
    chown www-data:www-data /var/www/html/dashboard-api.py
    chmod +x /var/www/html/dashboard-api.py

    # Copiar dashboard HTML
    cp "$SCRIPT_DIR/dashboard.html" /var/www/html/ 2>/dev/null || {
        log_warning "dashboard.html não encontrado, usando versão padrão"
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
            <h1>BoxServer Dashboard</h1>
            <p>Monitoramento em tempo real</p>
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
    }

    chown www-data:www-data /var/www/html/dashboard.html

    # Parar serviços conflitantes na porta 80
    log_info "Parando serviços web conflitantes..."
    systemctl stop nginx apache2 lighttpd httpd 2>/dev/null || true
    systemctl disable nginx apache2 lighttpd httpd 2>/dev/null || true
    
    # Matar processos residuais na porta 80
    fuser -k 80/tcp 2>/dev/null || true
    pkill -f "nginx\|apache\|lighttpd\|httpd" 2>/dev/null || true
    
    # Aguardar liberação da porta
    sleep 2

    systemctl daemon-reload
    systemctl enable dashboard-api.service
    systemctl start dashboard-api.service

    DASHBOARD_INSTALLED=true
    save_config

    log_success "Dashboard Inteligente instalado"
}

install_wireguard() {
    log_step "Instalando WireGuard-UI"

    if [[ "$WIREGUARD_CONFIGURED" == "true" ]]; then
        log_info "WireGuard já configurado, pulando..."
        return 0
    fi

    # Instalar WireGuard (resolvconf pode não estar disponível em sistemas mais recentes)
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
        # Instalação manual do WireGuard-UI
        wget https://github.com/ngoduykhanh/wireguard-ui/releases/latest/download/wireguard-ui-linux-amd64.tar.gz
        tar -xvzf wireguard-ui-linux-amd64.tar.gz
        mv wireguard-ui /usr/local/bin/
        rm wireguard-ui-linux-amd64.tar.gz
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

    systemctl enable --now syncthing@"$(whoami)"

    SYNC_INSTALLED=true
    save_config

    log_success "Syncthing instalado"
}

configure_lighttpd_for_pihole() {
    log_step "Configurando lighttpd para Pi-hole na porta 8090"
    
    # Parar lighttpd para evitar conflitos
    systemctl stop lighttpd 2>/dev/null || true
    
    # Criar configuração limpa do lighttpd com porta alternativa
    cat > /etc/lighttpd/lighttpd.conf << 'EOF'
server.modules = (
    "mod_indexfile",
    "mod_access",
    "mod_alias",
    "mod_redirect",
    "mod_dirlisting",
    "mod_staticfile"
)

server.document-root        = "/var/www/html"
server.upload-dirs          = ( "/var/cache/lighttpd/uploads" )
server.errorlog             = "/var/log/lighttpd/error.log"
server.pid-file             = "/run/lighttpd.pid"
server.username             = "www-data"
server.groupname            = "www-data"
server.port                 = 8090

# features
server.feature-flags       += ("server.h2proto" => "enable")
server.feature-flags       += ("server.h2c"     => "enable")
server.feature-flags       += ("server.graceful-shutdown-timeout" => 5)

# strict parsing and normalization of URL for consistency and security
server.http-parseopts = (
  "header-strict"           => "enable",
  "host-strict"             => "enable", 
  "host-normalize"          => "enable",
  "url-normalize-unreserved"=> "enable",
  "url-normalize-required"  => "enable",
  "url-ctrls-reject"        => "enable",
  "url-path-2f-decode"      => "enable",
  "url-path-dotseg-remove"  => "enable"
)

index-file.names            = ( "index.php", "index.html" )
url.access-deny             = ( "~", ".inc" )
static-file.exclude-extensions = ( ".php", ".pl", ".fcgi" )

# IPv6 support
include_shell "/usr/share/lighttpd/use-ipv6.pl " + server.port

# MIME types
include_shell "/usr/share/lighttpd/create-mime.conf.pl"
include "/etc/lighttpd/conf-enabled/*.conf"

# Increase max request size for Pi-hole
server.max-request-size = 2048
EOF

    # Criar diretórios necessários
    mkdir -p /var/cache/lighttpd/uploads
    mkdir -p /var/log/lighttpd
    chown www-data:www-data /var/cache/lighttpd/uploads
    chown www-data:www-data /var/log/lighttpd
    
    # Testar configuração
    if lighttpd -tt -f /etc/lighttpd/lighttpd.conf; then
        systemctl enable lighttpd
        systemctl start lighttpd
        log_success "Lighttpd configurado e iniciado com sucesso na porta 8090"
    else
        log_error "Falha na configuração do lighttpd"
        return 1
    fi
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
        echo "8) 📋 Logs"
        echo "9) ℹ️  Sobre"
        echo "10) 🚪 Sair"
        echo ""

        read -p "Digite sua opção [1-10]: " choice

        case $choice in
            1) quick_install ;;
            2) custom_install ;;
            3) show_status ;;
            4) manage_services ;;
            5) backup_restore ;;
            6) show_settings ;;
            7) clean_installation ;;
            8) show_logs ;;
            9) show_about ;;
            10)
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
    echo "🚀 Instalação Rápida - BoxServer Essencial"
    echo ""
    echo "Serão instalados:"
    echo "✅ Otimizações do sistema"
    echo "✅ Dependências base"
    echo "✅ Firewall e segurança"
    echo "✅ Serviços DNS (Pi-hole)"
    echo "✅ Armazenamento (Samba + FileBrowser)"
    echo "✅ Dashboard Inteligente"
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

        log_success "Instalação rápida concluída!"
        echo ""
        echo "🎉 BoxServer instalado com sucesso!"
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

        # Mostrar status dos serviços
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
    echo "📊 Status do BoxServer"
    echo ""

    # Verificar sistema
    echo "🔧 Sistema:"
    echo "   CPU: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}')%"
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
        ["dashboard-api"]="Dashboard API"
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
        echo "6) 🔄 Atualizar sistema"
        echo "0) 🔙 Voltar"
        echo ""

        read -p "Selecione uma opção [0-6]: " choice

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
    purge_service "pi-hole"
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

show_about() {
    show_header
    cat << 'EOF'
🏗️  BoxServer Installer v3.0

Um instalador profissional para transformar qualquer dispositivo
em um servidor completo e otimizado.

🎯 Recursos:
• Instalação assistida com menu interativo
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
• Python API server
• HTML5/JavaScript frontend
• Network optimization
• Security hardening

© 2023 BoxServer Team
Licença: MIT
EOF

    read -p "Pressione Enter para continuar..."
}

# =============================================================================
# FUNÇÃO PRINCIPAL
# =============================================================================

main() {
    # Verificar se estamos rodando como root
    check_root

    # Inicializar ambiente
    initialize_environment

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
