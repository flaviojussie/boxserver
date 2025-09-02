#!/bin/bash

################################################################################
# Script de Instalação Automatizado - Boxserver MXQ-4k
# 
# DESCRIÇÃO:
#   Script completo para configuração automatizada de servidor doméstico
#   em dispositivos MXQ-4k com chip RK322x e memória NAND limitada.
#
# REQUISITOS DE HARDWARE:
#   - CPU: RK322X (ARM Cortex-A7)
#   - RAM: Mínimo 512MB (testado com 961MB)
#   - Storage: Mínimo 2GB NAND disponível
#   - Rede: Interface Ethernet ativa
#
# REQUISITOS DE SOFTWARE:
#   - Sistema: Debian/Ubuntu/Armbian
#   - Acesso: root/sudo
#   - Internet: Conexão ativa
#
# APLICATIVOS DISPONÍVEIS:
#   1. Pi-hole - Bloqueio de anúncios e DNS
#   2. Unbound - DNS recursivo local
#   3. WireGuard - Servidor VPN
#   4. Cockpit - Painel de administração web
#   5. FileBrowser - Gerenciamento de arquivos web
#   6. Netdata - Monitoramento em tempo real
#   7. Fail2Ban - Proteção contra ataques
#   8. UFW - Firewall simplificado
#   9. RNG-tools - Gerador de entropia
#   10. Rclone - Sincronização com nuvem
#   11. Rsync - Backup local
#   12. MiniDLNA - Servidor de mídia
#   13. Cloudflared - Tunnel Cloudflare
#
# USO:
#   sudo bash install-boxserver-mxq4k.sh
#
# AUTOR: Baseado na base de conhecimento Boxserver Arandutec
# DATA: $(date '+%d/%m/%Y')
# VERSÃO: 1.0
################################################################################

set -euo pipefail  # Modo rigoroso: sair em erro, variáveis não definidas, pipes

# Configurações globais
SCRIPT_NAME="install-boxserver-mxq4k"
LOG_FILE="/var/log/${SCRIPT_NAME}.log"
CONFIG_DIR="/etc/boxserver"
BACKUP_DIR="/var/backups/boxserver"
STATIC_IP_CONFIGURED="false"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variáveis de ambiente (podem ser pré-definidas)
NETWORK_INTERFACE="${NETWORK_INTERFACE:-}"
SERVER_IP="${SERVER_IP:-}"
VPN_NETWORK="${VPN_NETWORK:-10.200.200.0/24}"
VPN_PORT="${VPN_PORT:-51820}"
PIHOLE_PASSWORD="${PIHOLE_PASSWORD:-}"
FILEBROWSER_PORT="${FILEBROWSER_PORT:-8080}"
COCKPIT_PORT="${COCKPIT_PORT:-9090}"

# Modo de configuração (apenas interativo)
INTERACTIVE_MODE="true"

################################################################################
# FUNÇÕES AUXILIARES
################################################################################

# Função de logging
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "${YELLOW}$*${NC}"; }
log_error() { log "ERROR" "${RED}$*${NC}"; }
log_success() { log "SUCCESS" "${GREEN}$*${NC}"; }

# Função para exibir progresso
show_progress() {
    local current=$1
    local total=$2
    local message="$3"
    local percent=$((current * 100 / total))
    printf "\r${BLUE}[%3d%%]${NC} %s" "$percent" "$message"
    if [ "$current" -eq "$total" ]; then
        echo
    fi
}

# Função para solicitar confirmação do usuário
confirm_action() {
    local message="$1"
    local default="${2:-n}"
    
    if [ "$INTERACTIVE_MODE" != "true" ]; then
        return 0  # Modo não-interativo, prosseguir automaticamente
    fi
    
    echo -e "\n${YELLOW}$message${NC}"
    if [ "$default" = "y" ]; then
        echo -e "${BLUE}Pressione Enter para confirmar ou 'n' para pular: ${NC}"
    else
        echo -e "${BLUE}Digite 'y' para confirmar ou pressione Enter para pular: ${NC}"
    fi
    
    read -r response
    
    if [ "$default" = "y" ]; then
        [[ "$response" != "n" && "$response" != "N" ]]
    else
        [[ "$response" = "y" || "$response" = "Y" ]]
    fi
}

# Função para coletar configurações do usuário
collect_user_input() {
    local prompt="$1"
    local default="$2"
    local variable_name="$3"
    
    if [ "$INTERACTIVE_MODE" != "true" ]; then
        return 0  # Modo não-interativo, usar valores padrão
    fi
    
    echo -e "\n${YELLOW}$prompt${NC}"
    if [ -n "$default" ]; then
        echo -e "${BLUE}Valor padrão: $default${NC}"
        echo -e "${BLUE}Pressione Enter para usar o padrão ou digite um novo valor: ${NC}"
    else
        echo -e "${BLUE}Digite o valor: ${NC}"
    fi
    
    read -r user_input
    
    if [ -n "$user_input" ]; then
        eval "$variable_name='$user_input'"
    elif [ -n "$default" ]; then
        eval "$variable_name='$default'"
    fi
}

# Verificar distribuição Linux compatível
check_linux_distribution() {
    log_info "Verificando distribuição Linux..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|armbian|raspbian)
                log_success "Distribuição compatível: $NAME ✓"
                ;;
            *)
                log_error "Distribuição não suportada: $NAME"
                log_error "Este script requer Ubuntu, Debian, Armbian ou Raspbian"
                exit 1
                ;;
        esac
    else
        log_error "Não foi possível detectar a distribuição Linux"
        exit 1
    fi
}

# Verificar se é root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Este script deve ser executado como root (sudo)"
        exit 1
    fi
}

# Verificar dependências do sistema
check_dependencies() {
    local deps=("curl" "wget" "tar" "gzip" "openssl" "iproute2" "procps" "net-tools")
    local missing_deps=()
    
    log_info "Verificando dependências do sistema..."
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_warn "Dependências ausentes: ${missing_deps[*]}"
        log_info "Instalando dependências..."
        apt-get update -qq
        apt-get install -y -qq "${missing_deps[@]}"
    fi
    
    log_success "Todas as dependências instaladas ✓"
}

# Validar formato de IP/CIDR
validate_cidr() {
    local cidr="$1"
    if [[ ! "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        return 1
    fi
    
    local ip="${cidr%/*}"
    local prefix="${cidr#*/}"
    
    # Validar IP
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    # Validar prefixo
    if [ "$prefix" -lt 0 ] || [ "$prefix" -gt 32 ]; then
        return 1
    fi
    
    return 0
}

# Validar formato de IP
validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    # Verificar se cada octeto está entre 0-255
    IFS='.' read -ra OCTETS <<< "$ip"
    for octet in "${OCTETS[@]}"; do
        if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
            return 1
        fi
    done
    
    return 0
}

# Verificar disponibilidade de porta
check_port_availability() {
    local port="$1"
    local service="${2:-}"
    
    if ss -tuln | grep -q ":$port "; then
        local process=$(ss -tulnp | grep ":$port " | awk '{print $7}' | cut -d',' -f1 | cut -d'"' -f2)
        log_warn "Porta $port já está em uso por: $process"
        
        if [ "$INTERACTIVE_MODE" = "true" ]; then
            read -p "Deseja usar esta porta mesmo assim? (s/N): " use_anyway
            use_anyway=${use_anyway:-n}
            if [[ ! "$use_anyway" =~ ^[Ss]$ ]]; then
                return 1
            fi
        else
            return 1
        fi
    fi
    
    return 0
}

# Gerar senha segura
generate_secure_password() {
    openssl rand -base64 32 | tr -d /=+ | cut -c -16
}

# Verificar requisitos do sistema
check_system_requirements() {
    log_info "Verificando requisitos do sistema..."
    
    # Verificar RAM
    local ram_mb=$(free -m | awk 'NR==2{print $2}')
    if [ "$ram_mb" -lt 512 ]; then
        log_error "RAM insuficiente: ${ram_mb}MB (mínimo: 512MB)"
        exit 1
    fi
    log_success "RAM: ${ram_mb}MB ✓"
    
    # Verificar espaço em disco
    local disk_gb=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    if [ "$disk_gb" -lt 2 ]; then
        log_error "Espaço em disco insuficiente: ${disk_gb}GB (mínimo: 2GB)"
        exit 1
    fi
    log_success "Espaço em disco: ${disk_gb}GB disponível ✓"
    
    # Verificar arquitetura
    local arch=$(uname -m)
    if [[ ! "$arch" =~ ^(arm|aarch64)$ ]]; then
        log_warn "Arquitetura não testada: $arch (esperado: arm/aarch64)"
    fi
    log_success "Arquitetura: $arch ✓"
    
    # Verificar conectividade
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_error "Sem conectividade com a internet"
        exit 1
    fi
    log_success "Conectividade com internet ✓"
}

# Detectar interface de rede principal
detect_network_interface() {
    if [ -z "$NETWORK_INTERFACE" ]; then
        NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
        if [ -z "$NETWORK_INTERFACE" ]; then
            log_error "Não foi possível detectar interface de rede principal"
            echo "Interfaces disponíveis:"
            ip link show | grep '^[0-9]' | awk '{print $2}' | sed 's/:$//'
            exit 1
        fi
    fi
    
    # Verificar se interface existe e está ativa
    if ! ip link show "$NETWORK_INTERFACE" >/dev/null 2>&1; then
        log_error "Interface $NETWORK_INTERFACE não encontrada"
        exit 1
    fi
    
    # Obter IP da interface
    SERVER_IP=$(ip addr show "$NETWORK_INTERFACE" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1)
    if [ -z "$SERVER_IP" ]; then
        log_error "Não foi possível obter IP da interface $NETWORK_INTERFACE"
        exit 1
    fi
    
    log_success "Interface de rede: $NETWORK_INTERFACE ($SERVER_IP) ✓"
}

# Configurar IP fixo/estático
configure_static_ip() {
    log_info "=== CONFIGURAÇÃO DE IP FIXO ==="
    
    echo -e "${YELLOW}IMPORTANTE: Para um servidor doméstico, é recomendado configurar um IP fixo.${NC}"
    echo -e "${YELLOW}Isso garante que os serviços (Pi-hole, VPN, etc.) funcionem corretamente.${NC}"
    echo ""
    echo -e "Configuração atual:"
    echo -e "  Interface: ${GREEN}$NETWORK_INTERFACE${NC}"
    echo -e "  IP atual:  ${GREEN}$SERVER_IP${NC}"
    echo -e "  Gateway:   ${GREEN}$(ip route | grep default | awk '{print $3}' | head -1)${NC}"
    echo ""
    
    read -p "Deseja configurar um IP fixo? (s/N): " configure_static
    configure_static=${configure_static:-n}
    
    if [[ "$configure_static" =~ ^[Ss]$ ]]; then
        # Detectar método de configuração de rede
        local config_method=""
        
        if [ -d "/etc/netplan" ] && ls /etc/netplan/*.yaml >/dev/null 2>&1; then
            config_method="netplan"
        elif [ -f "/etc/network/interfaces" ] && grep -q "iface" /etc/network/interfaces; then
            config_method="interfaces"
        elif systemctl is-enabled systemd-networkd >/dev/null 2>&1; then
            config_method="systemd-networkd"
        else
            config_method="netplan"  # Padrão para Ubuntu moderno
        fi
        
        log_info "Método detectado: $config_method"
        
        # Coletar informações de rede
        local current_gateway=$(ip route | grep default | awk '{print $3}' | head -1)
        local current_dns=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | head -1)
        
        echo ""
        echo -e "${CYAN}=== CONFIGURAÇÃO DE REDE ESTÁTICA ===${NC}"
        
        read -p "IP fixo desejado [$SERVER_IP]: " static_ip
        static_ip=${static_ip:-$SERVER_IP}
        
        read -p "Máscara de rede [24]: " netmask
        netmask=${netmask:-24}
        
        read -p "Gateway [$current_gateway]: " gateway
        gateway=${gateway:-$current_gateway}
        
        read -p "DNS primário [$current_dns]: " dns1
        dns1=${dns1:-$current_dns}
        
        read -p "DNS secundário [8.8.8.8]: " dns2
        dns2=${dns2:-8.8.8.8}
        
        # Fazer backup da configuração atual
        local backup_dir="/etc/boxserver/network-backup-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$backup_dir"
        
        case "$config_method" in
            "netplan")
                configure_netplan_static "$static_ip" "$netmask" "$gateway" "$dns1" "$dns2" "$backup_dir"
                ;;
            "interfaces")
                configure_interfaces_static "$static_ip" "$netmask" "$gateway" "$dns1" "$dns2" "$backup_dir"
                ;;
            "systemd-networkd")
                configure_systemd_networkd_static "$static_ip" "$netmask" "$gateway" "$dns1" "$dns2" "$backup_dir"
                ;;
        esac
        
        # Atualizar variáveis
         SERVER_IP="$static_ip"
         STATIC_IP_CONFIGURED="true"
         
         echo ""
         log_success "Configuração de IP fixo aplicada!"
         log_warn "IMPORTANTE: O sistema será reiniciado ao final da instalação para aplicar as mudanças de rede."
         echo ""
    else
        log_info "Mantendo configuração DHCP atual"
    fi
}

# Configurar IP estático via Netplan
configure_netplan_static() {
    local static_ip="$1"
    local netmask="$2"
    local gateway="$3"
    local dns1="$4"
    local dns2="$5"
    local backup_dir="$6"
    
    log_info "Configurando IP estático via Netplan..."
    
    # Backup dos arquivos existentes
    cp -r /etc/netplan/* "$backup_dir/" 2>/dev/null || true
    
    # Criar configuração Netplan
    cat > "/etc/netplan/01-boxserver-static.yaml" << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $NETWORK_INTERFACE:
      dhcp4: false
      addresses:
        - $static_ip/$netmask
      gateway4: $gateway
      nameservers:
        addresses:
          - $dns1
          - $dns2
EOF
    
    # Remover configurações DHCP conflitantes
    find /etc/netplan -name "*.yaml" -not -name "01-boxserver-static.yaml" -exec rm -f {} \;
    
    # Testar configuração
    if netplan try --timeout=10 2>/dev/null; then
        log_success "Configuração Netplan aplicada com sucesso"
    else
        log_error "Erro na configuração Netplan. Restaurando backup..."
        rm -f /etc/netplan/01-boxserver-static.yaml
        cp "$backup_dir"/* /etc/netplan/ 2>/dev/null || true
        netplan apply
        return 1
    fi
}

# Configurar IP estático via /etc/network/interfaces
configure_interfaces_static() {
    local static_ip="$1"
    local netmask="$2"
    local gateway="$3"
    local dns1="$4"
    local dns2="$5"
    local backup_dir="$6"
    
    log_info "Configurando IP estático via /etc/network/interfaces..."
    
    # Backup
    cp /etc/network/interfaces "$backup_dir/interfaces.backup"
    
    # Criar nova configuração
    cat > "/etc/network/interfaces" << EOF
# Configuração gerada pelo Boxserver
auto lo
iface lo inet loopback

auto $NETWORK_INTERFACE
iface $NETWORK_INTERFACE inet static
    address $static_ip
    netmask $(cidr_to_netmask $netmask)
    gateway $gateway
    dns-nameservers $dns1 $dns2
EOF
    
    # Configurar DNS
    echo "nameserver $dns1" > /etc/resolv.conf
    echo "nameserver $dns2" >> /etc/resolv.conf
    
    log_success "Configuração interfaces aplicada"
}

# Configurar IP estático via systemd-networkd
configure_systemd_networkd_static() {
    local static_ip="$1"
    local netmask="$2"
    local gateway="$3"
    local dns1="$4"
    local dns2="$5"
    local backup_dir="$6"
    
    log_info "Configurando IP estático via systemd-networkd..."
    
    # Backup
    cp -r /etc/systemd/network/* "$backup_dir/" 2>/dev/null || true
    
    # Criar configuração de rede
    cat > "/etc/systemd/network/10-$NETWORK_INTERFACE.network" << EOF
[Match]
Name=$NETWORK_INTERFACE

[Network]
DHCP=no
Address=$static_ip/$netmask
Gateway=$gateway
DNS=$dns1
DNS=$dns2
EOF
    
    # Habilitar e reiniciar systemd-networkd
    systemctl enable systemd-networkd
    systemctl restart systemd-networkd
    
    log_success "Configuração systemd-networkd aplicada"
}

# Converter CIDR para máscara de rede
cidr_to_netmask() {
    local cidr=$1
    local mask=""
    local full_octets=$((cidr / 8))
    local partial_octet=$((cidr % 8))
    
    for ((i=0; i<4; i++)); do
        if [ $i -lt $full_octets ]; then
            mask="${mask}255"
        elif [ $i -eq $full_octets ]; then
            mask="${mask}$((256 - 2**(8-partial_octet)))"
        else
            mask="${mask}0"
        fi
        [ $i -lt 3 ] && mask="${mask}."
    done
    
    echo "$mask"
}

# Registrar serviço instalado
register_installation() {
    local service_name="$1"
    echo "$service_name" >> "$CONFIG_DIR/installed_services"
    log_info "Serviço $service_name registrado para possível rollback"
}

# Sistema de rollback
rollback_installation() {
    log_warn "Iniciando rollback devido a erro na instalação..."
    
    if [ -f "$CONFIG_DIR/installed_services" ]; then
        while IFS= read -r service; do
            case "$service" in
                pihole)
                    log_info "Removendo Pi-hole..."
                    pihole uninstall --yes || true
                    ;;
                unbound)
                    log_info "Removendo Unbound..."
                    apt-get remove -y unbound unbound-anchor || true
                    apt-get autoremove -y || true
                    ;;
                wireguard)
                    log_info "Removendo WireGuard..."
                    apt-get remove -y wireguard wireguard-tools || true
                    apt-get autoremove -y || true
                    ;;
                cockpit)
                    log_info "Removendo Cockpit..."
                    apt-get remove -y cockpit cockpit-bridge cockpit-ws || true
                    apt-get autoremove -y || true
                    ;;
                filebrowser)
                    log_info "Removendo FileBrowser..."
                    systemctl stop filebrowser || true
                    systemctl disable filebrowser || true
                    rm -f /usr/local/bin/filebrowser
                    rm -f /etc/systemd/system/filebrowser.service
                    userdel -r filebrowser || true
                    ;;
                netdata)
                    log_info "Removendo Netdata..."
                    bash <(curl -Ss https://my-netdata.io/kickstart.sh) --uninstall --non-interactive || true
                    ;;
                fail2ban)
                    log_info "Removendo Fail2Ban..."
                    apt-get remove -y fail2ban || true
                    apt-get autoremove -y || true
                    ;;
                ufw)
                    log_info "Removendo UFW..."
                    apt-get remove -y ufw || true
                    ;;
                cloudflared)
                    log_info "Removendo Cloudflared..."
                    systemctl stop cloudflared || true
                    systemctl disable cloudflared || true
                    rm -f /usr/local/bin/cloudflared
                    rm -f /etc/systemd/system/cloudflared.service
                    ;;
            esac
        done < "$CONFIG_DIR/installed_services"
        
        # Restaurar backups de rede se necessário
        if [ "$STATIC_IP_CONFIGURED" = "true" ]; then
            log_info "Verificando backups de configuração de rede..."
            local backup_dirs=$(find /etc/boxserver -name "network-backup-*" -type d | sort -r | head -1)
            if [ -n "$backup_dirs" ]; then
                log_warn "Configurações de rede foram modificadas. Verifique manualmente se necessário."
            fi
        fi
        
        rm -f "$CONFIG_DIR/installed_services"
    fi
    
    log_success "Rollback concluído"
}

# Criar diretórios necessários
setup_directories() {
    log_info "Criando estrutura de diretórios..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "/var/log/boxserver"
    
    # Inicializar arquivo de serviços instalados
    > "$CONFIG_DIR/installed_services"
    
    # Salvar configurações detectadas
    cat > "$CONFIG_DIR/system.conf" << EOF
# Configurações do sistema detectadas automaticamente
NETWORK_INTERFACE="$NETWORK_INTERFACE"
SERVER_IP="$SERVER_IP"
VPN_NETWORK="$VPN_NETWORK"
VPN_PORT="$VPN_PORT"
FILEBROWSER_PORT="$FILEBROWSER_PORT"
COCKPIT_PORT="$COCKPIT_PORT"
INSTALL_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
STATIC_IP_CONFIGURED="$STATIC_IP_CONFIGURED"
EOF
    
    log_success "Diretórios criados ✓"
}

# Atualizar sistema
update_system() {
    log_info "Atualizando sistema..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq
    apt-get install -y -qq curl wget gnupg2 software-properties-common apt-transport-https
    
    log_success "Sistema atualizado ✓"
}

################################################################################
# FUNÇÕES DE INSTALAÇÃO DOS APLICATIVOS
################################################################################

# Instalar Pi-hole
install_pihole() {
    log_info "Instalando Pi-hole..."
    
    # Configurações interativas
    local pihole_interface="$NETWORK_INTERFACE"
    local pihole_ip="$SERVER_IP"
    local pihole_dns="127.0.0.1#5335"
    local pihole_password="$PIHOLE_PASSWORD"
    local enable_dnssec="true"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                    ${GREEN}CONFIGURAÇÃO DO PI-HOLE${NC}                     ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        collect_user_input "Interface de rede para o Pi-hole:" "$pihole_interface" "pihole_interface"
        collect_user_input "Endereço IP do servidor:" "$pihole_ip" "pihole_ip"
        collect_user_input "Servidor DNS upstream (recomendado: 127.0.0.1#5335 para Unbound):" "$pihole_dns" "pihole_dns"
        collect_user_input "Senha para interface web (deixe vazio para gerar automaticamente):" "" "pihole_password"
        
        echo -e "\n${YELLOW}Configurações do Pi-hole:${NC}"
        echo -e "${BLUE}Interface: $pihole_interface${NC}"
        echo -e "${BLUE}IP: $pihole_ip${NC}"
        echo -e "${BLUE}DNS Upstream: $pihole_dns${NC}"
        echo -e "${BLUE}DNSSEC: Habilitado${NC}"
        
        if ! confirm_action "Confirma a instalação do Pi-hole com essas configurações?" "y"; then
            log_warn "Instalação do Pi-hole cancelada pelo usuário"
            return 1
        fi
    fi
    
    # Configuração baseada nas entradas do usuário
    mkdir -p /etc/pihole
    cat > /etc/pihole/setupVars.conf << EOF
PIHOLE_INTERFACE=$pihole_interface
IPV4_ADDRESS=$pihole_ip/24
IPV6_ADDRESS=
PIHOLE_DNS_1=$pihole_dns
PIHOLE_DNS_2=
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSSEC=$enable_dnssec
TEMPERATURE_UNIT=C
WEBUI_BOXED_LAYOUT=boxed
WEBPASSWORD=
EOF
    
    # Instalação silenciosa
    curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
    
    # Configurar senha se fornecida
    if [ -n "$pihole_password" ]; then
        echo "$pihole_password" | pihole -a -p
        log_info "Senha da interface web configurada"
    else
        log_info "Senha da interface web gerada automaticamente. Use 'pihole -a -p' para definir uma senha personalizada."
    fi
    
    systemctl enable pihole-FTL
    
    log_success "Pi-hole instalado ✓"
}

# Instalar Unbound
install_unbound() {
    log_info "Instalando Unbound..."
    
    # Configurações interativas
    local unbound_port="5335"
    local cache_size="50m"
    local rrset_cache="100m"
    local num_threads="1"
    local enable_ipv6="no"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                    ${GREEN}CONFIGURAÇÃO DO UNBOUND${NC}                     ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        collect_user_input "Porta do Unbound (padrão: 5335):" "$unbound_port" "unbound_port"
        collect_user_input "Tamanho do cache de mensagens (padrão: 50m):" "$cache_size" "cache_size"
        collect_user_input "Tamanho do cache RRset (padrão: 100m):" "$rrset_cache" "rrset_cache"
        collect_user_input "Número de threads (padrão: 1 para ARM):" "$num_threads" "num_threads"
        
        echo -e "\n${YELLOW}Configurações do Unbound:${NC}"
        echo -e "${BLUE}Porta: $unbound_port${NC}"
        echo -e "${BLUE}Cache de mensagens: $cache_size${NC}"
        echo -e "${BLUE}Cache RRset: $rrset_cache${NC}"
        echo -e "${BLUE}Threads: $num_threads${NC}"
        echo -e "${BLUE}IPv6: Desabilitado (otimização ARM)${NC}"
        
        if ! confirm_action "Confirma a instalação do Unbound com essas configurações?" "y"; then
            log_warn "Instalação do Unbound cancelada pelo usuário"
            return 1
        fi
    fi
    
    # Validar porta
    if [ "$unbound_port" -lt 1 ] || [ "$unbound_port" -gt 65535 ]; then
        log_error "Porta inválida: $unbound_port (deve estar entre 1-65535)"
        return 1
    fi
    
    # Verificar disponibilidade da porta
    if ! check_port_availability "$unbound_port" "Unbound"; then
        return 1
    fi
    
    if ! apt-get install -y unbound; then
        log_error "Falha na instalação do Unbound"
        return 1
    fi
    
    # Configuração otimizada para ARM baseada nas entradas do usuário
    cat > /etc/unbound/unbound.conf.d/pi-hole.conf << EOF
server:
    verbosity: 1
    interface: 127.0.0.1
    port: $unbound_port
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: $enable_ipv6
    prefer-ip6: no
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    edns-buffer-size: 1232
    prefetch: yes
    # Otimizado para ARM/baixa RAM
    num-threads: $num_threads
    msg-cache-slabs: 1
    rrset-cache-slabs: 1
    infra-cache-slabs: 1
    key-cache-slabs: 1
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
    # Trust anchor automático
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    root-hints: "/var/lib/unbound/root.hints"
EOF
    
    # Configurar trust anchor e root hints
    wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
    unbound-anchor -a /var/lib/unbound/root.key || {
        wget -O /var/lib/unbound/root.key https://data.iana.org/root-anchors/icannbundle.pem
    }
    
    chown unbound:unbound /var/lib/unbound/root.key /var/lib/unbound/root.hints
    chmod 644 /var/lib/unbound/root.key /var/lib/unbound/root.hints
    
    systemctl enable unbound
    systemctl restart unbound
    register_installation "unbound"
    
    log_success "Unbound instalado com sucesso ✓"
    log_info "Porta: $unbound_port (localhost)"
    log_info "Verificação: dig @127.0.0.1 -p $unbound_port google.com"
}

# Instalar WireGuard
install_wireguard() {
    log_info "Instalando WireGuard..."
    
    # Configurações interativas
    local vpn_network="$VPN_NETWORK"
    local vpn_port="$VPN_PORT"
    local vpn_interface="$NETWORK_INTERFACE"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                   ${GREEN}CONFIGURAÇÃO DO WIREGUARD${NC}                   ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        collect_user_input "Rede VPN (formato CIDR):" "$vpn_network" "vpn_network"
        collect_user_input "Porta do servidor VPN:" "$vpn_port" "vpn_port"
        collect_user_input "Interface de rede para NAT:" "$vpn_interface" "vpn_interface"
        
        echo -e "\n${YELLOW}Configurações do WireGuard:${NC}"
        echo -e "${BLUE}Rede VPN: $vpn_network${NC}"
        echo -e "${BLUE}Porta: $vpn_port${NC}"
        echo -e "${BLUE}Interface NAT: $vpn_interface${NC}"
        echo -e "${BLUE}IP do Servidor: $(echo $vpn_network | sed 's|0/24|1|')${NC}"
        
        if ! confirm_action "Confirma a instalação do WireGuard com essas configurações?" "y"; then
            log_warn "Instalação do WireGuard cancelada pelo usuário"
            return 1
        fi
    fi
    
    apt-get install -y wireguard wireguard-tools
    
    # Criar diretórios
    mkdir -p /etc/wireguard/keys
    mkdir -p /etc/wireguard/clients
    
    # Gerar chaves do servidor
    cd /etc/wireguard/keys
    umask 077
    wg genkey | tee privatekey | wg pubkey | tee publickey
    chmod 600 privatekey
    chmod 644 publickey
    
    local server_private_key=$(cat privatekey)
    local server_ip=$(echo $vpn_network | sed 's|0/24|1|')
    
    # Configurar IP forwarding permanente
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.ip_forward=1
    
    # Criar configuração do servidor
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $server_private_key
Address = $server_ip/24
ListenPort = $vpn_port

# Regras de NAT e forwarding
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $vpn_interface -j MASQUERADE; iptables -A INPUT -i %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $vpn_interface -j MASQUERADE; iptables -D INPUT -i %i -j ACCEPT

# Adicione peers aqui conforme necessário
EOF
    
    systemctl enable wg-quick@wg0
    
    log_success "WireGuard instalado ✓"
}

# Instalar Cockpit
install_cockpit() {
    log_info "Instalando Cockpit..."
    
    # Configurações interativas
    local cockpit_port="$COCKPIT_PORT"
    local install_machines="yes"
    local install_podman="yes"
    local install_networkmanager="yes"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                    ${GREEN}CONFIGURAÇÃO DO COCKPIT${NC}                     ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        collect_user_input "Porta do Cockpit (padrão: 9090):" "$cockpit_port" "cockpit_port"
        
        echo -e "\n${YELLOW}Módulos adicionais disponíveis:${NC}"
        if confirm_action "Instalar cockpit-machines (gerenciamento de VMs)?" "y"; then
            install_machines="yes"
        else
            install_machines="no"
        fi
        
        if confirm_action "Instalar cockpit-podman (gerenciamento de containers)?" "y"; then
            install_podman="yes"
        else
            install_podman="no"
        fi
        
        if confirm_action "Instalar cockpit-networkmanager (gerenciamento de rede)?" "y"; then
            install_networkmanager="yes"
        else
            install_networkmanager="no"
        fi
        
        echo -e "\n${YELLOW}Configurações do Cockpit:${NC}"
        echo -e "${BLUE}Porta: $cockpit_port${NC}"
        echo -e "${BLUE}Módulo Machines: $install_machines${NC}"
        echo -e "${BLUE}Módulo Podman: $install_podman${NC}"
        echo -e "${BLUE}Módulo NetworkManager: $install_networkmanager${NC}"
        echo -e "${BLUE}Acesso: https://$SERVER_IP:$cockpit_port${NC}"
        
        if ! confirm_action "Confirma a instalação do Cockpit com essas configurações?" "y"; then
            log_warn "Instalação do Cockpit cancelada pelo usuário"
            return 1
        fi
    fi
    
    # Instalação base
    local packages="cockpit cockpit-system"
    
    # Adicionar módulos conforme seleção do usuário
    [ "$install_machines" = "yes" ] && packages="$packages cockpit-machines"
    [ "$install_podman" = "yes" ] && packages="$packages cockpit-podman"
    [ "$install_networkmanager" = "yes" ] && packages="$packages cockpit-networkmanager"
    
    apt-get install -y $packages
    
    # Configuração da porta se diferente do padrão
    if [ "$cockpit_port" != "9090" ]; then
        mkdir -p /etc/systemd/system/cockpit.socket.d
        cat > /etc/systemd/system/cockpit.socket.d/listen.conf << EOF
[Socket]
ListenStream=
ListenStream=$cockpit_port
EOF
    fi
    
    systemctl enable cockpit.socket
    systemctl start cockpit.socket
    
    log_success "Cockpit instalado ✓ (Acesso: https://$SERVER_IP:$cockpit_port)"
}

# Instalar FileBrowser
install_filebrowser() {
    log_info "Instalando FileBrowser..."
    
    # Configurações interativas
    local fb_port="$FILEBROWSER_PORT"
    local fb_username="admin"
    local fb_password="admin"
    local fb_root_dir="/"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                  ${GREEN}CONFIGURAÇÃO DO FILEBROWSER${NC}                 ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        collect_user_input "Porta do FileBrowser:" "$fb_port" "fb_port"
        collect_user_input "Nome de usuário admin:" "$fb_username" "fb_username"
        collect_user_input "Senha do admin:" "$fb_password" "fb_password"
        collect_user_input "Diretório raiz para navegação:" "$fb_root_dir" "fb_root_dir"
        
        echo -e "\n${YELLOW}Configurações do FileBrowser:${NC}"
        echo -e "${BLUE}Porta: $fb_port${NC}"
        echo -e "${BLUE}Usuário: $fb_username${NC}"
        echo -e "${BLUE}Diretório raiz: $fb_root_dir${NC}"
        echo -e "${BLUE}Acesso: http://$SERVER_IP:$fb_port${NC}"
        
        if ! confirm_action "Confirma a instalação do FileBrowser com essas configurações?" "y"; then
            log_warn "Instalação do FileBrowser cancelada pelo usuário"
            return 1
        fi
    fi
    
    # Download da versão mais recente
    local fb_version=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    wget -O /usr/local/bin/filebrowser "https://github.com/filebrowser/filebrowser/releases/download/${fb_version}/linux-arm-filebrowser.tar.gz"
    tar -xzf /usr/local/bin/filebrowser -C /usr/local/bin/
    chmod +x /usr/local/bin/filebrowser
    
    # Configuração baseada nas entradas do usuário
    mkdir -p /etc/filebrowser
    filebrowser config init --database /etc/filebrowser/filebrowser.db
    filebrowser config set --port $fb_port --database /etc/filebrowser/filebrowser.db --root "$fb_root_dir"
    filebrowser users add "$fb_username" "$fb_password" --perm.admin --database /etc/filebrowser/filebrowser.db
    
    # Criar serviço systemd
    cat > /etc/systemd/system/filebrowser.service << EOF
[Unit]
Description=File Browser
After=network.target

[Service]
ExecStart=/usr/local/bin/filebrowser --database /etc/filebrowser/filebrowser.db
User=root
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable filebrowser
    systemctl start filebrowser
    
    log_success "FileBrowser instalado ✓ (Acesso: http://$SERVER_IP:$fb_port)"
}

# Instalar Netdata
install_netdata() {
    log_info "Instalando Netdata..."
    
    # Configurações interativas
    local netdata_port="19999"
    local allowed_networks="localhost 10.* 192.168.* 172.16.* 172.17.* 172.18.* 172.19.* 172.20.* 172.21.* 172.22.* 172.23.* 172.24.* 172.25.* 172.26.* 172.27.* 172.28.* 172.29.* 172.30.* 172.31.*"
    local disable_telemetry="yes"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                    ${GREEN}CONFIGURAÇÃO DO NETDATA${NC}                     ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        collect_user_input "Porta do Netdata:" "$netdata_port" "netdata_port"
        collect_user_input "Redes permitidas (separadas por espaço):" "$allowed_networks" "allowed_networks"
        
        echo -e "\n${YELLOW}Configurações do Netdata:${NC}"
        echo -e "${BLUE}Porta: $netdata_port${NC}"
        echo -e "${BLUE}Redes permitidas: $allowed_networks${NC}"
        echo -e "${BLUE}Telemetria: Desabilitada${NC}"
        echo -e "${BLUE}Acesso: http://$SERVER_IP:$netdata_port${NC}"
        
        if ! confirm_action "Confirma a instalação do Netdata com essas configurações?" "y"; then
            log_warn "Instalação do Netdata cancelada pelo usuário"
            return 1
        fi
    fi
    
    # Download e instalação
    local install_options="--dont-wait"
    [ "$disable_telemetry" = "yes" ] && install_options="$install_options --disable-telemetry"
    
    bash <(curl -Ss https://my-netdata.io/kickstart.sh) $install_options
    
    # Configuração baseada nas entradas do usuário
    cat > /etc/netdata/netdata.conf << EOF
[global]
    run as user = netdata
    web files owner = root
    web files group = netdata
    bind socket to IP = 0.0.0.0
    default port = $netdata_port
    
[web]
    web files owner = root
    web files group = netdata
    allow connections from = $allowed_networks
EOF
    
    systemctl restart netdata
    
    log_success "Netdata instalado ✓ (Acesso: http://$SERVER_IP:$netdata_port)"
}

# Instalar Fail2Ban
install_fail2ban() {
    log_info "Instalando Fail2Ban..."
    
    # Configurações interativas
    local ban_time="3600"
    local find_time="600"
    local max_retry="3"
    local ssh_enabled="true"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                   ${GREEN}CONFIGURAÇÃO DO FAIL2BAN${NC}                    ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        collect_user_input "Tempo de banimento em segundos (padrão: 3600 = 1 hora):" "$ban_time" "ban_time"
        collect_user_input "Janela de tempo para detecção em segundos (padrão: 600 = 10 min):" "$find_time" "find_time"
        collect_user_input "Máximo de tentativas antes do banimento:" "$max_retry" "max_retry"
        
        echo -e "\n${YELLOW}Configurações do Fail2Ban:${NC}"
        echo -e "${BLUE}Tempo de banimento: $ban_time segundos${NC}"
        echo -e "${BLUE}Janela de detecção: $find_time segundos${NC}"
        echo -e "${BLUE}Máximo de tentativas: $max_retry${NC}"
        echo -e "${BLUE}Proteção SSH: Habilitada${NC}"
        
        if ! confirm_action "Confirma a instalação do Fail2Ban com essas configurações?" "y"; then
            log_warn "Instalação do Fail2Ban cancelada pelo usuário"
            return 1
        fi
    fi
    
    apt-get install -y fail2ban
    
    # Configuração baseada nas entradas do usuário
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = $ban_time
findtime = $find_time
maxretry = $max_retry

[sshd]
enabled = $ssh_enabled
port = ssh
logpath = /var/log/auth.log
maxretry = $max_retry
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_success "Fail2Ban instalado ✓"
}

# Instalar UFW
install_ufw() {
    log_info "Instalando UFW..."
    
    # Configurações interativas
    local allow_ssh="yes"
    local ssh_port="22"
    local custom_ports=""
    local default_policy_in="deny"
    local default_policy_out="allow"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                     ${GREEN}CONFIGURAÇÃO DO UFW${NC}                        ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        if confirm_action "Permitir acesso SSH (recomendado)?" "y"; then
            allow_ssh="yes"
            collect_user_input "Porta SSH (padrão: 22):" "$ssh_port" "ssh_port"
        else
            allow_ssh="no"
        fi
        
        collect_user_input "Portas adicionais para permitir (formato: porta/protocolo, separadas por espaço):" "$custom_ports" "custom_ports"
        
        echo -e "\n${YELLOW}Configurações do UFW:${NC}"
        echo -e "${BLUE}Política padrão entrada: $default_policy_in${NC}"
        echo -e "${BLUE}Política padrão saída: $default_policy_out${NC}"
        echo -e "${BLUE}SSH permitido: $allow_ssh${NC}"
        [ "$allow_ssh" = "yes" ] && echo -e "${BLUE}Porta SSH: $ssh_port${NC}"
        echo -e "${BLUE}Portas dos serviços: Serão permitidas automaticamente${NC}"
        [ -n "$custom_ports" ] && echo -e "${BLUE}Portas adicionais: $custom_ports${NC}"
        
        if ! confirm_action "Confirma a instalação do UFW com essas configurações?" "y"; then
            log_warn "Instalação do UFW cancelada pelo usuário"
            return 1
        fi
    fi
    
    apt-get install -y ufw
    
    # Configuração baseada nas entradas do usuário
    ufw --force reset
    ufw default $default_policy_in incoming
    ufw default $default_policy_out outgoing
    
    # Permitir SSH se solicitado
    if [ "$allow_ssh" = "yes" ]; then
        if [ "$ssh_port" = "22" ]; then
            ufw allow ssh
        else
            ufw allow $ssh_port/tcp
        fi
    fi
    
    # Permitir serviços essenciais
    ufw allow 53  # DNS
    ufw allow $VPN_PORT/udp  # WireGuard
    ufw allow $COCKPIT_PORT  # Cockpit
    ufw allow $FILEBROWSER_PORT  # FileBrowser
    ufw allow 19999  # Netdata
    
    # Permitir portas adicionais
    if [ -n "$custom_ports" ]; then
        for port in $custom_ports; do
            ufw allow $port
        done
    fi
    
    ufw --force enable
    
    log_success "UFW instalado ✓"
}

# Instalar RNG-tools
install_rng_tools() {
    log_info "Instalando RNG-tools..."
    
    # Configurações interativas
    local rng_device="auto"
    local enable_service="yes"
    local watermark="2048"
    local feed_interval="60"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                   ${GREEN}CONFIGURAÇÃO DO RNG-TOOLS${NC}                   ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        echo -e "\n${YELLOW}Opções de dispositivo RNG:${NC}"
        echo -e "${BLUE}1. auto - Detectar automaticamente (recomendado)${NC}"
        echo -e "${BLUE}2. /dev/hwrng - Hardware RNG (se disponível)${NC}"
        echo -e "${BLUE}3. /dev/urandom - Software RNG${NC}"
        
        collect_user_input "Escolha o dispositivo RNG (auto/hwrng/urandom):" "auto" "rng_choice"
        
        case "$rng_choice" in
            "hwrng") rng_device="/dev/hwrng" ;;
            "urandom") rng_device="/dev/urandom" ;;
            *) rng_device="auto" ;;
        esac
        
        collect_user_input "Watermark de preenchimento (padrão: 2048):" "$watermark" "watermark"
        collect_user_input "Intervalo de alimentação em segundos (padrão: 60):" "$feed_interval" "feed_interval"
        
        echo -e "\n${YELLOW}Configurações do RNG-tools:${NC}"
        echo -e "${BLUE}Dispositivo RNG: $rng_device${NC}"
        echo -e "${BLUE}Watermark: $watermark${NC}"
        echo -e "${BLUE}Intervalo: $feed_interval segundos${NC}"
        echo -e "${BLUE}Função: Melhora a entropia do sistema${NC}"
        echo -e "${BLUE}Recomendado para: Sistemas ARM com pouca entropia${NC}"
        
        if ! confirm_action "Confirma a instalação do RNG-tools com essas configurações?" "y"; then
            log_warn "Instalação do RNG-tools cancelada pelo usuário"
            return 1
        fi
    fi
    
    apt-get install -y rng-tools
    
    # Configuração baseada nas entradas do usuário
    cat > /etc/default/rng-tools << EOF
# Configuração gerada automaticamente pelo Boxserver
if [ "$rng_device" = "auto" ]; then
    # Detectar automaticamente
    if [ -e "/dev/hwrng" ]; then
        RNGDEVICE="/dev/hwrng"
    else
        RNGDEVICE="/dev/urandom"
    fi
else
    RNGDEVICE="$rng_device"
fi

# Opções otimizadas para ARM
RNGDOPTIONS="--fill-watermark=$watermark --feed-interval=$feed_interval --timeout=10"
EOF
    
    if [ "$enable_service" = "yes" ]; then
        systemctl enable rng-tools
        systemctl restart rng-tools
    fi
    
    log_success "RNG-tools instalado ✓"
}

# Instalar Rclone
install_rclone() {
    log_info "Instalando Rclone..."
    
    # Configurações interativas
    local install_method="script"
    local create_config="no"
    local enable_webui="no"
    local webui_port="5572"
    local webui_user="admin"
    local webui_pass=""
    local setup_gdrive="no"
    local gdrive_accounts="1"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                    ${GREEN}CONFIGURAÇÃO DO RCLONE${NC}                      ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        echo -e "\n${YELLOW}Informações sobre o Rclone:${NC}"
        echo -e "${BLUE}• Ferramenta para sincronização com armazenamento em nuvem${NC}"
        echo -e "${BLUE}• Suporta Google Drive, Dropbox, OneDrive, AWS S3, etc.${NC}"
        echo -e "${BLUE}• Web UI disponível para gerenciamento via navegador${NC}"
        echo -e "${BLUE}• Suporte a múltiplas contas Google Drive${NC}"
        
        if confirm_action "Deseja habilitar o Rclone Web UI?" "y"; then
            enable_webui="yes"
            collect_user_input "Porta para Web UI (padrão: 5572):" "$webui_port" "webui_port"
            collect_user_input "Usuário para Web UI (padrão: admin):" "$webui_user" "webui_user"
            
            while [ -z "$webui_pass" ]; do
                collect_user_input "Senha para Web UI (obrigatória):" "" "webui_pass"
                if [ -z "$webui_pass" ]; then
                    echo -e "${RED}Senha é obrigatória para segurança!${NC}"
                fi
            done
        fi
        
        if confirm_action "Deseja configurar Google Drive agora?" "n"; then
            setup_gdrive="yes"
            collect_user_input "Quantas contas Google Drive configurar (1-5):" "$gdrive_accounts" "gdrive_accounts"
            
            # Validar número de contas
            if ! [[ "$gdrive_accounts" =~ ^[1-5]$ ]]; then
                gdrive_accounts="1"
            fi
        fi
        
        echo -e "\n${YELLOW}Configurações do Rclone:${NC}"
        echo -e "${BLUE}Método de instalação: Script oficial${NC}"
        echo -e "${BLUE}Web UI habilitado: $enable_webui${NC}"
        [ "$enable_webui" = "yes" ] && echo -e "${BLUE}Web UI porta: $webui_port${NC}"
        [ "$enable_webui" = "yes" ] && echo -e "${BLUE}Web UI usuário: $webui_user${NC}"
        echo -e "${BLUE}Google Drive: $setup_gdrive${NC}"
        [ "$setup_gdrive" = "yes" ] && echo -e "${BLUE}Contas Google Drive: $gdrive_accounts${NC}"
        
        if ! confirm_action "Confirma a instalação do Rclone com essas configurações?" "y"; then
            log_warn "Instalação do Rclone cancelada pelo usuário"
            return 1
        fi
    fi
    
    # Instalação
    curl https://rclone.org/install.sh | bash
    
    # Configurar Web UI se solicitado
    if [ "$enable_webui" = "yes" ]; then
        # Criar serviço systemd para Rclone Web UI
        cat > /etc/systemd/system/rclone-webui.service << EOF
[Unit]
Description=Rclone Web UI
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rclone rcd --rc-web-gui --rc-addr 0.0.0.0:$webui_port --rc-user $webui_user --rc-pass $webui_pass --rc-web-gui-no-open-browser
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable rclone-webui
        
        echo -e "\n${GREEN}Rclone Web UI configurado como serviço${NC}"
        echo -e "${BLUE}Acesse em: http://$(hostname -I | awk '{print $1}'):$webui_port${NC}"
        echo -e "${BLUE}Usuário: $webui_user${NC}"
        echo -e "${BLUE}Senha: [configurada]${NC}"
    fi
    
    # Configurar Google Drive se solicitado
    if [ "$setup_gdrive" = "yes" ] && [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${YELLOW}Configurando Google Drive...${NC}"
        echo -e "${BLUE}IMPORTANTE: Para múltiplas contas, você precisará:${NC}"
        echo -e "${BLUE}1. Criar um projeto no Google Cloud Console${NC}"
        echo -e "${BLUE}2. Habilitar a Google Drive API${NC}"
        echo -e "${BLUE}3. Criar credenciais OAuth 2.0${NC}"
        echo -e "${BLUE}4. Configurar cada conta como um 'remote' separado${NC}"
        
        for i in $(seq 1 $gdrive_accounts); do
            echo -e "\n${YELLOW}Configurando conta Google Drive #$i...${NC}"
            echo -e "${BLUE}Nome sugerido: gdrive$i${NC}"
            
            if confirm_action "Configurar conta #$i agora?" "y"; then
                echo -e "${BLUE}Iniciando configuração interativa...${NC}"
                sleep 2
                rclone config || true
            else
                echo -e "${BLUE}Configure depois com: rclone config${NC}"
            fi
        done
        
        echo -e "\n${GREEN}Dicas para Google Drive:${NC}"
        echo -e "${BLUE}• Use 'rclone config' para adicionar mais contas${NC}"
        echo -e "${BLUE}• Cada conta será um 'remote' separado (ex: gdrive1:, gdrive2:)${NC}"
        echo -e "${BLUE}• No Web UI, você verá todos os remotes configurados${NC}"
    fi
    
    # Iniciar Web UI se configurado
    if [ "$enable_webui" = "yes" ]; then
        systemctl start rclone-webui
        sleep 2
        
        if systemctl is-active --quiet rclone-webui; then
            echo -e "\n${GREEN}Rclone Web UI iniciado com sucesso!${NC}"
        else
            echo -e "\n${RED}Erro ao iniciar Rclone Web UI. Verifique os logs.${NC}"
        fi
    fi
    
    log_success "Rclone instalado ✓ (Configure com: rclone config ou Web UI)"
}

# Instalar Rsync
install_rsync() {
    log_info "Instalando Rsync..."
    
    # Configurações interativas
    local enable_daemon="no"
    local rsync_port="873"
    local create_config="no"
    local backup_dir="/var/backups"
    local enable_websync="no"
    local websync_port="3000"
    local websync_user="admin"
    local websync_pass=""
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                    ${GREEN}CONFIGURAÇÃO DO RSYNC${NC}                       ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        echo -e "\n${YELLOW}Informações sobre o Rsync:${NC}"
        echo -e "${BLUE}• Ferramenta para sincronização e backup de arquivos${NC}"
        echo -e "${BLUE}• Pode funcionar como daemon para backups remotos${NC}"
        echo -e "${BLUE}• Útil para backups incrementais e sincronização${NC}"
        echo -e "${BLUE}• Websync disponível para interface web${NC}"
        
        if confirm_action "Deseja habilitar o daemon do Rsync (para backups remotos)?" "n"; then
            enable_daemon="yes"
            collect_user_input "Porta do daemon Rsync (padrão: 873):" "$rsync_port" "rsync_port"
            
            if confirm_action "Criar configuração básica do daemon?" "y"; then
                create_config="yes"
                collect_user_input "Diretório para backups (padrão: /var/backups):" "$backup_dir" "backup_dir"
            fi
        fi
        
        if confirm_action "Deseja instalar Websync (interface web para Rsync)?" "y"; then
            enable_websync="yes"
            collect_user_input "Porta para Websync (padrão: 3000):" "$websync_port" "websync_port"
            collect_user_input "Usuário para Websync (padrão: admin):" "$websync_user" "websync_user"
            
            while [ -z "$websync_pass" ]; do
                collect_user_input "Senha para Websync (obrigatória):" "" "websync_pass"
                if [ -z "$websync_pass" ]; then
                    echo -e "${RED}Senha é obrigatória para segurança!${NC}"
                fi
            done
        fi
        
        echo -e "\n${YELLOW}Configurações do Rsync:${NC}"
        echo -e "${BLUE}Daemon habilitado: $enable_daemon${NC}"
        [ "$enable_daemon" = "yes" ] && echo -e "${BLUE}Porta daemon: $rsync_port${NC}"
        [ "$create_config" = "yes" ] && echo -e "${BLUE}Diretório de backup: $backup_dir${NC}"
        echo -e "${BLUE}Websync habilitado: $enable_websync${NC}"
        [ "$enable_websync" = "yes" ] && echo -e "${BLUE}Porta Websync: $websync_port${NC}"
        [ "$enable_websync" = "yes" ] && echo -e "${BLUE}Usuário Websync: $websync_user${NC}"
        echo -e "${BLUE}Uso: Sincronização e backup de arquivos${NC}"
        
        if ! confirm_action "Confirma a instalação do Rsync com essas configurações?" "y"; then
            log_warn "Instalação do Rsync cancelada pelo usuário"
            return 1
        fi
    fi
    
    apt-get install -y rsync
    
    # Configuração do daemon se solicitada
    if [ "$enable_daemon" = "yes" ]; then
        # Habilitar daemon no systemd
        systemctl enable rsync
        
        # Criar configuração básica se solicitada
        if [ "$create_config" = "yes" ]; then
            mkdir -p "$backup_dir"
            
            cat > /etc/rsyncd.conf << EOF
# Configuração gerada automaticamente pelo Boxserver
port = $rsync_port
log file = /var/log/rsyncd.log
pid file = /var/run/rsyncd.pid
lock file = /var/run/rsync.lock

[backup]
path = $backup_dir
comment = Diretório de backup do Boxserver
uid = root
gid = root
read only = false
list = yes
auth users = backup
secrets file = /etc/rsyncd.secrets
hosts allow = 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12
EOF
            
            # Criar arquivo de senhas (usuário deve configurar)
            echo "# Configure as credenciais: backup:senha" > /etc/rsyncd.secrets
            chmod 600 /etc/rsyncd.secrets
            
            echo -e "\n${YELLOW}IMPORTANTE:${NC}"
            echo -e "${BLUE}Configure a senha em /etc/rsyncd.secrets${NC}"
            echo -e "${BLUE}Formato: backup:suasenha${NC}"
        fi
        
        systemctl start rsync
    fi
    
    # Instalar Websync se solicitado
    if [ "$enable_websync" = "yes" ]; then
        # Verificar se Docker está instalado
        if ! command -v docker &> /dev/null; then
            echo -e "\n${YELLOW}Docker não encontrado. Instalando Docker...${NC}"
            curl -fsSL https://get.docker.com -o get-docker.sh
            sh get-docker.sh
            systemctl enable docker
            systemctl start docker
            rm get-docker.sh
        fi
        
        # Criar diretório para configurações do Websync
        mkdir -p /opt/websync
        
        # Criar docker-compose.yml para Websync
        cat > /opt/websync/docker-compose.yml << EOF
version: '3.8'
services:
  websync:
    image: furier/websync:latest
    container_name: websync
    ports:
      - "$websync_port:3000"
    environment:
      - WEBSYNC_USER=$websync_user
      - WEBSYNC_PASSWORD=$websync_pass
      - NODE_ENV=production
    volumes:
      - /opt/websync/data:/app/data
      - /opt/websync/logs:/app/logs
      - $backup_dir:$backup_dir:rw
      - /etc/ssh:/etc/ssh:ro
    restart: unless-stopped
    network_mode: host
EOF
        
        # Criar diretórios necessários
        mkdir -p /opt/websync/data /opt/websync/logs
        
        # Criar serviço systemd para Websync
        cat > /etc/systemd/system/websync.service << EOF
[Unit]
Description=Websync - Web interface for Rsync
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/websync
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
        
        # Instalar docker-compose se não estiver instalado
        if ! command -v docker-compose &> /dev/null; then
            curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            chmod +x /usr/local/bin/docker-compose
        fi
        
        # Habilitar e iniciar Websync
        systemctl daemon-reload
        systemctl enable websync
        systemctl start websync
        
        sleep 5
        
        echo -e "\n${GREEN}Websync configurado!${NC}"
        echo -e "${BLUE}Acesse em: http://$(hostname -I | awk '{print $1}'):$websync_port${NC}"
        echo -e "${BLUE}Usuário: $websync_user${NC}"
        echo -e "${BLUE}Senha: [configurada]${NC}"
        echo -e "\n${YELLOW}Funcionalidades do Websync:${NC}"
        echo -e "${BLUE}• Gerenciar tarefas Rsync via interface web${NC}"
        echo -e "${BLUE}• Agendar backups automáticos${NC}"
        echo -e "${BLUE}• Monitorar logs em tempo real${NC}"
        echo -e "${BLUE}• Gerenciar hosts SSH${NC}"
        
        # Verificar se o serviço está rodando
        if systemctl is-active --quiet websync; then
            echo -e "\n${GREEN}Websync iniciado com sucesso!${NC}"
        else
            echo -e "\n${RED}Erro ao iniciar Websync. Verifique os logs com: journalctl -u websync${NC}"
        fi
    fi
    
    log_success "Rsync instalado ✓ $([ "$enable_websync" = "yes" ] && echo "com Websync")"
}

# Instalar MiniDLNA
install_minidlna() {
    log_info "Instalando MiniDLNA..."
    
    # Configurações interativas
    local media_dirs="/home"
    local friendly_name="Boxserver DLNA"
    local enable_inotify="yes"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                   ${GREEN}CONFIGURAÇÃO DO MINIDLNA${NC}                    ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        collect_user_input "Diretórios de mídia (separados por vírgula):" "$media_dirs" "media_dirs"
        collect_user_input "Nome amigável do servidor DLNA:" "$friendly_name" "friendly_name"
        
        echo -e "\n${YELLOW}Configurações do MiniDLNA:${NC}"
        echo -e "${BLUE}Diretórios de mídia: $media_dirs${NC}"
        echo -e "${BLUE}Nome do servidor: $friendly_name${NC}"
        echo -e "${BLUE}Monitoramento automático: Habilitado${NC}"
        
        if ! confirm_action "Confirma a instalação do MiniDLNA com essas configurações?" "y"; then
            log_warn "Instalação do MiniDLNA cancelada pelo usuário"
            return 1
        fi
    fi
    
    apt-get install -y minidlna
    
    # Configuração baseada nas entradas do usuário
    cat > /etc/minidlna.conf << EOF
# Configuração gerada automaticamente pelo Boxserver
EOF
    
    # Adicionar diretórios de mídia
    IFS=',' read -ra DIRS <<< "$media_dirs"
    for dir in "${DIRS[@]}"; do
        dir=$(echo "$dir" | xargs)  # Remove espaços
        echo "media_dir=V,$dir" >> /etc/minidlna.conf
        echo "media_dir=A,$dir" >> /etc/minidlna.conf
        echo "media_dir=P,$dir" >> /etc/minidlna.conf
    done
    
    # Adicionar configurações restantes
    cat >> /etc/minidlna.conf << EOF
friendly_name=$friendly_name
db_dir=/var/cache/minidlna
log_dir=/var/log
inotify=$enable_inotify
enable_tivo=no
strict_dlna=no
EOF
    
    systemctl enable minidlna
    systemctl restart minidlna
    
    log_success "MiniDLNA instalado ✓"
}

# Instalar Cloudflared
install_cloudflared() {
    log_info "Instalando Cloudflared..."
    
    # Configurações interativas
    local install_location="/usr/local/bin/cloudflared"
    local create_tunnel="no"
    local tunnel_name="boxserver-tunnel"
    
    if [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}                  ${GREEN}CONFIGURAÇÃO DO CLOUDFLARED${NC}                  ${BLUE}║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        echo -e "\n${YELLOW}Informações sobre o Cloudflared:${NC}"
        echo -e "${BLUE}• Cria túneis seguros para expor serviços locais${NC}"
        echo -e "${BLUE}• Requer conta Cloudflare (gratuita)${NC}"
        echo -e "${BLUE}• Permite acesso remoto sem abrir portas no roteador${NC}"
        
        collect_user_input "Local de instalação:" "$install_location" "install_location"
        
        if confirm_action "Deseja configurar um túnel agora (requer login Cloudflare)?" "n"; then
            create_tunnel="yes"
            collect_user_input "Nome do túnel:" "$tunnel_name" "tunnel_name"
        fi
        
        echo -e "\n${YELLOW}Configurações do Cloudflared:${NC}"
        echo -e "${BLUE}Local de instalação: $install_location${NC}"
        echo -e "${BLUE}Configuração de túnel: $create_tunnel${NC}"
        [ "$create_tunnel" = "yes" ] && echo -e "${BLUE}Nome do túnel: $tunnel_name${NC}"
        echo -e "${BLUE}Comandos úteis:${NC}"
        echo -e "${BLUE}  - Login: cloudflared tunnel login${NC}"
        echo -e "${BLUE}  - Criar túnel: cloudflared tunnel create <nome>${NC}"
        
        if ! confirm_action "Confirma a instalação do Cloudflared com essas configurações?" "y"; then
            log_warn "Instalação do Cloudflared cancelada pelo usuário"
            return 1
        fi
    fi
    
    # Download da versão ARM
    wget -O "$install_location" https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm
    chmod +x "$install_location"
    
    # Configuração de túnel se solicitada
    if [ "$create_tunnel" = "yes" ] && [ "$INTERACTIVE_MODE" = "true" ]; then
        echo -e "\n${YELLOW}Iniciando configuração do túnel Cloudflare...${NC}"
        echo -e "${BLUE}1. Primeiro faça login:${NC}"
        cloudflared tunnel login || true
        
        echo -e "\n${BLUE}2. Criando túnel '$tunnel_name':${NC}"
        cloudflared tunnel create "$tunnel_name" || true
        
        echo -e "\n${BLUE}3. Configure o arquivo de configuração em ~/.cloudflared/config.yml${NC}"
    fi
    
    log_success "Cloudflared instalado ✓ (Configure com: cloudflared tunnel login)"
}

################################################################################
# MENU INTERATIVO
################################################################################

show_menu() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}              ${GREEN}BOXSERVER MXQ-4K - INSTALADOR AUTOMATIZADO${NC}              ${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC} Sistema detectado: $(uname -m) - RAM: $(free -h | awk 'NR==2{print $2}') - Interface: $NETWORK_INTERFACE ${BLUE}║${NC}"
    
    # Mostrar modo atual
    echo -e "${BLUE}║${NC} Modo: ${GREEN}INTERATIVO${NC} (configurações serão solicitadas)           ${BLUE}║${NC}"
    
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}Selecione os aplicativos para instalar:${NC}                        ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [ 1] Pi-hole          - Bloqueio de anúncios e DNS          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [ 2] Unbound          - DNS recursivo local                 ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [ 3] WireGuard        - Servidor VPN                        ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [ 4] Cockpit          - Painel de administração web         ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [ 5] FileBrowser      - Gerenciamento de arquivos web       ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [ 6] Netdata          - Monitoramento em tempo real         ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [ 7] Fail2Ban         - Proteção contra ataques             ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [ 8] UFW              - Firewall simplificado               ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [ 9] RNG-tools        - Gerador de entropia                 ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [10] Rclone           - Sincronização com nuvem             ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [11] Rsync            - Backup local                        ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [12] MiniDLNA         - Servidor de mídia                   ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [13] Cloudflared      - Tunnel Cloudflare                   ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                              ${BLUE}║${NC}"

    echo -e "${BLUE}║${NC}  [99] Instalar TODOS os aplicativos                          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [88] DESINSTALAR serviços instalados                        ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  [ 0] Sair                                                   ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${YELLOW}Digite os números separados por espaço (ex: 1 2 3) ou 99 para todos:${NC}"
}

# Processar seleção do usuário
process_selection() {
    local selection="$1"
    local apps_to_install=()
    
    if [[ "$selection" == *"99"* ]]; then
        apps_to_install=(1 2 3 4 5 6 7 8 9 10 11 12 13)
        
        # Confirmação para instalação completa
        echo -e "\n${YELLOW}ATENÇÃO: Modo interativo ativo!${NC}"
        echo -e "${BLUE}Cada aplicativo solicitará configurações individuais.${NC}"
        if ! confirm_action "Deseja continuar com a instalação de TODOS os aplicativos?" "y"; then
            log_warn "Instalação cancelada pelo usuário"
            return 0
        fi
    else
        read -ra apps_to_install <<< "$selection"
    fi
    
    local total_apps=${#apps_to_install[@]}
    local current_app=0
    
    for app in "${apps_to_install[@]}"; do
        ((current_app++))
        
        case $app in
            1)
                show_progress $current_app $total_apps "Instalando Pi-hole..."
                install_pihole
                ;;
            2)
                show_progress $current_app $total_apps "Instalando Unbound..."
                install_unbound
                ;;
            3)
                show_progress $current_app $total_apps "Instalando WireGuard..."
                install_wireguard
                ;;
            4)
                show_progress $current_app $total_apps "Instalando Cockpit..."
                install_cockpit
                ;;
            5)
                show_progress $current_app $total_apps "Instalando FileBrowser..."
                install_filebrowser
                ;;
            6)
                show_progress $current_app $total_apps "Instalando Netdata..."
                install_netdata
                ;;
            7)
                show_progress $current_app $total_apps "Instalando Fail2Ban..."
                install_fail2ban
                ;;
            8)
                show_progress $current_app $total_apps "Instalando UFW..."
                install_ufw
                ;;
            9)
                show_progress $current_app $total_apps "Instalando RNG-tools..."
                install_rng_tools
                ;;
            10)
                show_progress $current_app $total_apps "Instalando Rclone..."
                install_rclone
                ;;
            11)
                show_progress $current_app $total_apps "Instalando Rsync..."
                install_rsync
                ;;
            12)
                show_progress $current_app $total_apps "Instalando MiniDLNA..."
                install_minidlna
                ;;
            13)
                show_progress $current_app $total_apps "Instalando Cloudflared..."
                install_cloudflared
                ;;
            0)
                log_info "Saindo..."
                exit 0
                ;;
            88)
                log_info "Iniciando desinstalação dos serviços..."
                rollback_installation
                exit 0
                ;;
            *)
                log_warn "Opção inválida: $app"
                ;;
        esac
    done
}

################################################################################
# CONFIGURAÇÕES FINAIS E OTIMIZAÇÕES
################################################################################

setup_thermal_optimizations() {
    log_info "Configurando otimizações térmicas para RK322x..."
    
    # Instalar cpufrequtils se não estiver presente
    if ! command -v cpufreq-info &> /dev/null; then
        apt-get update
        apt-get install -y cpufrequtils
    fi
    
    # Configurar governor para powersave (reduz temperatura)
    echo "GOVERNOR=\"powersave\"" > /etc/default/cpufrequtils
    echo "MIN_SPEED=\"240000\"" >> /etc/default/cpufrequtils
    echo "MAX_SPEED=\"1200000\"" >> /etc/default/cpufrequtils
    
    # Configurar thermal throttling mais agressivo
    if [ -d /sys/class/thermal/thermal_zone0 ]; then
        # Definir temperatura crítica mais baixa (75°C ao invés de 85°C)
        echo 75000 > /sys/class/thermal/thermal_zone0/trip_point_0_temp 2>/dev/null || true
        echo 70000 > /sys/class/thermal/thermal_zone0/trip_point_1_temp 2>/dev/null || true
    fi
    
    # Criar script de monitoramento térmico
    cat > /usr/local/bin/thermal-monitor << 'EOF'
#!/bin/bash
# Monitor térmico para RK322x
TEMP_THRESHOLD=75
COOLDOWN_THRESHOLD=65
LOG_FILE="/var/log/boxserver/thermal.log"

while true; do
    if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
        TEMP=$(($(cat /sys/class/thermal/thermal_zone0/temp)/1000))
        
        if [ $TEMP -gt $TEMP_THRESHOLD ]; then
            echo "$(date): ALERTA - Temperatura alta: ${TEMP}°C" >> $LOG_FILE
            # Forçar governor powersave
            echo powersave > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true
            echo powersave > /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor 2>/dev/null || true
            echo powersave > /sys/devices/system/cpu/cpu2/cpufreq/scaling_governor 2>/dev/null || true
            echo powersave > /sys/devices/system/cpu/cpu3/cpufreq/scaling_governor 2>/dev/null || true
            
            # Reduzir frequência máxima temporariamente
            echo 816000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq 2>/dev/null || true
            echo 816000 > /sys/devices/system/cpu/cpu1/cpufreq/scaling_max_freq 2>/dev/null || true
            echo 816000 > /sys/devices/system/cpu/cpu2/cpufreq/scaling_max_freq 2>/dev/null || true
            echo 816000 > /sys/devices/system/cpu/cpu3/cpufreq/scaling_max_freq 2>/dev/null || true
        elif [ $TEMP -lt $COOLDOWN_THRESHOLD ]; then
            # Restaurar frequência normal quando esfriar
            echo 1200000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq 2>/dev/null || true
            echo 1200000 > /sys/devices/system/cpu/cpu1/cpufreq/scaling_max_freq 2>/dev/null || true
            echo 1200000 > /sys/devices/system/cpu/cpu2/cpufreq/scaling_max_freq 2>/dev/null || true
            echo 1200000 > /sys/devices/system/cpu/cpu3/cpufreq/scaling_max_freq 2>/dev/null || true
        fi
    fi
    sleep 30
done
EOF
    
    chmod +x /usr/local/bin/thermal-monitor
    
    # Criar serviço systemd para o monitor térmico
    cat > /etc/systemd/system/thermal-monitor.service << EOF
[Unit]
Description=Monitor Térmico RK322x
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/local/bin/thermal-monitor
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable thermal-monitor.service
    systemctl start thermal-monitor.service
    
    log_success "Otimizações térmicas configuradas ✓"
}

setup_optimizations() {
    log_info "Aplicando otimizações para ARM..."
    
    # Otimizações de memória para ARM
    cat >> /etc/sysctl.conf << EOF

# Otimizações Boxserver ARM
vm.swappiness=10
vm.vfs_cache_pressure=50
vm.dirty_ratio=15
vm.dirty_background_ratio=5
EOF
    
    sysctl -p
    
    # Configurar logrotate
    cat > /etc/logrotate.d/boxserver << EOF
/var/log/boxserver/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF
    
    log_success "Otimizações aplicadas ✓"
}

setup_monitoring_scripts() {
    log_info "Criando scripts de monitoramento..."
    
    # Script de saúde do sistema
    cat > /usr/local/bin/boxserver-health << 'EOF'
#!/bin/bash
echo "=== RELATÓRIO DE SAÚDE DO BOXSERVER ==="
echo "Data: $(date)"
echo "Uptime: $(uptime -p)"
echo "Memória: $(free -h | awk 'NR==2{printf "%.1f%% (%s/%s)", $3*100/$2, $3, $2}')"
echo "Disco: $(df -h / | awk 'NR==2{printf "%s usado de %s (%s)", $3, $2, $5}')"
if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
    echo "Temperatura CPU: $(($(cat /sys/class/thermal/thermal_zone0/temp)/1000))°C"
fi
echo "Entropia: $(cat /proc/sys/kernel/random/entropy_avail)"
echo
echo "=== SERVIÇOS ==="
for service in pihole-FTL unbound wg-quick@wg0 cockpit.socket filebrowser netdata fail2ban ufw; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "✅ $service: ATIVO"
    else
        echo "❌ $service: INATIVO"
    fi
done
EOF
    
    chmod +x /usr/local/bin/boxserver-health
    
    # Agendar execução diária
    echo "0 8 * * * root /usr/local/bin/boxserver-health >> /var/log/boxserver/health.log" >> /etc/crontab
    
    log_success "Scripts de monitoramento criados ✓"
}

generate_summary() {
    log_info "Gerando relatório final..."
    
    local summary_file="/var/log/boxserver/installation-summary.txt"
    
    cat > "$summary_file" << EOF
=== RELATÓRIO DE INSTALAÇÃO BOXSERVER MXQ-4K ===
Data: $(date)
Interface de rede: $NETWORK_INTERFACE
IP do servidor: $SERVER_IP
Rede VPN: $VPN_NETWORK

=== APLICATIVOS INSTALADOS ===
EOF
    
    # Verificar quais serviços estão ativos
    local services=("pihole-FTL:Pi-hole" "unbound:Unbound" "wg-quick@wg0:WireGuard" 
                   "cockpit.socket:Cockpit" "filebrowser:FileBrowser" "netdata:Netdata" 
                   "fail2ban:Fail2Ban" "ufw:UFW" "rng-tools:RNG-tools")
    
    for service_info in "${services[@]}"; do
        local service_name=$(echo "$service_info" | cut -d: -f1)
        local display_name=$(echo "$service_info" | cut -d: -f2)
        
        if systemctl is-active --quiet "$service_name" 2>/dev/null; then
            echo "✅ $display_name" >> "$summary_file"
        fi
    done
    
    cat >> "$summary_file" << EOF

=== ACESSOS WEB ===
Cockpit: https://$SERVER_IP:$COCKPIT_PORT
FileBrowser: http://$SERVER_IP:$FILEBROWSER_PORT
Netdata: http://$SERVER_IP:19999
Pi-hole Admin: http://$SERVER_IP/admin

=== PRÓXIMOS PASSOS ===
1. Configure clientes WireGuard usando: /etc/wireguard/keys/publickey
2. Configure Rclone para backup: rclone config
3. Configure Cloudflared tunnel: cloudflared tunnel login
4. Monitore o sistema: /usr/local/bin/boxserver-health

=== LOGS ===
Instalação: $LOG_FILE
Saúde do sistema: /var/log/boxserver/health.log
EOF
    
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}                    ${YELLOW}INSTALAÇÃO CONCLUÍDA!${NC}                        ${GREEN}║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} Relatório completo salvo em: $summary_file ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} ${YELLOW}Acessos principais:${NC}                                          ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} • Cockpit: https://$SERVER_IP:$COCKPIT_PORT                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} • FileBrowser: http://$SERVER_IP:$FILEBROWSER_PORT                     ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} • Netdata: http://$SERVER_IP:19999                           ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} • Pi-hole: http://$SERVER_IP/admin                           ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} Execute 'boxserver-health' para verificar o status          ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    log_success "Instalação do Boxserver MXQ-4k concluída com sucesso!"
}

################################################################################
# FUNÇÃO PRINCIPAL
################################################################################

main() {
    # Inicializar log
    echo "=== INÍCIO DA INSTALAÇÃO BOXSERVER MXQ-4K ===" > "$LOG_FILE"
    
    log_info "Iniciando instalação do Boxserver MXQ-4k..."
    
    # Verificações iniciais
    check_root
    check_linux_distribution
    check_system_requirements
    detect_network_interface
    configure_static_ip
    setup_directories
    
    # Atualizar sistema
    update_system
    
    # Mostrar menu e processar seleção
    while true; do
        show_menu
        read -r selection
        
        if [ "$selection" = "0" ]; then
            log_info "Instalação cancelada pelo usuário"
            exit 0
        fi
        
        if [ -n "$selection" ]; then
            log_info "Iniciando instalação dos aplicativos selecionados: $selection"
            process_selection "$selection"
            break
        else
            echo -e "${RED}Por favor, selecione pelo menos uma opção.${NC}"
            sleep 2
        fi
    done
    
    # Configurações finais
    setup_optimizations
    setup_thermal_optimizations
    setup_monitoring_scripts
    
    # Reiniciar serviços críticos
    log_info "Reiniciando serviços..."
    systemctl restart pihole-FTL 2>/dev/null || true
    systemctl restart unbound 2>/dev/null || true
    systemctl start wg-quick@wg0 2>/dev/null || true
    
    # Gerar relatório final
    generate_summary
    
    # Verificar se precisa reiniciar para aplicar IP fixo
    if [ "$STATIC_IP_CONFIGURED" = "true" ]; then
        echo ""
        log_warn "=== REINICIALIZAÇÃO NECESSÁRIA ==="
        echo -e "${YELLOW}Um IP fixo foi configurado e o sistema precisa ser reiniciado${NC}"
        echo -e "${YELLOW}para aplicar as mudanças de rede corretamente.${NC}"
        echo ""
        
        read -p "Deseja reiniciar agora? (S/n): " restart_now
        restart_now=${restart_now:-s}
        
        if [[ "$restart_now" =~ ^[Ss]$ ]]; then
            log_info "Reiniciando sistema em 10 segundos..."
            echo -e "${RED}Pressione Ctrl+C para cancelar${NC}"
            
            for i in {10..1}; do
                echo -ne "\rReiniciando em $i segundos..."
                sleep 1
            done
            
            echo ""
            log_info "Reiniciando sistema..."
            reboot
        else
            echo ""
            log_warn "IMPORTANTE: Reinicie manualmente o sistema com 'sudo reboot'"
            log_warn "para que as configurações de rede sejam aplicadas corretamente."
            echo ""
        fi
    fi
}

################################################################################
# TRATAMENTO DE SINAIS E LIMPEZA
################################################################################

cleanup() {
    log_warn "Instalação interrompida. Limpando..."
    if [ -f "$INSTALL_DIR/installed_services" ]; then
        log_warn "Serviços parcialmente instalados detectados. Executando rollback..."
        rollback_installation
    fi
    exit 1
}

error_handler() {
    local exit_code=$?
    local line_number=$1
    log_error "Erro na linha $line_number com código de saída $exit_code"
    if [ -f "$INSTALL_DIR/installed_services" ]; then
        log_warn "Erro detectado durante instalação. Executando rollback..."
        rollback_installation
    fi
    exit $exit_code
}

trap cleanup INT TERM

################################################################################
# EXECUÇÃO
################################################################################

# Verificar se está sendo executado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
