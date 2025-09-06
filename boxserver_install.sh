#!/bin/bash

# BoxServer Setup Script
# Automatização completa com interface TUI
# Versão: 2.0
# Compatível: Debian/Ubuntu/Armbian
# Hardware: Otimizado para ARM RK322x

set -euo pipefail

# =============================================================================
# CONFIGURAÇÕES GLOBAIS
# =============================================================================

SCRIPT_NAME="BoxServer Setup"
SCRIPT_VERSION="2.0"
LOG_FILE="/var/log/boxserver-setup.log"
CONFIG_DIR="/etc/boxserver"
BACKUP_DIR="/etc/boxserver/backups"
TEMP_DIR="/tmp/boxserver-setup"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configurações padrão (podem ser alteradas pelo usuário)
DEFAULT_PIHOLE_IP="192.168.0.50"
DEFAULT_PIHOLE_PORT="80"
DEFAULT_UNBOUND_PORT="5335"
DEFAULT_WIREGUARD_PORT="51820"
DEFAULT_VPN_NETWORK="10.200.200.0/24"
DEFAULT_VPN_SERVER_IP="10.200.200.1"

# =============================================================================
# FUNÇÕES UTILITÁRIAS
# =============================================================================

# Logging
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# TUI Functions
show_info() {
    whiptail --title "$SCRIPT_NAME" --msgbox "$1" 12 70
}

show_error() {
    whiptail --title "ERRO" --msgbox "$1" 10 60
    log_message "ERRO: $1"
}

ask_yes_no() {
    whiptail --title "$SCRIPT_NAME" --yesno "$1" 10 60
    return $?
}

get_input() {
    local title="$1"
    local prompt="$2"
    local default="${3:-}"
    whiptail --title "$title" --inputbox "$prompt" 10 60 "$default" 3>&1 1>&2 2>&3
}

get_password() {
    local title="$1"
    local prompt="$2"
    whiptail --title "$title" --passwordbox "$prompt" 10 60 3>&1 1>&2 2>&3
}

show_menu() {
    local title="$1"
    shift
    whiptail --title "$title" --menu "Escolha uma opção:" 20 70 12 "$@" 3>&1 1>&2 2>&3
}

show_checklist() {
    local title="$1"
    shift
    whiptail --title "$title" --checklist "Selecione os itens:" 20 70 10 "$@" 3>&1 1>&2 2>&3
}

# Verificar se é root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        show_error "Este script precisa ser executado como root (sudo)."
        exit 1
    fi
}

# Criar diretórios necessários
create_directories() {
    mkdir -p "$CONFIG_DIR" "$BACKUP_DIR" "$TEMP_DIR"
    chmod 700 "$CONFIG_DIR" "$BACKUP_DIR"
}

# Verificar conectividade
check_internet() {
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        show_error "Sem conexão com a internet. Verificar conectividade."
        return 1
    fi
    return 0
}

# Detectar interface de rede
detect_network_interface() {
    local interface
    interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$interface" ]]; then
        show_error "Não foi possível detectar a interface de rede principal."
        return 1
    fi
    echo "$interface"
}

# Verificar hardware
check_hardware() {
    local ram_mb cpu_temp_c disk_usage

    # RAM em MB
    ram_mb=$(free -m | awk 'NR==2{print $2}')

    # Temperatura CPU (se disponível)
    if [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
        cpu_temp_c=$(($(cat /sys/class/thermal/thermal_zone0/temp)/1000))
    else
        cpu_temp_c="N/A"
    fi

    # Uso do disco
    disk_usage=$(df / | awk 'NR==2{print $5}' | sed 's/%//')

    # Verificações críticas
    if [[ $ram_mb -lt 512 ]]; then
        if ! ask_yes_no "RAM detectada: ${ram_mb}MB (recomendado: 1GB+)\nContinuar mesmo assim?"; then
            exit 1
        fi
    fi

    # Apenas logar a temperatura sem bloquear
    if [[ "$cpu_temp_c" != "N/A" ]] && [[ $cpu_temp_c -gt 75 ]]; then
        log_message "AVISO: Temperatura CPU alta: ${cpu_temp_c}°C"
    fi


    if [[ $disk_usage -gt 90 ]]; then
        if ! ask_yes_no "Disco com ${disk_usage}% de uso. Continuar?"; then
            exit 1
        fi
    fi

    log_message "Hardware verificado: RAM=${ram_mb}MB, CPU=${cpu_temp_c}°C, Disco=${disk_usage}%"
}

# =============================================================================
# CONFIGURAÇÃO INICIAL
# =============================================================================

configure_system_settings() {
    local pihole_ip pihole_port unbound_port wireguard_port vpn_network

    show_info "Vamos configurar os parâmetros básicos do sistema."

    # IP do Pi-hole
    pihole_ip=$(get_input "Configuração IP" "IP fixo para Pi-hole:" "$DEFAULT_PIHOLE_IP")
    [[ -z "$pihole_ip" ]] && pihole_ip="$DEFAULT_PIHOLE_IP"

    # Portas dos serviços
    pihole_port=$(get_input "Configuração Portas" "Porta do Pi-hole (web):" "$DEFAULT_PIHOLE_PORT")
    [[ -z "$pihole_port" ]] && pihole_port="$DEFAULT_PIHOLE_PORT"

    unbound_port=$(get_input "Configuração Portas" "Porta do Unbound DNS:" "$DEFAULT_UNBOUND_PORT")
    [[ -z "$unbound_port" ]] && unbound_port="$DEFAULT_UNBOUND_PORT"

    wireguard_port=$(get_input "Configuração Portas" "Porta do WireGuard VPN:" "$DEFAULT_WIREGUARD_PORT")
    [[ -z "$wireguard_port" ]] && wireguard_port="$DEFAULT_WIREGUARD_PORT"

    # Rede VPN
    vpn_network=$(get_input "Configuração VPN" "Rede VPN (CIDR):" "$DEFAULT_VPN_NETWORK")
    [[ -z "$vpn_network" ]] && vpn_network="$DEFAULT_VPN_NETWORK"

    # Salvar configurações
    cat > "$CONFIG_DIR/config.conf" <<EOF
# BoxServer Configuration
PIHOLE_IP="$pihole_ip"
PIHOLE_PORT="$pihole_port"
UNBOUND_PORT="$unbound_port"
WIREGUARD_PORT="$wireguard_port"
VPN_NETWORK="$vpn_network"
VPN_SERVER_IP="$(echo "$vpn_network" | sed 's|/.*|.1|')"
NETWORK_INTERFACE="$(detect_network_interface)"
INSTALLATION_DATE="$(date)"
EOF

    log_message "Configurações salvas em $CONFIG_DIR/config.conf"
    show_info "Configurações salvas com sucesso!"
}

# Carregar configurações
load_config() {
    if [[ -f "$CONFIG_DIR/config.conf" ]]; then
        source "$CONFIG_DIR/config.conf"
        return 0
    else
        return 1
    fi
}

# =============================================================================
# DETECÇÃO DE ESTADO DOS SERVIÇOS
# =============================================================================

detect_service_state() {
    local service_name="$1"
    local config_file="${2:-}"

    local installed=false
    local configured=false
    local running=false

    # Verificar se está instalado
    case "$service_name" in
        "pihole")
            [[ -f /usr/local/bin/pihole ]] && installed=true
            [[ -f /etc/pihole/setupVars.conf ]] && configured=true
            systemctl is-active --quiet pihole-FTL && running=true
            ;;
        "unbound")
            which unbound &>/dev/null && installed=true
            [[ -f /etc/unbound/unbound.conf.d/pi-hole.conf ]] && configured=true
            systemctl is-active --quiet unbound && running=true
            ;;
        "wireguard")
            which wg &>/dev/null && installed=true
            [[ -f /etc/wireguard/wg0.conf ]] && configured=true
            systemctl is-active --quiet wg-quick@wg0 && running=true
            ;;
        "cloudflared")
            which cloudflared &>/dev/null && installed=true
            [[ -f /etc/cloudflared/config.yml ]] && configured=true
            systemctl is-active --quiet cloudflared && running=true
            ;;
        "rng-tools"|"haveged")
            if which rng-tools &>/dev/null || which haveged &>/dev/null; then
                installed=true
                configured=true
                if systemctl is-active --quiet rng-tools || systemctl is-active --quiet haveged; then
                    running=true
                fi
            fi
            ;;
        "chrony")
            which chrony &>/dev/null && installed=true
            [[ -f /etc/chrony/chrony.conf ]] && configured=true
            systemctl is-active --quiet chrony && running=true
            ;;
    esac

    echo "installed=$installed configured=$configured running=$running"
}

# =============================================================================
# FUNÇÕES DE INSTALAÇÃO
# =============================================================================

install_basic_tools() {
    log_message "Instalando ferramentas básicas..."

    apt update
    apt install -y curl wget gnupg lsb-release software-properties-common \
                   dnsutils net-tools htop iotop qrencode dialog whiptail \
                   ufw fail2ban logrotate cron

    log_message "Ferramentas básicas instaladas"
}

install_entropy() {
    log_message "Configurando entropia..."

    # Para ARM, tentar rng-tools primeiro
    if uname -m | grep -q arm; then
        apt install -y rng-tools

        cat > /etc/default/rng-tools <<EOF
RNGDEVICE="/dev/hwrng"
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10"
EOF

        # Se hwrng não existir, usar urandom
        if [[ ! -e /dev/hwrng ]]; then
            sed -i 's|/dev/hwrng|/dev/urandom|' /etc/default/rng-tools
        fi

        systemctl enable rng-tools
        systemctl restart rng-tools
    else
        # Para x86, usar haveged
        apt install -y haveged
        systemctl enable haveged
        systemctl restart haveged
    fi

    # Verificar entropia
    local entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    if [[ $entropy -lt 1000 ]]; then
        show_error "Entropia baixa: $entropy (recomendado: >1000)"
        return 1
    fi

    log_message "Entropia configurada: $entropy"
}

install_ntp() {
    log_message "Instalando e configurando NTP..."

    apt install -y chrony

    # Backup da configuração original
    cp /etc/chrony/chrony.conf "$BACKUP_DIR/chrony.conf.backup"

    # Configurar servidores NTP brasileiros
    cat >> /etc/chrony/chrony.conf <<EOF

# Servidores NTP brasileiros
server a.st1.ntp.br iburst
server b.st1.ntp.br iburst
server c.st1.ntp.br iburst
server d.st1.ntp.br iburst
EOF

    systemctl enable chrony
    systemctl restart chrony

    # Aguardar sincronização
    sleep 5

    if chrony sources &>/dev/null; then
        log_message "NTP configurado e sincronizado"
    else
        log_message "AVISO: NTP instalado mas pode não estar sincronizado"
    fi
}

optimize_system() {
    log_message "Aplicando otimizações do sistema..."

    # Otimizações para ARM
    cat >> /etc/sysctl.conf <<EOF

# Otimizações BoxServer para ARM
vm.swappiness=1
vm.vfs_cache_pressure=50
net.ipv4.ip_forward=1
EOF

    sysctl -p

    # Governor para ARM
    if [[ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
        echo ondemand | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
    fi

    # Script de controle de temperatura
    cat > /etc/cron.hourly/check-temp <<'EOF'
#!/bin/bash
if [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
    TEMP=$(cat /sys/class/thermal/thermal_zone0/temp)
    TEMP_C=$((TEMP/1000))
    if [[ $TEMP_C -gt 75 ]]; then
        logger "ALERTA: CPU acima de 75°C ($TEMP_C°C)! Reduzindo clock."
        if [[ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq ]]; then
            echo 816000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq
        fi
    fi
fi
EOF

    chmod +x /etc/cron.hourly/check-temp

    log_message "Otimizações aplicadas"
}

setup_basic_firewall() {
    log_message "Configurando firewall básico..."

    # Resetar regras UFW
    ufw --force reset

    # Configurações básicas
    ufw default deny incoming
    ufw default allow outgoing

    # Permitir SSH
    ufw allow ssh

    # Não habilitar ainda - aguardar configuração completa
    log_message "Firewall configurado (não habilitado ainda)"
}

install_unbound() {
    log_message "Instalando Unbound..."

    if ! load_config; then
        show_error "Configuração não encontrada. Execute a configuração inicial primeiro."
        return 1
    fi

    apt install -y unbound

    # Parar serviço do Unbound
    systemctl stop unbound

    # Limpar TODAS as configurações existentes
    rm -rf /var/lib/unbound/*
    rm -rf /etc/unbound/unbound.conf.d/*
    rm -f /etc/unbound/*.conf
    rm -f /etc/unbound/keys.d/*
    mkdir -p /var/lib/unbound

    # Baixar root hints
    wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root

    # Configuração otimizada para ARM
    cat > /etc/unbound/unbound.conf.d/pi-hole.conf <<EOF
server:
    verbosity: 1
    interface: 127.0.0.1
    port: $UNBOUND_PORT
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    prefer-ip6: no

    # Configurações básicas de DNS
    root-hints: "/var/lib/unbound/root.hints"
    trust-anchor-file: ""
    auto-trust-anchor-file: ""
    module-config: "iterator"

    # Otimizações
    num-threads: 1
    msg-cache-slabs: 1
    rrset-cache-slabs: 1
    infra-cache-slabs: 1
    key-cache-slabs: 1
    so-rcvbuf: 512k
    so-sndbuf: 512k
    edns-buffer-size: 1232
    prefetch: yes
    use-caps-for-id: no

    # Cache
    cache-min-ttl: 0
    cache-max-ttl: 86400

    # Privacidade
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
    hide-identity: yes
    hide-version: yes
EOF

    # Configurar permissões
    # Configurar permissões
    chown -R unbound:unbound /var/lib/unbound /etc/unbound
    chmod 755 /var/lib/unbound
    chmod 644 /var/lib/unbound/root.hints
    chmod -R 644 /etc/unbound/unbound.conf.d/*
    chmod 755 /etc/unbound/unbound.conf.d

    # Verificar configuração
    if ! unbound-checkconf; then
        show_error "Erro na configuração do Unbound"
        return 1
    fi

    systemctl enable unbound
    systemctl restart unbound

    # Testar funcionamento
    sleep 3
    if dig @127.0.0.1 -p "$UNBOUND_PORT" google.com +short &>/dev/null; then
        log_message "Unbound instalado e funcionando"
    else
        show_error "Unbound instalado mas não está funcionando corretamente"
        return 1
    fi
}

install_pihole() {
    log_message "Instalando Pi-hole..."

    if ! load_config; then
        show_error "Configuração não encontrada."
        return 1
    fi

    # Configurar setupVars.conf antes da instalação
    mkdir -p /etc/pihole
    cat > /etc/pihole/setupVars.conf <<EOF
PIHOLE_INTERFACE=$NETWORK_INTERFACE
IPV4_ADDRESS=$PIHOLE_IP/24
IPV6_ADDRESS=
PIHOLE_DNS_1=127.0.0.1#$UNBOUND_PORT
PIHOLE_DNS_2=
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSSEC=true
DNSMASQ_LISTENING=single
PIHOLE_DOMAIN=lan
LIGHTTPD_ENABLED=true
WEBPORT=$PIHOLE_PORT
EOF

    # Instalar Pi-hole automaticamente
    curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended

    # Configurar senha admin
    local admin_password
    admin_password=$(get_password "Pi-hole Admin" "Digite a senha do admin do Pi-hole:")

    if [[ -n "$admin_password" ]]; then
        pihole -a -p "$admin_password"
    fi

    # Reiniciar para aplicar configurações
    systemctl restart pihole-FTL

    # Testar funcionamento
    sleep 5
    if dig @127.0.0.1 google.com +short &>/dev/null; then
        log_message "Pi-hole instalado e funcionando"
    else
        show_error "Pi-hole instalado mas não está funcionando corretamente"
        return 1
    fi
}

# =============================================================================
# WIREGUARD COM GESTÃO DE CLIENTES
# =============================================================================

install_wireguard() {
    log_message "Instalando WireGuard..."

    if ! load_config; then
        show_error "Configuração não encontrada."
        return 1
    fi

    apt install -y wireguard wireguard-tools

    # Criar diretório para chaves
    mkdir -p /etc/wireguard/keys /etc/wireguard/clients
    chmod 700 /etc/wireguard/keys /etc/wireguard/clients

    cd /etc/wireguard/keys

    # Gerar chaves do servidor
    umask 077
    wg genkey | tee server_private.key | wg pubkey > server_public.key

    # Configuração do servidor
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $(cat server_private.key)
Address = $VPN_SERVER_IP/24
ListenPort = $WIREGUARD_PORT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE

EOF

    # Salvar informações do servidor
    cat > /etc/wireguard/server.conf <<EOF
SERVER_PUBLIC_KEY=$(cat server_public.key)
SERVER_ENDPOINT=$PIHOLE_IP:$WIREGUARD_PORT
VPN_NETWORK=$VPN_NETWORK
VPN_SERVER_IP=$VPN_SERVER_IP
DNS_SERVER=$VPN_SERVER_IP
NEXT_CLIENT_IP=2
EOF

    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0

    log_message "WireGuard instalado e configurado"
}

generate_client_config() {
    local client_name="$1"
    local client_ip="$2"

    if ! load_config; then
        show_error "Configuração não encontrada."
        return 1
    fi

    source /etc/wireguard/server.conf

    # Gerar chaves do cliente
    cd /etc/wireguard/keys
    wg genkey | tee "${client_name}_private.key" | wg pubkey > "${client_name}_public.key"

    local client_private_key=$(cat "${client_name}_private.key")
    local client_public_key=$(cat "${client_name}_public.key")

    # Configuração do cliente
    cat > "/etc/wireguard/clients/${client_name}.conf" <<EOF
[Interface]
PrivateKey = $client_private_key
Address = $client_ip/32
DNS = $DNS_SERVER

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_ENDPOINT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # Adicionar peer ao servidor
    cat >> /etc/wireguard/wg0.conf <<EOF
# Cliente: $client_name
[Peer]
PublicKey = $client_public_key
AllowedIPs = $client_ip/32

EOF

    # Reiniciar WireGuard
    systemctl restart wg-quick@wg0

    # Gerar QR Code
    local qr_file="/tmp/wireguard_${client_name}_qr.txt"
    qrencode -t ansiutf8 < "/etc/wireguard/clients/${client_name}.conf" > "$qr_file"

    # Exibir QR Code na TUI
    whiptail --title "QR Code - $client_name" --textbox "$qr_file" 25 80

    # Salvar informações do cliente
    echo "$client_name:$client_ip:$client_public_key:$(date)" >> /etc/wireguard/clients.db

    # Atualizar próximo IP
    local next_ip=$((${client_ip##*.} + 1))
    sed -i "s/NEXT_CLIENT_IP=.*/NEXT_CLIENT_IP=$next_ip/" /etc/wireguard/server.conf

    rm -f "$qr_file"

    log_message "Cliente WireGuard '$client_name' criado com IP $client_ip"
}

manage_wireguard_clients() {
    while true; do
        local choice
        choice=$(show_menu "Gerenciar Clientes WireGuard" \
            "1" "Criar novo cliente" \
            "2" "Listar clientes" \
            "3" "Exibir QR Code de cliente existente" \
            "4" "Remover cliente" \
            "5" "Mostrar configuração de cliente" \
            "0" "Voltar")

        case $choice in
            1) create_new_wireguard_client ;;
            2) list_wireguard_clients ;;
            3) show_existing_qr ;;
            4) remove_wireguard_client ;;
            5) show_client_config ;;
            0) break ;;
        esac
    done
}

create_new_wireguard_client() {
    local client_name client_ip

    source /etc/wireguard/server.conf
    local next_ip="$VPN_SERVER_IP"
    next_ip="${next_ip%.*}.$NEXT_CLIENT_IP"

    client_name=$(get_input "Novo Cliente WireGuard" "Nome do cliente:" "")
    if [[ -z "$client_name" ]]; then
        show_error "Nome do cliente é obrigatório."
        return 1
    fi

    # Verificar se cliente já existe
    if [[ -f "/etc/wireguard/clients/${client_name}.conf" ]]; then
        show_error "Cliente '$client_name' já existe."
        return 1
    fi

    client_ip=$(get_input "IP do Cliente" "IP do cliente VPN:" "$next_ip")
    if [[ -z "$client_ip" ]]; then
        client_ip="$next_ip"
    fi

    # Validar IP
    if ! [[ "$client_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        show_error "IP inválido: $client_ip"
        return 1
    fi

    # Verificar se IP já está em uso
    if grep -q "$client_ip/32" /etc/wireguard/wg0.conf; then
        show_error "IP $client_ip já está em uso."
        return 1
    fi

    generate_client_config "$client_name" "$client_ip"
    show_info "Cliente '$client_name' criado com sucesso!\nIP: $client_ip\nArquivo de configuração: /etc/wireguard/clients/${client_name}.conf"
}

list_wireguard_clients() {
    if [[ ! -f /etc/wireguard/clients.db ]]; then
        show_info "Nenhum cliente configurado ainda."
        return
    fi

    local clients_info
    clients_info="Clientes WireGuard configurados:\n\n"
    clients_info+="Nome | IP | Data de Criação\n"
    clients_info+="-----|----|-----------------\n"

    while IFS=':' read -r name ip pubkey date; do
        clients_info+="$name | $ip | $date\n"
    done < /etc/wireguard/clients.db

    whiptail --title "Lista de Clientes WireGuard" --msgbox "$clients_info" 20 70
}

show_existing_qr() {
    if [[ ! -f /etc/wireguard/clients.db ]]; then
        show_info "Nenhum cliente configurado."
        return
    fi

    local clients=()
    while IFS=':' read -r name ip pubkey date; do
        clients+=("$name" "$ip")
    done < /etc/wireguard/clients.db

    if [[ ${#clients[@]} -eq 0 ]]; then
        show_info "Nenhum cliente encontrado."
        return
    fi

    local selected_client
    selected_client=$(show_menu "Selecionar Cliente" "${clients[@]}")

    if [[ -n "$selected_client" ]] && [[ -f "/etc/wireguard/clients/${selected_client}.conf" ]]; then
        local qr_file="/tmp/wireguard_${selected_client}_qr.txt"
        qrencode -t ansiutf8 < "/etc/wireguard/clients/${selected_client}.conf" > "$qr_file"
        whiptail --title "QR Code - $selected_client" --textbox "$qr_file" 25 80
        rm -f "$qr_file"
    fi
}

remove_wireguard_client() {
    if [[ ! -f /etc/wireguard/clients.db ]]; then
        show_info "Nenhum cliente configurado."
        return
    fi

    local clients=()
    while IFS=':' read -r name ip pubkey date; do
        clients+=("$name" "$ip")
    done < /etc/wireguard/clients.db

    if [[ ${#clients[@]} -eq 0 ]]; then
        show_info "Nenhum cliente encontrado."
        return
    fi

    local selected_client
    selected_client=$(show_menu "Remover Cliente" "${clients[@]}")

    if [[ -n "$selected_client" ]]; then
        if ask_yes_no "Tem certeza que deseja remover o cliente '$selected_client'?"; then
            # Remover peer do servidor
            local client_pubkey
            client_pubkey=$(grep "^${selected_client}:" /etc/wireguard/clients.db | cut -d: -f3)

            # Remover seção do peer do wg0.conf
            sed -i "/# Cliente: $selected_client/,/^$/d" /etc/wireguard/wg0.conf

            # Remover arquivos do cliente
            rm -f "/etc/wireguard/clients/${selected_client}.conf"
            rm -f "/etc/wireguard/keys/${selected_client}_private.key"
            rm -f "/etc/wireguard/keys/${selected_client}_public.key"

            # Remover da base de dados
            sed -i "/^${selected_client}:/d" /etc/wireguard/clients.db

            # Reiniciar WireGuard
            systemctl restart wg-quick@wg0

            log_message "Cliente WireGuard '$selected_client' removido"
            show_info "Cliente '$selected_client' removido com sucesso!"
        fi
    fi
}

show_client_config() {
    if [[ ! -f /etc/wireguard/clients.db ]]; then
        show_info "Nenhum cliente configurado."
        return
    fi

    local clients=()
    while IFS=':' read -r name ip pubkey date; do
        clients+=("$name" "$ip")
    done < /etc/wireguard/clients.db

    if [[ ${#clients[@]} -eq 0 ]]; then
        show_info "Nenhum cliente encontrado."
        return
    fi

    local selected_client
    selected_client=$(show_menu "Mostrar Configuração" "${clients[@]}")

    if [[ -n "$selected_client" ]] && [[ -f "/etc/wireguard/clients/${selected_client}.conf" ]]; then
        whiptail --title "Configuração - $selected_client" --textbox "/etc/wireguard/clients/${selected_client}.conf" 20 70
    fi
}

# =============================================================================
# CLOUDFLARE TUNNEL
# =============================================================================

install_cloudflare() {
    log_message "Instalando Cloudflare Tunnel..."

    # Detectar arquitetura
    local arch
    case "$(uname -m)" in
        x86_64) arch="amd64" ;;
        armv7l) arch="arm" ;;
        aarch64) arch="arm64" ;;
        *) arch="arm" ;;
    esac

    # Baixar cloudflared
    wget -O /tmp/cloudflared "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}"
    chmod +x /tmp/cloudflared
    mv /tmp/cloudflared /usr/local/bin/cloudflared

    # Verificar instalação
    if ! cloudflared --version; then
        show_error "Erro na instalação do cloudflared"
        return 1
    fi

    log_message "Cloudflared instalado"
}

configure_cloudflare() {
    local domain tunnel_name

    show_info "Configuração do Cloudflare Tunnel\n\nVocê precisará:\n1. Conta no Cloudflare (gratuita)\n2. Domínio configurado no Cloudflare\n3. Fazer login no navegador durante o processo"

    domain=$(get_input "Configuração Cloudflare" "Seu domínio (ex: exemplo.com):" "")
    if [[ -z "$domain" ]]; then
        show_error "Domínio é obrigatório"
        return 1
    fi

    tunnel_name=$(get_input "Nome do Tunnel" "Nome do tunnel:" "boxserver")
    if [[ -z "$tunnel_name" ]]; then
        tunnel_name="boxserver"
    fi

    show_info "Faça login no Cloudflare. Uma janela do navegador será aberta."

    # Login no Cloudflare
    if ! cloudflared tunnel login; then
        show_error "Erro no login do Cloudflare"
        return 1
    fi

    # Criar tunnel
    if ! cloudflared tunnel create "$tunnel_name"; then
        show_error "Erro ao criar tunnel"
        return 1
    fi

    # Obter UUID do tunnel
    local tunnel_uuid
    tunnel_uuid=$(cloudflared tunnel list | grep "$tunnel_name" | awk '{print $1}')

    if [[ -z "$tunnel_uuid" ]]; then
        show_error "Não foi possível obter UUID do tunnel"
        return 1
    fi

    # Configurar DNS
    local subdomains=("pihole" "admin" "vpn")
    for subdomain in "${subdomains[@]}"; do
        if ask_yes_no "Configurar subdomínio ${subdomain}.${domain}?"; then
            cloudflared tunnel route dns "$tunnel_name" "${subdomain}.${domain}"
            log_message "DNS configurado: ${subdomain}.${domain}"
        fi
    done

    # Criar configuração
    mkdir -p /etc/cloudflared

    cat > /etc/cloudflared/config.yml <<EOF
tunnel: $tunnel_name
credentials-file: /root/.cloudflared/${tunnel_uuid}.json

ingress:
  # Pi-hole Admin Interface
  - hostname: pihole.${domain}
    service: http://localhost:${PIHOLE_PORT}
    originRequest:
      httpHostHeader: pihole.${domain}

  # Admin Panel
  - hostname: admin.${domain}
    service: http://localhost:${PIHOLE_PORT}
    originRequest:
      httpHostHeader: admin.${domain}

  # VPN Management (se configurado)
  - hostname: vpn.${domain}
    service: http://localhost:8080
    originRequest:
      httpHostHeader: vpn.${domain}

  # Catch-all rule (obrigatório)
  - service: http_status:404
EOF

    # Copiar credenciais
    cp "/root/.cloudflared/${tunnel_uuid}.json" /etc/cloudflared/

    # Ajustar permissões
    chown root:root /etc/cloudflared/config.yml
    chmod 600 /etc/cloudflared/config.yml
    chmod 600 /etc/cloudflared/*.json

    # Instalar como serviço
    cloudflared service install --config /etc/cloudflared/config.yml

    # Iniciar serviço
    systemctl start cloudflared
    systemctl enable cloudflared

    # Configurar Pi-hole para Cloudflare
    pihole -w cloudflare.com cloudflareinsights.com cloudflarestream.com cloudflarestatus.com
    pihole restartdns

    # Salvar configuração
    echo "CLOUDFLARE_DOMAIN=$domain" >> "$CONFIG_DIR/config.conf"
    echo "CLOUDFLARE_TUNNEL=$tunnel_name" >> "$CONFIG_DIR/config.conf"

    log_message "Cloudflare Tunnel configurado: $tunnel_name"
    show_info "Cloudflare Tunnel configurado!\n\nDomínios disponíveis:\n- https://pihole.${domain}\n- https://admin.${domain}\n- https://vpn.${domain}"
}

# =============================================================================
# FINALIZAÇÃO E TESTES
# =============================================================================

finalize_firewall() {
    log_message "Finalizando configuração do firewall..."

    if ! load_config; then
        show_error "Configuração não encontrada."
        return 1
    fi

    # Permitir portas específicas
    ufw allow "$WIREGUARD_PORT"/udp comment "WireGuard VPN"

    if ask_yes_no "Permitir acesso externo ao Pi-hole na porta $PIHOLE_PORT?"; then
        ufw allow "$PIHOLE_PORT" comment "Pi-hole Web"
    fi

    # Habilitar firewall
    ufw --force enable

    log_message "Firewall habilitado e configurado"
}

setup_monitoring() {
    log_message "Configurando monitoramento..."

    # Script de saúde do sistema
    cat > /usr/local/bin/boxserver-health <<'EOF'
#!/bin/bash
# Script de monitoramento de saúde do BoxServer

echo "==========================================="
echo "    RELATÓRIO DE SAÚDE DO BOXSERVER"
echo "==========================================="
echo "Data: $(date)"
echo

# Informações do sistema
echo "=== SISTEMA ==="
echo "Uptime: $(uptime -p)"
echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
echo "Memória: $(free -h | awk 'NR==2{printf "%.1f%% (%s/%s)", $3*100/$2, $3, $2}')"
echo "Disco: $(df -h / | awk 'NR==2{printf "%s usado de %s (%s)", $3, $2, $5}')"
if [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
    echo "Temperatura CPU: $(($(cat /sys/class/thermal/thermal_zone0/temp)/1000))°C"
fi
echo

# Status dos serviços
echo "=== SERVIÇOS ==="
services=("pihole-FTL" "unbound" "wg-quick@wg0" "rng-tools" "haveged" "chrony" "cloudflared")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "✅ $service: ATIVO"
    elif systemctl list-unit-files "$service.service" --no-legend | grep -q "$service"; then
        echo "❌ $service: INATIVO"
    fi
done
echo

# Testes de conectividade
echo "=== CONECTIVIDADE ==="
echo "Entropia: $(cat /proc/sys/kernel/random/entropy_avail)"
echo "DNS Pi-hole: $(timeout 5 dig @127.0.0.1 google.com +short | head -1 || echo 'FALHOU')"
if [[ -f /etc/boxserver/config.conf ]]; then
    source /etc/boxserver/config.conf
    echo "DNS Unbound: $(timeout 5 dig @127.0.0.1 -p ${UNBOUND_PORT:-5335} google.com +short | head -1 || echo 'FALHOU')"
fi
echo "Internet: $(timeout 5 ping -c 1 8.8.8.8 >/dev/null 2>&1 && echo 'OK' || echo 'FALHOU')"

# WireGuard
if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
    echo "VPN Ativa: SIM"
    if command -v wg >/dev/null; then
        echo "VPN Clientes: $(wg show wg0 peers 2>/dev/null | wc -l)"
    fi
else
    echo "VPN Ativa: NÃO"
fi

# Cloudflare Tunnel
if systemctl is-active --quiet cloudflared 2>/dev/null; then
    echo "Cloudflare Tunnel: ATIVO"
    if command -v cloudflared >/dev/null 2>&1; then
        echo "Tunnels: $(cloudflared tunnel list 2>/dev/null | grep -c 'HEALTHY' || echo '0')"
    fi
else
    echo "Cloudflare Tunnel: INATIVO"
fi
echo

# Alertas
echo "=== ALERTAS ==="
RAM_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [[ $RAM_USAGE -gt 80 ]]; then
    echo "⚠️  Uso de RAM alto: ${RAM_USAGE}%"
fi

DISK_USAGE=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
if [[ $DISK_USAGE -gt 85 ]]; then
    echo "⚠️  Uso de disco alto: ${DISK_USAGE}%"
fi

ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail)
if [[ $ENTROPY -lt 1000 ]]; then
    echo "⚠️  Entropia baixa: $ENTROPY"
fi

if [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
    TEMP=$(($(cat /sys/class/thermal/thermal_zone0/temp)/1000))
    if [[ $TEMP -gt 75 ]]; then
        echo "⚠️  Temperatura alta: ${TEMP}°C"
    fi
fi

echo "==========================================="
EOF

    chmod +x /usr/local/bin/boxserver-health

    # Script de limpeza
    cat > /etc/cron.weekly/cleanup-boxserver <<'EOF'
#!/bin/bash
# Script de limpeza automática do Boxserver

# Limpeza de pacotes
apt autoremove --purge -y
apt clean

# Limpeza de logs (manter últimos 7 dias)
journalctl --vacuum-time=7d

# Limpeza de logs do Pi-hole (manter últimos 30 dias)
find /var/log -name "pihole*.log*" -mtime +30 -delete 2>/dev/null

# Verificar espaço em disco
df -h > /var/log/disk-usage.log

# Verificar entropia
echo "Entropia: $(cat /proc/sys/kernel/random/entropy_avail)" >> /var/log/system-health.log

echo "Limpeza concluída em $(date)" >> /var/log/cleanup.log
EOF

    chmod +x /etc/cron.weekly/cleanup-boxserver

    # Agendar relatório de saúde diário
    echo "0 8 * * * root /usr/local/bin/boxserver-health >> /var/log/boxserver-health.log" >> /etc/crontab

    # Configurar logrotate para Pi-hole
    cat > /etc/logrotate.d/pihole <<'EOF'
/var/log/pihole.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 pihole pihole
    postrotate
        systemctl reload pihole-FTL
    endscript
}
EOF

    log_message "Monitoramento configurado"
}

run_final_tests() {
    log_message "Executando testes finais..."

    local failed_tests=()

    # Testar serviços
    echo "Testando serviços..."
    local services=("pihole-FTL" "unbound" "chrony")

    if systemctl list-unit-files | grep -q "wg-quick@wg0"; then
        services+=("wg-quick@wg0")
    fi

    if systemctl list-unit-files | grep -q "cloudflared"; then
        services+=("cloudflared")
    fi

    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            failed_tests+=("Serviço $service não está ativo")
        fi
    done

    # Testar DNS
    echo "Testando DNS..."
    if ! timeout 5 dig @127.0.0.1 google.com +short >/dev/null; then
        failed_tests+=("Pi-hole DNS não está funcionando")
    fi

    if [[ -f /etc/boxserver/config.conf ]]; then
        source /etc/boxserver/config.conf
        if ! timeout 5 dig @127.0.0.1 -p "${UNBOUND_PORT:-5335}" google.com +short >/dev/null; then
            failed_tests+=("Unbound DNS não está funcionando")
        fi
    fi

    # Testar conectividade
    echo "Testando conectividade..."
    if ! timeout 10 ping -c 3 8.8.8.8 >/dev/null; then
        failed_tests+=("Sem conectividade com internet")
    fi

    # Verificar entropia
    local entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    if [[ $entropy -lt 1000 ]]; then
        failed_tests+=("Entropia baixa: $entropy")
    fi

    # Mostrar resultados
    if [[ ${#failed_tests[@]} -eq 0 ]]; then
        show_info "✅ TODOS OS TESTES PASSARAM!\n\nBoxServer está funcionando corretamente."
        log_message "Testes finais: SUCESSO"
    else
        local failures
        failures=$(printf "❌ %s\n" "${failed_tests[@]}")
        show_error "ALGUNS TESTES FALHARAM:\n\n$failures"
        log_message "Testes finais: FALHAS - ${failed_tests[*]}"
        return 1
    fi
}

# =============================================================================
# INSTALAÇÃO COMPLETA
# =============================================================================

full_installation() {
    log_message "Iniciando instalação completa do BoxServer"

    local steps=(
        "Verificação do sistema"
        "Instalação de ferramentas básicas"
        "Configuração de entropia"
        "Sincronização temporal"
        "Otimizações do sistema"
        "Firewall básico"
        "Unbound DNS"
        "Pi-hole"
        "WireGuard VPN"
        "Cloudflare Tunnel (opcional)"
        "Finalização do firewall"
        "Monitoramento"
        "Testes finais"
    )

    local total_steps=${#steps[@]}
    local current_step=0

    for step in "${steps[@]}"; do
        current_step=$((current_step + 1))
        echo "[$current_step/$total_steps] $step..." | tee -a "$LOG_FILE"

        case "$step" in
            "Verificação do sistema")
                check_hardware || return 1
                ;;
            "Instalação de ferramentas básicas")
                install_basic_tools || return 1
                ;;
            "Configuração de entropia")
                install_entropy || return 1
                ;;
            "Sincronização temporal")
                install_ntp || return 1
                ;;
            "Otimizações do sistema")
                optimize_system || return 1
                ;;
            "Firewall básico")
                setup_basic_firewall || return 1
                ;;
            "Unbound DNS")
                install_unbound || return 1
                ;;
            "Pi-hole")
                install_pihole || return 1
                ;;
            "WireGuard VPN")
                install_wireguard || return 1
                ;;
            "Cloudflare Tunnel (opcional)")
                if ask_yes_no "Deseja configurar Cloudflare Tunnel para acesso remoto seguro?"; then
                    install_cloudflare && configure_cloudflare
                fi
                ;;
            "Finalização do firewall")
                finalize_firewall || return 1
                ;;
            "Monitoramento")
                setup_monitoring || return 1
                ;;
            "Testes finais")
                run_final_tests || return 1
                ;;
        esac
    done

    show_info "🎉 INSTALAÇÃO COMPLETA!\n\nBoxServer foi instalado e configurado com sucesso.\n\nExecute: sudo boxserver-setup\nPara gerenciar o sistema."
    log_message "Instalação completa finalizada com sucesso"
}

# =============================================================================
# MENU PRINCIPAL
# =============================================================================

show_main_menu() {
    local choice
    choice=$(show_menu "$SCRIPT_NAME v$SCRIPT_VERSION" \
        "1" "Instalação completa" \
        "2" "Configuração inicial" \
        "3" "Instalar componente específico" \
        "4" "Gerenciar WireGuard" \
        "5" "Diagnóstico do sistema" \
        "6" "Ver logs" \
        "7" "Backup/Restaurar configuração" \
        "8" "Desinstalar serviços" \
        "0" "Sair")

    echo "$choice"
}

component_menu() {
    local choice
    choice=$(show_menu "Instalar Componente" \
        "1" "Pi-hole" \
        "2" "Unbound DNS" \
        "3" "WireGuard VPN" \
        "4" "Cloudflare Tunnel" \
        "5" "Entropia (RNG-tools)" \
        "6" "NTP (Chrony)" \
        "7" "Monitoramento" \
        "0" "Voltar")

    case $choice in
        1) install_pihole ;;
        2) install_unbound ;;
        3) install_wireguard ;;
        4) install_cloudflare && configure_cloudflare ;;
        5) install_entropy ;;
        6) install_ntp ;;
        7) setup_monitoring ;;
    esac
}

show_logs() {
    local choice
    choice=$(show_menu "Visualizar Logs" \
        "1" "Log do BoxServer Setup" \
        "2" "Log do Pi-hole" \
        "3" "Log do Unbound" \
        "4" "Log do WireGuard" \
        "5" "Log do Cloudflared" \
        "6" "Log do Sistema" \
        "0" "Voltar")

    case $choice in
        1)
            if [[ -f "$LOG_FILE" ]]; then
                whiptail --title "Log BoxServer Setup" --textbox "$LOG_FILE" 25 80
            else
                show_info "Arquivo de log não encontrado."
            fi
            ;;
        2)
            if [[ -f /var/log/pihole.log ]]; then
                whiptail --title "Log Pi-hole" --textbox /var/log/pihole.log 25 80
            else
                show_info "Log do Pi-hole não encontrado."
            fi
            ;;
        3)
            journalctl -u unbound --no-pager > /tmp/unbound.log
            whiptail --title "Log Unbound" --textbox /tmp/unbound.log 25 80
            rm -f /tmp/unbound.log
            ;;
        4)
            journalctl -u wg-quick@wg0 --no-pager > /tmp/wireguard.log
            whiptail --title "Log WireGuard" --textbox /tmp/wireguard.log 25 80
            rm -f /tmp/wireguard.log
            ;;
        5)
            journalctl -u cloudflared --no-pager > /tmp/cloudflared.log
            whiptail --title "Log Cloudflared" --textbox /tmp/cloudflared.log 25 80
            rm -f /tmp/cloudflared.log
            ;;
        6)
            journalctl --no-pager -n 100 > /tmp/system.log
            whiptail --title "Log do Sistema" --textbox /tmp/system.log 25 80
            rm -f /tmp/system.log
            ;;
    esac
}

backup_restore_menu() {
    local choice
    choice=$(show_menu "Backup/Restaurar" \
        "1" "Criar backup completo" \
        "2" "Restaurar backup" \
        "3" "Listar backups" \
        "4" "Remover backup" \
        "0" "Voltar")

    case $choice in
        1) create_backup ;;
        2) restore_backup ;;
        3) list_backups ;;
        4) remove_backup ;;
    esac
}

create_backup() {
    local backup_name backup_file

    backup_name=$(get_input "Criar Backup" "Nome do backup:" "backup-$(date +%Y%m%d-%H%M%S)")
    if [[ -z "$backup_name" ]]; then
        backup_name="backup-$(date +%Y%m%d-%H%M%S)"
    fi

    backup_file="$BACKUP_DIR/${backup_name}.tar.gz"

    echo "Criando backup..." | tee -a "$LOG_FILE"

    # Criar arquivo de backup
    tar -czf "$backup_file" \
        /etc/pihole/ \
        /etc/unbound/unbound.conf.d/ \
        /etc/wireguard/ \
        /etc/cloudflared/ \
        /etc/boxserver/ \
        2>/dev/null

    if [[ -f "$backup_file" ]]; then
        show_info "Backup criado com sucesso!\nArquivo: $backup_file"
        log_message "Backup criado: $backup_file"
    else
        show_error "Erro ao criar backup"
        return 1
    fi
}

list_backups() {
    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z "$(ls -A "$BACKUP_DIR")" ]]; then
        show_info "Nenhum backup encontrado."
        return
    fi

    local backup_list
    backup_list="Backups disponíveis:\n\n"

    for backup in "$BACKUP_DIR"/*.tar.gz; do
        if [[ -f "$backup" ]]; then
            local filename=$(basename "$backup")
            local size=$(du -h "$backup" | cut -f1)
            local date=$(stat -c %y "$backup" | cut -d' ' -f1)
            backup_list+="$filename ($size) - $date\n"
        fi
    done

    whiptail --title "Lista de Backups" --msgbox "$backup_list" 20 70
}

system_diagnosis() {
    echo "Executando diagnóstico..." | tee -a "$LOG_FILE"

    # Executar script de saúde se existir
    if [[ -x /usr/local/bin/boxserver-health ]]; then
        /usr/local/bin/boxserver-health > /tmp/diagnosis.log 2>&1
        whiptail --title "Diagnóstico do Sistema" --textbox /tmp/diagnosis.log 25 80
        rm -f /tmp/diagnosis.log
    else
        # Diagnóstico básico
        local diag_info
        diag_info="DIAGNÓSTICO DO BOXSERVER\n"
        diag_info+="========================\n\n"
        diag_info+="Sistema: $(uname -a)\n"
        diag_info+="Uptime: $(uptime)\n"
        diag_info+="Memória: $(free -h | grep Mem)\n"
        diag_info+="Disco: $(df -h / | tail -1)\n"

        if [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
            diag_info+="CPU: $(($(cat /sys/class/thermal/thermal_zone0/temp)/1000))°C\n"
        fi

        diag_info+="\nServiços:\n"
        local services=("pihole-FTL" "unbound" "wg-quick@wg0" "cloudflared" "chrony")
        for service in "${services[@]}"; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                diag_info+="✅ $service\n"
            else
                diag_info+="❌ $service\n"
            fi
        done

        echo -e "$diag_info" > /tmp/diagnosis.log
        whiptail --title "Diagnóstico do Sistema" --textbox /tmp/diagnosis.log 25 80
        rm -f /tmp/diagnosis.log
    fi
}

# =============================================================================
# INSTALAÇÃO DO SCRIPT NO SISTEMA
# =============================================================================

install_script() {
    local install_path="/usr/local/bin/boxserver-setup"

    # Copiar script para local permanente
    cp "$0" "$install_path"
    chmod +x "$install_path"

    # Criar link simbólico para facilitar
    ln -sf "$install_path" /usr/local/bin/boxserver

    log_message "Script instalado em $install_path"
    show_info "Script instalado com sucesso!\n\nExecute: sudo boxserver-setup\nou: sudo boxserver\n\nPara acessar este menu."
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    # Verificações iniciais
    check_root
    check_internet || exit 1
    create_directories

    # Verificar se é primeira execução
    if [[ ! -f "$CONFIG_DIR/config.conf" ]]; then
        show_info "Bem-vindo ao BoxServer Setup!\n\nEste é um script completo para instalação e configuração de:\n- Pi-hole (bloqueio de anúncios)\n- Unbound (DNS recursivo)\n- WireGuard (VPN)\n- Cloudflare Tunnel\n- Monitoramento\n\nVamos começar!"

        configure_system_settings || exit 1

        if ask_yes_no "Deseja instalar o script permanentemente no sistema?"; then
            install_script
        fi
    else
        load_config
    fi

    # Menu principal
    while true; do
        choice=$(show_main_menu)

        case $choice in
            1)
                if ask_yes_no "Deseja executar a instalação completa do BoxServer?\n\nIsso instalará todos os componentes automaticamente."; then
                    full_installation
                fi
                ;;
            2)
                configure_system_settings
                ;;
            3)
                component_menu
                ;;
            4)
                manage_wireguard_clients
                ;;
            5)
                system_diagnosis
                ;;
            6)
                show_logs
                ;;
            7)
                backup_restore_menu
                ;;
            8)
                if ask_yes_no "⚠️ ATENÇÃO: Isso removerá TODOS os serviços instalados!\n\nTem certeza que deseja desinstalar?"; then
                    uninstall_services
                fi
                ;;
            0)
                log_message "Script finalizado pelo usuário"
                echo "Obrigado por usar o BoxServer Setup!"
                exit 0
                ;;
            *)
                show_error "Opção inválida: $choice"
                ;;
        esac
    done
}

uninstall_services() {
    log_message "Iniciando desinstalação de serviços..."

    local services_to_remove=()

    # Verificar quais serviços estão instalados
    if systemctl list-unit-files | grep -q pihole-FTL; then
        services_to_remove+=("Pi-hole")
    fi

    if systemctl list-unit-files | grep -q unbound; then
        services_to_remove+=("Unbound")
    fi

    if systemctl list-unit-files | grep -q "wg-quick@wg0"; then
        services_to_remove+=("WireGuard")
    fi

    if systemctl list-unit-files | grep -q cloudflared; then
        services_to_remove+=("Cloudflare")
    fi

    if [[ ${#services_to_remove[@]} -eq 0 ]]; then
        show_info "Nenhum serviço do BoxServer encontrado para remover."
        return 0
    fi

    local services_list
    services_list=$(printf "- %s\n" "${services_to_remove[@]}")

    if ! ask_yes_no "Serviços encontrados para remoção:\n\n$services_list\n\nContinuar com a desinstalação?"; then
        return 0
    fi

    # Parar e desabilitar serviços
    echo "Parando serviços..." | tee -a "$LOG_FILE"
    systemctl stop pihole-FTL unbound wg-quick@wg0 cloudflared 2>/dev/null || true
    systemctl disable pihole-FTL unbound wg-quick@wg0 cloudflared 2>/dev/null || true

    # Remover pacotes
    echo "Removendo pacotes..." | tee -a "$LOG_FILE"
    apt remove --purge -y pihole unbound wireguard wireguard-tools 2>/dev/null || true

    # Remover cloudflared
    rm -f /usr/local/bin/cloudflared

    # Remover arquivos de configuração
    echo "Removendo arquivos de configuração..." | tee -a "$LOG_FILE"
    rm -rf /etc/pihole /etc/unbound/unbound.conf.d/pi-hole.conf
    rm -rf /etc/wireguard /etc/cloudflared
    rm -rf /usr/local/bin/boxserver-health
    rm -f /etc/cron.weekly/cleanup-boxserver
    rm -f /etc/cron.hourly/check-temp

    # Remover configurações do sistema
    sed -i '/# Otimizações BoxServer/,$d' /etc/sysctl.conf 2>/dev/null || true

    # Resetar firewall
    ufw --force reset 2>/dev/null || true

    # Limpeza final
    apt autoremove --purge -y
    apt autoclean

    show_info "Desinstalação concluída!\n\nTodos os serviços do BoxServer foram removidos."
    log_message "Desinstalação concluída com sucesso"
}

# Executar função principal se script for executado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
