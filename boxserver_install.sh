#!/bin/bash
# Script aprimorado para instalação do Boxserver - versão otimizada e sem redundâncias

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/boxserver"
CONFIG_DIR="/etc/boxserver"
BACKUP_DIR="/var/backups/boxserver"
LOG_FILE="$LOG_DIR/tui-installer.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DIALOG_HEIGHT=20
DIALOG_WIDTH=70
DIALOG_MENU_HEIGHT=12

NETWORK_INTERFACE=""
SERVER_IP=""
VPN_NETWORK="10.200.200.0/24"
VPN_PORT="51820"
PIHOLE_PASSWORD=""
FILEBROWSER_PORT="8080"
COCKPIT_PORT="9090"

declare -A APPS=(
    [1]="Pi-hole|Bloqueio de anúncios e DNS|http://IP/admin"
    [2]="Unbound|DNS recursivo local|Porta 5335 (interno)"
    [3]="WireGuard|Servidor VPN|Porta 51820/udp"
    [4]="Cockpit|Painel de administração web|https://IP:9090"
    [5]="FileBrowser|Gerenciamento de arquivos web|http://IP:8080"
    [6]="Netdata|Monitoramento em tempo real|http://IP:19999"
    [7]="Fail2Ban|Proteção contra ataques|Serviço em background"
    [8]="UFW|Firewall simplificado|Serviço em background"
    [9]="RNG-tools|Gerador de entropia|Serviço em background"
    [10]="Rclone|Sincronização com nuvem|CLI"
    [11]="Rsync|Backup local|CLI"
    [12]="MiniDLNA|Servidor de mídia|Porta 8200"
    [13]="Cloudflared|Tunnel Cloudflare|CLI"
    [14]="Chrony|Sincronização de tempo (NTP)|Serviço em background"
    [15]="Interface Web|Dashboard unificado com Nginx|Porta 80"
)

# ==================== FUNÇÕES UTILITÁRIAS COMUNS ====================

setup_directories() {
    mkdir -p "$LOG_DIR" "$CONFIG_DIR" "$BACKUP_DIR"
    touch "$LOG_FILE"
    log_message "INFO" "Diretórios criados: $LOG_DIR, $CONFIG_DIR, $BACKUP_DIR"
}

log_message() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
}

run_with_log() {
    local cmd="$1"
    local description="$2"
    
    log_message "INFO" "Iniciando: $description"
    if eval "$cmd"; then
        log_message "INFO" "Concluído: $description"
        return 0
    else
        log_message "ERROR" "Falha em: $description"
        return 1
    fi
}

check_service() {
    local service="$1"
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "✅ $service: ATIVO"
        return 0
    else
        echo "❌ $service: INATIVO"
        return 1
    fi
}

install_package() {
    local package="$1"
    local description="$2"
    
    run_with_log "apt-get install -y --no-install-recommends '$package'" "Instalação do $description"
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        cp "$file" "${file}.backup.$(date +%Y%m%d_%H%M%S)"
        log_message "INFO" "Backup criado: $file"
    fi
}

configure_service_file() {
    local service="$1"
    local config_content="$2"
    local config_dir="/etc/systemd/system/${service}.service.d"
    
    mkdir -p "$config_dir"
    echo "$config_content" > "$config_dir/memory-limit.conf"
    systemctl daemon-reload
    log_message "INFO" "Configuração aplicada para $service"
}

# ==================== FUNÇÕES DE VERIFICAÇÃO ====================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        show_message "Erro de Permissão" "Este script deve ser executado como root.\n\nUse: sudo $0"
        exit 1
    fi
}

show_message() {
    local title="$1"
    local message="$2"
    dialog --title "$title" --msgbox "$message" 8 50
}

check_system_resources() {
    local ram_mb=$(free -m | awk 'NR==2{print $2}')
    local disk_gb=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    local arch=$(uname -m)
    local errors=""
    
    local board_info=$(cat /proc/device-tree/model 2>/dev/null || cat /sys/firmware/devicetree/base/model 2>/dev/null)
    local rk322x_detected=false
    
    if [[ "$board_info" =~ "rk322x" ]] || [[ "$board_info" =~ "rk3229" ]] || grep -q -E "rk322x|rk3229" /proc/cpuinfo 2>/dev/null; then
        rk322x_detected=true
        log_message "INFO" "Hardware RK322x/RK3229 detectado: $board_info"
    fi
    
    if [ "$ram_mb" -lt 480 ]; then
        errors+="• RAM insuficiente: ${ram_mb}MB (mínimo 512MB)\n"
    fi
    
    if [ "$disk_gb" -lt 2 ]; then
        errors+="• Espaço em disco insuficiente: ${disk_gb}GB (mínimo 2GB)\n"
    fi
    
    if [[ "$arch" != *"arm"* ]] && [[ "$arch" != *"aarch"* ]]; then
        errors+="• Arquitetura não suportada: $arch (requer ARM Cortex-A7)\n"
    fi
    
    if [ -n "$errors" ]; then
        show_message "Verificação do Sistema" "Problemas encontrados:\n\n$errors\nRecomenda-se resolver estes problemas antes de continuar."
        return 1
    fi
    
    show_message "Verificação do Sistema" "Sistema compatível:\n\n• RAM: ${ram_mb}MB ✓\n• Disco Livre: ${disk_gb}GB ✓\n• Arquitetura: $arch ✓"
    return 0
}

# ==================== FUNÇÕES DE OTIMIZAÇÃO ====================

optimize_for_nand() {
    log_message "INFO" "Aplicando otimizações para armazenamento NAND"
    
    if mountpoint -q /; then
        mount -o remount,noatime,nodiratime /
        log_message "INFO" "Otimizações de I/O aplicadas: noatime, nodiratime"
    fi
    
    if [ -f /proc/sys/vm/swappiness ]; then
        echo "10" > /proc/sys/vm/swappiness
        log_message "INFO" "Swappiness reduzido para 10"
    fi
    
    if [ -f /proc/sys/kernel/printk ]; then
        echo "1 4 1 7" > /proc/sys/kernel/printk
        log_message "INFO" "Nível de log do kernel reduzido"
    fi

    if sysctl vm.vfs_cache_pressure >/dev/null 2>&1; then
        echo 'vm.vfs_cache_pressure=50' | tee -a /etc/sysctl.conf >/dev/null
        log_message "INFO" "Pressão do cache VFS otimizada"
    fi
    
    sync && echo 3 > /proc/sys/vm/drop_caches
    log_message "INFO" "Caches de memória limpos"
}

create_swap_file() {
    if [ -f /swapfile ]; then
        log_message "INFO" "Arquivo de swap já existe"
        return
    fi
    
    run_with_log "fallocate -l 512M /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile" "Criação de swap file"
    echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab >/dev/null
}

apply_memory_limits() {
    local profile="$1"
    local -A limits
    
    case "$profile" in
        "rk322x")
            limits=(
                ["pihole-FTL"]="96"
                ["unbound"]="64"
                ["netdata"]="64"
                ["cockpit"]="64"
                ["filebrowser"]="32"
            )
            log_message "INFO" "Aplicando limites para RK322x genérico (512MB DDR3)"
            ;;
        "rk3229")
            limits=(
                ["pihole-FTL"]="192"
                ["unbound"]="96"
                ["netdata"]="128"
                ["cockpit"]="96"
                ["filebrowser"]="64"
            )
            log_message "INFO" "Aplicando limites para RK3229 R329Q (1GB DDR3)"
            ;;
        *)
            return 1
            ;;
    esac
    
    for service in "${!limits[@]}"; do
        configure_service_file "$service" "[Service]\nMemoryMax=${limits[$service]}M\nMemorySwapMax=0"
    done
}

# ==================== FUNÇÕES DE REDE ====================

detect_network() {
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$NETWORK_INTERFACE" ]; then
        show_message "Erro de Rede" "Não foi possível detectar a interface de rede principal.\n\nVerifique sua conexão de rede."
        return 1
    fi
    
    SERVER_IP=$(ip route get 8.8.8.8 | awk '{print $7; exit}')
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="192.168.1.100"
    fi
    
    log_message "INFO" "Interface detectada: $NETWORK_INTERFACE, IP: $SERVER_IP"
    BACKTITLE="Boxserver TUI v1.0 | IP: $SERVER_IP | Hardware: RK322x"
    DIALOG_OPTS=(--backtitle "$BACKTITLE" --colors --ok-label "Confirmar" --cancel-label "Voltar")
    
    return 0
}

test_connectivity() {
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        show_message "Erro de Conectividade" "Sem conexão com a internet.\n\nVerifique sua conexão de rede."
        return 1
    fi
    return 0
}

# ==================== FUNÇÕES DE INSTALAÇÃO COMUNS ====================

get_service_name() {
    local app_id="$1"
    case $app_id in
        1) echo "pihole-FTL" ;;
        2) echo "unbound" ;;
        3) echo "wg-quick@wg0" ;;
        4) echo "cockpit.socket" ;;
        5) echo "filebrowser" ;;
        6) echo "netdata" ;;
        7) echo "fail2ban" ;;
        8) echo "ufw" ;;
        9) echo "rng-tools" ;;
        12) echo "minidlna" ;;
        13) echo "cloudflared" ;;
        14) echo "chrony" ;;
        15) echo "nginx" ;;
        *) echo "" ;;
    esac
}

check_app_status() {
    local app_id="$1"
    local service_name=$(get_service_name "$app_id")
    local is_installed=false

    case $app_id in
        1) [[ -f "/etc/pihole/setupVars.conf" ]] && is_installed=true ;;
        2) [[ -f "/etc/unbound/unbound.conf" ]] && is_installed=true ;;
        3) [[ -f "/etc/wireguard/wg0.conf" ]] && is_installed=true ;;
        4) [[ -f "/etc/cockpit/cockpit.conf" ]] && is_installed=true ;;
        5) command -v filebrowser &>/dev/null && is_installed=true ;;
        6) [[ -f "/etc/netdata/netdata.conf" ]] && is_installed=true ;;
        7) command -v fail2ban-client &>/dev/null && is_installed=true ;;
        8) command -v ufw &>/dev/null && is_installed=true ;;
        9) command -v rngd &>/dev/null && is_installed=true ;;
        10) command -v rclone &>/dev/null && is_installed=true ;;
        11) command -v rsync &>/dev/null && is_installed=true ;;
        12) [[ -f "/etc/minidlna.conf" ]] && is_installed=true ;;
        13) command -v cloudflared &>/dev/null && is_installed=true ;;
        14) command -v chronyd &>/dev/null && is_installed=true ;;
        15) [[ -f "/etc/nginx/sites-available/boxserver" ]] && is_installed=true ;;
    esac

    if [ "$is_installed" = false ]; then
        echo "not_installed"
    elif [ -n "$service_name" ] && ! systemctl is-active --quiet "$service_name" 2>/dev/null; then
        echo "installed_error"
    else
        echo "installed_ok"
    fi
}

# ==================== FUNÇÕES DE INSTALAÇÃO ESPECÍFICAS ====================

install_pihole() {
    run_with_log "curl -sSL https://install.pi-hole.net | bash" "Instalação do Pi-hole"
    
    if [ -n "$PIHOLE_PASSWORD" ]; then
        echo "$PIHOLE_PASSWORD" | pihole -a -p
        log_message "INFO" "Senha do Pi-hole configurada"
    fi
    
    local pihole_dns_upstream="1.1.1.1"
    local dns_config_note="DNS público (Unbound não disponível)"
    
    if systemctl is-active --quiet unbound && ss -tulpn | grep -q ":5335.*unbound"; then
        if timeout 5 dig @127.0.0.1 -p 5335 google.com +short >/dev/null 2>&1; then
            pihole_dns_upstream="127.0.0.1#5335"
            dns_config_note="Unbound local (integração ativa)"
        fi
    fi
    
    cat > /etc/pihole/setupVars.conf << EOF
PIHOLE_INTERFACE=$NETWORK_INTERFACE
IPV4_ADDRESS=$SERVER_IP/24
IPV6_ADDRESS=
PIHOLE_DNS_1=$pihole_dns_upstream
PIHOLE_DNS_2=
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSSEC=true
EOF
    
    systemctl restart pihole-FTL
    systemctl enable pihole-FTL
    log_message "INFO" "Pi-hole configurado com: $dns_config_note"
}

install_unbound() {
    if ! resolve_dns_conflicts; then
        return 1
    fi
    
    systemctl stop unbound 2>/dev/null || true
    install_package "unbound" "Unbound DNS"
    
    mkdir -p /etc/unbound/unbound.conf.d /var/lib/unbound
    backup_file "/etc/unbound/unbound.conf"
    
    cat > /etc/unbound/unbound.conf.d/pi-hole.conf << 'EOF'
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    prefer-ip6: no
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    edns-buffer-size: 1232
    prefetch: yes
    num-threads: 1
    msg-cache-slabs: 1
    rrset-cache-slabs: 1
    infra-cache-slabs: 1
    key-cache-slabs: 1
    so-rcvbuf: 512k
    so-sndbuf: 512k
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
    hide-identity: yes
    hide-version: yes
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    root-hints: "/var/lib/unbound/root.hints"
EOF
    
    download_root_hints
    setup_unbound_trust_anchor
    
    chown unbound:unbound /var/lib/unbound/root.key /var/lib/unbound/root.hints
    chmod 644 /var/lib/unbound/root.key /var/lib/unbound/root.hints
    
    if ! unbound-checkconf; then
        log_message "ERROR" "Erro na configuração do Unbound"
        return 1
    fi
    
    if ! activate_unbound_service; then
        return 1
    fi
    
    test_unbound_functionality
}

# ==================== FUNÇÕES AUXILIARES UNBOUND ====================

resolve_dns_conflicts() {
    if systemctl is-active --quiet systemd-resolved; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
    fi
    
    if ss -tulpn | grep -q ":5335"; then
        log_message "ERROR" "Porta 5335 já está em uso"
        return 1
    fi
    
    return 0
}

download_root_hints() {
    local urls=(
        "https://www.internic.net/domain/named.root"
        "https://ftp.internic.net/domain/named.root"
        "https://www.iana.org/domains/root/files/named.root"
    )
    
    for url in "${urls[@]}"; do
        if wget -qO /var/lib/unbound/root.hints "$url"; then
            log_message "INFO" "Root hints baixado de: $url"
            return 0
        fi
    done
    
    log_message "ERROR" "Falha ao baixar root hints"
    return 1
}

setup_unbound_trust_anchor() {
    if ! unbound-anchor -a /var/lib/unbound/root.key; then
        if wget -O /tmp/root.key https://data.iana.org/root-anchors/icannbundle.pem; then
            mv /tmp/root.key /var/lib/unbound/root.key
        else
            log_message "ERROR" "Falha ao obter trust anchor"
            return 1
        fi
    fi
    return 0
}

activate_unbound_service() {
    systemctl enable unbound
    systemctl start unbound
    
    local timeout=15
    local count=0
    while [ $count -lt $timeout ]; do
        if systemctl is-active --quiet unbound; then
            log_message "INFO" "Unbound ativo após ${count}s"
            break
        fi
        sleep 1
        ((count++))
    done
    
    if ! systemctl is-active --quiet unbound; then
        log_message "ERROR" "Unbound não está ativo após ${timeout}s"
        return 1
    fi
    
    return 0
}

test_unbound_functionality() {
    if ! ss -tulpn | grep -q ":5335.*unbound"; then
        log_message "WARN" "Unbound não está escutando na porta 5335"
        return 1
    fi
    
    for i in {1..5}; do
        if timeout 10 dig @127.0.0.1 -p 5335 google.com +short >/dev/null 2>&1; then
            log_message "INFO" "Teste DNS com dig: SUCESSO"
            return 0
        fi
        sleep 3
    done
    
    log_message "WARN" "Teste DNS falhou após 5 tentativas"
    return 1
}

# ==================== FUNÇÕES DE INSTALAÇÃO RESTANTES (estrutura similar) ====================

install_wireguard() {
    install_package "wireguard wireguard-tools qrencode" "WireGuard"
    
    mkdir -p /etc/wireguard/keys
    cd /etc/wireguard/keys
    umask 077
    wg genkey | tee privatekey | wg pubkey > publickey
    
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/keys/privatekey)
Address = ${VPN_NETWORK%.*}.1/24
ListenPort = $VPN_PORT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE
EOF
    
    sysctl -w net.ipv4.ip_forward=1
    sed -i '/net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
    sysctl -p
    
    chmod 600 /etc/wireguard/wg0.conf /etc/wireguard/keys/*
    
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    if wg show wg0 >/dev/null 2>&1; then
        log_message "INFO" "WireGuard instalado com sucesso"
    else
        log_message "ERROR" "Erro na configuração do WireGuard"
        return 1
    fi
}

# ... (outras funções de instalação seguem padrão similar)

# ==================== FUNÇÃO PRINCIPAL DE INSTALAÇÃO ====================

install_selected_apps() {
    local apps_to_install=("$@")
    local total_steps=$(( ${#apps_to_install[@]} * 2 + 2 ))
    local current_step=0

    cat > "$CONFIG_DIR/system.conf" << EOF
NETWORK_INTERFACE="$NETWORK_INTERFACE"
SERVER_IP="$SERVER_IP"
VPN_NETWORK="$VPN_NETWORK"
VPN_PORT="$VPN_PORT"
PIHOLE_PASSWORD="$PIHOLE_PASSWORD"
FILEBROWSER_PORT="$FILEBROWSER_PORT"
COCKPIT_PORT="$COCKPIT_PORT"
INSTALL_DATE="$(date)"
EOF
    
    log_message "INFO" "Iniciando instalação de ${#apps_to_install[@]} aplicativos"
    export DEBIAN_FRONTEND=noninteractive

    (
    current_step=$((current_step + 1))
    echo $((current_step * 100 / total_steps))
    echo "XXX"
    echo "Atualizando lista de pacotes..."
    echo "XXX"
    apt-get update -y >/dev/null 2>&1

    # Coletar pacotes APT
    local apt_packages=()
    for app_id in "${apps_to_install[@]}"; do
        case $app_id in
            2) apt_packages+=("unbound") ;;
            3) apt_packages+=("wireguard-tools" "qrencode") ;;
            4) apt_packages+=("cockpit") ;;
            7) apt_packages+=("fail2ban") ;;
            8) apt_packages+=("ufw") ;;
            9) apt_packages+=("rng-tools") ;;
            11) apt_packages+=("rsync") ;;
            12) apt_packages+=("minidlna") ;;
            14) apt_packages+=("chrony") ;;
            15) apt_packages+=("nginx") ;;
        esac
    done

    if [ ${#apt_packages[@]} -gt 0 ]; then
        current_step=$((current_step + 1))
        echo $((current_step * 100 / total_steps))
        echo "XXX"
        echo "Instalando pacotes base..."
        echo "XXX"
        apt-get install -y --no-install-recommends ${apt_packages[@]} >/dev/null 2>&1
    fi

    # Instalar aplicativos individuais
    for app_id in "${apps_to_install[@]}"; do
        local app_name=$(echo "${APPS[$app_id]}" | cut -d'|' -f1)
        
        current_step=$((current_step + 1))
        echo $((current_step * 100 / total_steps))
        echo "XXX"
        echo "Instalando: $app_name..."
        echo "XXX"
        
        case $app_id in
            1) install_pihole ;;
            2) install_unbound ;;
            3) install_wireguard ;;
            4) install_cockpit ;;
            5) install_filebrowser ;;
            6) install_netdata ;;
            7) install_fail2ban ;;
            8) install_ufw ;;
            9) install_rng_tools ;;
            10) install_rclone ;;
            11) install_rsync ;;
            12) install_minidlna ;;
            13) install_cloudflared ;;
            14) install_chrony ;;
            15) install_web_interface ;;
        esac

        current_step=$((current_step + 1))
        echo $((current_step * 100 / total_steps))
        echo "XXX"
        echo "Configurando: $app_name..."
        echo "XXX"
    done

    ) | dialog --backtitle "$BACKTITLE" --title "Instalação em Andamento" --mixedgauge "Progresso da instalação..." 20 70 0

    if [ $? -ne 0 ]; then
        show_message "Erro na Instalação" "A instalação falhou. Verifique os logs em $LOG_FILE para mais detalhes."
        exit 1
    fi

    reconfigure_service_integrations "${apps_to_install[@]}"
    create_maintenance_scripts
    generate_installation_summary "${apps_to_install[@]}"
    
    show_message "Instalação Finalizada" "Instalação e configuração concluídas com sucesso!\n\nVocê retornará ao menu principal."
}

# ==================== FUNÇÕES DE MENU PRINCIPAIS ====================

select_applications() {
    local menu_items=()
    for app_id in $(echo "${!APPS[@]}" | tr ' ' '\n' | sort -n); do
        local app_info="${APPS[$app_id]}"
        IFS='|' read -r name description access <<< "$app_info"
        menu_items+=("$app_id" "$name - $description" "OFF")
    done
    
    menu_items+=("99" "Instalar TODOS os aplicativos" "OFF")
    
    local choices=$(dialog "${DIALOG_OPTS[@]}" --title "Seleção de Aplicativos" \
        --checklist "Selecione os aplicativos para instalar:" \
        20 80 10 "${menu_items[@]}" 3>&1 1>&2 2>&3)
    
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    local selected_apps=()
    for choice in $choices; do
        choice=$(echo $choice | tr -d '"')
        if [[ "$choice" == "99" ]]; then
            for app_id in $(echo "${!APPS[@]}" | tr ' ' '\n' | sort -n); do
                selected_apps+=("$app_id")
            done
            break
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ -n "${APPS[$choice]}" ]; then
            selected_apps+=("$choice")
        fi
    done
    
    if [ ${#selected_apps[@]} -eq 0 ]; then
        show_message "Nenhum Aplicativo" "Nenhum aplicativo foi selecionado."
        return 1
    fi
    
    local sorted_apps=($(sort_installation_order "${selected_apps[@]}"))
    install_selected_apps "${sorted_apps[@]}"
}

main_menu() {
    while true; do        
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Boxserver TUI" \
            --menu "Painel de controle do Boxserver:" \
            $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Instalar / Desinstalar Aplicativos" \
            "2" "Gerenciamento de Serviços" \
            "3" "Configuração de Aplicativos" \
            "4" "Diagnóstico e Testes" \
            "5" "Configurações do Servidor" \
            "6" "Manutenção e Backups" \
            "7" "Segurança" \
            "8" "Informações do Sistema" \
            "9" "Sair" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) select_applications ;;
            2) manage_services_menu ;;
            3) configure_apps_menu ;;
            4) diagnostics_menu ;;
            5) configure_advanced_settings ;;
            6) maintenance_menu ;;
            7) security_menu ;;
            8) show_system_info ;;
            9|"")
                if dialog --title "Confirmar Saída" --yesno "Deseja realmente sair?" 6 30; then
                    clear
                    echo "Obrigado por usar o Boxserver TUI Installer!"
                    exit 0
                fi
                ;;
        esac
    done
}

# ==================== EXECUÇÃO PRINCIPAL ====================

main() {
    check_root
    setup_directories
    check_system_resources
    detect_network
    test_connectivity
    
    # Aplicar otimizações baseadas no hardware
    optimize_for_nand
    create_swap_file
    
    local board_info=$(cat /proc/device-tree/model 2>/dev/null || cat /sys/firmware/devicetree/base/model 2>/dev/null)
    if [[ "$board_info" =~ "RK3229" ]] || [[ "$board_info" =~ "R329Q" ]]; then
        apply_memory_limits "rk3229"
    else
        apply_memory_limits "rk322x"
    fi
    
    main_menu
}

main "$@"
