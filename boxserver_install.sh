#!/bin/bash
# Boxserver TUI Installer - Interface Gráfica Terminal
# Instalador automatizado para MXQ-4K com chip RK322x
# Autor: Boxserver Team
# Versão: 1.1 (Revisada)
# Data: $(date +%Y-%m-%d)

set -euo pipefail

# Configurações globais
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/boxserver"
CONFIG_DIR="/etc/boxserver"
BACKUP_DIR="/var/backups/boxserver"
LOG_FILE="$LOG_DIR/tui-installer.log"
DIALOG_HEIGHT=20
DIALOG_WIDTH=70
DIALOG_MENU_HEIGHT=12
BACKTITLE="Boxserver TUI v1.1 | IP: ${SERVER_IP:-Detectando...} | Hardware: RK322x"
DIALOG_OPTS=(--backtitle "$BACKTITLE" --colors --ok-label "Confirmar" --cancel-label "🔙 Voltar")

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variáveis globais
NETWORK_INTERFACE=""
SERVER_IP=""
VPN_NETWORK="10.200.200.0/24"
VPN_PORT="51820"
PIHOLE_PASSWORD=""
PIHOLE_PORT="8081"
FILEBROWSER_PORT="8080"
COCKPIT_PORT="9090"

# Array de aplicativos
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

# Função de logging
log_message() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
}

# Função para erro
error_exit() {
    local line_number="${BASH_LINENO[0]}"
    local error_code="${2:-1}"
    local error_message="${3:-"Erro desconhecido"}"
    log_message "ERROR" "Erro na linha $line_number com código $error_code: $error_message"
    echo "Erro fatal na linha $line_number: $error_message" >&2
    exit "$error_code"
}

# Função de limpeza
cleanup_on_exit() {
    log_message "INFO" "Realizando limpeza de recursos..."
    rm -rf "/tmp/boxserver_*" 2>/dev/null || true
    local exit_code=$?
    log_message "INFO" "Script finalizado com código de saída: $exit_code"
}

# Traps
trap 'cleanup_on_exit' EXIT
trap 'error_exit ${BASH_LINENO[0]} $? "Erro capturado"' ERR
trap 'error_exit ${BASH_LINENO[0]} 130 "Interrupção pelo usuário (SIGINT)"' INT
trap 'error_exit ${BASH_LINENO[0]} 143 "Terminação solicitada (SIGTERM)"' TERM

# Funções de validação
validate_port_number() {
    local port="$1"
    [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$port" -le 65535 ]
}

validate_ip_address() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        [ "$octet" -ge 0 ] && [ "$octet" -le 255 ] || return 1
    done
    return 0
}

validate_domain_name() {
    local domain="$1"
    [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}

validate_file_path() {
    local path="$1"
    [[ ! "$path" =~ [;|\&$\`()] ]] && [[ "$path" =~ ^(/|\.|~) ]]
}

# Criação de diretórios
setup_directories() {
    mkdir -p "$LOG_DIR" "$CONFIG_DIR" "$BACKUP_DIR"
    touch "$LOG_FILE"
    log_message "INFO" "Diretórios criados."
}

# Verificação de root
check_root() {
    [[ $EUID -eq 0 ]] || { dialog --title "Erro" --msgbox "Execute como root: sudo $0" 8 50; exit 1; }
}

# Verificação de dependências
check_dependencies() {
    local deps=("dialog" "curl" "wget" "tar" "grep" "awk" "sed" "systemctl" "apt-get" "ss" "dig" "ping")
    local missing=()
    for dep in "${deps[@]}"; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        apt-get update -q && apt-get install -y -q "${missing[@]}" || { dialog --title "Erro" --msgbox "Falha ao instalar dependências." 8 60; return 1; }
    fi
    return 0
}

# Locks
create_lock() {
    local lock_name="$1"
    local lock_file="/var/lock/boxserver-${lock_name}.lock"
    mkdir -p "/var/lock"
    if mkdir "$lock_file" 2>/dev/null; then
        echo $$ > "$lock_file/pid"
        return 0
    fi
    # Verificar lock órfão
    local lock_pid=$(cat "$lock_file/pid" 2>/dev/null)
    kill -0 "$lock_pid" 2>/dev/null || { rm -rf "$lock_file"; return 0; }
    return 1
}

remove_lock() {
    local lock_name="$1"
    local lock_file="/var/lock/boxserver-${lock_name}.lock"
    rm -rf "$lock_file"
}

# Verificações de sistema (otimizada)
check_system_resources() {
    local ram_mb=$(free -m | awk 'NR==2{print $2}')
    local disk_gb=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    local arch=$(uname -m)
    local board_info=$(cat /proc/device-tree/model 2>/dev/null || cat /sys/firmware/devicetree/base/model 2>/dev/null || grep -E "rk322x|rk3229" /proc/cpuinfo)
    [[ "$board_info" =~ rk322x|rk3229 ]] || { dialog --title "Hardware" --yesno "Hardware não RK322x. Continuar?" 8 50 || exit 1; }
    [ "$ram_mb" -ge 480 ] && [ "$disk_gb" -ge 2 ] && [[ "$arch" =~ arm|aarch ]] || { dialog --title "Recursos" --msgbox "Recursos insuficientes." 8 50; return 1; }
    return 0
}

# Otimização para NAND
optimize_for_nand() {
    mount -o remount,noatime,nodiratime / || log_message "WARN" "Falha ao remount /"
    echo 10 > /proc/sys/vm/swappiness
    echo "1 4 1 7" > /proc/sys/kernel/printk
    echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.conf
    sysctl -p
    sync; echo 3 > /proc/sys/vm/drop_caches
}

# Cria swap
create_swap_file() {
    [ -f /swapfile ] && return
    dd if=/dev/zero of=/swapfile bs=1M count=512 status=progress
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
}

# Limites de memória (consolidado)
apply_memory_limits() {
    local is_rk3229=$(grep -q "RK3229|R329Q" /proc/device-tree/model && echo true || echo false)
    local limits
    if [[ "$is_rk3229" == true ]]; then
        limits=("pihole-FTL:192" "unbound:96" "netdata:128" "cockpit:96" "filebrowser:64")
    else
        limits=("pihole-FTL:96" "unbound:64" "netdata:64" "cockpit:64" "filebrowser:32")
    fi
    for limit in "${limits[@]}"; do
        IFS=':' read -r service mem <<< "$limit"
        mkdir -p "/etc/systemd/system/${service}.service.d"
        echo "[Service]\nMemoryMax=${mem}M\nMemorySwapMax=0" > "/etc/systemd/system/${service}.service.d/memory-limit.conf"
    done
    systemctl daemon-reload
}

# Detecção de rede
detect_network_interface() {
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    [ -n "$NETWORK_INTERFACE" ] || { dialog --title "Erro" --msgbox "Interface de rede não detectada." 8 50; return 1; }
    SERVER_IP=$(ip addr show "$NETWORK_INTERFACE" | grep "inet " | awk '{print $2}' | cut -d/ -f1)
    [ -n "$SERVER_IP" ] || SERVER_IP="192.168.1.100"
    return 0
}

# Teste de conectividade
test_connectivity() {
    ping -c 1 8.8.8.8 &>/dev/null || { dialog --title "Erro" --msgbox "Sem internet." 8 50; return 1; }
    return 0
}

# Execução inicial de verificações
run_system_checks() {
    check_root
    check_system_resources || { dialog --title "Continuar?" --yesno "Problemas encontrados. Continuar?" 8 50 || exit 1; }
    detect_network_interface || exit 1
    test_connectivity || exit 1
    optimize_for_nand
    create_swap_file
    apply_memory_limits
}

# Funções de instalação (placeholders para apps, expandir conforme necessário)
install_pihole() {
    local temp_script=$(mktemp)
    curl -sSL https://install.pi-hole.net -o "$temp_script"
    bash "$temp_script" --unattended
    rm "$temp_script"
}

# ... (Adicione funções semelhantes para outros apps, seguindo o padrão seguro)

# Menu principal (simplificado)
main_menu() {
    while true; do
        local choice=$(dialog "${DIALOG_OPTS[@]}" --menu "Boxserver TUI" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            1 "Instalar Apps" 2 "Gerenciar Serviços" 3 "Configurar Apps" 4 "Diagnóstico" 5 "Configurações" 6 "Manutenção" 7 "Segurança" 8 "Info Sistema" 9 "Sobre" 10 "Sair" 3>&1 1>&2 2>&3)
        case $choice in
            1) select_applications ;;
            2) manage_services_menu ;;
            # ... (Implemente outros menus semelhantes)
            10) exit 0 ;;
        esac
    done
}

# Função principal
main() {
    setup_directories
    check_dependencies || exit 1
    run_system_checks
    main_menu
}

main "$@"
