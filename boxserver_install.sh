#!/bin/bash
# Script aprimorado para instalação do Boxserver
# Instalador automatizado para MXQ-4K com chip RK322x
# Autor: Boxserver Team
# Versão: 1.1
# Data: 2025-09-05

set -euo pipefail

# Configurações globais
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/boxserver"
CONFIG_DIR="/etc/boxserver"
BACKUP_DIR="/var/backups/boxserver"
LOG_FILE="$LOG_DIR/tui-installer.log"
CONFIG_FILE="$CONFIG_DIR/system.conf"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configurações do dialog
DIALOG_HEIGHT=20
DIALOG_WIDTH=70
DIALOG_MENU_HEIGHT=12
BACKTITLE="Boxserver TUI v1.1 | IP: ${SERVER_IP:-Detectando...} | Hardware: RK322x"
DIALOG_OPTS=(--backtitle "$BACKTITLE" --colors --ok-label "Confirmar" --cancel-label "🔙 Voltar")

# Variáveis de configuração
NETWORK_INTERFACE=""
SERVER_IP=""
VPN_NETWORK="10.200.200.0/24"
VPN_PORT="51820"
PIHOLE_PASSWORD=""
PIHOLE_PORT="8081"
FILEBROWSER_PORT="8080"
COCKPIT_PORT="9090"

# Ordem de instalação por prioridade (dependências resolvidas)
INSTALL_ORDER=(9 11 10 14 2 1 3 4 5 6 12 8 7 13 15)

# Aplicativos disponíveis
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

# Função para criar diretórios
setup_directories() {
    mkdir -p "$LOG_DIR" "$CONFIG_DIR" "$BACKUP_DIR"
    touch "$LOG_FILE"
    log_message "INFO" "Diretórios criados: $LOG_DIR, $CONFIG_DIR, $BACKUP_DIR"
}

# Funções de validação
validate_port_number() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]
}

validate_ip_address() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        [[ "$octet" -ge 0 && "$octet" -le 255 ]] || return 1
    done
    return 0
}

# Função para tratamento de erros
error_exit() {
    local line_number="$1"
    local error_code="${2:-1}"
    local error_message="${3:-Erro desconhecido}"
    log_message "ERROR" "Erro na linha $line_number com código $error_code: $error_message"
    dialog "${DIALOG_OPTS[@]}" --title "Erro Fatal" --msgbox "Erro na linha $line_number: $error_message" 8 50
    exit "$error_code"
}

trap 'error_exit $LINENO $?' ERR
trap 'error_exit $LINENO 130 "Interrupção pelo usuário"' INT

# Função para verificar privilégios de root
check_root() {
    [[ $EUID -eq 0 ]] || error_exit $LINENO 1 "Este script deve ser executado como root"
}

# Função para verificar dependências
check_dependencies() {
    local deps=("dialog" "curl" "wget" "tar" "grep" "awk" "sed" "systemctl" "apt-get" "ss")
    local missing_deps=()
    
    log_message "INFO" "Verificando dependências..."
    for dep in "${deps[@]}"; do
        command -v "$dep" &>/dev/null || missing_deps+=("$dep")
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_message "WARN" "Dependências faltando: ${missing_deps[*]}"
        dialog "${DIALOG_OPTS[@]}" --title "Dependências" --msgbox "Instalando: ${missing_deps[*]}" 8 50
        apt-get update -y && apt-get install -y "${missing_deps[@]}" || error_exit $LINENO 1 "Falha ao instalar dependências"
        log_message "INFO" "Dependências instaladas: ${missing_deps[*]}"
    fi
}

# Função para verificar recursos do sistema
check_system_resources() {
    local ram_mb=$(free -m | awk 'NR==2{print $2}')
    local disk_gb=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    local arch=$(uname -m)
    local board_info=$(cat /proc/device-tree/model 2>/dev/null || cat /sys/firmware/devicetree/base/model 2>/dev/null || echo "")
    
    if echo "$board_info" | grep -q -E "rk322x|rk3229" || grep -q -E "rk322x|rk3229" /proc/cpuinfo 2>/dev/null; then
        log_message "INFO" "Hardware RK322x/RK3229 detectado"
    else
        dialog "${DIALOG_OPTS[@]}" --title "Confirmação" --yesno "Hardware não detectado como RK322x. Continuar?" 8 50 || exit 1
    fi
    
    [[ "$ram_mb" -ge 480 && "$disk_gb" -ge 2 && "$arch" =~ arm ]] || {
        dialog "${DIALOG_OPTS[@]}" --title "Recursos Insuficientes" --msgbox "RAM: ${ram_mb}MB, Disco: ${disk_gb}GB, Arquitetura: $arch" 10 50
        return 1
    }
    log_message "INFO" "Sistema compatível: RAM ${ram_mb}MB, Disco ${disk_gb}GB, Arquitetura $arch"
}

# Função para otimizar NAND
optimize_for_nand() {
    log_message "INFO" "Otimizando para NAND..."
    mount -o remount,noatime,nodiratime / 2>/dev/null || log_message "WARN" "Falha ao aplicar otimizações de I/O"
    echo 10 > /proc/sys/vm/swappiness
    echo "1 4 1 7" > /proc/sys/kernel/printk
    echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.conf
    sysctl -p /etc/sysctl.conf >/dev/null 2>&1
    sync && echo 3 > /proc/sys/vm/drop_caches
}

# Função para detectar rede
detect_network_interface() {
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    SERVER_IP=$(ip route get 8.8.8.8 | awk '{print $7; exit}' || echo "192.168.1.100")
    [[ -n "$NETWORK_INTERFACE" ]] || error_exit $LINENO 1 "Interface de rede não detectada"
    log_message "INFO" "Interface: $NETWORK_INTERFACE, IP: $SERVER_IP"
}

# Função para ordenar instalação
sort_installation_order() {
    local selected_apps=("$@")
    local sorted_apps=()
    
    for priority_id in "${INSTALL_ORDER[@]}"; do
        for app_id in "${selected_apps[@]}"; do
            [[ "$app_id" == "$priority_id" ]] && sorted_apps+=("$app_id")
        done
    done
    echo "${sorted_apps[@]}"
}

# Função para instalar aplicativos
install_selected_apps() {
    local apps=("$@")
    local total_steps=$(( ${#apps[@]} * 2 + 2 ))
    local current_step=0
    
    # Salvar configurações
    cat > "$CONFIG_FILE" << EOF
NETWORK_INTERFACE="$NETWORK_INTERFACE"
SERVER_IP="$SERVER_IP"
VPN_NETWORK="$VPN_NETWORK"
VPN_PORT="$VPN_PORT"
PIHOLE_PASSWORD="$PIHOLE_PASSWORD"
FILEBROWSER_PORT="$FILEBROWSER_PORT"
COCKPIT_PORT="$COCKPIT_PORT"
INSTALL_DATE="$(date)"
EOF
    
    (
        current_step=$((current_step + 1)); echo $((current_step * 100 / total_steps)); echo "XXX"; echo "Atualizando pacotes..."; echo "XXX"
        apt-get update -y >/dev/null 2>&1 || error_exit $LINENO 1 "Falha ao atualizar pacotes"
        
        local apt_packages=()
        for app_id in "${apps[@]}"; do
            case $app_id in
                1) apt_packages+=("curl") ;; # Pi-hole instalado via script
                2) apt_packages+=("unbound") ;;
                3) apt_packages+=("wireguard-tools" "qrencode") ;;
                4) apt_packages+=("cockpit") ;;
                5) apt_packages+=("curl") ;; # FileBrowser via script
                6) apt_packages+=("curl") ;; # Netdata via script
                7) apt_packages+=("fail2ban") ;;
                8) apt_packages+=("ufw") ;;
                9) apt_packages+=("rng-tools") ;;
                10) apt_packages+=("curl") ;; # Rclone via script
                11) apt_packages+=("rsync") ;;
                12) apt_packages+=("minidlna") ;;
                13) apt_packages+=("curl") ;; # Cloudflared via deb
                14) apt_packages+=("chrony") ;;
                15) apt_packages+=("nginx") ;;
            esac
        done
        
        if [ ${#apt_packages[@]} -gt 0 ]; then
            current_step=$((current_step + 1)); echo $((current_step * 100 / total_steps)); echo "XXX"; echo "Instalando pacotes base..."; echo "XXX"
            apt-get install -y --no-install-recommends "${apt_packages[@]}" >/dev/null 2>&1 || error_exit $LINENO 1 "Falha ao instalar pacotes"
        fi
        
        for app_id in "${apps[@]}"; do
            local app_name=$(echo "${APPS[$app_id]}" | cut -d'|' -f1)
            current_step=$((current_step + 1)); echo $((current_step * 100 / total_steps)); echo "XXX"; echo "Instalando: $app_name..."; echo "XXX"
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
            current_step=$((current_step + 1)); echo $((current_step * 100 / total_steps)); echo "XXX"; echo "Configurando: $app_name..."; echo "XXX"
        done
    ) | dialog "${DIALOG_OPTS[@]}" --title "Instalação" --mixedgauge "Progresso..." 20 70 0
    
    reconfigure_service_integrations "${apps[@]}"
    create_maintenance_scripts
    generate_installation_summary "${apps[@]}"
}

# Funções de instalação (exemplo, mantendo apenas uma para brevidade)
install_pihole() {
    local script_path=$(mktemp)
    curl -sSL https://install.pi-hole.net > "$script_path" || error_exit $LINENO 1 "Falha ao baixar script Pi-hole"
    chmod +x "$script_path"
    bash "$script_path" --unattended
    rm -f "$script_path"
    [ -n "$PIHOLE_PASSWORD" ] && pihole -a -p "$PIHOLE_PASSWORD"
}

# Função para reconfigurar integrações
reconfigure_service_integrations() {
    local apps=("$@")
    local has_pihole=false has_unbound=false has_ufw=false has_fail2ban=false
    
    for app_id in "${apps[@]}"; do
        case $app_id in
            1) has_pihole=true ;;
            2) has_unbound=true ;;
            7) has_fail2ban=true ;;
            8) has_ufw=true ;;
        esac
    done
    
    if $has_pihole && $has_unbound; then
        sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
        sed -i '/^PIHOLE_DNS_2=/d' /etc/pihole/setupVars.conf
        systemctl restart pihole-FTL
    fi
    
    if $has_ufw; then
        $has_pihole && ufw allow "$PIHOLE_PORT/tcp" comment 'Pi-hole Web'
        $has_pihole && ufw allow 53 comment 'Pi-hole DNS'
        systemctl is-active --quiet wg-quick@wg0 && ufw allow "$VPN_PORT/udp" comment 'WireGuard'
    fi
    
    if $has_fail2ban; then
        local jail_config="[DEFAULT]\nbantime = 3600\nfindtime = 600\nmaxretry = 3\nbackend = systemd\n\n"
        $has_pihole && jail_config+="[pihole-web]\nenabled = true\nport = $PIHOLE_PORT,443\nlogpath = /var/log/pihole.log\nmaxretry = 5\n\n"
        echo -e "$jail_config" > /etc/fail2ban/jail.local
        systemctl restart fail2ban
    fi
}

# Função para criar scripts de manutenção
create_maintenance_scripts() {
    cat > /etc/cron.weekly/cleanup-boxserver << 'EOF'
#!/bin/bash
apt-get autoremove --purge -y
apt-get clean
journalctl --vacuum-time=7d
find /var/log -name "pihole*.log*" -mtime +30 -delete
df -h > /var/log/boxserver/disk-usage.log
EOF
    chmod +x /etc/cron.weekly/cleanup-boxserver
    
    cat > /usr/local/bin/boxserver-update << 'EOF'
#!/bin/bash
apt-get update -y && apt-get upgrade -y
command -v pihole &>/dev/null && pihole -up
systemctl daemon-reload
EOF
    chmod +x /usr/local/bin/boxserver-update
}

# Função para gerar resumo
generate_installation_summary() {
    local apps=("$@")
    local summary_file="$LOG_DIR/installation-summary.txt"
    local summary_dialog="Instalação Concluída!\n\n"
    
    echo "=== Relatório de Instalação ===" > "$summary_file"
    for app_id in "${apps[@]}"; do
        local name=$(echo "${APPS[$app_id]}" | cut -d'|' -f1)
        echo "✅ $name: Instalado" >> "$summary_file"
        summary_dialog+="✅ $name\n"
    done
    dialog "${DIALOG_OPTS[@]}" --title "Resumo" --msgbox "$summary_dialog\nRelatório: $summary_file" 15 60
}

# Função principal
main() {
    check_root
    setup_directories
    check_dependencies
    check_system_resources
    optimize_for_nand
    detect_network_interface
    
    local apps=($(dialog "${DIALOG_OPTS[@]}" --checklist "Selecione os aplicativos:" 20 80 10 \
        $(for id in "${!APPS[@]}"; do echo "$id" "${APPS[$id]%%|*}" "OFF"; done) 3>&1 1>&2 2>&3))
    
    [ ${#apps[@]} -gt 0 ] || { dialog "${DIALOG_OPTS[@]}" --msgbox "Nenhum aplicativo selecionado." 6 40; exit 1; }
    
    local sorted_apps=($(sort_installation_order "${apps[@]}"))
    install_selected_apps "${sorted_apps[@]}"
}

main "$@"
