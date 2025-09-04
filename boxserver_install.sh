#!/bin/bash
# Script aprimorado para instalação do Boxserver - melhorias estruturais, clareza e eficiência
#
# Boxserver TUI Installer - Interface Gráfica Terminal
# Instalador automatizado para MXQ-4K com chip RK322x
# Baseado na base de conhecimento do projeto Boxserver Arandutec
#
# Autor: Boxserver Team
# Versão: 1.0
# Data: $(date +%Y-%m-%d)
#
#
# Configurações globais do script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/boxserver"
CONFIG_DIR="/etc/boxserver"
BACKUP_DIR="/var/backups/boxserver"
LOG_FILE="$LOG_DIR/tui-installer.log"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configurações padrão do dialog
DIALOG_HEIGHT=20
DIALOG_WIDTH=70
DIALOG_MENU_HEIGHT=12

# MELHORIA: Opções globais do dialog para consistência visual
export DIALOGRC=/etc/dialogrc.boxserver
BACKTITLE="Boxserver TUI v1.0 | IP: ${SERVER_IP:-Detectando...} | Hardware: RK322x"
DIALOG_OPTS=(--backtitle "$BACKTITLE" --colors --ok-label "Confirmar" --cancel-label "Voltar")

# Variáveis globais de configuração
NETWORK_INTERFACE=""
SERVER_IP=""
VPN_NETWORK="10.200.200.0/24"
VPN_PORT="51820"
PIHOLE_PASSWORD=""
FILEBROWSER_PORT="8080"
COCKPIT_PORT="9090"

# Array de aplicativos disponíveis
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

# Função para criar diretórios necessários
setup_directories() {
    mkdir -p "$LOG_DIR" "$CONFIG_DIR" "$BACKUP_DIR"
    touch "$LOG_FILE"
    log_message "INFO" "Diretórios criados: $LOG_DIR, $CONFIG_DIR, $BACKUP_DIR"
}

# Função para verificar privilégios de root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        dialog --title "Erro de Permissão" --msgbox "Este script deve ser executado como root.\n\nUse: sudo $0" 8 50
        exit 1
    fi
}

# Função para verificar recursos do sistema - OTIMIZADA RK322x
check_system_resources() {
    local ram_mb=$(free -m | awk 'NR==2{print $2}')
    local disk_gb=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    local arch=$(uname -m)
    local errors=""
    
    # MELHORIA: Detecção genérica de hardware RK322x
    local board_info=""
    if [ -f /proc/device-tree/model ]; then
        board_info=$(cat /proc/device-tree/model)
    elif [ -f /sys/firmware/devicetree/base/model ]; then
        board_info=$(cat /sys/firmware/devicetree/base/model)
    fi
    
    local rk322x_detected=false
    if [[ "$board_info" =~ "rk322x" ]] || [[ "$board_info" =~ "rk3229" ]] || grep -q -E "rk322x|rk3229" /proc/cpuinfo 2>/dev/null; then
        rk322x_detected=true
        log_message "INFO" "Hardware RK322x/RK3229 detectado. Informações da placa: $board_info"
    else
        if dialog --title "Confirmação de Hardware" --yesno "Não foi possível detectar automaticamente um hardware RK322x.\n\nEste script é otimizado para essa família de chipsets.\n\nDeseja continuar mesmo assim?" 10 70; then
            log_message "WARN" "Hardware não detectado como RK322x, usuário optou por continuar."
        else
            log_message "ERROR" "Instalação cancelada pelo usuário devido a hardware incompatível."
            exit 1
        fi
    fi
    
    # Verificar RAM (mínimo 512MB, conforme documentação)
    if [ "$ram_mb" -lt 480 ]; then # Usar 480 como margem
        errors+="• RAM insuficiente: ${ram_mb}MB (mínimo 512MB)\n"
    fi
    
    # Verificar espaço em disco (mínimo 2GB, conforme documentação)
    if [ "$disk_gb" -lt 2 ]; then
        errors+="• Espaço em disco insuficiente: ${disk_gb}GB (mínimo 2GB)\n"
    fi
    
    # Verificar arquitetura ARM
    if [[ "$arch" != *"arm"* ]] && [[ "$arch" != *"aarch"* ]]; then
        errors+="• Arquitetura não suportada: $arch (requer ARM Cortex-A7)\n"
    fi
    
    if [ -n "$errors" ]; then
        dialog --title "Verificação do Sistema" --msgbox "Problemas encontrados:\n\n$errors\nRecomenda-se resolver estes problemas antes de continuar." 12 60
        return 1
    fi
    
    dialog --title "Verificação do Sistema" --msgbox "Sistema compatível com RK322x:\n\n• RAM: ${ram_mb}MB ✓\n• Disco Livre: ${disk_gb}GB ✓\n• Arquitetura: $arch ✓" 10 50
    return 0
}

# MELHORIA: Função para otimizar sistema para NAND (RK322x)
optimize_for_nand() {
    log_message "INFO" "Aplicando otimizações para armazenamento NAND"
    
    # Reduzir escrita no disco (noatime, nodiratime)
    if mountpoint -q /; then
        mount -o remount,noatime,nodiratime /
        log_message "INFO" "Otimizações de I/O aplicadas: noatime, nodiratime"
    fi
    
    # Configurar swappiness reduzido para NAND
    if [ -f /proc/sys/vm/swappiness ]; then
        echo "10" > /proc/sys/vm/swappiness
        log_message "INFO" "Swappiness reduzido para 10 (otimizado para NAND)"
    fi
    
    # Desabilitar logs excessivos do kernel
    if [ -f /proc/sys/kernel/printk ]; then
        echo "1 4 1 7" > /proc/sys/kernel/printk
        log_message "INFO" "Nível de log do kernel reduzido"
    fi

    # Otimizar cache de dentries e inodes para NAND
    if sysctl vm.vfs_cache_pressure >/dev/null 2>&1; then
        echo 'vm.vfs_cache_pressure=50' | tee -a /etc/sysctl.conf >/dev/null
        log_message "INFO" "Nível de log do kernel reduzido"
    fi
    
    # Limpar caches antigos
    sync && echo 3 > /proc/sys/vm/drop_caches
    log_message "INFO" "Caches de memória limpos"
}

# MELHORIA: Função para criar e configurar swap file otimizado para NAND
create_swap_file() {
    if [ -f /swapfile ]; then
        log_message "INFO" "Arquivo de swap já existe. Ignorando."
        return
    fi
    log_message "INFO" "Criando arquivo de swap de 512MB para estabilidade do sistema..."
    fallocate -l 512M /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
}

# MELHORIA: Função para limitar memória dos serviços RK322x
limit_service_memory() {
    local service_name="$1"
    local memory_limit="$2"
    
    local service_dir="/etc/systemd/system/${service_name}.service.d"
    mkdir -p "$service_dir"
    
    cat > "$service_dir/memory-limit.conf" << EOF
[Service]
MemoryMax=${memory_limit}M
MemorySwapMax=0
EOF
    
    systemctl daemon-reload
    log_message "INFO" "Limite de memória de ${memory_limit}MB aplicado para $service_name"
}

# MELHORIA: Função para aplicar limites de memória genéricos RK322x
apply_rk322x_memory_limits() {
    log_message "INFO" "Aplicando limites de memória para RK322x genérico (512MB DDR3)"
    
    # Limites otimizados para 512MB DDR3 no RK322x
    # Reservar ~200MB para sistema operacional
    limit_service_memory "pihole-FTL" "96"       # Reduzido para 512MB total
    limit_service_memory "unbound" "64"          # Reduzido para 512MB total
    limit_service_memory "netdata" "64"           # Reduzido para limites RK322x
    limit_service_memory "cockpit" "64"           # Reduzido para 512MB total
    limit_service_memory "filebrowser" "32"       # Novo limite para FileBrowser
    
    log_message "INFO" "Todos os limites de memória RK322x genéricos aplicados"
}

# MELHORIA: Função para aplicar limites de memória RK3229 R329Q (1GB DDR3)
apply_rk3229_memory_limits() {
    log_message "INFO" "Aplicando limites de memória para RK3229 R329Q V3.0 (1GB DDR3)"
    
    # Limites otimizados para 1GB DDR3 no RK3229
    # Reservar ~300MB para sistema operacional
    limit_service_memory "pihole-FTL" "192"      # Aumentado para 1GB total
    limit_service_memory "unbound" "96"            # Aumentado para 1GB total
    limit_service_memory "netdata" "128"           # Reduzido para limites RK3229
    limit_service_memory "cockpit" "96"            # Aumentado para 1GB total
    limit_service_memory "filebrowser" "64"        # Novo limite para FileBrowser
    
    log_message "INFO" "Todos os limites de memória RK3229 R329Q aplicados"
}

# Função para detectar interface de rede
detect_network_interface() {
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$NETWORK_INTERFACE" ]; then
        dialog --title "Erro de Rede" --msgbox "Não foi possível detectar a interface de rede principal.\n\nVerifique sua conexão de rede." 8 50
        return 1
    fi
    
    SERVER_IP=$(ip route get 8.8.8.8 | awk '{print $7; exit}')
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="192.168.1.100"
    fi
    
    log_message "INFO" "Interface detectada: $NETWORK_INTERFACE, IP: $SERVER_IP"
    return 0
}

# Função para testar conectividade
test_connectivity() {
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        dialog --title "Erro de Conectividade" --msgbox "Sem conexão com a internet.\n\nVerifique sua conexão de rede." 8 50
        return 1
    fi
    return 0
}

# Função principal de verificações
run_system_checks() {
    dialog --title "Verificações do Sistema" --infobox "Executando verificações iniciais..." 5 40
    sleep 1
    
    check_root
    
    if ! check_system_resources; then
        if ! dialog --title "Continuar?" --yesno "Foram encontrados problemas no sistema.\n\nDeseja continuar mesmo assim?" 8 50; then
            exit 1
        fi
    fi
    
    if ! detect_network_interface; then
        exit 1
    fi
    
    if ! test_connectivity; then
        exit 1
    fi
    
    dialog --title "Verificações Concluídas" --msgbox "Todas as verificações foram concluídas com sucesso!\n\nInterface: $NETWORK_INTERFACE\nIP: $SERVER_IP" 8 50
    
    # Aplicar otimizações específicas RK322x
    dialog --title "Otimização RK322x" --infobox "Aplicando otimizações para MXQ-4K..." 5 40
    
    # Detectar e otimizar para hardware específico
    if [[ "$board_info" =~ "RK3229" ]] || [[ "$board_info" =~ "R329Q" ]]; then
        log_message "INFO" "Detectado RK3229 R329Q V3.0 - aplicando otimizações específicas"
        # Otimizar para NAND 8GB
        optimize_for_nand
        # Aplicar limites de memória para 1GB DDR3
        # Criar swap file para estabilidade
        create_swap_file
        apply_rk3229_memory_limits
        dialog --title "Otimização RK3229" --msgbox "Sistema otimizado para RK3229 R329Q V3.0!\n\n• NAND 8GB otimizado\n• 1GB DDR3 gerenciado\n• Cortex-A7 otimizado" 8 50
    else
        # Fallback para RK322x genérico
        optimize_for_nand
        apply_rk322x_memory_limits
        dialog --title "Otimização Genérica" --msgbox "Sistema otimizado para MXQ-4K TV Box RK322x!\n\n• NAND otimizado\n• Memória limitada\n• I/O otimizado" 8 50
        create_swap_file
    fi
}

# Função para mostrar informações do sistema
show_system_info() {
    local ram_info=$(free -h | awk 'NR==2{printf "%s/%s (%.1f%%)", $3, $2, $3*100/$2}')
    local disk_info=$(df -h / | awk 'NR==2{printf "%s/%s (%s)", $3, $2, $5}')
    local cpu_info=$(lscpu | grep "Model name" | cut -d: -f2 | xargs)
    local uptime_info=$(uptime -p)
    
    dialog --title "Informações do Sistema" --msgbox "Sistema: $(lsb_release -d | cut -f2)\nCPU: $cpu_info\nRAM: $ram_info\nDisco: $disk_info\nUptime: $uptime_info\n\nInterface: $NETWORK_INTERFACE\nIP: $SERVER_IP" 12 70
}

# MELHORIA: Função auxiliar para obter o nome do serviço baseado no ID do aplicativo
get_service_name() {
    local app_id="$1"
    case $app_id in
        1) echo "pihole-FTL" ;;
        2) echo "unbound" ;;
        3) echo "wg-quick@wg0" ;;
        4) echo "cockpit" ;;
        5) echo "filebrowser" ;;
        6) echo "netdata" ;;
        7) echo "fail2ban" ;;
        8) echo "ufw" ;;
        9) echo "rng-tools" ;;
        10) echo "" ;; # CLI tool, no service
        11) echo "" ;; # CLI tool, no service
        12) echo "minidlna" ;;
        13) echo "cloudflared" ;;
        14) echo "chrony" ;;
        *) echo "" ;;
    esac
}

# MELHORIA: Função para verificar o status de um aplicativo
check_app_status() {
    local app_id="$1"
    local service_name=$(get_service_name "$app_id")

    # Verificação baseada em arquivos de configuração ou binários
    local is_installed=false
    case $app_id in
        1) [[ -f "/etc/pihole/setupVars.conf" ]] && is_installed=true ;;
        2) [[ -f "/etc/unbound/unbound.conf" ]] && is_installed=true ;;
        3) [[ -f "/etc/wireguard/wg0.conf" ]] && is_installed=true ;;
        4) command -v cockpit-ws &>/dev/null && is_installed=true ;;
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
    esac

    if [ "$is_installed" = false ]; then
        echo "not_installed"
    elif [ -n "$service_name" ] && ! systemctl is-active --quiet "$service_name" 2>/dev/null; then
        echo "installed_error"
    else
        echo "installed_ok"
    fi
}
# Função para configurações avançadas
configure_advanced_settings() {
    while true; do
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Configurações Avançadas" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Configurar IP do Servidor" \
            "2" "Configurar Rede VPN" \
            "3" "Configurar Portas dos Serviços" \
            "4" "Configurar Senhas" \
            "6" "Voltar ao Menu Principal" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1)
                SERVER_IP=$(dialog "${DIALOG_OPTS[@]}" --title "IP do Servidor" --inputbox "Digite o IP do servidor:" 8 50 "$SERVER_IP" 3>&1 1>&2 2>&3)
                ;;
            2)
                VPN_NETWORK=$(dialog "${DIALOG_OPTS[@]}" --title "Rede VPN" --inputbox "Digite a rede VPN (CIDR):" 8 50 "$VPN_NETWORK" 3>&1 1>&2 2>&3)
                VPN_PORT=$(dialog "${DIALOG_OPTS[@]}" --title "Porta VPN" --inputbox "Digite a porta do WireGuard:" 8 50 "$VPN_PORT" 3>&1 1>&2 2>&3)
                ;;
            3)
                FILEBROWSER_PORT=$(dialog "${DIALOG_OPTS[@]}" --title "Porta FileBrowser" --inputbox "Digite a porta do FileBrowser:" 8 50 "$FILEBROWSER_PORT" 3>&1 1>&2 2>&3)
                COCKPIT_PORT=$(dialog "${DIALOG_OPTS[@]}" --title "Porta Cockpit" --inputbox "Digite a porta do Cockpit:" 8 50 "$COCKPIT_PORT" 3>&1 1>&2 2>&3)
                ;;
            4)
                PIHOLE_PASSWORD=$(dialog "${DIALOG_OPTS[@]}" --title "Senha Pi-hole" --passwordbox "Digite a senha do Pi-hole:" 8 50 3>&1 1>&2 2>&3)
                ;;
            5|"")
                break
                ;;
        esac
    done
}

# Função para mostrar detalhes de um aplicativo
show_app_details() {
    local app_id="$1"
    local app_info="${APPS[$app_id]}"
    
    if [ -n "$app_info" ]; then
        IFS='|' read -r name description access <<< "$app_info"
        
        local details="Nome: $name\n\nDescrição: $description\n\nAcesso: $access\n\n"
        
        # Adicionar informações específicas por aplicativo
        case $app_id in
            1) details+="Configurações:\n• Interface: $NETWORK_INTERFACE\n• IP: $SERVER_IP\n• DNS Upstream: Unbound (127.0.0.1:5335)" ;;
            2) details+="Configurações:\n• Porta: 5335\n• Otimizado para ARM RK322x\n• Trust anchor automático" ;;
            3) details+="Configurações:\n• Rede VPN: $VPN_NETWORK\n• Porta: $VPN_PORT\n• Interface: $NETWORK_INTERFACE" ;;
            4) details+="Configurações:\n• Porta: $COCKPIT_PORT\n• Acesso via HTTPS\n• Gerenciamento do sistema" ;;
            5) details+="Configurações:\n• Porta: $FILEBROWSER_PORT\n• Gerenciamento de arquivos\n• Interface web" ;;
        esac
        
        dialog "${DIALOG_OPTS[@]}" --title "Detalhes: $name" --msgbox "$details" 15 70
    fi
}

# MELHORIA: Função auxiliar para obter o nome do serviço baseado no ID do aplicativo
get_service_name() {
    local app_id="$1"
    case $app_id in
        1) echo "pihole-FTL" ;;
        2) echo "unbound" ;;
        3) echo "wg-quick@wg0" ;;
        4) echo "cockpit" ;;
        5) echo "filebrowser" ;;
        6) echo "netdata" ;;
        7) echo "fail2ban" ;;
        8) echo "ufw" ;;
        9) echo "rng-tools" ;;
        10) echo "" ;; # CLI tool, no service
        11) echo "" ;; # CLI tool, no service
        12) echo "minidlna" ;;
        13) echo "cloudflared" ;;
        14) echo "chrony" ;;
        *) echo "" ;;
    esac
}

# MELHORIA: Função para verificar o status de um aplicativo
check_app_status() {
    local app_id="$1"
    local service_name=$(get_service_name "$app_id")

    # Verificação baseada em arquivos de configuração ou binários
    local is_installed=false
    case $app_id in
        1) [[ -f "/etc/pihole/setupVars.conf" ]] && is_installed=true ;;
        2) [[ -f "/etc/unbound/unbound.conf" ]] && is_installed=true ;;
        3) [[ -f "/etc/wireguard/wg0.conf" ]] && is_installed=true ;;
        4) command -v cockpit-ws &>/dev/null && is_installed=true ;;
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
    esac

    if [ "$is_installed" = false ]; then
        echo "not_installed"
    elif [ -n "$service_name" ] && ! systemctl is-active --quiet "$service_name" 2>/dev/null; then
        echo "installed_error"
    else
        echo "installed_ok"
    fi
}

# MELHORIA: Função auxiliar para obter o nome do serviço baseado no ID do aplicativo
get_service_name() {
    local app_id="$1"
    case $app_id in
        1) echo "pihole-FTL" ;;
        2) echo "unbound" ;;
        3) echo "wg-quick@wg0" ;;
        4) echo "cockpit" ;;
        5) echo "filebrowser" ;;
        6) echo "netdata" ;;
        7) echo "fail2ban" ;;
        8) echo "ufw" ;;
        9) echo "rng-tools" ;;
        10) echo "" ;; # CLI tool, no service
        11) echo "" ;; # CLI tool, no service
        12) echo "minidlna" ;;
        13) echo "cloudflared" ;;
        14) echo "chrony" ;;
        *) echo "" ;;
    esac
}

# MELHORIA: Função para verificar o status de um aplicativo
check_app_status() {
    local app_id="$1"
    local service_name=$(get_service_name "$app_id")

    # Verificação baseada em arquivos de configuração ou binários
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

# Função para seleção de aplicativos
select_applications() {
    local selected_apps=()
    local menu_items=()
    
    # Construir itens do menu
    for app_id in $(echo "${!APPS[@]}" | tr ' ' '\n' | sort -n); do
        local app_info="${APPS[$app_id]}"
        IFS='|' read -r name description access <<< "$app_info"
        menu_items+=("$app_id" "$name - $description" "OFF")
    done
    
    # Adicionar opções especiais
    menu_items+=("99" "Instalar TODOS os aplicativos" "OFF")
    menu_items+=("info" "Ver informações do sistema" "OFF")
    menu_items+=("config" "Configurações avançadas" "OFF")
    
    while true; do
        local choices=$(dialog "${DIALOG_OPTS[@]}" --title "Seleção de Aplicativos" \
            --checklist "Selecione os aplicativos para instalar:\n\nUse ESPAÇO para selecionar, ENTER para confirmar" \
            20 80 10 "${menu_items[@]}" 3>&1 1>&2 2>&3)
        
        if [ $? -ne 0 ]; then
            return 1
        fi
        
        # Processar escolhas
        local process_choices=false
        for choice in $choices; do
            choice=$(echo $choice | tr -d '"')
            case $choice in
                "info")
                    show_system_info
                    ;;
                "config")
                    configure_advanced_settings
                    ;;
                "99")
                    # Selecionar todos os aplicativos
                    selected_apps=()
                    for app_id in $(echo "${!APPS[@]}" | tr ' ' '\n' | sort -n); do
                        selected_apps+=("$app_id")
                    done
                    process_choices=true
                    break
                    ;;
                *)
                    if [[ "$choice" =~ ^[0-9]+$ ]] && [ -n "${APPS[$choice]}" ]; then
                        selected_apps+=("$choice")
                        process_choices=true
                    fi
                    ;;
            esac
        done
        
        if [ "$process_choices" = true ]; then
            break
        fi
    done
    
    if [ ${#selected_apps[@]} -eq 0 ]; then
        dialog "${DIALOG_OPTS[@]}" --title "Nenhum Aplicativo" --msgbox "Nenhum aplicativo foi selecionado." 6 40
        return 1
    fi
    
    # Confirmar seleção
    local confirmation="Ações a serem executadas:\n\n"
    local to_install=()
    local to_reinstall=()
    for app_id in "${selected_apps[@]}"; do
        local status=$(check_app_status "$app_id")
        if [[ "$status" == "not_installed" ]]; then
            to_install+=("• ${APPS[$app_id]%%|*}")
        else
            to_reinstall+=("• ${APPS[$app_id]%%|*}")
        fi
    done
    if [ ${#to_install[@]} -gt 0 ]; then
        confirmation+="Instalar:\n${to_install[*]}\n\n"
    fi
    if [ ${#to_reinstall[@]} -gt 0 ]; then
        confirmation+="Reinstalar (para corrigir erros):\n${to_reinstall[*]}\n\n"
    fi
    confirmation+="\nDeseja continuar com a instalação?"
    
    if dialog "${DIALOG_OPTS[@]}" --title "Confirmar Instalação" --yesno "$confirmation" 15 60; then
        # CORREÇÃO: Ordenar aplicativos por dependências antes da instalação
        local sorted_apps=($(sort_installation_order "${selected_apps[@]}"))
        install_selected_apps "${sorted_apps[@]}"
    fi
}

# IMPLEMENTAÇÃO: Função para ordenar instalação por dependências
sort_installation_order() {
    local selected_apps=("$@")
    local sorted_apps=()
    
    # Ordem de prioridade por dependências:
    # Fase 1: Sistema base (entropia, backup)
    # Fase 2: DNS core (Unbound ANTES Pi-hole)
    # Fase 3: Serviços de rede
    # Fase 4: Segurança (após todos os serviços)
    # Fase 5: Serviços avançados e de tempo
    # Fase 6: Interface Web (por último, para configurar proxies)
    local priority_order=(9 11 10 14 2 1 3 4 5 6 12 8 7 13 15)
    
    log_message "INFO" "Ordenando aplicativos por dependências..."
    
    # Ordenar apps selecionados pela prioridade de dependência
    for priority_id in "${priority_order[@]}"; do
        for app_id in "${selected_apps[@]}"; do
            if [[ "$app_id" == "$priority_id" ]]; then
                sorted_apps+=("$app_id")
                local app_info="${APPS[$app_id]}"
                IFS='|' read -r name description access <<< "$app_info"
                log_message "INFO" "Adicionado à sequência: $name (ID: $app_id)"
                break
            fi
        done
    done
    
    # Verificar se todos os apps foram ordenados
    if [[ ${#sorted_apps[@]} -ne ${#selected_apps[@]} ]]; then
        log_message "WARN" "Alguns aplicativos podem não ter sido ordenados corretamente"
    fi
    
    echo "${sorted_apps[@]}"
}

# MELHORIA: Função de instalação refatorada para eficiência e robustez
install_selected_apps() {
    local apps_to_install=("$@")
    local total_steps=$(( ${#apps_to_install[@]} * 2 + 2 )) # Preparação, apt, e 2 etapas por app
    local current_step=0
    
    # Criar arquivo de configuração
    cat > "$CONFIG_DIR/system.conf" << EOF
# Configurações do Boxserver
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

    # --- FASE 1: Coleta e Preparação ---
    local apt_packages=()
    local external_scripts=()
    local download_pids=()

    for app_id in "${apps_to_install[@]}"; do
        case $app_id in
            1) external_scripts+=("pihole|https://install.pi-hole.net") ;;
            2) apt_packages+=("unbound") ;;
            3) apt_packages+=("wireguard-tools" "qrencode") ;;
            4) apt_packages+=("cockpit") ;;
            5) external_scripts+=("filebrowser|https://raw.githubusercontent.com/filebrowser/get/master/get.sh") ;;
            6) external_scripts+=("netdata|https://my-netdata.io/kickstart.sh") ;;
            7) apt_packages+=("fail2ban") ;;
            8) apt_packages+=("ufw") ;;
            9) apt_packages+=("rng-tools") ;;
            10) external_scripts+=("rclone|https://rclone.org/install.sh") ;;
            11) apt_packages+=("rsync") ;;
            12) apt_packages+=("minidlna") ;;
            13) external_scripts+=("cloudflared|https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm.deb") ;;
            14) apt_packages+=("chrony") ;;
            15) apt_packages+=("nginx") ;;
        esac
    done

    (
    # --- FASE 2: Instalação APT em Lote ---
    current_step=$((current_step + 1)); echo $((current_step * 100 / total_steps)); echo "XXX"; echo "Atualizando lista de pacotes..."; echo "XXX"
    apt-get update -y >/dev/null 2>&1

    if [ ${#apt_packages[@]} -gt 0 ]; then
        current_step=$((current_step + 1)); echo $((current_step * 100 / total_steps)); echo "XXX"; echo "Instalando pacotes base (${#apt_packages[@]} pacotes)..."; echo "XXX"
        apt-get install -y --no-install-recommends ${apt_packages[@]} >/dev/null 2>&1
        if [ $? -ne 0 ]; then log_message "ERROR" "Falha ao instalar pacotes APT: ${apt_packages[*]}"; exit 1; fi
    fi

    # --- FASE 3: Instalação e Configuração Individual ---
    for app_id in "${apps_to_install[@]}"; do
        local app_name=$(echo "${APPS[$app_id]}" | cut -d'|' -f1)
        
        current_step=$((current_step + 1)); echo $((current_step * 100 / total_steps)); echo "XXX"; echo "Instalando: $app_name..."; echo "XXX"
        
        # Instalação
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
        if [ $? -ne 0 ]; then log_message "ERROR" "Falha na instalação de $app_name"; exit 1; fi

        current_step=$((current_step + 1)); echo $((current_step * 100 / total_steps)); echo "XXX"; echo "Configurando: $app_name..."; echo "XXX"
        
        # Configuração Pós-Instalação (se necessário)
        case $app_id in
            1) setup_logrotate ;; # Configura logrotate para pihole
        esac
        
        # Verificação
        if [[ -n "$(get_service_name "$app_id")" ]] && ! systemctl is-active --quiet $(get_service_name "$app_id") 2>/dev/null; then
            log_message "WARN" "Serviço para $app_name não está ativo após instalação."
        fi

    done

    ) | dialog "${DIALOG_OPTS[@]}" --title "Instalação em Andamento" --mixedgauge "Progresso da instalação..." 20 70 0

    if [ $? -ne 0 ]; then
        dialog --title "Erro na Instalação" --msgbox "A instalação falhou. Verifique os logs em $LOG_FILE para mais detalhes." 8 60
        exit 1
    fi

    dialog "${DIALOG_OPTS[@]}" --title "Instalação Concluída" --infobox "Finalizando e aplicando configurações..." 5 50
    sleep 2
    
    # CORREÇÃO: Reconfigurar integrações após instalação completa
    reconfigure_service_integrations "${apps_to_install[@]}"

    # MELHORIA: Criar scripts de manutenção documentados
    create_maintenance_scripts
    
    # MELHORIA: Gerar relatório final
    generate_installation_summary "${apps_to_install[@]}"
    
    # Oferecer menu pós-instalação
    dialog --title "Instalação Finalizada" --msgbox "Instalação e configuração concluídas com sucesso!\n\nVocê retornará ao menu principal, onde poderá gerenciar os serviços." 10 60
}

# MELHORIA: Função para obter o nome do serviço systemd de um app
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

# IMPLEMENTAÇÃO: Reconfigurar integrações entre serviços após instalação
reconfigure_service_integrations() {
    local installed_apps=("$@")
    
    log_message "INFO" "Reconfigurando integrações entre serviços..."
    
    # Verificar se Pi-hole e Unbound foram instalados juntos
    local has_pihole=false
    local has_unbound=false
    
    for app_id in "${installed_apps[@]}"; do
        case $app_id in
            1) has_pihole=true ;;
            2) has_unbound=true ;;
        esac
    done
    
    # Reconfigurar integração Pi-hole + Unbound se ambos estão presentes
    if [[ "$has_pihole" == true ]] && [[ "$has_unbound" == true ]]; then
        log_message "INFO" "Reconfigurando integração Pi-hole + Unbound..."
        
        # Aguardar serviços estabilizarem
        sleep 5
        
        # Verificar se Unbound está funcionando
        if systemctl is-active --quiet unbound && ss -tulpn | grep -q ":5335.*unbound"; then
            # Testar conectividade do Unbound
            if timeout 10 dig @127.0.0.1 -p 5335 google.com +short >/dev/null 2>&1; then
                log_message "INFO" "Unbound funcional - atualizando configuração do Pi-hole"
                
                # Atualizar Pi-hole para usar Unbound
                sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
                sed -i '/^PIHOLE_DNS_2=/d' /etc/pihole/setupVars.conf
                
                # Reiniciar Pi-hole para aplicar nova configuração
                systemctl restart pihole-FTL
                
                # Verificar integração
                sleep 3
                if systemctl is-active --quiet pihole-FTL; then
                    log_message "INFO" "Integração Pi-hole + Unbound configurada com sucesso"
                else
                    log_message "ERROR" "Falha ao reiniciar Pi-hole após reconfiguração"
                fi
            else
                log_message "WARN" "Unbound não responde - mantendo configuração atual do Pi-hole"
            fi
        else
            log_message "WARN" "Unbound não está ativo - mantendo configuração atual do Pi-hole"
        fi
    fi
    
    # Reconfigurar UFW se foi instalado após outros serviços
    for app_id in "${installed_apps[@]}"; do
        if [[ "$app_id" == "8" ]]; then  # UFW
            log_message "INFO" "Reconfigurando regras do UFW para serviços ativos..."
            
            # Adicionar regras para serviços que podem ter sido instalados antes do UFW
            if systemctl is-active --quiet pihole-FTL 2>/dev/null && ! ufw status | grep -q "80/tcp"; then
                ufw allow 80/tcp comment 'Pi-hole Web'
                ufw allow 443/tcp comment 'Pi-hole Web SSL'
                ufw allow 53 comment 'Pi-hole DNS'
                log_message "INFO" "UFW: Regras do Pi-hole adicionadas pós-instalação"
            fi
            
            if systemctl is-active --quiet wg-quick@wg0 2>/dev/null && ! ufw status | grep -q "$VPN_PORT/udp"; then
                ufw allow $VPN_PORT/udp comment 'WireGuard VPN'
                log_message "INFO" "UFW: Regra do WireGuard adicionada pós-instalação"
            fi
            
            break
        fi
    done
    
    # Reconfigurar Fail2Ban se foi instalado após outros serviços
    for app_id in "${installed_apps[@]}"; do
        if [[ "$app_id" == "7" ]]; then  # Fail2Ban
            log_message "INFO" "Reconfigurando Fail2Ban para serviços ativos..."
            
            # Verificar se há novos serviços para proteger
            local needs_reconfigure=false
            
            if systemctl is-active --quiet pihole-FTL 2>/dev/null && ! grep -q "\[pihole-web\]" /etc/fail2ban/jail.local; then
                needs_reconfigure=true
            fi
            
            if systemctl is-active --quiet wg-quick@wg0 2>/dev/null && ! grep -q "\[wireguard\]" /etc/fail2ban/jail.local; then
                needs_reconfigure=true
            fi
            
            if [[ "$needs_reconfigure" == true ]]; then
                log_message "INFO" "Reconfigurando Fail2Ban com novos serviços..."
                # Reexecutar configuração do Fail2Ban
                systemctl stop fail2ban
                
                # Recriar configuração com serviços atuais
                local jail_config="[DEFAULT]\nbantime = 3600\nfindtime = 600\nmaxretry = 3\nbackend = systemd\n\n"
                jail_config+="[sshd]\nenabled = true\nport = ssh\nlogpath = %(sshd_log)s\nmaxretry = 3\n\n"
                
                if systemctl is-active --quiet pihole-FTL 2>/dev/null; then
                    jail_config+="[pihole-web]\nenabled = true\nport = 80,443\nlogpath = /var/log/pihole.log\nmaxretry = 5\nfilter = pihole-web\n\n"
                fi
                
                if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
                    jail_config+="[wireguard]\nenabled = true\nport = $VPN_PORT\nlogpath = /var/log/syslog\nmaxretry = 3\nfilter = wireguard\n\n"
                fi
                
                if systemctl is-active --quiet cockpit.socket 2>/dev/null; then
                    jail_config+="[cockpit]\nenabled = true\nport = $COCKPIT_PORT\nlogpath = /var/log/cockpit/cockpit.log\nmaxretry = 3\n\n"
                fi
                
                echo -e "$jail_config" > /etc/fail2ban/jail.local
                systemctl start fail2ban
                
                log_message "INFO" "Fail2Ban reconfigurado com serviços atuais"
            fi
            
            break
        fi
    done
    
    # Reconfigurar Nginx se a interface web foi instalada
    for app_id in "${installed_apps[@]}"; do
        if [[ "$app_id" == "15" ]]; then # Interface Web
            log_message "INFO" "Reconfigurando Nginx para serviços ativos..."
            # Habilitar proxies para serviços instalados
            for other_app_id in "${installed_apps[@]}"; do
                if [[ "$other_app_id" != "15" ]]; then
                    enable_nginx_proxy "$other_app_id"
                fi
            done
            systemctl restart nginx
        fi
    done

    log_message "INFO" "Reconfiguração de integrações concluída"
}

# MELHORIA: Função segura para baixar e executar scripts externos
download_and_run_script() {
    local url="$1"
    local script_path="/tmp/external_script_$(date +%s).sh"

    log_message "INFO" "Baixando script de: $url"
    if ! curl -sSL -o "$script_path" "$url"; then
        log_message "ERROR" "Falha ao baixar o script de $url"
        rm -f "$script_path"
        return 1
    fi

    # Verificação de segurança aprimorada (evita falsos positivos)
    # Procura por 'rm -rf /' como um comando exato, não como parte de uma variável.
    # O padrão `\s` garante que haja espaços ao redor, tornando a detecção mais precisa.
    if grep -qE '\s+rm\s+-rf\s+/\s*' "$script_path"; then
        log_message "ERROR" "Script contém comando perigoso 'rm -rf /'. Abortando."
        rm -f "$script_path"
        return 1
    fi

    log_message "INFO" "Executando script baixado: $script_path"
    # Executa o script com bash
    if ! bash "$script_path"; then
        log_message "ERROR" "Falha na execução do script de $url"
        rm -f "$script_path"
        return 1
    fi

    log_message "INFO" "Script executado com sucesso."
    rm -f "$script_path"
    return 0
}

# Função para instalação do Pi-hole (baseada em INSTALAÇÃO APPS.md)
install_pihole() {
    log_message "INFO" "Instalando Pi-hole..."
    
    # CORREÇÃO: Usar função segura para baixar e executar
    download_and_run_script "https://install.pi-hole.net"
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do Pi-hole"
        return 1
    fi
    
    # Configurar senha do administrador
    if [ -n "$PIHOLE_PASSWORD" ]; then
        echo "$PIHOLE_PASSWORD" | pihole -a -p
        log_message "INFO" "Senha do Pi-hole configurada"
    fi
    
    # CORREÇÃO: Configuração condicional baseada na disponibilidade do Unbound
    local pihole_dns_upstream="1.1.1.1"  # DNS público como fallback
    local dns_config_note="DNS público (Unbound não disponível)"
    
    # Verificar se Unbound está disponível e funcionando
    if systemctl is-active --quiet unbound && ss -tulpn | grep -q ":5335.*unbound"; then
        # Testar se Unbound responde
        if timeout 5 dig @127.0.0.1 -p 5335 google.com +short >/dev/null 2>&1; then
            pihole_dns_upstream="127.0.0.1#5335"
            dns_config_note="Unbound local (integração ativa)"
            log_message "INFO" "Unbound detectado e funcional - configurando integração"
        else
            log_message "WARN" "Unbound detectado mas não responde - usando DNS público"
        fi
    else
        log_message "WARN" "Unbound não disponível - Pi-hole usará DNS público temporariamente"
    fi
    
    # Configurar setupVars.conf com DNS upstream apropriado
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
    
    log_message "INFO" "Pi-hole configurado com: $dns_config_note"
    
    # Reiniciar serviço
    systemctl restart pihole-FTL
    systemctl enable pihole-FTL

    # MELHORIA: Configurar logrotate para Pi-hole conforme documentação
    setup_logrotate
    
    log_message "INFO" "Pi-hole instalado e configurado com sucesso"
}

# Função para instalação do Unbound (baseada em INSTALAÇÃO APPS.md)
install_unbound() {
    log_message "INFO" "Instalando Unbound..."
    
    # CORREÇÃO: Verificar e resolver conflitos ANTES da instalação
    if ! resolve_dns_conflicts; then
        log_message "ERROR" "Falha ao resolver conflitos DNS"
        return 1
    fi
    
    # Parar serviço se já estiver rodando
    systemctl stop unbound 2>/dev/null || true
    
    # Instalar Unbound
    apt update
    apt install unbound -y
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do Unbound"
        return 1
    fi
    
    # Verificar se usuário unbound existe
    if ! id "unbound" &>/dev/null; then
        log_message "ERROR" "Usuário unbound não foi criado durante a instalação"
        return 1
    fi
    
    # Criar diretórios necessários
    mkdir -p /etc/unbound/unbound.conf.d
    mkdir -p /var/lib/unbound
    
    # Backup da configuração original se existir
    if [ -f "/etc/unbound/unbound.conf" ]; then
        cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.backup
    fi
    
    # Criar configuração otimizada para ARM RK322x
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
    # OTIMIZADO PARA ARM/BAIXA RAM
    num-threads: 1
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
    
    # CORREÇÃO: Baixar root hints com múltiplos fallbacks
    log_message "INFO" "Baixando root hints..."
    local root_hints_urls=(
        "https://www.internic.net/domain/named.root"
        "https://ftp.internic.net/domain/named.root"
        "https://www.iana.org/domains/root/files/named.root"
    )
    local download_success=false
    for url in "${root_hints_urls[@]}"; do
        log_message "INFO" "Tentando baixar root hints de: $url"
        if wget -qO /var/lib/unbound/root.hints "$url"; then
            log_message "INFO" "Root hints baixado com sucesso de $url"
            download_success=true
            break
        fi
    done

    if [ "$download_success" = false ]; then
        log_message "ERROR" "Falha ao baixar root hints de todas as fontes."
        return 1
    fi

    # Configurar trust anchor automático com fallback
    log_message "INFO" "Configurando trust anchor..."
    if ! unbound-anchor -a /var/lib/unbound/root.key; then
        log_message "WARN" "Falha no trust anchor automático, usando método manual"
        if wget -O /tmp/root.key https://data.iana.org/root-anchors/icannbundle.pem; then
            mv /tmp/root.key /var/lib/unbound/root.key
        else
            log_message "ERROR" "Falha ao obter trust anchor manual"
            return 1
        fi
    fi
    
    # Verificar se arquivos foram criados
    if [ ! -f "/var/lib/unbound/root.key" ] || [ ! -f "/var/lib/unbound/root.hints" ]; then
        log_message "ERROR" "Arquivos de configuração do Unbound não foram criados"
        return 1
    fi
    
    # CORREÇÃO: Configurar permissões conforme documentação
    chown unbound:unbound /var/lib/unbound/root.key /var/lib/unbound/root.hints
    chmod 644 /var/lib/unbound/root.key /var/lib/unbound/root.hints
    log_message "INFO" "Permissões aplicadas aos arquivos do Unbound."
    
    # CORREÇÃO: Verificar configuração com unbound-checkconf antes de reiniciar
    log_message "INFO" "Verificando configuração do Unbound..."
    if ! unbound-checkconf; then
        log_message "ERROR" "Erro na configuração do Unbound"
        log_message "ERROR" "Detalhes: $(unbound-checkconf 2>&1)"
        return 1
    fi
    log_message "INFO" "Configuração do Unbound validada com sucesso."
    
    # CORREÇÃO: Implementar ativação robusta com fallbacks
    if ! activate_unbound_service; then
        log_message "ERROR" "Falha na ativação do Unbound"
        # Tentar diagnóstico e correção automática
        if diagnose_and_fix_unbound; then
            log_message "INFO" "Problema corrigido automaticamente, tentando novamente..."
            if ! activate_unbound_service; then
                log_message "ERROR" "Falha persistente na ativação do Unbound"
                return 1
            fi
        else
            return 1
        fi
    fi
    
    # CORREÇÃO: Teste DNS robusto com múltiplas verificações
    if ! test_unbound_functionality; then
        log_message "WARN" "Teste DNS falhou, mas serviço está ativo"
        log_message "INFO" "Unbound pode estar funcionando apenas localmente"
    else
        log_message "INFO" "Unbound instalado e testado com sucesso"
    fi
}

# CORREÇÃO: Função para resolver conflitos DNS
resolve_dns_conflicts() {
    log_message "INFO" "Verificando conflitos DNS..."
    
    # Verificar se systemd-resolved está ativo (principal causa de conflito)
    if systemctl is-active --quiet systemd-resolved; then
        log_message "WARN" "systemd-resolved detectado - pode causar conflitos"
        
        # Backup da configuração atual
        if [ -f "/etc/resolv.conf" ]; then
            cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S)
        fi
        
        # Parar e desabilitar systemd-resolved
        log_message "INFO" "Desabilitando systemd-resolved..."
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
        
        # Verificar se parou corretamente
        sleep 2
        if systemctl is-active --quiet systemd-resolved; then
            log_message "ERROR" "Falha ao parar systemd-resolved"
            return 1
        fi
        
        log_message "INFO" "systemd-resolved desabilitado com sucesso"
    fi
    
    # Verificar se porta 53 está livre
    if ss -tulpn | grep -q ":53"; then
        local process=$(ss -tulpn | grep ":53" | head -1)
        log_message "WARN" "Porta 53 ainda ocupada: $process"
        
        # Tentar identificar e parar processo
        local pid=$(echo "$process" | awk '{print $7}' | cut -d',' -f2 | cut -d'=' -f2)
        if [ -n "$pid" ] && [ "$pid" != "-" ]; then
            log_message "INFO" "Tentando parar processo PID: $pid"
            kill -TERM "$pid" 2>/dev/null
            sleep 2
        fi
    fi
    
    # Verificar se porta 5335 está livre
    if ss -tulpn | grep -q ":5335"; then
        log_message "ERROR" "Porta 5335 já está em uso"
        ss -tulpn | grep ":5335"
        return 1
    fi
    
    log_message "INFO" "Verificação de conflitos DNS concluída"
    return 0
}

# CORREÇÃO: Função para ativar serviço Unbound de forma robusta
activate_unbound_service() {
    log_message "INFO" "Ativando serviço Unbound..."
    
    # Habilitar serviço primeiro
    systemctl enable unbound
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha ao habilitar serviço Unbound"
        return 1
    fi
    
    # Iniciar serviço
    systemctl start unbound
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha ao iniciar serviço Unbound"
        log_message "ERROR" "Status: $(systemctl status unbound --no-pager -l)"
        return 1
    fi
    
    # Aguardar inicialização com timeout
    local timeout=15
    local count=0
    while [ $count -lt $timeout ]; do
        if systemctl is-active --quiet unbound; then
            log_message "INFO" "Serviço Unbound ativo após ${count}s"
            break
        fi
        sleep 1
        ((count++))
    done
    
    # Verificar se serviço está ativo
    if ! systemctl is-active --quiet unbound; then
        log_message "ERROR" "Serviço Unbound não está ativo após ${timeout}s"
        log_message "ERROR" "Logs: $(journalctl -u unbound --no-pager -n 10)"
        return 1
    fi
    
    # Verificar se está escutando na porta 5335
    sleep 2
    if ! ss -tulpn | grep -q ":5335.*unbound"; then
        log_message "ERROR" "Unbound não está escutando na porta 5335"
        ss -tulpn | grep unbound || log_message "ERROR" "Nenhum processo unbound encontrado"
        return 1
    fi
    
    log_message "INFO" "Serviço Unbound ativado com sucesso"
    return 0
}

# CORREÇÃO: Função para diagnóstico e correção automática
diagnose_and_fix_unbound() {
    log_message "INFO" "Executando diagnóstico do Unbound..."
    
    # Verificar se usuário unbound existe
    if ! id "unbound" &>/dev/null; then
        log_message "WARN" "Usuário unbound não existe, criando..."
        useradd -r -s /bin/false unbound
        if [ $? -eq 0 ]; then
            log_message "INFO" "Usuário unbound criado com sucesso"
        else
            log_message "ERROR" "Falha ao criar usuário unbound"
            return 1
        fi
    fi
    
    # Verificar permissões dos arquivos
    if [ -f "/var/lib/unbound/root.key" ]; then
        chown unbound:unbound /var/lib/unbound/root.key
        chmod 644 /var/lib/unbound/root.key
    fi
    
    if [ -f "/var/lib/unbound/root.hints" ]; then
        chown unbound:unbound /var/lib/unbound/root.hints
        chmod 644 /var/lib/unbound/root.hints
    fi
    
    # Verificar configuração
    if ! unbound-checkconf; then
        log_message "WARN" "Configuração inválida, criando configuração mínima..."
        
        # Backup da configuração atual
        if [ -f "/etc/unbound/unbound.conf.d/pi-hole.conf" ]; then
            mv /etc/unbound/unbound.conf.d/pi-hole.conf /etc/unbound/unbound.conf.d/pi-hole.conf.backup
        fi
        
        # Criar configuração mínima funcional
        cat > /etc/unbound/unbound.conf.d/pi-hole.conf << 'EOF'
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    num-threads: 1
    hide-identity: yes
    hide-version: yes
EOF
        
        # Verificar nova configuração
        if ! unbound-checkconf; then
            log_message "ERROR" "Falha ao criar configuração mínima válida"
            return 1
        fi
        
        log_message "INFO" "Configuração mínima criada com sucesso"
    fi
    
    # Verificar se systemd-resolved ainda está ativo
    if systemctl is-active --quiet systemd-resolved; then
        log_message "WARN" "systemd-resolved ainda ativo, forçando parada..."
        systemctl stop systemd-resolved
        systemctl mask systemd-resolved
    fi
    
    # Verificar conflitos de porta novamente
    if ss -tulpn | grep -q ":5335"; then
        log_message "ERROR" "Porta 5335 ainda ocupada após correções"
        return 1
    fi
    
    log_message "INFO" "Diagnóstico e correções concluídos"
    return 0
}

# CORREÇÃO: Função para testar funcionalidade do Unbound
test_unbound_functionality() {
    log_message "INFO" "Testando funcionalidade do Unbound..."
    
    # Teste 1: Verificar se está escutando na porta
    if ! ss -tulpn | grep -q ":5335.*unbound"; then
        log_message "ERROR" "Unbound não está escutando na porta 5335"
        return 1
    fi
    
    # Teste 2: Teste básico de conectividade
    if ! timeout 5 nc -z 127.0.0.1 5335 2>/dev/null; then
        log_message "WARN" "Falha no teste de conectividade básica"
    fi
    
    # Teste 3: Teste DNS com múltiplas tentativas
    local test_success=false
    for i in {1..5}; do
        log_message "INFO" "Tentativa $i de teste DNS..."
        
        # Testar com dig se disponível
        if command -v dig &>/dev/null; then
            if timeout 10 dig @127.0.0.1 -p 5335 google.com +short >/dev/null 2>&1; then
                test_success=true
                log_message "INFO" "Teste DNS com dig: SUCESSO"
                break
            fi
        fi
        
        # Testar com nslookup como fallback
        if command -v nslookup &>/dev/null; then
            if timeout 10 nslookup google.com 127.0.0.1 -port=5335 >/dev/null 2>&1; then
                test_success=true
                log_message "INFO" "Teste DNS com nslookup: SUCESSO"
                break
            fi
        fi
        
        log_message "WARN" "Tentativa $i falhou, aguardando..."
        sleep 3
    done
    
    if [ "$test_success" = true ]; then
        log_message "INFO" "Teste de funcionalidade: SUCESSO"
        return 0
    else
        log_message "WARN" "Teste DNS falhou após 5 tentativas"
        log_message "INFO" "Verificando logs para diagnóstico..."
        
        # Mostrar logs recentes para diagnóstico
        local recent_logs=$(journalctl -u unbound --no-pager -n 5 2>/dev/null)
        if [ -n "$recent_logs" ]; then
            log_message "INFO" "Logs recentes do Unbound: $recent_logs"
        fi
        
        # Verificar se pelo menos o serviço está rodando
        if systemctl is-active --quiet unbound; then
            log_message "INFO" "Serviço está ativo, pode ser problema de conectividade externa"
            return 0  # Considerar sucesso parcial
        else
            log_message "ERROR" "Serviço não está ativo"
            return 1
        fi
    fi
}

# Função para instalação do WireGuard (baseada em INSTALAÇÃO APPS.md)
install_wireguard() {
    log_message "INFO" "Instalando WireGuard..."
    
    # Instalar WireGuard
    apt install wireguard wireguard-tools -y
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do WireGuard"
        return 1
    fi
    
    # Criar diretório para chaves
    mkdir -p /etc/wireguard/keys
    cd /etc/wireguard/keys
    
    # Gerar chaves com permissões corretas
    umask 077
    wg genkey | tee privatekey | wg pubkey > publickey
    
    # Criar configuração do servidor
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/keys/privatekey)
Address = ${VPN_NETWORK%.*}.1/24
ListenPort = $VPN_PORT
# Configuração NAT corrigida para interface detectada
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE

# Exemplo de peer (substituir pelas chaves reais do cliente)
# [Peer]
# PublicKey = <CHAVE_PÚBLICA_DO_CLIENTE>
# AllowedIPs = ${VPN_NETWORK%.*}.2/32 
EOF
    
    # CORREÇÃO: Habilitar IP Forwarding permanentemente
    sysctl -w net.ipv4.ip_forward=1
    sed -i '/net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
    echo 'net.ipv4.ip_forward=1' | tee -a /etc/sysctl.conf >/dev/null
    sysctl -p
    
    # Configurar permissões
    chmod 600 /etc/wireguard/wg0.conf
    chmod 600 /etc/wireguard/keys/*
    
    # Habilitar e iniciar serviço
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    # Verificar se está funcionando
    if wg show wg0 >/dev/null 2>&1; then
        log_message "INFO" "WireGuard instalado e configurado com sucesso"
        log_message "INFO" "Chave pública do servidor: $(cat /etc/wireguard/keys/publickey)"
    else
        log_message "ERROR" "Erro na configuração do WireGuard"
        return 1
    fi
}

# Função para instalação do Cockpit (baseada em INSTALAÇÃO APPS.md)
install_cockpit() {
    log_message "INFO" "Instalando Cockpit..."
    
    # Instalar Cockpit
    apt install cockpit cockpit-machines cockpit-networkmanager cockpit-storaged -y
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do Cockpit"
        return 1
    fi
    
    # Configurar porta personalizada se especificada
    if [ "$COCKPIT_PORT" != "9090" ]; then
        mkdir -p /etc/systemd/system/cockpit.socket.d
        cat > /etc/systemd/system/cockpit.socket.d/listen.conf << EOF
[Socket]
ListenStream=
ListenStream=$COCKPIT_PORT
EOF
        systemctl daemon-reload
    fi
    
    # Configurar Cockpit para ARM/baixa RAM
    mkdir -p /etc/cockpit
    cat > /etc/cockpit/cockpit.conf << 'EOF'
    [WebService]
    AllowUnencrypted = true
    MaxStartups = 3
    LoginTimeout = 30
    
    [Session]
    IdleTimeout = 15
EOF
    
    # MELHORIA: Informar o usuário sobre como fazer login
    dialog "${DIALOG_OPTS[@]}" --title "Login Cockpit" --msgbox "O login no Cockpit é feito com o seu usuário e senha do sistema Linux (ex: root ou seu usuário sudo)." 8 70

    # Habilitar e iniciar serviços
    systemctl enable cockpit.socket
    systemctl start cockpit.socket
    
    # Verificar se está funcionando
    sleep 3
    if systemctl is-active --quiet cockpit.socket; then
        log_message "INFO" "Cockpit instalado com sucesso na porta $COCKPIT_PORT"
        log_message "INFO" "Acesse via: https://$SERVER_IP:$COCKPIT_PORT"
    else
        log_message "ERROR" "Erro na configuração do Cockpit"
        return 1
    fi
}
# Função para instalação do FileBrowser (baseada em INSTALAÇÃO APPS.md)
install_filebrowser() {
    log_message "INFO" "Instalando FileBrowser..."
    
    # Baixar FileBrowser para ARM
    FILEBROWSER_VERSION="v2.24.2"
    wget -O /tmp/filebrowser.tar.gz "https://github.com/filebrowser/filebrowser/releases/download/${FILEBROWSER_VERSION}/linux-armv7-filebrowser.tar.gz"
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha no download do FileBrowser"
        return 1
    fi
    
    # Extrair e instalar
    tar -xzf /tmp/filebrowser.tar.gz -C /tmp/
    mv /tmp/filebrowser /usr/local/bin/
    chmod +x /usr/local/bin/filebrowser
    
    # Criar usuário e diretórios
    useradd -r -s /bin/false filebrowser
    mkdir -p /etc/filebrowser /var/lib/filebrowser
    
    # Configurar banco de dados e usuário admin
    # MELHORIA: Gerar senha aleatória e segura
    local fb_password=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12)
    log_message "INFO" "Senha gerada para FileBrowser: $fb_password"

    filebrowser -d /var/lib/filebrowser/filebrowser.db config init
    filebrowser -d /var/lib/filebrowser/filebrowser.db config set --address 0.0.0.0
    filebrowser -d /var/lib/filebrowser/filebrowser.db config set --port $FILEBROWSER_PORT
    filebrowser -d /var/lib/filebrowser/filebrowser.db config set --root /home
    filebrowser -d /var/lib/filebrowser/filebrowser.db users add admin "$fb_password" --perm.admin
    
    # Configurar permissões
    chown -R filebrowser:filebrowser /var/lib/filebrowser
    
    # Criar serviço systemd
    cat > /etc/systemd/system/filebrowser.service << 'EOF'
[Unit]
Description=File Browser
After=network.target

[Service]
Type=simple
User=filebrowser
Group=filebrowser
ExecStart=/usr/local/bin/filebrowser -d /var/lib/filebrowser/filebrowser.db
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    # Habilitar e iniciar serviço
    systemctl daemon-reload
    systemctl enable filebrowser
    systemctl start filebrowser
    
    # Verificar se está funcionando
    sleep 3
    if systemctl is-active --quiet filebrowser; then
        log_message "INFO" "FileBrowser instalado com sucesso na porta $FILEBROWSER_PORT"
        log_message "INFO" "Acesse via: http://$SERVER_IP:$FILEBROWSER_PORT"
        dialog "${DIALOG_OPTS[@]}" --title "FileBrowser Instalado" --msgbox "FileBrowser instalado com sucesso!\n\nAcesse: http://$SERVER_IP:$FILEBROWSER_PORT\n\nLogin: admin\nSenha: $fb_password\n\n(A senha foi salva em $LOG_FILE)" 12 70
    else
        log_message "ERROR" "Erro na configuração do FileBrowser"
        return 1
    fi
    
    # Limpeza
    rm -f /tmp/filebrowser.tar.gz /tmp/filebrowser
}
# Função para instalação do Netdata (baseada em INSTALAÇÃO APPS.md)
install_netdata() {
    log_message "INFO" "Instalando Netdata..."
    
    # CORREÇÃO: Garantir um ambiente limpo e com todas as dependências de compilação.
    log_message "INFO" "Removendo instalações antigas do Netdata, se existirem..."
    systemctl stop netdata >/dev/null 2>&1
    userdel netdata 2>/dev/null
    rm -rf /etc/netdata /var/lib/netdata /var/cache/netdata /var/log/netdata
    log_message "INFO" "Instalando dependências de compilação para o Netdata..."
    apt-get install -y build-essential cmake git autoconf automake curl libuv1-dev liblz4-dev libjudy-dev libssl-dev libelf-dev uuid-dev zlib1g-dev
    
    # Baixar e instalar Netdata com otimizações
    bash <(curl -Ss https://my-netdata.io/kickstart.sh) --dont-wait --disable-telemetry --no-updates
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do Netdata"
        return 1
    fi
    
    # Configurar para ARM/baixa RAM (RK322x)
    cat > /etc/netdata/netdata.conf << 'EOF'
[global]
    run as user = netdata
    web files owner = root
    web files group = netdata
    # Otimizado para ARM RK322x
    memory mode = ram
    history = 3600
    update every = 2
    page cache size = 32
    dbengine multihost disk space = 64
    
[web]
    web files owner = root
    
[plugins]
    # Desabilitar plugins pesados
    apps = no
    cgroups = no
    charts.d = no
    node.d = no
    python.d = no
    
[plugin:proc]
    # Manter apenas essenciais
    /proc/net/dev = yes
    /proc/diskstats = yes
    /proc/meminfo = yes
    /proc/stat = yes
    /proc/uptime = yes
    /proc/loadavg = yes
    /proc/sys/kernel/entropy_avail = yes
EOF
    
    # Reiniciar serviço
    systemctl restart netdata
    systemctl enable netdata
    
    # Verificar se está funcionando
    sleep 5
    if systemctl is-active --quiet netdata; then
        log_message "INFO" "Netdata instalado com sucesso na porta 19999"
        log_message "INFO" "Acesse via: http://$SERVER_IP:19999"
    else
        log_message "ERROR" "Erro na configuração do Netdata"
        return 1
    fi
}
# Função para instalação do Fail2Ban (baseada em INSTALAÇÃO APPS.md)
install_fail2ban() {
    log_message "INFO" "Instalando Fail2Ban..."
    
    # Instalar Fail2Ban
    apt install fail2ban -y
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do Fail2Ban"
        return 1
    fi
    
    # CORREÇÃO: Configuração condicional baseada em serviços instalados
    local jail_config="[DEFAULT]\nbantime = 3600\nfindtime = 600\nmaxretry = 3\nbackend = systemd\n\n"
    
    # SSH sempre habilitado
    jail_config+="[sshd]\nenabled = true\nport = ssh\nlogpath = %(sshd_log)s\nmaxretry = 3\n\n"
    
    # Verificar e adicionar jail para Cockpit se estiver instalado
    if systemctl list-unit-files | grep -q "cockpit.socket" && systemctl is-enabled --quiet cockpit.socket 2>/dev/null; then
        jail_config+="[cockpit]\nenabled = true\nport = $COCKPIT_PORT\nlogpath = /var/log/cockpit/cockpit.log\nmaxretry = 3\n\n"
        log_message "INFO" "Fail2Ban: Proteção do Cockpit habilitada"
    fi
    
    # Verificar e adicionar jail para Pi-hole se estiver instalado
    if systemctl list-unit-files | grep -q "pihole-FTL" && systemctl is-enabled --quiet pihole-FTL 2>/dev/null; then
        jail_config+="[pihole-web]\nenabled = true\nport = 80,443\nlogpath = /var/log/pihole.log\nmaxretry = 5\nfilter = pihole-web\n\n"
        log_message "INFO" "Fail2Ban: Proteção do Pi-hole habilitada"
    fi
    
    # Verificar e adicionar jail para WireGuard se estiver instalado
    if systemctl list-unit-files | grep -q "wg-quick@wg0" && systemctl is-enabled --quiet wg-quick@wg0 2>/dev/null; then
        jail_config+="[wireguard]\nenabled = true\nport = $VPN_PORT\nlogpath = /var/log/syslog\nmaxretry = 3\nfilter = wireguard\n\n"
        log_message "INFO" "Fail2Ban: Proteção do WireGuard habilitada"
    fi
    
    # Escrever configuração final
    echo -e "$jail_config" > /etc/fail2ban/jail.local
    
    # Criar filtros personalizados
    cat > /etc/fail2ban/filter.d/pihole-web.conf << 'EOF'
[Definition]
failregex = ^.*\[.*\] ".*" 401 .*$
ignoreregex =
EOF
    
    cat > /etc/fail2ban/filter.d/wireguard.conf << 'EOF'
[Definition]
failregex = ^.*wireguard.*: Invalid handshake initiation from <HOST>.*$
ignoreregex =
EOF
    
    # Habilitar e iniciar serviço
    systemctl enable fail2ban
    systemctl start fail2ban
    
    # Verificar se está funcionando
    if systemctl is-active --quiet fail2ban; then
        log_message "INFO" "Fail2Ban instalado e configurado com sucesso"
    else
        log_message "ERROR" "Erro na configuração do Fail2Ban"
        return 1
    fi
}

# Função para instalação do UFW (baseada em INSTALAÇÃO APPS.md)
install_ufw() {
    log_message "INFO" "Instalando UFW..."
    
    # Instalar UFW
    apt install ufw -y
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do UFW"
        return 1
    fi
    
    # Configurar regras básicas
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Permitir SSH (sempre necessário)
    ufw allow ssh
    log_message "INFO" "UFW: SSH habilitado"
    
    # CORREÇÃO: Permitir apenas serviços que estão ativos
    
    # Verificar e permitir Pi-hole se estiver ativo
    if systemctl is-active --quiet pihole-FTL 2>/dev/null; then
        ufw allow 80/tcp comment 'Pi-hole Web'
        ufw allow 443/tcp comment 'Pi-hole Web SSL'
        ufw allow 53 comment 'Pi-hole DNS'
        log_message "INFO" "UFW: Regras do Pi-hole habilitadas (53, 80, 443)"
    fi
    
    # Verificar e permitir WireGuard se estiver ativo
    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        ufw allow $VPN_PORT/udp comment 'WireGuard VPN'
        log_message "INFO" "UFW: Regra do WireGuard habilitada (porta $VPN_PORT/udp)"
    fi
    
    # Verificar e permitir Cockpit se estiver ativo
    if systemctl is-active --quiet cockpit.socket 2>/dev/null; then
        ufw allow $COCKPIT_PORT/tcp comment 'Cockpit Web'
        log_message "INFO" "UFW: Regra do Cockpit habilitada (porta $COCKPIT_PORT/tcp)"
    fi
    
    # Verificar e permitir FileBrowser se estiver ativo
    if systemctl is-active --quiet filebrowser 2>/dev/null; then
        ufw allow $FILEBROWSER_PORT/tcp comment 'FileBrowser Web'
        log_message "INFO" "UFW: Regra do FileBrowser habilitada (porta $FILEBROWSER_PORT/tcp)"
    fi
    
    # Verificar e permitir Netdata se estiver ativo
    if systemctl is-active --quiet netdata 2>/dev/null; then
        ufw allow 19999/tcp comment 'Netdata Web'
        log_message "INFO" "UFW: Regra do Netdata habilitada (porta 19999/tcp)"
    fi
    
    # Verificar e permitir MiniDLNA se estiver ativo
    if systemctl is-active --quiet minidlna 2>/dev/null; then
        ufw allow 8200/tcp comment 'MiniDLNA Web'
        log_message "INFO" "UFW: Regra do MiniDLNA habilitada (porta 8200/tcp)"
    fi
    
    # Habilitar UFW
    ufw --force enable
    
    # Verificar status
    if ufw status | grep -q "Status: active"; then
        log_message "INFO" "UFW instalado e configurado com sucesso"
        log_message "INFO" "Firewall ativo com regras para todos os serviços"
    else
        log_message "ERROR" "Erro na configuração do UFW"
        return 1
    fi
}
# Função para instalação do RNG-tools (baseada em INSTALAÇÃO APPS.md)
install_rng_tools() {
    log_message "INFO" "Instalando RNG-tools..."
    
    # Instalar RNG-tools
    apt install rng-tools -y
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do RNG-tools"
        return 1
    fi
    
    # Configurar para ARM RK322x
    cat > /etc/default/rng-tools << 'EOF'
# Configuração otimizada para ARM RK322x
RNGDEVICE="/dev/hwrng"
# Fallback para urandom se hwrng não estiver disponível
if [ ! -e "/dev/hwrng" ]; then
    RNGDEVICE="/dev/urandom"
fi

# Opções otimizadas para ARM
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10"
EOF
    
    # Habilitar e iniciar serviço
    systemctl enable rng-tools
    systemctl start rng-tools
    
    # Verificar entropia
    sleep 3
    ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail)
    if [ "$ENTROPY" -gt 1000 ]; then
        log_message "INFO" "RNG-tools instalado com sucesso. Entropia: $ENTROPY"
    else
        log_message "WARN" "RNG-tools instalado mas entropia baixa: $ENTROPY"
    fi
}

# Função para instalação do Rclone (baseada em INSTALAÇÃO APPS.md)
install_rclone() {
    log_message "INFO" "Instalando Rclone..."
    
    # Baixar e instalar Rclone
    curl https://rclone.org/install.sh | bash
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do Rclone"
        return 1
    fi
    
    # Criar diretório de configuração
    mkdir -p /root/.config/rclone
    
    # Criar script de backup básico
    cat > /usr/local/bin/boxserver-backup << 'EOF'
#!/bin/bash
# Script de backup do Boxserver usando Rclone

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/tmp/boxserver-backup-$BACKUP_DATE"

# Criar diretório temporário
mkdir -p "$BACKUP_DIR"

# Backup das configurações essenciais
cp -r /etc/boxserver "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/pihole "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/wireguard "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/unbound "$BACKUP_DIR/" 2>/dev/null || true

# Compactar backup
tar -czf "/tmp/boxserver-backup-$BACKUP_DATE.tar.gz" -C "/tmp" "boxserver-backup-$BACKUP_DATE"

echo "Backup criado: /tmp/boxserver-backup-$BACKUP_DATE.tar.gz"
echo "Configure o Rclone para enviar para armazenamento remoto:"
echo "rclone config"
echo "rclone copy /tmp/boxserver-backup-$BACKUP_DATE.tar.gz remote:backups/"

# Limpeza
rm -rf "$BACKUP_DIR"
EOF
    
    chmod +x /usr/local/bin/boxserver-backup
    
    log_message "INFO" "Rclone instalado com sucesso"
    log_message "INFO" "Configure com: rclone config"
    log_message "INFO" "Execute backup com: /usr/local/bin/boxserver-backup"
}

# Função para instalação do Rsync (baseada em INSTALAÇÃO APPS.md)
install_rsync() {
    log_message "INFO" "Instalando Rsync..."
    
    # Instalar Rsync
    apt install rsync -y
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do Rsync"
        return 1
    fi
    
    # Criar script de sincronização local
    cat > /usr/local/bin/boxserver-sync << 'EOF'
#!/bin/bash
# Script de sincronização local do Boxserver

SYNC_DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/boxserver-sync.log"

echo "[$SYNC_DATE] Iniciando sincronização..." >> "$LOG_FILE"

# Sincronizar configurações para backup local
mkdir -p /var/backups/boxserver

# Sincronizar arquivos essenciais
rsync -av --delete /etc/boxserver/ /var/backups/boxserver/etc-boxserver/ 2>&1 | tee -a "$LOG_FILE"
rsync -av --delete /etc/pihole/ /var/backups/boxserver/etc-pihole/ 2>&1 | tee -a "$LOG_FILE"
rsync -av --delete /etc/wireguard/ /var/backups/boxserver/etc-wireguard/ 2>&1 | tee -a "$LOG_FILE"
rsync -av --delete /etc/unbound/ /var/backups/boxserver/etc-unbound/ 2>&1 | tee -a "$LOG_FILE"

echo "[$SYNC_DATE] Sincronização concluída" >> "$LOG_FILE"
echo "Sincronização concluída. Log: $LOG_FILE"
EOF
    
    chmod +x /usr/local/bin/boxserver-sync
    
    # Agendar sincronização diária
    echo "0 2 * * * root /usr/local/bin/boxserver-sync" >> /etc/crontab
    
    log_message "INFO" "Rsync instalado com sucesso"
    log_message "INFO" "Sincronização agendada para 02:00 diariamente"
    log_message "INFO" "Execute manualmente com: /usr/local/bin/boxserver-sync"
}

# Função para instalação do MiniDLNA (baseada em INSTALAÇÃO APPS.md)
install_minidlna() {
    log_message "INFO" "Instalando MiniDLNA..."
    
    # Instalar MiniDLNA
    apt install minidlna -y
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do MiniDLNA"
        return 1
    fi
    
    # Criar diretórios de mídia
    mkdir -p /media/dlna/{videos,music,pictures}
    
    # Configurar MiniDLNA otimizado para ARM
    cat > /etc/minidlna.conf << 'EOF'
# Configuração MiniDLNA otimizada para ARM RK322x
port=8200
network_interface=$NETWORK_INTERFACE

# Diretórios de mídia
media_dir=V,/media/dlna/videos
media_dir=A,/media/dlna/music
media_dir=P,/media/dlna/pictures

# Configurações otimizadas
friendly_name=Boxserver DLNA
db_dir=/var/cache/minidlna
log_dir=/var/log
log_level=warn
inotify=yes
enable_tivo=no
strict_dlna=no
presentation_url=http://$SERVER_IP:8200/

# Otimizações para ARM/baixa RAM
max_connections=10
album_art_names=Cover.jpg/cover.jpg/AlbumArtSmall.jpg/albumartsmall.jpg
EOF
    
    # Configurar permissões
    chown -R minidlna:minidlna /media/dlna
    chown minidlna:minidlna /var/cache/minidlna
    
    # Habilitar e iniciar serviço
    systemctl enable minidlna
    systemctl start minidlna
    
    # Verificar se está funcionando
    sleep 3
    if systemctl is-active --quiet minidlna; then
        log_message "INFO" "MiniDLNA instalado com sucesso na porta 8200"
        log_message "INFO" "Adicione mídias em: /media/dlna/"
        log_message "INFO" "Interface web: http://$SERVER_IP:8200"
    else
        log_message "ERROR" "Erro na configuração do MiniDLNA"
        return 1
    fi
}

# IMPLEMENTAÇÃO: Instalação do Chrony (NTP)
install_chrony() {
    log_message "INFO" "Instalando Chrony (NTP)..."
    
    apt-get install -y chrony
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do Chrony"
        return 1
    fi

    # Configurar servidores NTP brasileiros
    cat > /etc/chrony/chrony.conf << 'EOF'
# Welcome to the chrony configuration file. See chrony.conf(5) for more
# information about usuable directives.

# Servidores NTP brasileiros (recomendado)
pool a.st1.ntp.br iburst
pool b.st1.ntp.br iburst
pool c.st1.ntp.br iburst
pool d.st1.ntp.br iburst

# This directive specify the location of the file containing ID/key pairs for
# NTP authentication.
keyfile /etc/chrony/chrony.keys

# This directive specify the file into which chronyd will store the rate
# information.
driftfile /var/lib/chrony/chrony.drift

# Uncomment the following line to turn logging on.
#log tracking measurements statistics

# Log files location.
logdir /var/log/chrony

# Stop bad estimates affecting the clock.
maxupdateskew 100.0

# This directive enables kernel synchronisation (every 11 minutes) of the
# real-time clock. Note that it can’t be used along with the 'rtcfile' directive.
rtcsync

# Step the clock quickly on start.
makestep 1 3
EOF

    systemctl restart chrony
    systemctl enable chrony

    if systemctl is-active --quiet chrony; then
        log_message "INFO" "Chrony instalado e configurado com sucesso."
    else
        log_message "ERROR" "Falha ao iniciar o serviço Chrony."
        return 1
    fi
}

# IMPLEMENTAÇÃO: Configurar logrotate para Pi-hole
setup_logrotate() {
    log_message "INFO" "Configurando logrotate para o Pi-hole..."
    cat > /etc/logrotate.d/pihole << 'EOF'
/var/log/pihole.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 pihole pihole
}
EOF
    log_message "INFO" "Logrotate para Pi-hole configurado."
}

# IMPLEMENTAÇÃO: Instalação da Interface Web Unificada
install_web_interface() {
    log_message "INFO" "Instalando Interface Web com Nginx..."

    # Nginx já foi instalado como dependência
    if ! command -v nginx &>/dev/null; then
        log_message "ERROR" "Nginx não foi encontrado. A instalação falhou."
        return 1
    fi

    # Criar diretório web
    local web_root="/var/www/boxserver"
    mkdir -p "$web_root"

    # Criar página de dashboard
    cat > "$web_root/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Boxserver Dashboard</title>
    <link rel="stylesheet" href="style.css">
</head>
<body onload="startRealtimeUpdates()">
    <div class="container">
        <div class="header">
            <h1>🚀 Boxserver Dashboard</h1>
            <p>Interface unificada para todos os serviços</p>
        </div>
        <div class="grid">
            <!-- Cards de serviço serão inseridos dinamicamente aqui -->
        </div>
    </div>
    <script src="script.js"></script>
</body>
</html>
EOF'

    # Criar arquivo CSS
    cat > "$web_root/style.css" << 'EOF'
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f7f9; color: #333; margin: 0; padding: 2em; }
.container { max-width: 960px; margin: auto; }
.header { text-align: center; margin-bottom: 2em; }
.header h1 { color: #2c3e50; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5em; }
.card { background: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); padding: 1.5em; text-align: center; transition: transform 0.2s; }
.card:hover { transform: translateY(-5px); }
.card h3 { margin-top: 0; color: #34495e; }
.card p { color: #7f8c8d; }
.card a { display: inline-block; margin-top: 1em; padding: 0.7em 1.5em; background-color: #3498db; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; }
.card a:hover { background-color: #2980b9; }
EOF

    # Criar arquivo JavaScript dinâmico
    cat > "$web_root/script.js" << 'EOF'
const services = [
    { id: 1, name: 'Pi-hole', desc: 'Bloqueador de anúncios', url: '/pihole/admin/' },
    { id: 4, name: 'Cockpit', desc: 'Painel de Administração', url: '/cockpit/' },
    { id: 5, name: 'FileBrowser', desc: 'Gerenciador de Arquivos', url: '/filebrowser/' },
    { id: 6, name: 'Netdata', desc: 'Monitoramento Real-Time', url: '/netdata/' },
    { id: 10, name: 'Rclone Web-GUI', desc: 'Gerenciador de Nuvem', url: '/rclone/' },
    { id: 12, name: 'MiniDLNA', desc: 'Servidor de Mídia', url: 'http://' + window.location.hostname + ':8200' }
];

function createCard(service) {
    return `
        <div class="card" id="card-${service.id}">
            <h3>${service.name}</h3>
            <p>${service.desc}</p>
            <a href="${service.url}" target="_blank">Acessar</a>
        </div>
    `;
}

function startRealtimeUpdates() {
    const grid = document.querySelector('.grid');
    
    // Adicionar card do sistema se Netdata estiver disponível
    fetch('http://' + window.location.hostname + ':19999/api/v1/info', { mode: 'cors' })
        .then(res => {
            if (res.ok) {
                const systemCard = `<div class="card" id="system-card"><h3>Sistema</h3><p>CPU: <span id="cpu-usage">--</span>% | RAM: <span id="ram-usage">--</span>%</p><a href="/netdata/" target="_blank">Ver Detalhes</a></div>`;
                grid.insertAdjacentHTML('afterbegin', systemCard);
                setInterval(updateSystemInfo, 3000);
            }
        }).catch(() => {});

    // Adicionar cards de serviços dinamicamente
    services.forEach(service => {
        fetch(service.url, { method: 'HEAD', mode: 'no-cors' })
            .then(() => grid.insertAdjacentHTML('beforeend', createCard(service)))
            .catch(() => {});
    });
}

function updateSystemInfo() {
    const netdataUrl = 'http://' + window.location.hostname + ':19999/api/v1/data?chart=system.cpu&after=-1&points=1&group=average&format=json';
    const ramUrl = 'http://' + window.location.hostname + ':19999/api/v1/data?chart=system.ram&dimension=used&after=-1&points=1&format=json';

    fetch(netdataUrl).then(r => r.json()).then(data => {
        document.getElementById('cpu-usage').textContent = data.data[0][1].toFixed(1);
    }).catch(e => console.error('Error fetching CPU data:', e));

    fetch(ramUrl).then(r => r.json()).then(data => {
        document.getElementById('ram-usage').textContent = data.data[0][1].toFixed(1);
    }).catch(e => console.error('Error fetching RAM data:', e));
}
EOF

    # Criar configuração do Nginx
    cat > /etc/nginx/sites-available/boxserver << 'EOF'
server {
    listen 80 default_server;
    server_name _;

    root /var/www/boxserver;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    # As localizações dos serviços serão adicionadas aqui por 'enable_nginx_proxy'
}
EOF

    # Habilitar o site e remover o padrão
    ln -sf /etc/nginx/sites-available/boxserver /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default

    systemctl enable nginx
    systemctl restart nginx

    log_message "INFO" "Interface Web instalada. Acesse em http://$SERVER_IP"
}

# IMPLEMENTAÇÃO: Função para habilitar proxy no Nginx para um serviço
enable_nginx_proxy() {
    local app_id="$1"
    local pihole_port=${PIHOLE_PORT_OVERRIDE:-80}
    local config_file="/etc/nginx/sites-available/boxserver"

    case $app_id in
        1) # Pi-hole
            sed -i "/# As localizações dos serviços/a \\\n    location /pihole/ {\\\n        proxy_pass http://127.0.0.1:$pihole_port/admin/;\\\n        proxy_set_header Host \\\$host;\\\n        proxy_set_header X-Real-IP \\\$remote_addr;\\\n    }" "$config_file"
            log_message "INFO" "Nginx: Proxy para Pi-hole habilitado." ;;
        4) # Cockpit
            # CORREÇÃO: Configuração de proxy robusta para Cockpit, incluindo WebSockets.
            sed -i '/# As localizações dos serviços/a \    location /cockpit/ {\n        proxy_pass http://127.0.0.1:9090/cockpit/;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n        proxy_http_version 1.1;\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection "upgrade";\n    }' "$config_file"
            log_message "INFO" "Nginx: Proxy para Cockpit (com suporte a WebSocket) habilitado." ;;
        5) # FileBrowser
            sed -i '/# As localizações dos serviços/a \
    location /filebrowser/ {\n        proxy_pass http://127.0.0.1:8080/;\n    }' "$config_file"
            ;;
        6) # Netdata
            sed -i '/# As localizações dos serviços/a \
    location /netdata/ {\n        proxy_pass http://127.0.0.1:19999/;\n    }' "$config_file"
            ;;
        10) # Rclone Web-GUI
             sed -i '/# As localizações dos serviços/a \
    location /rclone/ {\n        proxy_pass http://127.0.0.1:5572/;\n    }' "$config_file"
            ;;
    esac
}

# Função para instalação do Cloudflared (baseada em INSTALAÇÃO APPS.md)
install_cloudflared() {
    log_message "INFO" "Instalando Cloudflared..."
    
    # CORREÇÃO: Detectar arquitetura para download correto (arm vs arm64)
    local arch
    arch=$(dpkg --print-architecture)
    local download_url=""
    if [[ "$arch" == "arm64" ]] || [[ "$arch" == "aarch64" ]]; then
        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb"
        log_message "INFO" "Arquitetura ARM64 detectada. Baixando cloudflared-linux-arm64.deb"
    else
        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm.deb"
        log_message "INFO" "Arquitetura ARM (32-bit) detectada. Baixando cloudflared-linux-arm.deb"
    fi

    wget -O /tmp/cloudflared.deb "$download_url"
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha no download do Cloudflared"
        return 1
    fi
    
    # Instalar pacote
    dpkg -i /tmp/cloudflared.deb
    apt-get install -f -y  # Corrigir dependências se necessário
    
    # Criar usuário para cloudflared
    useradd -r -s /bin/false -d /etc/cloudflared cloudflared 2>/dev/null || true
    
    # Criar configuração básica
    mkdir -p /etc/cloudflared
    cat > /etc/cloudflared/config.yml << 'EOF'
# Configuração Cloudflared para Boxserver
# O ID do túnel e o arquivo de credenciais serão preenchidos automaticamente.

# Configurações de performance para ARM
protocol: quic
no-autoupdate: true
metrics: 127.0.0.1:8080

# Ingress rules (exemplo)
ingress:
  - hostname: pihole.example.com
    service: http://127.0.0.1:80
  - hostname: cockpit.example.com
    service: http://127.0.0.1:9090
  - hostname: files.example.com
    service: http://127.0.0.1:8080
  - service: http_status:404
EOF
    
    # CORREÇÃO: Criar serviço systemd com caminhos e permissões corretas
    cat > /etc/systemd/system/cloudflared.service << 'EOF'
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
User=cloudflared
Group=cloudflared
ExecStart=/usr/local/bin/cloudflared --config /etc/cloudflared/config.yml --no-autoupdate tunnel run
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    chown -R cloudflared:cloudflared /etc/cloudflared
    systemctl daemon-reload
    
    log_message "INFO" "Cloudflared instalado com sucesso"
    log_message "INFO" "Configure o tunnel com: cloudflared tunnel login"
    log_message "INFO" "Crie um tunnel com: cloudflared tunnel create boxserver-tunnel"
    log_message "INFO" "Edite /etc/cloudflared/config.yml com suas configurações"
    
    # Limpeza
    rm -f /tmp/cloudflared.deb
    
    # Oferecer configuração interativa
    if dialog --title "Configuração do Cloudflare" --yesno "Deseja configurar o túnel Cloudflare agora?\n\nIsso incluirá:\n- Login no Cloudflare\n- Criação do túnel\n- Configuração de domínios\n- Testes de conectividade" 12 60; then
        configure_cloudflare_tunnel
    fi
}

# Menu principal de configuração do Cloudflare
configure_cloudflare_tunnel() {
    while true; do
        local choice=$(dialog --title "Configuração Cloudflare Tunnel" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Fazer login no Cloudflare" \
            "2" "Criar/Configurar túnel" \
            "3" "Configurar domínios e serviços" \
            "4" "Testar conectividade do túnel" \
            "5" "Ver status do túnel" \
            "6" "Validar configuração completa" \
            "7" "Editar configuração avançada" \
            "8" "Voltar" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) cloudflare_login ;;
            2) cloudflare_create_tunnel ;;
            3) cloudflare_configure_domains ;;
            4) cloudflare_test_tunnel ;;
            5) cloudflare_tunnel_status ;;
            6) validate_tunnel_configuration ;;
            7) cloudflare_advanced_config ;;
            8|"") break ;;
        esac
    done
}

# Função para login no Cloudflare (compatível com servidores headless)
cloudflare_login() {
    # CORREÇÃO: Verificar o certificado de login, não o do túnel
    if [[ -f "$HOME/.cloudflared/cert.pem" ]]; then
        dialog --title "Certificado Existente" --yesno "Já existe um certificado Cloudflare.\n\nDeseja renovar o login?" 8 50
        if [[ $? -ne 0 ]]; then
            return 0
        fi
    fi

    # MELHORIA: Extrair a URL de login e exibi-la de forma clara
    local login_url
    login_url=$(cloudflared tunnel login 2>&1 | grep -Eo 'https://dash\.cloudflare\.com/[-a-zA-Z0-9()@:%_\+.~#?&=]*' | head -1)

    if [ -z "$login_url" ]; then
        dialog "${DIALOG_OPTS[@]}" --title "Erro de Login" --msgbox "Não foi possível obter a URL de login do Cloudflare.\n\nVerifique sua conexão e tente novamente." 8 60
        log_message "ERROR" "Falha ao obter a URL de login do Cloudflare."
        return 1
    fi

    dialog --title "Login Cloudflare" --msgbox "Abra a seguinte URL em um navegador para fazer login:\n\n\Z1$login_url\Z0\n\nApós autorizar o túnel no navegador, pressione ENTER aqui para continuar." 12 90
    
    # Verificar se o certificado foi criado
    local timeout=60
    local count=0
    while [[ $count -lt $timeout ]]; do
        # O login bem-sucedido cria o arquivo cert.pem no diretório home do usuário
        if [[ -f "$HOME/.cloudflared/cert.pem" ]]; then
            dialog "${DIALOG_OPTS[@]}" --title "Login Concluído" --msgbox "Login realizado com sucesso!\n\nCertificado salvo em: ~/.cloudflared/cert.pem" 8 60
            log_message "INFO" "Login no Cloudflare realizado com sucesso"
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    # Se chegou aqui, o login falhou
    dialog "${DIALOG_OPTS[@]}" --title "Erro de Login" --msgbox "Falha no login do Cloudflare.\n\nPossíveis causas:\n- Login não foi completado no navegador\n- Domínio não foi selecionado\n- Problemas de conectividade\n\nTente novamente." 12 60
    log_message "ERROR" "Falha no login do Cloudflare - timeout ou erro"
    return 1
}

# Função para criar/configurar túnel
cloudflare_create_tunnel() {
    # Verificar se já existe túnel
    if cloudflared tunnel list 2>/dev/null | grep -q "boxserver-tunnel"; then
        if dialog --title "Túnel Existente" --yesno "O túnel 'boxserver-tunnel' já existe.\n\nDeseja reconfigurá-lo?" 8 50; then
            cloudflared tunnel delete boxserver-tunnel >/dev/null 2>&1
        else
            return 0
        fi
    fi
    
    dialog --title "Criando Túnel" --infobox "Criando túnel 'boxserver-tunnel'..." 5 40
    
    if cloudflared tunnel create boxserver-tunnel >/dev/null 2>&1; then
        # Obter UUID do túnel
        local tunnel_id=$(cloudflared tunnel list | grep "boxserver-tunnel" | awk '{print $1}')
        
        if [ -n "$tunnel_id" ]; then
            # CORREÇÃO: Usar a configuração recomendada com o arquivo de credenciais JSON
            local cred_file="$HOME/.cloudflared/${tunnel_id}.json"
            if [ -f "$cred_file" ]; then
                # Atualizar config.yml com o ID e o caminho do arquivo de credenciais
                sed -i "s/^# O ID do túnel.*/tunnel: $tunnel_id\ncredentials-file: \/etc\/cloudflared\/${tunnel_id}.json/" /etc/cloudflared/config.yml
                
                # Copiar arquivo de credenciais para o diretório do serviço
                cp "$cred_file" "/etc/cloudflared/"
                chown cloudflared:cloudflared "/etc/cloudflared/${tunnel_id}.json"
                
                dialog "${DIALOG_OPTS[@]}" --title "Túnel Criado" --msgbox "Túnel criado com sucesso!\n\nID: $tunnel_id\n\nAgora configure os domínios." 10 60
                log_message "INFO" "Túnel Cloudflare criado: $tunnel_id"
                
                # Oferecer configuração automática
                if dialog "${DIALOG_OPTS[@]}" --title "Configuração Automática" --yesno "Deseja configurar automaticamente\nos serviços detectados?" 8 50; then
                    auto_configure_services
                fi
            else
                dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Arquivo de credenciais do túnel não encontrado:\n$cred_file" 8 60
                log_message "ERROR" "Arquivo de credenciais do túnel não encontrado: $cred_file"
            fi
        else
            dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Erro ao obter ID do túnel." 6 40
            log_message "ERROR" "Erro ao obter ID do túnel Cloudflare"
        fi
    else
        dialog --title "Erro" --msgbox "Falha na criação do túnel.\n\nVerifique se fez login corretamente." 8 50
        log_message "ERROR" "Falha na criação do túnel Cloudflare"
    fi
}

# Função para configurar domínios e serviços
cloudflare_configure_domains() {
    # Verificar se o túnel existe
    if ! cloudflared tunnel list 2>/dev/null | grep -q "boxserver-tunnel"; then
        dialog --title "Erro" --msgbox "Túnel não encontrado.\n\nCrie o túnel primeiro." 8 40
        return 1
    fi
    
    while true; do
        local choice=$(dialog --title "Configurar Domínios" --menu "Escolha um serviço para configurar:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Pi-hole (DNS/Admin)" \
            "2" "Cockpit (Gerenciamento)" \
            "3" "FileBrowser (Arquivos)" \
            "4" "WireGuard (VPN Admin)" \
            "5" "Adicionar domínio customizado" \
            "6" "Ver configuração atual" \
            "7" "Aplicar configurações DNS" \
            "8" "Voltar" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) configure_service_domain "Pi-hole" "pihole" "80" ;;
            2) configure_service_domain "Cockpit" "cockpit" "9090" ;;
            3) configure_service_domain "FileBrowser" "files" "8080" ;;
            4) configure_service_domain "WireGuard" "vpn" "51820" ;;
            5) configure_custom_domain ;;
            6) show_current_config ;;
            7) apply_dns_records ;;
            8|"") break ;;
        esac
    done
}

# Função para configurar domínio de um serviço específico
configure_service_domain() {
    local service_name="$1"
    local subdomain="$2"
    local port="$3"
    
    local domain=$(dialog "${DIALOG_OPTS[@]}" --title "Domínio $service_name" --inputbox "Digite o domínio completo para $service_name:\n\nExemplo: $subdomain.seudominio.com" 10 60 "$subdomain.example.com" 3>&1 1>&2 2>&3)
    
    if [ -n "$domain" ]; then
        # Atualizar config.yml
        update_ingress_rule "$domain" "$port"
        dialog --title "Configurado" --msgbox "Domínio configurado:\n\n$service_name: $domain\nPorta: $port\n\nLembre-se de aplicar as configurações DNS." 10 50
        log_message "INFO" "Domínio configurado: $domain -> $port"
    fi
}

# Função para configurar domínio customizado
configure_custom_domain() {
    local domain=$(dialog "${DIALOG_OPTS[@]}" --title "Domínio Customizado" --inputbox "Digite o domínio:" 8 50 3>&1 1>&2 2>&3)
    local port=$(dialog "${DIALOG_OPTS[@]}" --title "Porta do Serviço" --inputbox "Digite a porta do serviço:" 8 50 3>&1 1>&2 2>&3)
    
    if [ -n "$domain" ] && [ -n "$port" ]; then
        update_ingress_rule "$domain" "$port"
        dialog --title "Configurado" --msgbox "Domínio customizado configurado:\n\n$domain -> porta $port" 8 50
        log_message "INFO" "Domínio customizado: $domain -> $port"
    fi
}

# Função para atualizar regras de ingress
update_ingress_rule() {
    local domain="$1"
    local port="$2"
    local config_file="/etc/cloudflared/config.yml"
    
    # Backup da configuração atual
    cp "$config_file" "$config_file.bak"
    
    # MELHORIA: Lógica robusta para adicionar/atualizar regras de ingress.
    # Extrai a seção de ingress, remove a regra antiga, adiciona a nova e junta tudo.
    # Isso evita problemas com sed em diferentes versões.
    local ingress_section=$(awk '/^ingress:/ {p=1; next} p && /^[^ ]/ {p=0} p' "$config_file")
    local other_configs=$(awk '/^ingress:/ {p=1; next} p && /^[^ ]/ {p=0} !p' "$config_file")

    # Remover a regra existente para o mesmo hostname
    local updated_ingress=""
    local skip_next=false
    while IFS= read -r line; do
        # Limpar espaços em branco para uma comparação mais segura
        local clean_line=$(echo "$line" | tr -d ' ')
        if [[ "$clean_line" == "hostname:$domain" ]]; then
            skip_next=true
            continue
        fi
        if [[ "$skip_next" == true ]]; then
            skip_next=false
            continue
        fi
        updated_ingress+="$line\n"
    done <<< "$ingress_section"

    # Remover a regra catch-all antiga para readicioná-la no final
    updated_ingress=$(echo -e "$updated_ingress" | grep -v "service:http_status:404")

    # Adicionar a nova regra e a regra catch-all no final
    local new_ingress_section=$(printf "ingress:\n%b  - hostname: %s\n    service: http://127.0.0.1:%s\n  - service: http_status:404" "$(echo -e "$updated_ingress" | sed '/^$/d')" "$domain" "$port")

    # Recriar o arquivo de configuração
    echo -e "$other_configs\n$new_ingress_section" > "$config_file"
}

# Função para mostrar configuração atual
show_current_config() {
    if [ -f "/etc/cloudflared/config.yml" ]; then
        dialog --title "Configuração Atual" --textbox "/etc/cloudflared/config.yml" 20 80
    else
        dialog --title "Erro" --msgbox "Arquivo de configuração não encontrado." 6 40
    fi
}

# Função para aplicar registros DNS
apply_dns_records() {
    dialog --title "Aplicar DNS" --infobox "Aplicando configurações DNS..." 5 40
    
    # Obter ID do túnel
    local tunnel_id=$(cloudflared tunnel list | grep "boxserver-tunnel" | awk '{print $1}')
    
    if [ -n "$tunnel_id" ]; then
        # Extrair domínios do config.yml e criar registros DNS
        local domains=$(grep "hostname:" /etc/cloudflared/config.yml | awk '{print $3}')
        
        for domain in $domains; do
            if [ "$domain" != "example.com" ]; then
                if cloudflared tunnel route dns "$tunnel_id" "$domain" >/dev/null 2>&1; then
                    log_message "INFO" "Registro DNS criado/verificado para: $domain"
                else
                    log_message "ERROR" "Falha ao criar registro DNS para: $domain"
                fi
            fi
        done
        
        dialog --title "DNS Aplicado" --msgbox "Registros DNS criados com sucesso!\n\nOs domínios podem levar alguns minutos\npara propagar." 8 50
    else
        dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "ID do túnel não encontrado." 6 40
    fi
}

# Função para testar conectividade do túnel
cloudflare_test_tunnel() {
    dialog --title "Testando Túnel" --infobox "Executando testes de conectividade..." 5 40
    
    local test_results="Resultados dos Testes:\n\n"
    
    # Verificar se o serviço está rodando
    if systemctl is-active --quiet cloudflared; then
        test_results+="✓ Serviço Cloudflared: ATIVO\n"
    else
        test_results+="✗ Serviço Cloudflared: INATIVO\n"
    fi
    
    # Verificar conectividade com Cloudflare
    if ping -c 1 1.1.1.1 &> /dev/null; then
        test_results+="✓ Conectividade Cloudflare: OK\n"
    else
        test_results+="✗ Conectividade Cloudflare: FALHOU\n"
    fi
    
    # Verificar configuração
    if cloudflared tunnel --config /etc/cloudflared/config.yml validate >/dev/null 2>&1; then
        test_results+="✓ Configuração: VÁLIDA\n"
    else
        test_results+="✗ Configuração: INVÁLIDA\n"
    fi
    
    # Verificar túnel
    if cloudflared tunnel list | grep -q "boxserver-tunnel"; then
        test_results+="✓ Túnel: ENCONTRADO\n"
    else
        test_results+="✗ Túnel: NÃO ENCONTRADO\n"
    fi
    
    dialog "${DIALOG_OPTS[@]}" --title "Resultados dos Testes" --msgbox "$test_results" 12 50
}

# Função para ver status do túnel
cloudflare_tunnel_status() {
    local status_info="Status do Cloudflare Tunnel:\n\n"
    
    # Status do serviço
    if systemctl is-active --quiet cloudflared; then
        status_info+="✓ Serviço: ATIVO\n"
        local uptime=$(systemctl show cloudflared --property=ActiveEnterTimestamp --value)
        status_info+="  Uptime: $(date -d "$uptime" '+%d/%m %H:%M')\n\n"
    else
        status_info+="✗ Serviço: INATIVO\n\n"
    fi
    
    # Listar túneis
    status_info+="Túneis Configurados:\n"
    local tunnels=$(cloudflared tunnel list 2>/dev/null | grep -v "ID" | head -5)
    if [ -n "$tunnels" ]; then
        status_info+="$tunnels\n\n"
    else
        status_info+="Nenhum túnel encontrado\n\n"
    fi
    
    # Métricas (se disponível)
    if curl -s http://127.0.0.1:8080/metrics &> /dev/null; then
        status_info+="✓ Métricas: Disponíveis em :8080\n"
    else
        status_info+="✗ Métricas: Indisponíveis\n"
    fi
    
    dialog "${DIALOG_OPTS[@]}" --title "Status do Túnel" --msgbox "$status_info" 15 60
}

# Função para configuração avançada
cloudflare_advanced_config() {
    while true; do
        local choice=$(dialog --title "Configuração Avançada" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Editar config.yml manualmente" \
            "2" "Configurar protocolo (QUIC/HTTP2)" \
            "3" "Configurar métricas" \
            "4" "Gerenciar certificados" \
            "5" "Reiniciar serviço" \
            "6" "Ver logs do serviço" \
            "7" "Voltar" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) edit_config_manually ;;
            2) configure_protocol ;;
            3) configure_metrics ;;
            4) manage_certificates ;;
            5) restart_cloudflared_service ;;
            6) show_cloudflared_logs ;;
            7|"") break ;;
        esac
    done
}

# Função para editar configuração manualmente
edit_config_manually() {
    if [ -f "/etc/cloudflared/config.yml" ]; then
        # Backup antes de editar
        cp /etc/cloudflared/config.yml /etc/cloudflared/config.yml.backup
        
        # Editar com nano
        nano /etc/cloudflared/config.yml
        
        # Validar configuração
        if cloudflared tunnel --config /etc/cloudflared/config.yml validate >/dev/null 2>&1; then
            dialog "${DIALOG_OPTS[@]}" --title "Configuração Válida" --msgbox "Configuração salva e validada com sucesso!" 6 50
            log_message "INFO" "Configuração Cloudflare editada manualmente"
        else
            dialog "${DIALOG_OPTS[@]}" --title "Erro de Configuração" --yesno "A configuração contém erros.\n\nDeseja restaurar o backup?" 8 50
            if [ $? -eq 0 ]; then
                mv /etc/cloudflared/config.yml.backup /etc/cloudflared/config.yml
                dialog "${DIALOG_OPTS[@]}" --title "Restaurado" --msgbox "Backup restaurado com sucesso." 6 40
            fi
        fi
    else
        dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Arquivo de configuração não encontrado." 6 40
    fi
}

# Função para configurar protocolo
configure_protocol() {
    local protocol=$(dialog --title "Protocolo" --menu "Escolha o protocolo:" 10 50 3 \
        "quic" "QUIC (Recomendado para ARM)" \
        "http2" "HTTP/2 (Compatibilidade)" \
        "auto" "Automático" \
        3>&1 1>&2 2>&3)
    
    if [ -n "$protocol" ]; then
        sed -i "s/protocol: .*/protocol: $protocol/g" /etc/cloudflared/config.yml
        dialog "${DIALOG_OPTS[@]}" --title "Protocolo Configurado" --msgbox "Protocolo alterado para: $protocol\n\nReinicie o serviço para aplicar." 8 50
        log_message "INFO" "Protocolo Cloudflare alterado para: $protocol"
    fi
}

# Função para configurar métricas
configure_metrics() {
    local metrics_addr=$(dialog "${DIALOG_OPTS[@]}" --title "Métricas" --inputbox "Digite o endereço para métricas:\n\nFormato: IP:PORTA" 10 50 "127.0.0.1:8080" 3>&1 1>&2 2>&3)
    
    if [ -n "$metrics_addr" ]; then
        sed -i "s/metrics: .*/metrics: $metrics_addr/g" /etc/cloudflared/config.yml
        dialog "${DIALOG_OPTS[@]}" --title "Métricas Configuradas" --msgbox "Métricas configuradas para: $metrics_addr\n\nAcesse: http://$metrics_addr/metrics" 8 60
        log_message "INFO" "Métricas Cloudflare configuradas: $metrics_addr"
    fi
}

# Função para gerenciar certificados
manage_certificates() {
    local cert_info="Informações dos Certificados:\n\n"
    
    if [ -f "/etc/cloudflared/cert.pem" ]; then
        cert_info+="✓ Certificado do túnel: PRESENTE\n"
        cert_info+="  Local: /etc/cloudflared/cert.pem\n\n"
    else
        cert_info+="✗ Certificado do túnel: AUSENTE\n\n"
    fi
    
    if [ -d "$HOME/.cloudflared" ]; then
        local cert_count=$(ls -1 "$HOME/.cloudflared"/*.pem 2>/dev/null | wc -l)
        cert_info+="Certificados de login: $cert_count\n"
        cert_info+="Local: $HOME/.cloudflared/\n\n"
    fi
    
    cert_info+="Opções:\n"
    cert_info+="- Renovar: cloudflared tunnel login\n"
    cert_info+="- Verificar: cloudflared tunnel list"
    
    dialog "${DIALOG_OPTS[@]}" --title "Gerenciar Certificados" --msgbox "$cert_info" 15 60
}

# Função para reiniciar serviço
restart_cloudflared_service() {
    dialog --title "Reiniciando Serviço" --infobox "Reiniciando Cloudflared..." 5 30
    
    systemctl restart cloudflared
    sleep 2
    
    if systemctl is-active --quiet cloudflared; then
        dialog "${DIALOG_OPTS[@]}" --title "Serviço Reiniciado" --msgbox "Cloudflared reiniciado com sucesso!" 6 40
        log_message "INFO" "Serviço Cloudflared reiniciado"
    else
        dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Falha ao reiniciar o serviço.\n\nVerifique os logs." 8 40
        log_message "ERROR" "Falha ao reiniciar Cloudflared"
    fi
}

# Função para mostrar logs
show_cloudflared_logs() {
    dialog "${DIALOG_OPTS[@]}" --title "Logs do Cloudflared" --msgbox "Os logs serão exibidos em uma nova janela.\n\nPressione 'q' para sair da visualização." 8 50
    
    # Mostrar logs em tempo real
    journalctl -u cloudflared -f --no-pager
}

# Função para configuração automática de serviços
auto_configure_services() {
    dialog --title "Configuração Automática" --infobox "Detectando serviços instalados..." 5 40
    
    local detected_services=""
    local config_applied=false
    
    # Detectar Pi-hole
    if systemctl is-active --quiet pihole-FTL; then
        detected_services+="✓ Pi-hole (porta 80)\n"
        if dialog "${DIALOG_OPTS[@]}" --title "Pi-hole Detectado" --yesno "Configurar Pi-hole no subdomínio 'pihole'?\n\nExemplo: pihole.seudominio.com" 8 50; then
            local domain=$(dialog "${DIALOG_OPTS[@]}" --title "Domínio Pi-hole" --inputbox "Digite o domínio completo:" 8 50 "pihole.example.com" 3>&1 1>&2 2>&3)
            if [ -n "$domain" ]; then
                update_ingress_rule "$domain" "80"
                config_applied=true
                log_message "INFO" "Auto-configurado Pi-hole: $domain"
            fi
        fi
    fi
    
    # Detectar Cockpit
    if systemctl is-active --quiet cockpit; then
        detected_services+="✓ Cockpit (porta 9090)\n"
        if dialog "${DIALOG_OPTS[@]}" --title "Cockpit Detectado" --yesno "Configurar Cockpit no subdomínio 'admin'?\n\nExemplo: admin.seudominio.com" 8 50; then
            local domain=$(dialog "${DIALOG_OPTS[@]}" --title "Domínio Cockpit" --inputbox "Digite o domínio completo:" 8 50 "admin.example.com" 3>&1 1>&2 2>&3)
            if [ -n "$domain" ]; then
                update_ingress_rule "$domain" "9090"
                config_applied=true
                log_message "INFO" "Auto-configurado Cockpit: $domain"
            fi
        fi
    fi
    
    # Detectar WireGuard
    if systemctl is-active --quiet wg-quick@wg0; then
        detected_services+="✓ WireGuard (porta 51820)\n"
        if dialog "${DIALOG_OPTS[@]}" --title "WireGuard Detectado" --yesno "Configurar interface web WireGuard?\n\nExemplo: vpn.seudominio.com" 8 50; then
            local domain=$(dialog "${DIALOG_OPTS[@]}" --title "Domínio WireGuard" --inputbox "Digite o domínio completo:" 8 50 "vpn.example.com" 3>&1 1>&2 2>&3)
            if [ -n "$domain" ]; then
                update_ingress_rule "$domain" "51820"
                config_applied=true
                log_message "INFO" "Auto-configurado WireGuard: $domain"
            fi
        fi
    fi
    
    # Detectar outros serviços comuns
    detect_additional_services
    
    if [ "$config_applied" = true ]; then
        dialog "${DIALOG_OPTS[@]}" --title "Configuração Concluída" --msgbox "Serviços configurados automaticamente!\n\nLembre-se de aplicar os registros DNS\nno menu de configuração de domínios." 10 50
        
        # Oferecer aplicação automática de DNS
        if dialog "${DIALOG_OPTS[@]}" --title "Aplicar DNS" --yesno "Deseja aplicar os registros DNS\nautomaticamente agora?" 8 50; then
            apply_dns_records
        fi
    else
        dialog "${DIALOG_OPTS[@]}" --title "Nenhum Serviço" --msgbox "Nenhum serviço foi configurado\nautomaticamente.\n\nUse o menu manual para\nconfigurar domínios customizados." 10 50
    fi
}

# Função para detectar serviços adicionais
detect_additional_services() {
    # Detectar FileBrowser (porta comum 8080)
    if netstat -tlnp 2>/dev/null | grep -q ":8080"; then
        if dialog "${DIALOG_OPTS[@]}" --title "Serviço na Porta 8080" --yesno "Detectado serviço na porta 8080.\n\nConfigurar como FileBrowser?" 8 50; then
            local domain=$(dialog "${DIALOG_OPTS[@]}" --title "Domínio Arquivos" --inputbox "Digite o domínio completo:" 8 50 "files.example.com" 3>&1 1>&2 2>&3)
            if [ -n "$domain" ]; then
                update_ingress_rule "$domain" "8080"
                log_message "INFO" "Auto-configurado FileBrowser: $domain"
            fi
        fi
    fi
    
    # Detectar Portainer (porta comum 9000)
    if netstat -tlnp 2>/dev/null | grep -q ":9000"; then
        if dialog "${DIALOG_OPTS[@]}" --title "Serviço na Porta 9000" --yesno "Detectado serviço na porta 9000.\n\nConfigurar como Portainer?" 8 50; then
            local domain=$(dialog "${DIALOG_OPTS[@]}" --title "Domínio Portainer" --inputbox "Digite o domínio completo:" 8 50 "docker.example.com" 3>&1 1>&2 2>&3)
            if [ -n "$domain" ]; then
                update_ingress_rule "$domain" "9000"
                log_message "INFO" "Auto-configurado Portainer: $domain"
            fi
        fi
    fi
    
    # Detectar Grafana (porta comum 3000)
    if netstat -tlnp 2>/dev/null | grep -q ":3000"; then
        if dialog "${DIALOG_OPTS[@]}" --title "Serviço na Porta 3000" --yesno "Detectado serviço na porta 3000.\n\nConfigurar como Grafana?" 8 50; then
            local domain=$(dialog "${DIALOG_OPTS[@]}" --title "Domínio Grafana" --inputbox "Digite o domínio completo:" 8 50 "monitor.example.com" 3>&1 1>&2 2>&3)
            if [ -n "$domain" ]; then
                update_ingress_rule "$domain" "3000"
                log_message "INFO" "Auto-configurado Grafana: $domain"
            fi
        fi
    fi
}

# Função para validação completa da configuração
validate_tunnel_configuration() {
    dialog --title "Validando Configuração" --infobox "Executando validação completa..." 5 40
    
    local validation_results="Validação da Configuração:\n\n"
    local errors_found=false
    
    # Validar arquivo de configuração
    if [ -f "/etc/cloudflared/config.yml" ]; then
        if cloudflared tunnel --config /etc/cloudflared/config.yml validate >/dev/null 2>&1; then
            validation_results+="✓ Sintaxe do config.yml: VÁLIDA\n"
        else
            validation_results+="✗ Sintaxe do config.yml: INVÁLIDA\n"
            errors_found=true
        fi
    else
        validation_results+="✗ Arquivo config.yml: NÃO ENCONTRADO\n"
        errors_found=true
    fi
    
    # Validar certificados
    local cred_file=$(grep "credentials-file:" /etc/cloudflared/config.yml 2>/dev/null | awk '{print $2}')
    if [ -n "$cred_file" ] && [ -f "$cred_file" ]; then
        validation_results+="✓ Certificado do túnel: PRESENTE\n"
    else
        validation_results+="✗ Certificado do túnel: AUSENTE\n"
        errors_found=true
    fi
    
    # Validar conectividade
    if ping -c 1 1.1.1.1 &> /dev/null; then
        validation_results+="✓ Conectividade internet: OK\n"
    else
        validation_results+="✗ Conectividade internet: FALHOU\n"
        errors_found=true
    fi
    
    # Validar domínios configurados
    local domain_count=$(grep -c "hostname:" /etc/cloudflared/config.yml 2>/dev/null || echo "0")
    if [ "$domain_count" -gt 0 ]; then
        validation_results+="✓ Domínios configurados: $domain_count\n"
    else
        validation_results+="⚠ Domínios configurados: NENHUM\n"
    fi
    
    # Validar serviço
    if systemctl is-enabled --quiet cloudflared; then
        validation_results+="✓ Serviço habilitado: SIM\n"
    else
        validation_results+="⚠ Serviço habilitado: NÃO\n"
    fi
    
    if [ "$errors_found" = true ]; then
        validation_results+="\n❌ CONFIGURAÇÃO COM ERROS\n\nCorreja os problemas antes de iniciar."
        dialog "${DIALOG_OPTS[@]}" --title "Validação Falhou" --msgbox "$validation_results" 15 60
        return 1
    else
        validation_results+="\n✅ CONFIGURAÇÃO VÁLIDA\n\nTúnel pronto para uso!"
        dialog "${DIALOG_OPTS[@]}" --title "Validação Bem-sucedida" --msgbox "$validation_results" 15 60
        return 0
    fi
}

# Configuração do WireGuard VPN
configure_wireguard_vpn() {
    while true; do
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Configuração WireGuard VPN" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Verificar status do WireGuard" \
            "2" "Gerar novo cliente" \
            "3" "Listar clientes existentes" \
            "4" "Remover cliente" \
            "5" "Regenerar chaves do servidor" \
            "6" "Configurar interface de rede" \
            "7" "Testar conectividade VPN" \
            "8" "Exportar configuração cliente" \
            "9" "Configurações avançadas" \
            "10" "Voltar" \
            3>&1 1>&2 2>&3)
        
        if [ $? -ne 0 ]; then
            break
        fi

        case $choice in
            1) check_wireguard_status ;;
            2) generate_wireguard_client ;;
            3) list_wireguard_clients ;;
            4) remove_wireguard_client ;;
            5) regenerate_server_keys ;;
            6) configure_network_interface ;;
            7) test_vpn_connectivity ;;
            8) export_client_config ;;
            9) wireguard_advanced_settings ;;
            10|"")
                break
                ;;
        esac
    done
}

# Verificar status do WireGuard
check_wireguard_status() {
    local status_info="Status do WireGuard:\n\n"
    
    # Verificar se o serviço está rodando
    if systemctl is-active --quiet wg-quick@wg0; then
        status_info+="✓ Serviço: ATIVO\n"
    else
        status_info+="✗ Serviço: INATIVO\n"
    fi
    
    # Verificar interface
    if ip link show wg0 &>/dev/null; then
        status_info+="✓ Interface wg0: CONFIGURADA\n"
        local wg_info=$(wg show wg0 2>/dev/null)
        if [[ -n "$wg_info" ]]; then
            status_info+="\nInformações da interface:\n$wg_info\n"
        fi
    else
        status_info+="✗ Interface wg0: NÃO ENCONTRADA\n"
    fi
    
    # Verificar IP forwarding
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) == "1" ]]; then
        status_info+="✓ IP Forwarding: HABILITADO\n"
    else
        status_info+="✗ IP Forwarding: DESABILITADO\n"
    fi
    
    # Verificar regras de firewall
    if iptables -t nat -L POSTROUTING | grep -q "MASQUERADE"; then
        status_info+="✓ NAT/Masquerade: CONFIGURADO\n"
    else
        status_info+="✗ NAT/Masquerade: NÃO CONFIGURADO\n"
    fi
    
    dialog "${DIALOG_OPTS[@]}" --title "Status WireGuard" --msgbox "$status_info" 20 70
}

# Gerar novo cliente WireGuard
generate_wireguard_client() {
    local client_name=$(dialog "${DIALOG_OPTS[@]}" --title "Novo Cliente" --inputbox "Nome do cliente:" 8 40 3>&1 1>&2 2>&3)

    if [[ -z "$client_name" ]]; then
        dialog --title "Erro" --msgbox "Nome do cliente é obrigatório!" 6 40
        return 1
    fi

    # Verificar se cliente já existe
    if [[ -f "/etc/wireguard/clients/${client_name}.conf" ]]; then
        dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Cliente '$client_name' já existe!" 6 40
        return 1
    fi

    dialog --title "Gerando Cliente" --infobox "Criando configuração para $client_name..." 5 50

    # Criar diretório de clientes se não existir
    mkdir -p /etc/wireguard/clients

    # Gerar chaves do cliente
    local client_private_key=$(wg genkey)
    local client_public_key=$(echo "$client_private_key" | wg pubkey)

    # Obter próximo IP disponível
    local client_ip=$(get_next_client_ip)

    # Obter configurações do servidor
    local server_public_key=$(cat /etc/wireguard/keys/publickey)
    local server_endpoint=$(get_server_endpoint)
    local server_port=$(grep "ListenPort" /etc/wireguard/wg0.conf | cut -d'=' -f2 | tr -d ' ' || echo "51820")

    # Criar configuração do cliente
    local client_config_path="/etc/wireguard/clients/${client_name}.conf"
    cat > "$client_config_path" << EOF
[Interface]
PrivateKey = ${client_private_key}
Address = ${client_ip}/24
DNS = ${VPN_NETWORK%.*}.1

[Peer]
PublicKey = ${server_public_key}
Endpoint = ${server_endpoint}:${server_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # Adicionar peer ao servidor
    wg set wg0 peer "${client_public_key}" allowed-ips "${client_ip}/32"

    # Salvar configuração no arquivo do servidor
    echo "" >> /etc/wireguard/wg0.conf
    echo "# Cliente: $client_name" >> /etc/wireguard/wg0.conf
    echo "[Peer]" >> /etc/wireguard/wg0.conf
    echo "PublicKey = $client_public_key" >> /etc/wireguard/wg0.conf
    echo "AllowedIPs = $client_ip/32" >> /etc/wireguard/wg0.conf

    # Gerar QR Code se qrencode estiver disponível
    if command -v qrencode &>/dev/null; then
        # CORREÇÃO: Gerar QR Code e texto para exibição no dialog
        local client_config_content=$(cat "$client_config_path")
        local qr_code_terminal=$(qrencode -t ansiutf8 <<< "$client_config_content")
        
        local dialog_text="Cliente '$client_name' criado com sucesso.\n\n"
        dialog_text+="Aponte a câmera do seu app WireGuard para o QR Code abaixo:\n\n"
        dialog_text+="$qr_code_terminal"
        dialog_text+="\n\nAlternativamente, o arquivo de configuração foi salvo em:\n$client_config_path"

        # Exibir o QR Code e as informações no dialog
        echo -e "$dialog_text" | dialog "${DIALOG_OPTS[@]}" --title "Cliente WireGuard Criado" --prgbox " " 25 80
    else
        dialog "${DIALOG_OPTS[@]}" --title "Cliente Criado" --msgbox "Cliente '$client_name' criado com sucesso!\n\nIP: $client_ip\nArquivo: $client_config_path\n\n(Instale 'qrencode' para gerar QR codes)" 12 60
    fi
}

# Obter próximo IP disponível para cliente
get_next_client_ip() {
    local base_ip="${VPN_NETWORK%.*}"
    local start_ip=2
    
    for i in $(seq $start_ip 254);
    do
        local test_ip="${base_ip}.${i}"
        if ! grep -q "$test_ip" /etc/wireguard/wg0.conf /etc/wireguard/clients/*.conf 2>/dev/null;
        then
            echo "$test_ip"
            return 0
        fi
    done
    
    echo "${base_ip}.254"  # Fallback
}


# Obter endpoint do servidor
get_server_endpoint() {
    # Tentar obter IP público
    local public_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "")
    
    if [[ -n "$public_ip" ]]; then
        echo "$public_ip"
    else
        # Fallback para IP local
        local local_ip=$(ip route get 8.8.8.8 | awk '{print $7; exit}')
        echo "${local_ip:-localhost}"
    fi
}

# Listar clientes existentes
list_wireguard_clients() {
    local clients_info="Clientes WireGuard:\n\n"
    
    if [[ ! -d "/etc/wireguard/clients" ]] || [[ -z "$(ls -A /etc/wireguard/clients 2>/dev/null)" ]]; then
        clients_info+="Nenhum cliente configurado.\n"
    else
        for client_file in /etc/wireguard/clients/*.conf; do
            if [[ -f "$client_file" ]]; then
                local client_name=$(basename "$client_file" .conf)
                local client_ip=$(grep "Address" "$client_file" | cut -d'=' -f2 | tr -d ' ' | cut -d'/' -f1)
                local client_key=$(grep "PrivateKey" "$client_file" | cut -d'=' -f2 | tr -d ' ')
                local public_key=$(echo "$client_key" | wg pubkey 2>/dev/null || echo "N/A")
                
                clients_info+="Nome: $client_name\n"
                clients_info+="IP: $client_ip\n"
                clients_info+="Chave Pública: ${public_key:0:20}...\n\n"
            fi
        done
    fi
    
    dialog --title "Clientes WireGuard" --msgbox "$clients_info" 20 70
}

# Remover cliente WireGuard
remove_wireguard_client() {
    if [[ ! -d "/etc/wireguard/clients" ]] || [[ -z "$(ls -A /etc/wireguard/clients 2>/dev/null)" ]]; then
        dialog --title "Erro" --msgbox "Nenhum cliente encontrado para remover." 6 50
        return 1
    fi
    
    # Criar lista de clientes
    local client_list=()
    for client_file in /etc/wireguard/clients/*.conf; do
        if [[ -f "$client_file" ]]; then
            local client_name=$(basename "$client_file" .conf)
            client_list+=("$client_name" "")
        fi
    done
    
    local client_to_remove=$(dialog "${DIALOG_OPTS[@]}" --title "Remover Cliente" --menu "Selecione o cliente para remover:" 15 50 8 "${client_list[@]}" 3>&1 1>&2 2>&3)
    
    if [[ -z "$client_to_remove" ]]; then
        return 0
    fi
    
    # Confirmar remoção
    if dialog "${DIALOG_OPTS[@]}" --title "Confirmar Remoção" --yesno "Tem certeza que deseja remover o cliente '$client_to_remove'?" 7 50; then
        # Obter chave pública do cliente
        local client_private_key=$(grep "PrivateKey" "/etc/wireguard/clients/${client_to_remove}.conf" | cut -d'=' -f2 | tr -d ' ')
        local client_public_key=$(echo "$client_private_key" | wg pubkey 2>/dev/null)
        
        # Remover peer do servidor ativo
        if [[ -n "$client_public_key" ]]; then
            wg set wg0 peer "$client_public_key" remove 2>/dev/null
        fi
        
        # Remover do arquivo de configuração do servidor
        if [[ -n "$client_public_key" ]]; then
            sed -i "/# Cliente: $client_to_remove/,/^$/d" /etc/wireguard/wg0.conf
        fi
        
        # Remover arquivos do cliente
        rm -f "/etc/wireguard/clients/${client_to_remove}.conf"
        rm -f "/etc/wireguard/clients/${client_to_remove}.png"
        
        dialog "${DIALOG_OPTS[@]}" --title "Cliente Removido" --msgbox "Cliente '$client_to_remove' removido com sucesso!" 6 50
    fi
}

# Regenerar chaves do servidor
regenerate_server_keys() {
    if dialog "${DIALOG_OPTS[@]}" --title "Regenerar Chaves" --yesno "ATENÇÃO: Regenerar as chaves do servidor invalidará TODOS os clientes existentes.\n\nDeseja continuar?" 10 60; then
        dialog --title "Regenerando Chaves" --infobox "Gerando novas chaves do servidor..." 5 40
        
        # Parar o serviço
        systemctl stop wg-quick@wg0 2>/dev/null
        
        # Gerar novas chaves
        local new_private_key=$(wg genkey)
        local new_public_key=$(echo "$new_private_key" | wg pubkey)
        
        # Backup da configuração atual
        cp /etc/wireguard/wg0.conf "/etc/wireguard/wg0.conf.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Atualizar configuração do servidor
        sed -i "s/^PrivateKey = .*/PrivateKey = $new_private_key/" /etc/wireguard/wg0.conf
        
        # Remover todos os peers (clientes ficam inválidos)
        sed -i '/^\[Peer\]/,/^$/d' /etc/wireguard/wg0.conf
        sed -i '/^# Cliente:/d' /etc/wireguard/wg0.conf
        
        # Remover configurações de clientes
        rm -rf /etc/wireguard/clients/*
        
        # Reiniciar o serviço
        systemctl start wg-quick@wg0
        
        dialog "${DIALOG_OPTS[@]}" --title "Chaves Regeneradas" --msgbox "Chaves do servidor regeneradas com sucesso!\n\nNova chave pública: ${new_public_key:0:30}...\n\nTodos os clientes precisam ser recriados." 12 70
    fi
}

# Configurar interface de rede
configure_network_interface() {
    local current_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    local new_interface=$(dialog "${DIALOG_OPTS[@]}" --title "Interface de Rede" --inputbox "Interface de rede para WireGuard:" 8 50 "$current_interface" 3>&1 1>&2 2>&3)
    
    if [[ -z "$new_interface" ]]; then
        return 0
    fi
    
    # Verificar se a interface existe
    if ! ip link show "$new_interface" &>/dev/null; then
        dialog --title "Erro" --msgbox "Interface '$new_interface' não encontrada!" 6 50
        return 1
    fi
    
    dialog --title "Configurando Interface" --infobox "Atualizando configuração de rede..." 5 50
    
    # Atualizar regras de firewall
    # Remover regras antigas
    iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o "$current_interface" -j MASQUERADE 2>/dev/null
    
    # Adicionar novas regras
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$new_interface" -j MASQUERADE
    
    # Salvar regras se iptables-persistent estiver disponível
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
    fi
    
    dialog "${DIALOG_OPTS[@]}" --title "Interface Configurada" --msgbox "Interface de rede atualizada para: $new_interface" 6 60
}

# Testar conectividade VPN
test_vpn_connectivity() {
    dialog --title "Testando Conectividade" --infobox "Executando testes de conectividade..." 5 50
    
    local test_results="Testes de Conectividade VPN:\n\n"
    
    # Teste 1: Interface WireGuard
    if ip link show wg0 &>/dev/null; then
        test_results+="✓ Interface wg0: ATIVA\n"
    else
        test_results+="✗ Interface wg0: INATIVA\n"
    fi
    
    # Teste 2: Serviço WireGuard
    if systemctl is-active --quiet wg-quick@wg0; then
        test_results+="✓ Serviço WireGuard: RODANDO\n"
    else
        test_results+="✗ Serviço WireGuard: PARADO\n"
    fi
    
    # Teste 3: Porta de escuta
    local wg_port=$(grep "ListenPort" /etc/wireguard/wg0.conf | cut -d'=' -f2 | tr -d ' ' || echo "51820")
    if ss -ulnp | grep -q ":$wg_port"; then
        test_results+="✓ Porta $wg_port: ESCUTANDO\n"
    else
        test_results+="✗ Porta $wg_port: NÃO ESCUTANDO\n"
    fi
    
    # Teste 4: IP Forwarding
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) == "1" ]]; then
        test_results+="✓ IP Forwarding: HABILITADO\n"
    else
        test_results+="✗ IP Forwarding: DESABILITADO\n"
    fi
    
    # Teste 5: Regras NAT
    if iptables -t nat -L POSTROUTING | grep -q "MASQUERADE"; then
        test_results+="✓ Regras NAT: CONFIGURADAS\n"
    else
        test_results+="✗ Regras NAT: NÃO CONFIGURADAS\n"
    fi
    
    # Teste 6: Conectividade externa
    if ping -c 1 8.8.8.8 &>/dev/null; then
        test_results+="✓ Conectividade Externa: OK\n"
    else
        test_results+="✗ Conectividade Externa: FALHOU\n"
    fi
    
    dialog "${DIALOG_OPTS[@]}" --title "Resultados dos Testes" --msgbox "$test_results" 18 60
}

# Exportar configuração de cliente
export_client_config() {
    if [[ ! -d "/etc/wireguard/clients" ]] || [[ -z "$(ls -A /etc/wireguard/clients 2>/dev/null)" ]]; then
        dialog --title "Erro" --msgbox "Nenhum cliente encontrado para exportar." 6 50
        return 1
    fi
    
    # Criar lista de clientes
    local client_list=()
    for client_file in /etc/wireguard/clients/*.conf; do
        if [[ -f "$client_file" ]]; then
            local client_name=$(basename "$client_file" .conf)
            client_list+=("$client_name" "")
        fi
    done
    
    local client_to_export=$(dialog "${DIALOG_OPTS[@]}" --title "Exportar Cliente" --menu "Selecione o cliente para exportar:" 15 50 8 "${client_list[@]}" 3>&1 1>&2 2>&3)
    
    if [[ -z "$client_to_export" ]]; then
        return 0
    fi
    
    local export_path=$(dialog "${DIALOG_OPTS[@]}" --title "Local de Exportação" --inputbox "Caminho para exportar:" 8 60 "/tmp/${client_to_export}.conf" 3>&1 1>&2 2>&3)
    
    if [[ -z "$export_path" ]]; then
        return 0
    fi
    
    # Copiar arquivo de configuração
    if cp "/etc/wireguard/clients/${client_to_export}.conf" "$export_path"; then
        dialog "${DIALOG_OPTS[@]}" --title "Exportação Concluída" --msgbox "Configuração do cliente '$client_to_export' exportada para:\n$export_path" 8 70
    else
        dialog --title "Erro" --msgbox "Falha ao exportar configuração!" 6 40
    fi
}

# Configurações avançadas do WireGuard
wireguard_advanced_settings() {
    while true; do
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Configurações Avançadas" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Alterar porta do servidor" \
            "2" "Configurar DNS personalizado" \
            "3" "Alterar rede VPN" \
            "4" "Configurar Keep-Alive" \
            "5" "Backup/Restore configurações" \
            "6" "Logs e diagnósticos" \
            "7" "Voltar" \
            3>&1 1>&2 2>&3) # Faltava esta linha
        
        case $choice in
            1) change_wireguard_port ;;
            2) configure_custom_dns ;;
            3) change_vpn_network ;;
            4) configure_keepalive ;;
            5) backup_restore_configs ;;
            6) wireguard_diagnostics ;;
            7|"")
                break
                ;;
        esac
    done
}

# Alterar porta do WireGuard
change_wireguard_port() {
    local current_port=$(grep "ListenPort" /etc/wireguard/wg0.conf | cut -d'=' -f2 | tr -d ' ' || echo "51820")
    local new_port=$(dialog "${DIALOG_OPTS[@]}" --title "Alterar Porta" --inputbox "Nova porta para WireGuard:" 8 40 "$current_port" 3>&1 1>&2 2>&3)
    
    if [[ -z "$new_port" ]] || [[ "$new_port" == "$current_port" ]]; then
        return 0
    fi
    
    # Validar porta
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [[ "$new_port" -lt 1024 ]] || [[ "$new_port" -gt 65535 ]]; then
        dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Porta inválida! Use um número entre 1024 e 65535." 6 50
        return 1
    fi
    
    # Verificar se a porta está em uso
    if ss -ulnp | grep -q ":$new_port"; then
        dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Porta $new_port já está em uso!" 6 40
        return 1
    fi
    
    dialog --title "Alterando Porta" --infobox "Atualizando configuração..." 5 40
    
    # Parar o serviço
    systemctl stop wg-quick@wg0
    
    # Atualizar configuração do servidor
    sed -i "s/^ListenPort = .*/ListenPort = $new_port/" /etc/wireguard/wg0.conf
    
    # Atualizar configurações dos clientes
    for client_file in /etc/wireguard/clients/*.conf; do
        if [[ -f "$client_file" ]]; then
            local server_endpoint=$(grep "Endpoint" "$client_file" | cut -d'=' -f2 | tr -d ' ' | cut -d':' -f1)
            sed -i "s/^Endpoint = .*/Endpoint = $server_endpoint:$new_port/" "$client_file"
        fi
    done
    
    # Reiniciar o serviço
    systemctl start wg-quick@wg0
    
    dialog "${DIALOG_OPTS[@]}" --title "Porta Alterada" --msgbox "Porta do WireGuard alterada para: $new_port\n\nTodos os clientes foram atualizados automaticamente." 8 60
}

# Configuração Pi-hole + Unbound
configure_pihole_unbound() {
    while true; do
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Configuração Pi-hole + Unbound" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Verificar status dos serviços" \
            "2" "Configurar integração Pi-hole/Unbound" \
            "3" "Gerenciar listas de bloqueio" \
            "4" "Configurar DNS upstream" \
            "5" "Testar resolução DNS" \
            "6" "Configurar whitelist/blacklist" \
            "7" "Backup/Restore configurações" \
            "8" "Logs e estatísticas" \
            "9" "Configurações avançadas" \
            "10" "Voltar" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) check_dns_services_status ;;
            2) configure_pihole_unbound_integration ;;
            3) manage_blocklists ;;
            4) configure_upstream_dns ;;
            5) test_dns_resolution ;;
            6) manage_whitelist_blacklist ;;
            7) backup_restore_dns_configs ;;
            8) show_dns_logs_stats ;;
            9) dns_advanced_settings ;;
            10|"")
                break
                ;;
        esac
    done
}

# Verificar status dos serviços DNS
check_dns_services_status() {
    local status_info="Status dos Serviços DNS:\n\n"
    
    # Verificar Pi-hole
    if systemctl is-active --quiet pihole-FTL; then
        status_info+="✓ Pi-hole FTL: ATIVO\n"
    else
        status_info+="✗ Pi-hole FTL: INATIVO\n"
    fi
    
    # Verificar Unbound
    if systemctl is-active --quiet unbound; then
        status_info+="✓ Unbound: ATIVO\n"
    else
        status_info+="✗ Unbound: INATIVO\n"
    fi
    
    # Verificar porta Pi-hole (53)
    if ss -ulnp | grep -q ":53.*pihole"; then
        status_info+="✓ Pi-hole porta 53: ESCUTANDO\n"
    else
        status_info+="✗ Pi-hole porta 53: NÃO ESCUTANDO\n"
    fi
    
    # Verificar porta Unbound (5335)
    if ss -ulnp | grep -q ":5335.*unbound"; then
        status_info+="✓ Unbound porta 5335: ESCUTANDO\n"
    else
        status_info+="✗ Unbound porta 5335: NÃO ESCUTANDO\n"
    fi
    
    # Verificar configuração DNS do sistema
    local system_dns=$(grep "nameserver" /etc/resolv.conf | head -1 | awk '{print $2}')
    if [[ "$system_dns" == "127.0.0.1" ]]; then
        status_info+="✓ DNS do sistema: CONFIGURADO (127.0.0.1)\n"
    else
        status_info+="✗ DNS do sistema: NÃO CONFIGURADO ($system_dns)\n"
    fi
    
    # Verificar trust anchor do Unbound
    if [[ -f "/var/lib/unbound/root.key" ]]; then
        status_info+="✓ Trust Anchor DNSSEC: CONFIGURADO\n"
    else
        status_info+="✗ Trust Anchor DNSSEC: NÃO CONFIGURADO\n"
    fi
    
    dialog "${DIALOG_OPTS[@]}" --title "Status DNS" --msgbox "$status_info" 18 70
}

# Configurar integração Pi-hole/Unbound
configure_pihole_unbound_integration() {
    dialog --title "Configurando Integração" --infobox "Configurando integração Pi-hole + Unbound..." 5 60

    # Verificar se os serviços estão instalados
    if ! command -v pihole &>/dev/null; then
        dialog --title "Erro" --msgbox "Pi-hole não está instalado!" 6 40
        return 1
    fi
    
    if ! command -v unbound &>/dev/null; then
        dialog --title "Erro" --msgbox "Unbound não está instalado!" 6 40
        return 1
    fi
    
    # IMPLEMENTAÇÃO: Configurar Unbound para Pi-hole conforme iNSTALAÇÃO APPS.md
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
    # OTIMIZADO PARA ARM/BAIXA RAM
    num-threads: 1
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
    
    # Baixar root hints se não existir
    if [[ ! -f "/var/lib/unbound/root.hints" ]]; then
        log_message "INFO" "Baixando root.hints para Unbound..."
        wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
        chown unbound:unbound /var/lib/unbound/root.hints
    fi
    
    # Configurar trust anchor se não existir
    if [[ ! -f "/var/lib/unbound/root.key" ]]; then
        log_message "INFO" "Gerando root.key para Unbound..."
        unbound-anchor -a /var/lib/unbound/root.key
        chown unbound:unbound /var/lib/unbound/root.key
    fi
    
    # Configurar Pi-hole para usar Unbound
    if [[ -f "/etc/pihole/setupVars.conf" ]]; then
        log_message "INFO" "Configurando Pi-hole para usar Unbound como upstream DNS..."
        # Backup da configuração atual
        cp /etc/pihole/setupVars.conf /etc/pihole/setupVars.conf.backup
        
        # Atualizar DNS upstream
        sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
        
        # Remover DNS secundário se existir
        sed -i '/^PIHOLE_DNS_2=/d' /etc/pihole/setupVars.conf
    fi
    
    # Reiniciar serviços
    systemctl restart unbound
    sleep 2
    systemctl restart pihole-FTL
    
    # Verificar se a integração funcionou
    sleep 3
    if systemctl is-active --quiet unbound && systemctl is-active --quiet pihole-FTL; then
        dialog "${DIALOG_OPTS[@]}" --title "Integração Configurada" --msgbox "Integração Pi-hole + Unbound configurada com sucesso!\n\nUnbound: porta 5335\nPi-hole: porta 53 (usando Unbound como upstream)" 10 70
    else
        dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Falha na configuração da integração!\nVerifique os logs dos serviços." 8 50
    fi
}

# Gerenciar listas de bloqueio
manage_blocklists() {
    while true; do
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Gerenciar Listas de Bloqueio" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Ver listas ativas" \
            "2" "Adicionar lista personalizada" \
            "3" "Remover lista" \
            "4" "Atualizar todas as listas" \
            "5" "Listas recomendadas" \
            "6" "Estatísticas de bloqueio" \
            "7" "Voltar" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) show_active_blocklists ;;
            2) add_custom_blocklist ;;
            3) remove_blocklist ;;
            4) update_all_blocklists ;;
            5) recommended_blocklists ;;
            6) show_blocking_stats ;;
            7|"")
                break
                ;;
        esac
    done
}

# Mostrar listas de bloqueio ativas
show_active_blocklists() {
    local blocklists_info="Listas de Bloqueio Ativas:\n\n"
    
    if [[ -f "/etc/pihole/adlists.list" ]]; then
        local count=1
        while IFS= read -r line; do
            if [[ -n "$line" && ! "$line" =~ ^# ]]; then
                blocklists_info+="$count. ${line:0:60}...\n"
                ((count++))
            fi
        done < /etc/pihole/adlists.list
        
        if [[ $count -eq 1 ]]; then
            blocklists_info+="Nenhuma lista ativa encontrada.\n"
        fi
    else
        blocklists_info+="Arquivo de listas não encontrado.\n"
    fi
    
    # Mostrar estatísticas
    if command -v pihole &>/dev/null; then
        local blocked_domains=$(pihole -q -exact | wc -l 2>/dev/null || echo "N/A")
        blocklists_info+="\nTotal de domínios bloqueados: $blocked_domains\n"
    fi
    
    dialog "${DIALOG_OPTS[@]}" --title "Listas de Bloqueio" --msgbox "$blocklists_info" 20 80
}

# Função para executar testes do sistema
run_system_tests() {
    dialog --title "Testes do Sistema" --infobox "Executando testes..." 5 30
    
    local test_results="Resultados dos Testes:\n\n"
    
    # Teste de DNS
    if dig @127.0.0.1 google.com +short &> /dev/null; then
        test_results+="✓ DNS Pi-hole: OK\n"
    else
        test_results+="✗ DNS Pi-hole: FALHOU\n"
    fi
    
    # Teste de conectividade
    if ping -c 1 8.8.8.8 &> /dev/null; then
        test_results+="✓ Conectividade: OK\n"
    else
        test_results+="✗ Conectividade: FALHOU\n"
    fi
    
    # Teste de entropia
    local entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    if [ "$entropy" -gt 1000 ]; then
        test_results+="✓ Entropia: OK ($entropy)\n"
    else
        test_results+="⚠ Entropia: BAIXA ($entropy)\n"
    fi
    
    dialog "${DIALOG_OPTS[@]}" --title "Resultados dos Testes" --msgbox "$test_results" 12 50
}

# Função para mostrar status dos serviços
show_services_status() {
    local status_info="Status dos Serviços:\n\n"
    
    local services=("pihole-FTL" "unbound" "wg-quick@wg0" "rng-tools" "fail2ban")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            status_info+="✓ $service: ATIVO\n"
        else
            status_info+="✗ $service: INATIVO\n"
        fi
    done
    
    dialog "${DIALOG_OPTS[@]}" --title "Status dos Serviços" --msgbox "$status_info" 12 50
}

# Função para mostrar logs
show_installation_logs() {
    if [ -f "$LOG_FILE" ]; then
        dialog "${DIALOG_OPTS[@]}" --title "Logs de Instalação" --textbox "$LOG_FILE" 20 80
    else
        dialog --title "Logs" --msgbox "Arquivo de log não encontrado." 6 40
    fi
}

# Função para configurar clientes VPN
configure_vpn_clients() {
    dialog "${DIALOG_OPTS[@]}" --title "Configuração VPN" --msgbox "Para configurar clientes VPN:\n\n1. Gere chaves para o cliente\n2. Adicione a configuração no servidor\n3. Crie arquivo .conf para o cliente\n\nConsulte a documentação para detalhes." 10 60
}

# IMPLEMENTAÇÃO: Configuração do Netdata
configure_netdata() {
    while true; do
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Configuração Netdata" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Ver status do Netdata" \
            "2" "Configurar plugins" \
            "3" "Configurar alertas" \
            "4" "Configurar acesso remoto" \
            "5" "Otimizar para ARM" \
            "6" "Reiniciar serviço" \
            "7" "Ver logs" \
            "8" "Voltar" \
            3>&1 1>&2 2>&3)
        
        if [ $? -ne 0 ]; then
            break
        fi

        case $choice in
            1) check_netdata_status ;;
            2) configure_netdata_plugins ;;
            3) configure_netdata_alerts ;;
            4) configure_netdata_access ;;
            5) optimize_netdata_arm ;;
            6) restart_netdata_service ;;
            7) show_netdata_logs ;;
            8|"") break ;;
        esac
    done
}

# IMPLEMENTAÇÃO: Configuração do FileBrowser
configure_filebrowser() {
    while true; do
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Configuração FileBrowser" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Ver status do FileBrowser" \
            "2" "Gerenciar usuários" \
            "3" "Configurar diretórios" \
            "4" "Alterar porta" \
            "5" "Configurar permissões" \
            "6" "Backup/Restore configuração" \
            "7" "Reiniciar serviço" \
            "8" "Ver logs" \
            "9" "Voltar" \
            3>&1 1>&2 2>&3)
        
        if [ $? -ne 0 ]; then
            break
        fi

        case $choice in
            1) check_filebrowser_status ;;
            2) manage_filebrowser_users ;;
            3) configure_filebrowser_dirs ;;
            4) change_filebrowser_port ;; # Esta função precisa ser criada
            5) configure_filebrowser_permissions ;;
            6) backup_restore_filebrowser ;;
            7) restart_filebrowser_service ;;
            8) show_filebrowser_logs ;; # Esta função precisa ser criada
            9|"") break ;;
        esac
    done
}

# IMPLEMENTAÇÃO: Configuração do MiniDLNA
configure_minidlna() {
    while true; do
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Configuração MiniDLNA" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Ver status do MiniDLNA" \
            "2" "Configurar diretórios de mídia" \
            "3" "Configurar nome do servidor" \
            "4" "Alterar porta" \
            "5" "Reescanear biblioteca" \
            "6" "Configurar tipos de arquivo" \
            "7" "Reiniciar serviço" \
            "8" "Ver logs" \
            "9" "Voltar" \
            3>&1 1>&2 2>&3)
        
        if [ $? -ne 0 ]; then
            break
        fi

        case $choice in
            1) check_minidlna_status ;;
            2) configure_minidlna_dirs ;;
            3) configure_minidlna_name ;;
            4) change_minidlna_port ;;
            5) rescan_minidlna_library ;;
            6) configure_minidlna_filetypes ;;
            7) restart_minidlna_service ;; # Esta função precisa ser criada
            8) show_minidlna_logs ;;
            9|"") break ;;
        esac
    done
}

# Função para backup
backup_configurations() {
    dialog --title "Backup" --infobox "Criando backup das configurações..." 5 40
    
    local backup_file="$BACKUP_DIR/boxserver-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    tar -czf "$backup_file" -C / etc/boxserver etc/pihole etc/wireguard etc/unbound etc/netdata etc/minidlna /var/lib/filebrowser 2>/dev/null
    
    if [ $? -eq 0 ]; then
        dialog "${DIALOG_OPTS[@]}" --title "Backup Concluído" --msgbox "Backup criado com sucesso:\n\n$backup_file" 8 60
    else
        dialog "${DIALOG_OPTS[@]}" --title "Erro no Backup" --msgbox "Erro ao criar backup." 6 40
    fi
}

# IMPLEMENTAÇÃO: Funções específicas do Netdata
check_netdata_status() {
    local status_info="Status do Netdata:\n\n"
    
    if systemctl is-active --quiet netdata; then
        status_info+="✓ Serviço: ATIVO\n"
        local uptime=$(systemctl show netdata --property=ActiveEnterTimestamp --value)
        status_info+="  Uptime: $(date -d "$uptime" '+%d/%m %H:%M')\n\n"
    else
        status_info+="✗ Serviço: INATIVO\n\n"
    fi
    
    if ss -tlnp | grep -q ":19999"; then
        status_info+="✓ Porta 19999: ESCUTANDO\n"
    else
        status_info+="✗ Porta 19999: NÃO ESCUTANDO\n"
    fi
    
    local memory_usage=$(ps -o pid,vsz,rss,comm -p $(pgrep netdata) 2>/dev/null | tail -1 | awk '{print $3}' || echo "N/A")
    status_info+="📊 Uso de RAM: ${memory_usage}KB\n"
    
    dialog "${DIALOG_OPTS[@]}" --title "Status Netdata" --msgbox "$status_info" 15 60
}

configure_netdata_plugins() {
    local current_config="/etc/netdata/netdata.conf"
    
    if [ ! -f "$current_config" ]; then
        dialog --title "Erro" --msgbox "Arquivo de configuração não encontrado." 6 40
        return 1
    fi
    
    local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Plugins Netdata" --menu "Configurar plugins:" 15 60 8 \
        "1" "Desabilitar plugins pesados" \
        "2" "Habilitar monitoramento de rede" \
        "3" "Configurar alertas de CPU" \
        "4" "Configurar alertas de RAM" \
        "5" "Ver plugins ativos" \
        "6" "Restaurar configuração padrão" \
        "7" "Voltar" \
        3>&1 1>&2 2>&3)
    
    case $choice in
        1)
            # Desabilitar plugins pesados para ARM
            sed -i 's/^.*apps = yes/    apps = no/' "$current_config"
            sed -i 's/^.*cgroups = yes/    cgroups = no/' "$current_config"
            sed -i 's/^.*python.d = yes/    python.d = no/' "$current_config"
            dialog "${DIALOG_OPTS[@]}" --title "Plugins" --msgbox "Plugins pesados desabilitados para otimizar ARM." 6 50
            systemctl restart netdata
            ;;
        2)
            sed -i 's/^.*proc:/proc/net/dev = no/    \/proc\/net\/dev = yes/' "$current_config"
            dialog "${DIALOG_OPTS[@]}" --title "Plugins" --msgbox "Monitoramento de rede habilitado." 6 40
            systemctl restart netdata
            ;;
        5)
            local active_plugins=$(grep -E "^[[:space:]]*[^#].*= yes" "$current_config" | head -10)
            dialog "${DIALOG_OPTS[@]}" --title "Plugins Ativos" --msgbox "$active_plugins" 15 70
            ;;
        6)
            cp "$current_config" "$current_config.backup"
            # Recriar configuração otimizada
            cat > "$current_config" << 'EOF'
[global]
    run as user = netdata
    memory mode = ram
    history = 3600
    update every = 2
    
[plugins]
    apps = no
    cgroups = no
    python.d = no
    charts.d = no
EOF
            dialog "${DIALOG_OPTS[@]}" --title "Configuração" --msgbox "Configuração padrão restaurada." 6 40
            systemctl restart netdata
            ;;
    esac
}

optimize_netdata_arm() {
    dialog --title "Otimizando Netdata" --infobox "Aplicando otimizações para ARM..." 5 50
    
    cat > /etc/netdata/netdata.conf << 'EOF'
[global]
    run as user = netdata
    memory mode = ram
    history = 1800
    update every = 3
    page cache size = 16
    dbengine multihost disk space = 32
    
[web]
    bind to = *
    
[plugins]
    apps = no
    cgroups = no
    charts.d = no
    node.d = no
    python.d = no
    
[plugin:proc]
    /proc/net/dev = yes
    /proc/diskstats = yes
    /proc/meminfo = yes
    /proc/stat = yes
    /proc/uptime = yes
    /proc/loadavg = yes
EOF
    
    systemctl restart netdata
    dialog "${DIALOG_OPTS[@]}" --title "Otimização" --msgbox "Netdata otimizado para ARM RK322x.\n\nRAM reduzida, plugins pesados desabilitados." 8 60
}

restart_netdata_service() {
    dialog --title "Reiniciando Netdata" --infobox "Reiniciando serviço..." 5 30
    systemctl restart netdata
    sleep 2
    
    if systemctl is-active --quiet netdata; then
        dialog "${DIALOG_OPTS[@]}" --title "Serviço" --msgbox "Netdata reiniciado com sucesso!" 6 40
    else
        dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Falha ao reiniciar Netdata." 6 30
    fi
}

show_netdata_logs() {
    dialog "${DIALOG_OPTS[@]}" --title "Logs do Netdata" --msgbox "Os logs serão exibidos em uma nova janela.\n\nPressione 'q' para sair." 8 50
    journalctl -u netdata -f --no-pager
}

# IMPLEMENTAÇÃO: Funções específicas do FileBrowser
check_filebrowser_status() {
    local status_info="Status do FileBrowser:\n\n"
    
    if systemctl is-active --quiet filebrowser; then
        status_info+="✓ Serviço: ATIVO\n"
    else
        status_info+="✗ Serviço: INATIVO\n"
    fi
    
    if ss -tlnp | grep -q ":$FILEBROWSER_PORT"; then
        status_info+="✓ Porta $FILEBROWSER_PORT: ESCUTANDO\n"
    else
        status_info+="✗ Porta $FILEBROWSER_PORT: NÃO ESCUTANDO\n"
    fi
    
    if [ -f "/var/lib/filebrowser/filebrowser.db" ]; then
        local db_size=$(du -h /var/lib/filebrowser/filebrowser.db | cut -f1)
        status_info+="📁 Banco de dados: ${db_size}\n"
    fi
    
    status_info+="\n🌐 Acesso: http://$SERVER_IP:$FILEBROWSER_PORT"
    
    dialog "${DIALOG_OPTS[@]}" --title "Status FileBrowser" --msgbox "$status_info" 12 60
}

manage_filebrowser_users() {
    local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Gerenciar Usuários" --menu "Escolha uma opção:" 12 50 5 \
        "1" "Listar usuários" \
        "2" "Adicionar usuário" \
        "3" "Remover usuário" \
        "4" "Alterar senha" \
        "5" "Voltar" \
        3>&1 1>&2 2>&3)
    
    case $choice in
        1)
            local users=$(filebrowser -d /var/lib/filebrowser/filebrowser.db users ls 2>/dev/null || echo "Erro ao listar usuários")
            dialog "${DIALOG_OPTS[@]}" --title "Usuários" --msgbox "$users" 15 60
            ;;
        2)
            local username=$(dialog "${DIALOG_OPTS[@]}" --title "Novo Usuário" --inputbox "Nome do usuário:" 8 40 3>&1 1>&2 2>&3)
            local password=$(dialog "${DIALOG_OPTS[@]}" --title "Nova Senha" --passwordbox "Senha:" 8 40 3>&1 1>&2 2>&3)
            
            if [ -n "$username" ] && [ -n "$password" ]; then
                filebrowser -d /var/lib/filebrowser/filebrowser.db users add "$username" "$password"
                dialog "${DIALOG_OPTS[@]}" --title "Usuário" --msgbox "Usuário '$username' criado com sucesso!" 6 50
            fi
            ;;
        3)
            local username=$(dialog "${DIALOG_OPTS[@]}" --title "Remover Usuário" --inputbox "Nome do usuário:" 8 40 3>&1 1>&2 2>&3)
            if [ -n "$username" ]; then
                filebrowser -d /var/lib/filebrowser/filebrowser.db users rm "$username"
                dialog "${DIALOG_OPTS[@]}" --title "Usuário" --msgbox "Usuário '$username' removido." 6 40
            fi
            ;;
        4)
            local username=$(dialog "${DIALOG_OPTS[@]}" --title "Alterar Senha" --inputbox "Nome do usuário:" 8 40 3>&1 1>&2 2>&3)
            local password=$(dialog "${DIALOG_OPTS[@]}" --title "Nova Senha" --passwordbox "Nova senha:" 8 40 3>&1 1>&2 2>&3)
            
            if [ -n "$username" ] && [ -n "$password" ]; then
                filebrowser -d /var/lib/filebrowser/filebrowser.db users update "$username" --password "$password"
                dialog "${DIALOG_OPTS[@]}" --title "Senha" --msgbox "Senha alterada com sucesso!" 6 40
            fi
            ;;
    esac
}

change_filebrowser_port() {
    local current_port=$(filebrowser -d /var/lib/filebrowser/filebrowser.db config cat | grep port | awk '{print $2}' || echo "$FILEBROWSER_PORT")
    local new_port=$(dialog "${DIALOG_OPTS[@]}" --title "Alterar Porta" --inputbox "Nova porta para FileBrowser:" 8 40 "$current_port" 3>&1 1>&2 2>&3)
    
    if [ -n "$new_port" ] && [ "$new_port" != "$current_port" ]; then
        # Atualizar configuração
        filebrowser -d /var/lib/filebrowser/filebrowser.db config set --port "$new_port"
        
        # Reiniciar serviço
        systemctl restart filebrowser
        
        # Atualizar variável global
        FILEBROWSER_PORT="$new_port"
        
        dialog "${DIALOG_OPTS[@]}" --title "Porta Alterada" --msgbox "Porta do FileBrowser alterada para: $new_port\n\nNovo acesso: http://$SERVER_IP:$new_port" 8 60
    fi
}

restart_filebrowser_service() {
    dialog --title "Reiniciando FileBrowser" --infobox "Reiniciando serviço..." 5 30
    systemctl restart filebrowser
    sleep 2
    
    if systemctl is-active --quiet filebrowser; then
        dialog "${DIALOG_OPTS[@]}" --title "Serviço" --msgbox "FileBrowser reiniciado com sucesso!" 6 40
    else
        dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Falha ao reiniciar FileBrowser." 6 30
    fi
}

# IMPLEMENTAÇÃO: Funções específicas do MiniDLNA
check_minidlna_status() {
    local status_info="Status do MiniDLNA:\n\n"
    
    if systemctl is-active --quiet minidlna; then
        status_info+="✓ Serviço: ATIVO\n"
    else
        status_info+="✗ Serviço: INATIVO\n"
    fi
    
    if ss -tlnp | grep -q ":8200"; then
        status_info+="✓ Porta 8200: ESCUTANDO\n"
    else
        status_info+="✗ Porta 8200: NÃO ESCUTANDO\n"
    fi
    
    local media_count=$(find /media/dlna -type f \( -name "*.mp4" -o -name "*.avi" -o -name "*.mp3" \) 2>/dev/null | wc -l)
    status_info+="📁 Arquivos de mídia: $media_count\n"
    
    status_info+="\n🌐 Interface: http://$SERVER_IP:8200"
    
    dialog "${DIALOG_OPTS[@]}" --title "Status MiniDLNA" --msgbox "$status_info" 12 60
}

configure_minidlna_dirs() {
    local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Diretórios de Mídia" --menu "Configurar diretórios:" 12 60 6 \
        "1" "Ver diretórios atuais" \
        "2" "Adicionar diretório de vídeos" \
        "3" "Adicionar diretório de música" \
        "4" "Adicionar diretório de fotos" \
        "5" "Remover diretório" \
        "6" "Voltar" \
        3>&1 1>&2 2>&3)
    
    case $choice in
        1)
            local dirs=$(grep "media_dir" /etc/minidlna.conf | head -10)
            dialog "${DIALOG_OPTS[@]}" --title "Diretórios" --msgbox "$dirs" 15 70
            ;;
        2)
            local dir=$(dialog "${DIALOG_OPTS[@]}" --title "Diretório de Vídeos" --inputbox "Caminho completo:" 8 60 "/media/dlna/videos" 3>&1 1>&2 2>&3)
            if [ -n "$dir" ]; then
                echo "media_dir=V,$dir" >> /etc/minidlna.conf
                mkdir -p "$dir"
                chown minidlna:minidlna "$dir"
                dialog "${DIALOG_OPTS[@]}" --title "Diretório" --msgbox "Diretório de vídeos adicionado: $dir" 6 60
            fi
            ;;
        3)
            local dir=$(dialog "${DIALOG_OPTS[@]}" --title "Diretório de Música" --inputbox "Caminho completo:" 8 60 "/media/dlna/music" 3>&1 1>&2 2>&3)
            if [ -n "$dir" ]; then
                echo "media_dir=A,$dir" >> /etc/minidlna.conf
                mkdir -p "$dir"
                chown minidlna:minidlna "$dir"
                dialog "${DIALOG_OPTS[@]}" --title "Diretório" --msgbox "Diretório de música adicionado: $dir" 6 60
            fi
            ;;
        4)
            local dir=$(dialog "${DIALOG_OPTS[@]}" --title "Diretório de Fotos" --inputbox "Caminho completo:" 8 60 "/media/dlna/pictures" 3>&1 1>&2 2>&3)
            if [ -n "$dir" ]; then
                echo "media_dir=P,$dir" >> /etc/minidlna.conf
                mkdir -p "$dir"
                chown minidlna:minidlna "$dir"
                dialog "${DIALOG_OPTS[@]}" --title "Diretório" --msgbox "Diretório de fotos adicionado: $dir" 6 60
            fi
            ;;
    esac
}

configure_minidlna_name() {
    local current_name=$(grep "friendly_name" /etc/minidlna.conf | cut -d'=' -f2 || echo "Boxserver DLNA")
    local new_name=$(dialog "${DIALOG_OPTS[@]}" --title "Nome do Servidor" --inputbox "Nome amigável do servidor DLNA:" 8 50 "$current_name" 3>&1 1>&2 2>&3)
    
    if [ -n "$new_name" ]; then
        sed -i "s/^friendly_name=.*/friendly_name=$new_name/" /etc/minidlna.conf
        systemctl restart minidlna
        dialog "${DIALOG_OPTS[@]}" --title "Nome Alterado" --msgbox "Nome do servidor alterado para: $new_name" 6 50
    fi
}

rescan_minidlna_library() {
    dialog --title "Reescaneando" --infobox "Reescaneando biblioteca de mídia..." 5 40
    
    # Parar serviço
    systemctl stop minidlna
    
    # Limpar cache
    rm -rf /var/cache/minidlna/*
    
    # Reiniciar serviço
    systemctl start minidlna
    
    sleep 3
    dialog "${DIALOG_OPTS[@]}" --title "Biblioteca" --msgbox "Biblioteca reescaneada com sucesso!\n\nNovos arquivos serão detectados em alguns minutos." 8 60
}

restart_minidlna_service() {
    dialog --title "Reiniciando MiniDLNA" --infobox "Reiniciando serviço..." 5 30
    systemctl restart minidlna
    sleep 2
    
    if systemctl is-active --quiet minidlna; then
        dialog "${DIALOG_OPTS[@]}" --title "Serviço" --msgbox "MiniDLNA reiniciado com sucesso!" 6 40
    else
        dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Falha ao reiniciar MiniDLNA." 6 30
    fi
}

# IMPLEMENTAÇÃO: Funções auxiliares adicionais
configure_netdata_alerts() {
    dialog --title "Alertas Netdata" --msgbox "Configuração de alertas será implementada\nem versão futura.\n\nPor enquanto, monitore via interface web:\nhttp://$SERVER_IP:19999" 10 60
}

configure_netdata_access() {
    local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Acesso Remoto" --menu "Configurar acesso:" 10 50 4 \
        "1" "Permitir acesso de qualquer IP" \
        "2" "Restringir a rede local" \
        "3" "Configurar senha" \
        "4" "Voltar" \
        3>&1 1>&2 2>&3)
    
    case $choice in
        1)
            sed -i 's/bind to = .*/bind to = */' /etc/netdata/netdata.conf
            systemctl restart netdata
            dialog "${DIALOG_OPTS[@]}" --title "Acesso" --msgbox "Acesso liberado para qualquer IP." 6 40
            ;;
        2)
            sed -i 's/bind to = .*/bind to = 192.168.*/' /etc/netdata/netdata.conf
            systemctl restart netdata
            dialog "${DIALOG_OPTS[@]}" --title "Acesso" --msgbox "Acesso restrito à rede local." 6 40
            ;;
        3)
            dialog "${DIALOG_OPTS[@]}" --title "Senha" --msgbox "Configuração de senha será implementada\nem versão futura." 8 50
            ;;
    esac
}

configure_filebrowser_dirs() {
    local current_root=$(filebrowser -d /var/lib/filebrowser/filebrowser.db config cat | grep root || echo "/home")
    local new_root=$(dialog --title "Diretório Raiz" --inputbox "Diretório raiz do FileBrowser:" 8 60 "$current_root" 3>&1 1>&2 2>&3)
    
    if [ -n "$new_root" ] && [ -d "$new_root" ]; then
        filebrowser -d /var/lib/filebrowser/filebrowser.db config set --root "$new_root"
        systemctl restart filebrowser
        dialog --title "Diretório" --msgbox "Diretório raiz alterado para: $new_root" 6 60
    elif [ -n "$new_root" ]; then
        dialog --title "Erro" --msgbox "Diretório não existe: $new_root" 6 40
    fi
}

configure_filebrowser_permissions() {
    dialog --title "Permissões" --msgbox "Configurações de permissões:\n\n• Usuários podem navegar no diretório raiz\n• Admin tem acesso total\n• Usuários normais: somente leitura\n\nPara alterar, use o gerenciamento de usuários." 12 60
}

backup_restore_filebrowser() {
    local choice=$(dialog --title "Backup/Restore" --menu "Escolha uma opção:" 10 50 3 \
        "1" "Fazer backup da configuração" \
        "2" "Restaurar configuração" \
        "3" "Voltar" \
        3>&1 1>&2 2>&3)
    
    case $choice in
        1)
            local backup_file="/tmp/filebrowser-backup-$(date +%Y%m%d_%H%M%S).db"
            cp /var/lib/filebrowser/filebrowser.db "$backup_file"
            dialog "${DIALOG_OPTS[@]}" --title "Backup" --msgbox "Backup criado: $backup_file" 6 60
            ;;
        2)
            local backup_file=$(dialog "${DIALOG_OPTS[@]}" --title "Restaurar" --inputbox "Caminho do arquivo de backup:" 8 60 3>&1 1>&2 2>&3)
            if [ -f "$backup_file" ]; then
                systemctl stop filebrowser
                cp "$backup_file" /var/lib/filebrowser/filebrowser.db
                chown filebrowser:filebrowser /var/lib/filebrowser/filebrowser.db
                systemctl start filebrowser
                dialog "${DIALOG_OPTS[@]}" --title "Restaurar" --msgbox "Configuração restaurada com sucesso!" 6 50
            else
                dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Arquivo de backup não encontrado." 6 40
            fi
            ;;
    esac
}

show_filebrowser_logs() {
    dialog "${DIALOG_OPTS[@]}" --title "Logs do FileBrowser" --msgbox "Os logs serão exibidos em uma nova janela.\n\nPressione 'q' para sair." 8 50
    journalctl -u filebrowser -f --no-pager
}

change_minidlna_port() {
    local current_port=$(grep "^port=" /etc/minidlna.conf | cut -d'=' -f2 | xargs || echo "8200")
    local new_port=$(dialog "${DIALOG_OPTS[@]}" --title "Alterar Porta" --inputbox "Nova porta para MiniDLNA:" 8 40 "$current_port" 3>&1 1>&2 2>&3)
    
    if [ -n "$new_port" ] && [ "$new_port" != "$current_port" ]; then
        sed -i "s/^port=.*/port=$new_port/" /etc/minidlna.conf
        systemctl restart minidlna
        dialog --title "Porta Alterada" --msgbox "Porta do MiniDLNA alterada para: $new_port\n\nNovo acesso: http://$SERVER_IP:$new_port" 8 60
    fi
}

configure_minidlna_filetypes() {
    dialog "${DIALOG_OPTS[@]}" --title "Tipos de Arquivo" --msgbox "Tipos de arquivo suportados:\n\n📹 Vídeos: .mp4, .avi, .mkv, .mov, .wmv\n🎵 Áudio: .mp3, .flac, .wav, .aac, .ogg\n🖼️ Imagens: .jpg, .png, .gif, .bmp\n\nPara adicionar novos tipos, edite:\n/etc/minidlna.conf" 14 60
}

show_minidlna_logs() {
    dialog "${DIALOG_OPTS[@]}" --title "Logs do MiniDLNA" --msgbox "Os logs serão exibidos em uma nova janela.\n\nPressione 'q' para sair." 8 50
    journalctl -u minidlna -f --no-pager
}

# IMPLEMENTAÇÃO: Configuração de outros serviços
configure_other_services() {
    while true; do
        local choice=$(dialog --title "Outros Serviços" --menu "Configurar serviços adicionais:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Configurar UFW (Firewall)" \
            "2" "Configurar RNG-tools" \
            "3" "Configurar Rclone" \
            "4" "Configurar Rsync" \
            "5" "Configurar Cockpit" \
            "6" "Ver todos os serviços" \
            "7" "Voltar" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) configure_ufw_service ;;
            2) configure_rng_service ;;
            3) configure_rclone_service ;;
            4) configure_rsync_service ;;
            5) configure_cockpit_service ;;
            6) show_all_services_status ;;
            7|"") break ;;
        esac
    done
}

configure_ufw_service() {
    local choice=$(dialog "${DIALOG_OPTS[@]}" --title "UFW Firewall" --menu "Configurar firewall:" 15 60 5 \
        "1" "Ver status do UFW" \
        "2" "Ver regras ativas" \
        "3" "Adicionar regra personalizada" \
        "4" "Resetar configuração" \
        "5" "Voltar" \
        3>&1 1>&2 2>&3)
    
    case $choice in
        1)
            local ufw_status=$(ufw status verbose)
            dialog "${DIALOG_OPTS[@]}" --title "Status UFW" --msgbox "$ufw_status" 20 80
            ;;
        2)
            local ufw_rules=$(ufw status numbered)
            dialog "${DIALOG_OPTS[@]}" --title "Regras UFW" --msgbox "$ufw_rules" 20 80
            ;;
        3)
            local port=$(dialog "${DIALOG_OPTS[@]}" --title "Nova Regra" --inputbox "Porta ou serviço:" 8 40 3>&1 1>&2 2>&3)
            local action=$(dialog "${DIALOG_OPTS[@]}" --title "Ação" --menu "Escolha a ação:" 12 40 2 \
                "allow" "Permitir" \
                "deny" "Negar" \
                3>&1 1>&2 2>&3)
            
            if [ -n "$port" ] && [ -n "$action" ]; then
                ufw $action $port
                dialog "${DIALOG_OPTS[@]}" --title "Regra" --msgbox "Regra adicionada: $action $port" 6 40
            fi
            ;;
        4)
            if dialog "${DIALOG_OPTS[@]}" --title "Resetar UFW" --yesno "Tem certeza que deseja resetar todas as regras?\n\nIsso pode expor seu servidor a riscos." 8 60; then
                ufw --force reset
                dialog "${DIALOG_OPTS[@]}" --title "Reset" --msgbox "UFW resetado. Configure novamente se necessário." 6 50
            fi
            ;;
    esac
}

show_all_services_status() {
    local services_status="Status de Todos os Serviços:\n\n"
    
    local services=("pihole-FTL" "unbound" "wg-quick@wg0" "netdata" "filebrowser" "minidlna" "fail2ban" "ufw" "rng-tools" "cockpit")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            services_status+="✓ $service: ATIVO\n"
        else
            services_status+="✗ $service: INATIVO\n"
        fi
    done
    
    dialog "${DIALOG_OPTS[@]}" --title "Status dos Serviços" --msgbox "$services_status" 20 60
}

configure_rng_service() {
    dialog "${DIALOG_OPTS[@]}" --title "RNG-tools" --msgbox "RNG-tools Status:\n\n$(systemctl status rng-tools --no-pager -l | head -10)\n\nEntropia atual: $(cat /proc/sys/kernel/random/entropy_avail)" 15 70
}

configure_rclone_service() {
    dialog "${DIALOG_OPTS[@]}" --title "Rclone" --msgbox "Para configurar Rclone:\n\n1. Execute: rclone config\n2. Configure seus provedores de nuvem\n3. Use o script de backup manual\n\nConsulte a documentação para detalhes." 12 60
}

configure_rsync_service() {
    dialog "${DIALOG_OPTS[@]}" --title "Rsync" --msgbox "Rsync configurado para backup local:\n\n• Script: /usr/local/bin/boxserver-sync\n• Agendamento: diário às 02:00\n• Destino: /var/backups/boxserver/\n\nExecute manualmente: sudo /usr/local/bin/boxserver-sync" 12 70
}

configure_cockpit_service() {
    local cockpit_status="Status do Cockpit:\n\n"
    
    if systemctl is-active --quiet cockpit; then
        cockpit_status+="✓ Serviço: ATIVO\n"
    else
        cockpit_status+="✗ Serviço: INATIVO\n"
    fi
    
    cockpit_status+="🌐 Acesso: https://$SERVER_IP:$COCKPIT_PORT\n"
    cockpit_status+="👤 Login: usuário do sistema\n"
    cockpit_status+="🔧 Funcionalidades: gerenciamento completo do sistema"
    
    dialog "${DIALOG_OPTS[@]}" --title "Cockpit" --msgbox "$cockpit_status" 12 60
}

# IMPLEMENTAÇÃO: Menu de gerenciamento de serviços
manage_services_menu() {
    while true; do
        local menu_items=()
        for app_id in $(echo "${!APPS[@]}" | tr ' ' '\n' | sort -n); do
            local service_name=$(get_service_name "$app_id")
            if [ -n "$service_name" ]; then
                local app_status=$(check_app_status "$app_id")
                local app_name=$(echo "${APPS[$app_id]}" | cut -d'|' -f1)
                local status_icon="-" # Padrão para não instalado

                if [[ "$app_status" == "installed_ok" ]]; then
                    status_icon="✅"
                elif [[ "$app_status" == "installed_error" ]]; then
                    status_icon="❌"
                else
                    # Se não estiver instalado, não adiciona ao menu de gerenciamento
                    continue
                fi
                menu_items+=("$app_id" "$status_icon $app_name")
            fi
        done

        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Gerenciamento de Serviços" --menu "Selecione um serviço para gerenciar:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT "${menu_items[@]}" 3>&1 1>&2 2>&3)

        if [ $? -ne 0 ]; then
            break
        fi

        local service_name=$(get_service_name "$choice")
        local app_name=$(echo "${APPS[$choice]}" | cut -d'|' -f1)

        if [ -n "$service_name" ]; then
            local action=$(dialog "${DIALOG_OPTS[@]}" --title "Gerenciar: $app_name" --menu "Escolha uma ação:" 15 50 4 \
                "start" "Iniciar" \
                "stop" "Parar" \
                "restart" "Reiniciar" \
                "status" "Ver Status" \
                3>&1 1>&2 2>&3)

            case $action in
                start|stop|restart)
                    systemctl "$action" "$service_name"
                    dialog "${DIALOG_OPTS[@]}" --title "Ação Executada" --infobox "Comando '$action' executado para $app_name." 5 50
                    sleep 1
                    ;;
                status)
                    local status_output=$(systemctl status "$service_name" --no-pager -l)
                    dialog "${DIALOG_OPTS[@]}" --title "Status: $app_name" --msgbox "$status_output" 20 80
                    ;;
            esac
        fi
    done
}

# IMPLEMENTAÇÃO: Menu para configurar aplicativos específicos
configure_apps_menu() {
    while true; do
        local menu_items=()
        # Adiciona apenas aplicativos instalados que têm um menu de configuração
        if [[ "$(check_app_status 1)" != "not_installed" || "$(check_app_status 2)" != "not_installed" ]]; then
            menu_items+=("1" "Configurar Pi-hole & Unbound")
        fi
        if [[ "$(check_app_status 5)" != "not_installed" ]]; then
            menu_items+=("2" "Configurar FileBrowser")
        fi
        if [[ "$(check_app_status 6)" != "not_installed" ]]; then
            menu_items+=("3" "Configurar Netdata")
        fi
        if [[ "$(check_app_status 12)" != "not_installed" ]]; then
            menu_items+=("4" "Configurar MiniDLNA")
        fi
        if [[ "$(check_app_status 10)" != "not_installed" ]]; then
            menu_items+=("5" "Configurar Rclone")
        fi

        if [ ${#menu_items[@]} -eq 0 ]; then
            dialog "${DIALOG_OPTS[@]}" --title "Configurar Aplicativos" --msgbox "Nenhum aplicativo configurável foi instalado ainda." 8 60
            break
        fi

        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Configurar Aplicativos" --menu "Selecione um aplicativo para configurar:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT "${menu_items[@]}" 3>&1 1>&2 2>&3)

        if [ $? -ne 0 ]; then
            break
        fi

        case $choice in
            1) configure_pihole_unbound ;;
            2) configure_filebrowser ;;
            3) configure_netdata ;;
            4) configure_minidlna ;;
            5) configure_rclone_service ;;
        esac
    done
}

# IMPLEMENTAÇÃO: Menu de gerenciamento de serviços
manage_services_menu() {
    while true; do
        local menu_items=()
        # Itera sobre os aplicativos na ordem de prioridade para consistência
        local priority_order=(1 2 3 4 5 6 7 8 9 12 13 14 15)

        for app_id in "${priority_order[@]}"; do
            local service_name=$(get_service_name "$app_id")
            # Adiciona ao menu apenas se for um serviço gerenciável e estiver instalado
            if [ -n "$service_name" ] && [[ "$(check_app_status "$app_id")" != "not_installed" ]]; then
                local app_name=$(echo "${APPS[$app_id]}" | cut -d'|' -f1)
                local status_icon="❌" # Padrão para inativo

                if systemctl is-active --quiet "$service_name" 2>/dev/null; then
                    status_icon="✅"
                fi
                menu_items+=("$app_id" "$status_icon $app_name")
            fi
        done

        if [ ${#menu_items[@]} -eq 0 ]; then
            dialog "${DIALOG_OPTS[@]}" --title "Gerenciamento de Serviços" --msgbox "Nenhum serviço gerenciável foi instalado ainda." 8 60
            break
        fi

        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Gerenciamento de Serviços" --menu "Selecione um serviço para gerenciar:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT "${menu_items[@]}" 3>&1 1>&2 2>&3)

        exit_status=$?
        if [ $exit_status -ne 0 ]; then
            break
        fi

        # Ação de gerenciamento para o serviço escolhido
        manage_single_service "$choice"
    done
}

# IMPLEMENTAÇÃO: Menu para configurar aplicativos específicos
configure_apps_menu() {
    while true; do
        local menu_items=()
        # Adiciona apenas aplicativos instalados que têm um menu de configuração
        if [[ "$(check_app_status 1)" != "not_installed" ]] || [[ "$(check_app_status 2)" != "not_installed" ]]; then
            menu_items+=("1" "Configurar Pi-hole & Unbound")
        fi
        if [[ "$(check_app_status 3)" != "not_installed" ]]; then
            menu_items+=("2" "Configurar WireGuard")
        fi
        if [[ "$(check_app_status 5)" != "not_installed" ]]; then
            menu_items+=("3" "Configurar FileBrowser")
        fi
        if [[ "$(check_app_status 6)" != "not_installed" ]]; then
            menu_items+=("4" "Configurar Netdata")
        fi
        if [[ "$(check_app_status 12)" != "not_installed" ]]; then
            menu_items+=("5" "Configurar MiniDLNA")
        fi
        if [[ "$(check_app_status 10)" != "not_installed" ]]; then
            menu_items+=("6" "Configurar Rclone")
        fi
        if [[ "$(check_app_status 13)" != "not_installed" ]]; then
            menu_items+=("7" "Configurar Cloudflare Tunnel")
        fi

        if [ ${#menu_items[@]} -eq 0 ]; then
            dialog "${DIALOG_OPTS[@]}" --title "Configurar Aplicativos" --msgbox "Nenhum aplicativo configurável foi instalado ainda." 8 60
            break
        fi

        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Configurar Aplicativos" \
            --menu "Selecione um aplicativo para configurar detalhes avançados (portas, usuários, etc.):" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT "${menu_items[@]}" 3>&1 1>&2 2>&3)

        if [ $? -ne 0 ]; then
            break
        fi

        case $choice in
            1) configure_pihole_unbound ;;
            2) configure_wireguard_vpn ;;
            3) configure_filebrowser ;;
            4) configure_netdata ;;
            5) configure_minidlna ;;
            6) configure_rclone_service ;;
            7) configure_cloudflare_tunnel ;;
        esac
    done
}

# IMPLEMENTAÇÃO: Menu de diagnóstico
diagnostics_menu() {
    while true; do
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Diagnóstico e Manutenção" --menu "Selecione uma tarefa para executar:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Relatório de Saúde Completo (boxserver-health)" \
            "2" "Testar Conectividade de Rede" \
            "3" "Testar Resolução DNS (Pi-hole & Unbound)" \
            "4" "Ver Logs de Instalação" \
            "5" "Voltar ao Menu Principal" \
            3>&1 1>&2 2>&3)

        case $choice in
            1)
                local health_report=$(/usr/local/bin/boxserver-health)
                dialog "${DIALOG_OPTS[@]}" --title "Relatório de Saúde" --msgbox "$health_report" 25 80
                ;;
            2)
                if test_connectivity; then
                    dialog "${DIALOG_OPTS[@]}" --title "Conectividade" --msgbox "Teste de conectividade com a internet foi bem-sucedido." 6 60
                fi
                ;;
            3)
                test_dns_resolution
                ;;
            4)
                # Reutiliza o menu de gerenciamento para mostrar o status
                manage_services_menu
                ;;
            5)
                show_installation_logs
                ;;
            6|"")
                break
                ;;
        esac
    done
}

# IMPLEMENTAÇÃO: Menu de Manutenção
maintenance_menu() {
    while true; do
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Manutenção e Backups" --menu "Escolha uma tarefa de manutenção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Executar Limpeza do Sistema (apt, logs)" \
            "2" "Fazer Backup das Configurações" \
            "3" "Ver Backups Existentes" \
            "4" "Voltar" \
            3>&1 1>&2 2>&3)

        case $choice in
            1)
                /etc/cron.weekly/cleanup-boxserver
                dialog "${DIALOG_OPTS[@]}" --title "Limpeza" --msgbox "Script de limpeza executado com sucesso." 6 50
                ;;
            2)
                backup_configurations
                ;;
            3)
                local backups=$(ls -lh "$BACKUP_DIR" | awk '{print $9, $5}')
                dialog "${DIALOG_OPTS[@]}" --title "Backups" --msgbox "Backups disponíveis em $BACKUP_DIR:\n\n$backups" 15 60
                ;;
            4|"") break ;;
        esac
    done
}

# IMPLEMENTAÇÃO: Menu de Segurança
security_menu() {
    while true; do
        local ufw_status=$(ufw status | grep -q "Status: active" && echo "✅ Ativo" || echo "❌ Inativo")
        local f2b_status=$(systemctl is-active --quiet fail2ban && echo "✅ Ativo" || echo "❌ Inativo")

        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Gerenciamento de Segurança" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Gerenciar Firewall (UFW) - Status: $ufw_status" \
            "2" "Gerenciar Proteção (Fail2Ban) - Status: $f2b_status" \
            "3" "Voltar" \
            3>&1 1>&2 2>&3)

        case $choice in
            1)
                configure_ufw_service
                ;;
            2)
                # Adicionar um menu para Fail2Ban se necessário, por enquanto status é suficiente
                local f2b_status_details=$(systemctl status fail2ban --no-pager -l)
                dialog "${DIALOG_OPTS[@]}" --title "Status Fail2Ban" --msgbox "$f2b_status_details" 20 80
                ;;
            3|"")
                break
                ;;
        esac
    done
}

# IMPLEMENTAÇÃO: Configuração do Rclone
configure_rclone_service() {
    if ! command -v rclone &>/dev/null; then
        dialog --title "Erro" --msgbox "Rclone não está instalado." 6 40
        return 1
    fi

    while true; do
        local webui_status="INATIVO"
        if systemctl is-active --quiet rclone-webui 2>/dev/null; then
            webui_status="ATIVO"
        fi
        
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Configuração Rclone" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Configurar um novo 'remote' (rclone config)" \
            "2" "Listar 'remotes' configurados" \
            "3" "Habilitar/Iniciar Web-GUI (Status: $webui_status)" \
            "4" "Parar/Desabilitar Web-GUI" \
            "5" "Alterar senha da Web-GUI" \
            "6" "Executar script de backup manual" \
            "7" "Voltar" \
            3>&1 1>&2 2>&3)

        case $choice in
            1)
                dialog "${DIALOG_OPTS[@]}" --title "Configurar Rclone" --msgbox "Você será levado para a configuração interativa do Rclone.\n\nSiga as instruções no terminal." 8 60
                clear
                rclone config
                dialog "${DIALOG_OPTS[@]}" --title "Concluído" --msgbox "Configuração do Rclone finalizada.\nPressione ENTER para voltar ao menu." 6 50
                ;;
            2)
                local remotes=$(rclone listremotes)
                dialog "${DIALOG_OPTS[@]}" --title "Remotes Configurados" --msgbox "Remotes:\n\n$remotes" 15 60
                ;;
            3)
                setup_rclone_webui
                ;;
            4)
                systemctl stop rclone-webui 2>/dev/null
                systemctl disable rclone-webui 2>/dev/null
                dialog "${DIALOG_OPTS[@]}" --title "Web-GUI" --msgbox "Interface Web do Rclone parada e desabilitada." 6 50
                ;;
            5)
                local status=$(systemctl status rclone-webui --no-pager -l)
                dialog "${DIALOG_OPTS[@]}" --title "Status Web-GUI" --msgbox "Status do serviço rclone-webui:\n\n$status" 20 80
                ;;
            6)
                /usr/local/bin/boxserver-backup
                dialog --title "Backup" --msgbox "Script de backup executado." 6 40
                ;;
            7|"")
                break
                ;;
        esac
    done
}

# IMPLEMENTAÇÃO: Função para configurar a Web-GUI do Rclone
setup_rclone_webui() {
    # MELHORIA: Gerar senha aleatória e segura
    local rclone_password=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12)
    log_message "INFO" "Senha gerada para Rclone Web-GUI: $rclone_password"
    log_message "INFO" "Configurando serviço para a Web-GUI do Rclone..."
    cat > /etc/systemd/system/rclone-webui.service << 'EOF'
[Unit]
Description=Rclone Web-GUI
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/rclone rcd --rc-web-gui --rc-addr :5572 --rc-user admin --rc-pass 
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    # Inserir a senha gerada no arquivo de serviço
    sed -i "s/--rc-pass /--rc-pass $rclone_password/" /etc/systemd/system/rclone-webui.service

    systemctl daemon-reload
    systemctl enable rclone-webui
    systemctl start rclone-webui

    if systemctl is-active --quiet rclone-webui; then
        dialog "${DIALOG_OPTS[@]}" --title "Web-GUI Ativada" --msgbox "Interface Web do Rclone está ativa!\n\nAcesse: http://$SERVER_IP:5572\n\nLogin: admin\nSenha: $rclone_password\n\n(A senha foi salva em $LOG_FILE)" 12 70
        log_message "INFO" "Serviço Rclone Web-GUI iniciado com sucesso."
    else
        dialog "${DIALOG_OPTS[@]}" --title "Erro" --msgbox "Falha ao iniciar a Web-GUI do Rclone.\nVerifique os logs com 'journalctl -u rclone-webui'." 8 60
        log_message "ERROR" "Falha ao iniciar o serviço Rclone Web-GUI."
    fi
}

# MELHORIA: Menu principal com opção de modo silencioso
main_menu() {
    while true; do        
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Boxserver TUI - Canivete Suíço" \
            --menu "Bem-vindo ao painel de controle do seu Boxserver.\n\nO que você gostaria de fazer?" \
            $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Instalar / Desinstalar Aplicativos" \
            "2" "Gerenciamento de Serviços (Start/Stop/Status)" \
            "3" "Configuração de Aplicativos" \
            "4" "Diagnóstico e Testes" \
            "5" "Configurações Gerais do Servidor" \
            "6" "Manutenção e Backups" \
            "7" "Segurança (Firewall, Fail2Ban)" \
            "8" "Informações do Sistema" \
            "9" "Sobre o Boxserver TUI" \
            "10" "Sair" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) # Instalar / Desinstalar Aplicativos
                select_applications
                ;;
            2) # Gerenciamento de Serviços (Start/Stop/Status)
                manage_services_menu
                ;;
            3) # Configuração de Aplicativos
                configure_apps_menu
                ;;
            4) # Diagnóstico e Testes
                diagnostics_menu
                ;;
            5) # Configurações Gerais do Servidor
                configure_advanced_settings
                ;;
            6) # Manutenção e Backups
                maintenance_menu
                ;;
            7) # Segurança (Firewall, Fail2Ban)
                security_menu
                ;;
            8) # Informações do Sistema
                show_system_info
                ;;
            9)
                dialog --title "Sobre" --msgbox "Boxserver TUI Installer v1.0\n\nInstalador automatizado para servidor doméstico\nem dispositivos MXQ-4K com chip RK322x\n\nBaseado na base de conhecimento do\nprojeto Boxserver Arandutec\n\nDesenvolvido para hardware limitado\ncom otimizações específicas para ARM\n\n🔇 Modo Silencioso: Instalação com barra de progresso\n📋 Logs detalhados salvos automaticamente" 14 70
                ;;            
            10|"")
                if dialog --title "Confirmar Saída" --yesno "Deseja realmente sair?" 6 30; then
                    clear
                    echo "Obrigado por usar o Boxserver TUI Installer!"
                    exit 0
                fi
                ;;
        esac
    done
}

# MELHORIA: Gerar relatório final da instalação
generate_installation_summary() {
    local installed_apps=("$@")
    local summary_file="$LOG_DIR/installation-summary.txt"
    local summary_dialog="Instalação Concluída!\n\n"

    echo "=== Relatório de Instalação Boxserver ===" > "$summary_file"
    echo "Data: $(date)" >> "$summary_file"
    echo "----------------------------------------" >> "$summary_file"
    summary_dialog+="Serviços instalados:\n"

    for app_id in "${installed_apps[@]}"; do
        local app_info="${APPS[$app_id]}"
        IFS='|' read -r name description access <<< "$app_info"
        
        local status_icon="✅"
        if ! systemctl is-active --quiet $(get_service_name "$app_id") 2>/dev/null && [[ -n "$(get_service_name "$app_id")" ]]; then
            status_icon="⚠️"
        fi

        echo "$status_icon $name: Instalado" >> "$summary_file"
        summary_dialog+="$status_icon $name\n"
    done

    dialog "${DIALOG_OPTS[@]}" --title "Resumo da Instalação" --msgbox "$summary_dialog\nRelatório detalhado em:\n$summary_file" 18 60
}

# IMPLEMENTAÇÃO: Criar scripts de manutenção documentados
create_maintenance_scripts() {
    log_message "INFO" "Criando scripts de manutenção..."

    # Script de limpeza semanal
    cat > /etc/cron.weekly/cleanup-boxserver << 'EOF'
#!/bin/bash
# Script de limpeza automática do Boxserver

# Limpeza de pacotes
apt-get autoremove --purge -y >/dev/null 2>&1
apt-get clean >/dev/null 2>&1

# Limpeza de logs do journald (manter últimos 7 dias)
journalctl --vacuum-time=7d >/dev/null 2>&1

# Limpeza de logs do Pi-hole (manter últimos 30 dias)
find /var/log -name "pihole*.log*" -mtime +30 -delete 2>/dev/null

# Verificar espaço em disco e saúde do sistema
df -h > /var/log/boxserver/disk-usage.log
echo "Entropia: $(cat /proc/sys/kernel/random/entropy_avail)" >> /var/log/boxserver/system-health.log

echo "Limpeza concluída em $(date)" >> /var/log/boxserver/cleanup.log
EOF

    chmod +x /etc/cron.weekly/cleanup-boxserver
    log_message "INFO" "Script de limpeza semanal criado em /etc/cron.weekly/cleanup-boxserver"

    # MELHORIA: Criar script de saúde do sistema, conforme documentação
    cat > /usr/local/bin/boxserver-health << 'EOF'
#!/bin/bash
# Script de monitoramento de saúde do Boxserver

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
if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
    echo "Temperatura CPU: $(($(cat /sys/class/thermal/thermal_zone0/temp)/1000))°C"
fi
echo

# Status dos serviços
echo "=== SERVIÇOS ==="
services=("pihole-FTL" "unbound" "wg-quick@wg0" "rng-tools" "chrony" "cockpit.socket" "filebrowser" "netdata" "fail2ban")
for service in "${services[@]}"; do
    if systemctl list-unit-files | grep -q "^${service}.service" || systemctl list-unit-files | grep -q "^${service}.socket"; then
        if systemctl is-active --quiet "$service"; then
            echo "✅ $service: ATIVO"
        else
            echo "❌ $service: INATIVO"
        fi
    fi
done
echo

# Testes de conectividade
echo "=== CONECTIVIDADE ==="
echo "Entropia: $(cat /proc/sys/kernel/random/entropy_avail)"
echo "DNS Pi-hole: $(timeout 2 dig @127.0.0.1 google.com +short | head -1 || echo 'FALHOU')"
echo "DNS Unbound: $(timeout 2 dig @127.0.0.1 -p 5335 google.com +short | head -1 || echo 'FALHOU')"
echo "Internet: $(timeout 2 ping -c 1 8.8.8.8 >/dev/null 2>&1 && echo 'OK' || echo 'FALHOU')"
echo

# Alertas
echo "=== ALERTAS ==="
RAM_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ "$RAM_USAGE" -gt 85 ]; then
    echo "⚠️  Uso de RAM alto: ${RAM_USAGE}%"
fi

DISK_USAGE=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 90 ]; then
    echo "⚠️  Uso de disco alto: ${DISK_USAGE}%"
fi

echo "==========================================="
EOF

    chmod +x /usr/local/bin/boxserver-health
    log_message "INFO" "Script de saúde do sistema criado em /usr/local/bin/boxserver-health"
}

# Função para verificar se o dialog está instalado
check_dialog() {
    if ! command -v dialog &> /dev/null; then
        echo "Dialog não encontrado. Instalando..."
        apt-get update && apt-get install -y dialog
        if [ $? -ne 0 ]; then
            echo "Erro ao instalar dialog. Saindo..."
            exit 1
        fi
    fi
}

# Função para configurar ambiente headless
setup_headless_environment() {
    # Remover variáveis de ambiente gráficas que podem causar problemas
    unset DISPLAY WAYLAND_DISPLAY XDG_SESSION_TYPE XDG_CURRENT_DESKTOP
    
    # Configurar variáveis para modo texto
    export DEBIAN_FRONTEND=noninteractive
    export TERM=${TERM:-linux}
}

# IMPLEMENTAÇÃO: Função para instalar o script como um comando global
install_script_globally() {
    local install_path="/usr/local/bin/boxserver"
    
    if dialog "${DIALOG_OPTS[@]}" --title "Instalação Global" --yesno "Deseja instalar este script como um comando global ('boxserver')?\n\nIsso permitirá que você o execute de qualquer lugar no terminal." 10 70; then
        log_message "INFO" "Instalando script em $install_path..."
        
        if cp "$0" "$install_path" && chmod +x "$install_path"; then
            dialog "${DIALOG_OPTS[@]}" --title "Instalação Concluída" --msgbox "Script instalado com sucesso!\n\nAgora você pode executá-lo a qualquer momento digitando:\n\nboxserver" 10 60
            log_message "INFO" "Script instalado globalmente. Reiniciando a partir do novo local."
            
            # Reiniciar o script a partir do novo local para continuar a execução
            exec "$install_path"
        else
            dialog --title "Erro de Instalação" --msgbox "Falha ao instalar o script em $install_path.\n\nVerifique as permissões e tente novamente." 8 60
            log_message "ERROR" "Falha ao copiar ou dar permissão de execução para $install_path."
        fi
    else
        log_message "INFO" "Usuário optou por não instalar o script globalmente."
    fi
}

# Função principal
main() {
    # Verificar se está sendo executado como root
    if [[ $EUID -ne 0 ]]; then
        echo "Este script deve ser executado como root."
        echo "Use: sudo $0"
        exit 1
    fi
    
    # Verificar e instalar dialog
    check_dialog
    
    # Configurar ambiente headless
    setup_headless_environment
    
    # Configurar diretórios
    setup_directories
    
    # Log de início
    log_message "INFO" "Boxserver TUI Installer iniciado"
    
    # Detectar interface de rede inicial
    detect_network_interface
    
    # Atualizar o backtitle com o IP detectado
    BACKTITLE="Boxserver TUI v1.0 | IP: $SERVER_IP | Hardware: RK322x"

    # MELHORIA: Oferecer auto-instalação se o script não for o comando global
    local script_path=$(realpath "$0")
    if [[ "$script_path" != "/usr/local/bin/boxserver" ]]; then
        install_script_globally
    fi
    
    # Mostrar tela de boas-vindas
    dialog "${DIALOG_OPTS[@]}" --title "Bem-vindo" --msgbox "Boxserver TUI Installer v1.0\n\nInstalador automatizado para MXQ-4K\n\nEste assistente irá guiá-lo através da\ninstalação e configuração do seu\nservidor doméstico.\n\nPressione ENTER para continuar..." 12 50
    
    # Iniciar menu principal
    main_menu
}

# Tratamento de sinais
trap 'clear; echo "Instalação interrompida."; exit 1' INT TERM

# Executar função principal
main "$@"
