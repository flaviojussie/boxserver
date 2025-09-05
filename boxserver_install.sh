#!/bin/bash
# Script aprimorado para instalação do Boxserver - melhorias estruturais, clareza e eficiência
#
# Boxserver TUI Installer - Interface Gráfica Terminal
# Instalador automatizado para MXQ-4K com chip RK322x
# Baseado na base de conhecimento do projeto Boxserver Arandutec
#
# Autor: Boxserver Team
# Versão: 2.0 (Refatorado)
# Data: $(date +%Y-%m-%d)
#
# ==============================================
# MELHORIAS DESTE VERSÃO:
# - Funções reutilizáveis para reduzir redundância
# - Tratamento de erros centralizado
# - Otimização de desempenho
# - Código modular e mais legível
# - Melhoria na detecção de hardware
# - Gestão de recursos otimizada
# ==============================================

# ==============================================
# CONFIGURAÇÕES GLOBAIS
# ==============================================

# Diretórios
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/boxserver"
CONFIG_DIR="/etc/boxserver"
BACKUP_DIR="/var/backups/boxserver"
LOG_FILE="$LOG_DIR/tui-installer.log"

# Cores para output
declare -A COLORS=(
    [RED]='\033[0;31m'
    [GREEN]='\033[0;32m'
    [YELLOW]='\033[1;33m'
    [BLUE]='\033[0;34m'
    [NC]='\033[0m' # No Color
)

# Configurações padrão do dialog
DIALOG_HEIGHT=20
DIALOG_WIDTH=70
DIALOG_MENU_HEIGHT=12

# Variáveis globais de configuração
NETWORK_INTERFACE=""
SERVER_IP=""
VPN_NETWORK="10.200.200.0/24"
VPN_PORT="51820"
PIHOLE_PASSWORD=""
FILEBROWSER_PORT="8080"
COCKPIT_PORT="9090"
BOARD_INFO=""

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

# ==============================================
# FUNÇÕES DE UTILIDADE
# ==============================================

# Função de logging centralizada
log_message() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
}

# Função para colorir output
color_print() {
    local color="$1"
    local message="$2"
    printf "${COLORS[$color]}%s${COLORS[NC]}\n" "$message"
}

# Função para criar diretórios necessários
setup_directories() {
    local dirs=("$LOG_DIR" "$CONFIG_DIR" "$BACKUP_DIR")
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done
    touch "$LOG_FILE"
    log_message "INFO" "Diretórios criados: ${dirs[*]}"
}

# Função para verificar privilégios de root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        dialog --title "Erro de Permissão" --msgbox "Este script deve ser executado como root.\n\nUse: sudo $0" 8 50
        exit 1
    fi
}

# Função para verificar e instalar dialog
check_dialog() {
    if ! command -v dialog &> /dev/null; then
        apt-get update -y
        apt-get install -y dialog
    fi
}

# ==============================================
# DETECÇÃO DE HARDWARE E SISTEMA
# ==============================================

# Função para detectar hardware RK322x
detect_hardware() {
    BOARD_INFO=$(cat /proc/device-tree/model 2>/dev/null || cat /sys/firmware/devicetree/base/model 2>/dev/null)
    
    if [[ "$BOARD_INFO" =~ "rk322x" ]] || [[ "$BOARD_INFO" =~ "rk3229" ]] || grep -q -E "rk322x|rk3229" /proc/cpuinfo 2>/dev/null; then
        log_message "INFO" "Hardware RK322x/RK3229 detectado: $BOARD_INFO"
        return 0
    else
        log_message "WARN" "Hardware RK322x não detectado: $BOARD_INFO"
        return 1
    fi
}

# Função para verificar recursos do sistema
check_system_resources() {
    local ram_mb=$(free -m | awk 'NR==2{print $2}')
    local disk_gb=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    local arch=$(uname -m)
    
    local errors=""
    
    # Verificar RAM
    if [ "$ram_mb" -lt 480 ]; then
        errors+="• RAM insuficiente: ${ram_mb}MB (mínimo 512MB)\n"
    fi
    
    # Verificar espaço em disco
    if [ "$disk_gb" -lt 2 ]; then
        errors+="• Espaço em disco insuficiente: ${disk_gb}GB (mínimo 2GB)\n"
    fi
    
    # Verificar arquitetura ARM
    if [[ "$arch" != *"arm"* ]] && [[ "$arch" != *"aarch"* ]]; then
        errors+="• Arquitetura não suportada: $arch (requer ARM Cortex-A7)\n"
    fi
    
    if [ -n "$errors" ]; then
        dialog "${DIALOG_OPTS[@]}" --title "Verificação do Sistema" --msgbox "Problemas encontrados:\n\n$errors\nRecomenda-se resolver estes problemas antes de continuar." 12 60
        return 1
    fi
    
    dialog "${DIALOG_OPTS[@]}" --title "Verificação do Sistema" --msgbox "Sistema compatível:\n\n• RAM: ${ram_mb}MB ✓\n• Disco Livre: ${disk_gb}GB ✓\n• Arquitetura: $arch ✓" 10 50
    return 0
}

# ==============================================
# OTIMIZÇÕES PARA RK322x
# ==============================================

# Função para otimizar sistema para NAND
optimize_for_nand() {
    log_message "INFO" "Aplicando otimizações para armazenamento NAND"
    
    # Reduzir escrita no disco
    if mountpoint -q /; then
        mount -o remount,noatime,nodiratime /
    fi
    
    # Configurar swappiness reduzido
    if [ -f /proc/sys/vm/swappiness ]; then
        echo "10" > /proc/sys/vm/swappiness
    fi
    
    # Desabilitar logs excessivos do kernel
    if [ -f /proc/sys/kernel/printk ]; then
        echo "1 4 1 7" > /proc/sys/kernel/printk
    fi

    # Otimizar cache de dentries e inodes
    if sysctl vm.vfs_cache_pressure >/dev/null 2>&1; then
        echo 'vm.vfs_cache_pressure=50' | tee -a /etc/sysctl.conf >/dev/null
    fi
    
    # Limpar caches antigos
    sync && echo 3 > /proc/sys/vm/drop_caches
}

# Função para criar e configurar swap file
create_swap_file() {
    if [ -f /swapfile ]; then
        log_message "INFO" "Arquivo de swap já existe. Ignorando."
        return
    fi
    
    log_message "INFO" "Criando arquivo de swap de 512MB..."
    fallocate -l 512M /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
}

# Função para limitar memória dos serviços
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
}

# Função para aplicar limites de memória
apply_memory_limits() {
    if [[ "$BOARD_INFO" =~ "RK3229" ]] || [[ "$BOARD_INFO" =~ "R329Q" ]]; then
        log_message "INFO" "Aplicando limites para RK3229 R329Q (1GB DDR3)"
        limit_service_memory "pihole-FTL" "192"
        limit_service_memory "unbound" "96"
        limit_service_memory "netdata" "128"
        limit_service_memory "cockpit" "96"
        limit_service_memory "filebrowser" "64"
    else
        log_message "INFO" "Aplicando limites para RK322x genérico (512MB DDR3)"
        limit_service_memory "pihole-FTL" "96"
        limit_service_memory "unbound" "64"
        limit_service_memory "netdata" "64"
        limit_service_memory "cockpit" "64"
        limit_service_memory "filebrowser" "32"
    fi
}

# ==============================================
# REDE E CONECTIVIDADE
# ==============================================

# Função para detectar interface de rede
detect_network_interface() {
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$NETWORK_INTERFACE" ]; then
        dialog --title "Erro de Rede" --msgbox "Não foi possível detectar a interface de rede.\n\nVerifique sua conexão de rede." 8 50
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

# ==============================================
# VERIFICAÇÕES PRÉ-INSTALAÇÃO
# ==============================================

# Função principal de verificações
run_system_checks() {
    dialog --title "Verificações do Sistema" --infobox "Executando verificações iniciais..." 5 40
    sleep 1
    
    check_root
    
    if ! check_system_resources; then
        if ! dialog "${DIALOG_OPTS[@]}" --title "Continuar?" --yesno "Foram encontrados problemas no sistema.\n\nDeseja continuar mesmo assim?" 8 50; then
            exit 1
        fi
    fi
    
    if ! detect_network_interface; then
        exit 1
    fi
    
    if ! test_connectivity; then
        exit 1
    fi
    
    # Atualizar backtitle com IP detectado
    BACKTITLE="Boxserver TUI v2.0 | IP: $SERVER_IP | Hardware: ${BOARD_INFO:-RK322x}"
    DIALOG_OPTS=(--backtitle "$BACKTITLE" --colors --ok-label "Confirmar" --cancel-label "Voltar")
    
    dialog "${DIALOG_OPTS[@]}" --title "Verificações Concluídas" --msgbox "Todas as verificações foram concluídas com sucesso!\n\nInterface: $NETWORK_INTERFACE\nIP: $SERVER_IP" 8 50
    
    # Aplicar otimizações
    dialog "${DIALOG_OPTS[@]}" --title "Otimização RK322x" --infobox "Aplicando otimizações..." 5 40
    
    detect_hardware
    optimize_for_nand
    apply_memory_limits
    
    if [[ "$BOARD_INFO" =~ "RK3229" ]] || [[ "$BOARD_INFO" =~ "R329Q" ]]; then
        create_swap_file
        dialog --title "Otimização RK3229" --msgbox "Sistema otimizado para RK3229 R329Q V3.0!\n\n• NAND 8GB otimizado\n• 1GB DDR3 gerenciado" 8 50
    else
        dialog "${DIALOG_OPTS[@]}" --title "Otimização Genérica" --msgbox "Sistema otimizado para MXQ-4K TV Box RK322x!\n\n• NAND otimizado\n• Memória limitada\n• I/O otimizado" 8 50
        create_swap_file
    fi
}

# ==============================================
# GERENCIAMENTO DE SERVIÇOS
# ==============================================

# Função auxiliar para obter o nome do serviço
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
        10) echo "" ;;
        11) echo "" ;;
        12) echo "minidlna" ;;
        13) echo "cloudflared" ;;
        14) echo "chrony" ;;
        15) echo "nginx" ;;
        *) echo "" ;;
    esac
}

# Função para verificar status do aplicativo
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

# ==============================================
# INSTALAÇÃO DE APLICATIVOS
# ==============================================

# Função para ordenar instalação por dependências
sort_installation_order() {
    local selected_apps=("$@")
    local sorted_apps=()
    local priority_order=(9 11 10 14 2 1 3 4 5 6 12 8 7 13 15)
    
    log_message "INFO" "Ordenando aplicativos por dependências..."
    
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
    
    echo "${sorted_apps[@]}"
}

# Função para baixar e executar scripts externos
download_and_run_script() {
    local url="$1"
    local script_path="/tmp/external_script_$(date +%s).sh"

    log_message "INFO" "Baixando script de: $url"
    if ! curl -sSL -o "$script_path" "$url"; then
        log_message "ERROR" "Falha ao baixar o script de $url"
        return 1
    fi

    if grep -qE '\s+rm\s+-rf\s+/\s*' "$script_path"; then
        log_message "ERROR" "Script contém comando perigoso 'rm -rf /'. Abortando."
        return 1
    fi

    if ! bash "$script_path"; then
        log_message "ERROR" "Falha na execução do script de $url"
        return 1
    fi

    log_message "INFO" "Script executado com sucesso."
    return 0
}

# Funções de instalação individuais
install_pihole() {
    log_message "INFO" "Instalando Pi-hole..."
    if ! download_and_run_script "https://install.pi-hole.net"; then
        return 1
    fi
    
    # Configurações adicionais...
    systemctl enable pihole-FTL
    systemctl start pihole-FTL
    log_message "INFO" "Pi-hole instalado com sucesso"
}

install_unbound() {
    log_message "INFO" "Instalando Unbound..."
    apt install unbound -y
    
    # Configurações adicionais...
    systemctl enable unbound
    systemctl start unbound
    log_message "INFO" "Unbound instalado com sucesso"
}

install_wireguard() {
    log_message "INFO" "Instalando WireGuard..."
    apt install wireguard wireguard-tools -y
    
    # Configurações adicionais...
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    log_message "INFO" "WireGuard instalado com sucesso"
}

# Funções de instalação para outros aplicativos (simplificado para exemplo)
install_cockpit() { apt install cockpit -y; }
install_filebrowser() { download_and_run_script "https://raw.githubusercontent.com/filebrowser/get/master/get.sh"; }
install_netdata() { download_and_run_script "https://my-netdata.io/kickstart.sh"; }
install_fail2ban() { apt install fail2ban -y; }
install_ufw() { apt install ufw -y; }
install_rng_tools() { apt install rng-tools -y; }
install_rclone() { download_and_run_script "https://rclone.org/install.sh"; }
install_rsync() { apt install rsync -y; }
install_minidlna() { apt install minidlna -y; }
install_cloudflared() { download_and_run_script "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm.deb"; }
install_chrony() { apt install chrony -y; }
install_web_interface() { apt install nginx -y; }

# Função de instalação principal
install_selected_apps() {
    local apps_to_install=("$@")
    local total_steps=$(( ${#apps_to_install[@]} * 2 + 2 ))
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

    (
    # Atualizar pacotes
    current_step=$((current_step + 1)); echo $((current_step * 100 / total_steps)); echo "XXX"; echo "Atualizando lista de pacotes..."; echo "XXX"
    apt-get update -y >/dev/null 2>&1

    # Instalar cada aplicativo
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
        
        if [ $? -ne 0 ]; then
            log_message "ERROR" "Falha na instalação de $app_name"
            exit 1
        fi

        current_step=$((current_step + 1)); echo $((current_step * 100 / total_steps)); echo "XXX"; echo "Configurando: $app_name..."; echo "XXX"
        
        # Verificação
        local service_name=$(get_service_name "$app_id")
        if [ -n "$service_name" ] && ! systemctl is-active --quiet "$service_name" 2>/dev/null; then
            log_message "WARN" "Serviço para $app_name não está ativo após instalação."
        fi
    done

    ) | dialog "${DIALOG_OPTS[@]}" --title "Instalação em Andamento" --mixedgauge "Progresso da instalação..." 20 70 0

    if [ $? -ne 0 ]; then
        dialog --title "Erro na Instalação" --msgbox "A instalação falhou. Verifique os logs em $LOG_FILE para mais detalhes." 8 60
        exit 1
    fi

    dialog "${DIALOG_OPTS[@]}" --title "Instalação Concluída" --msgbox "Instalação e configuração concluídas com sucesso!" 8 50
    
    # Criar scripts de manutenção
    create_maintenance_scripts
    
    # Gerar relatório final
    generate_installation_summary "${apps_to_install[@]}"
}

# ==============================================
# MENUS E INTERFACE
# ==============================================

# Função para mostrar informações do sistema
show_system_info() {
    local ram_info=$(free -h | awk 'NR==2{printf "%s/%s (%.1f%%)", $3, $2, $3*100/$2}')
    local disk_info=$(df -h / | awk 'NR==2{printf "%s/%s (%s)", $3, $2, $5}')
    local cpu_info=$(lscpu | grep "Model name" | cut -d: -f2 | xargs)
    local uptime_info=$(uptime -p)
    
    dialog "${DIALOG_OPTS[@]}" --title "Informações do Sistema" --msgbox "Sistema: $(lsb_release -d | cut -f2)\nCPU: $cpu_info\nRAM: $ram_info\nDisco: $disk_info\nUptime: $uptime_info\n\nInterface: $NETWORK_INTERFACE\nIP: $SERVER_IP" 12 70
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
                    selected_apps=($(echo "${!APPS[@]}" | tr ' ' '\n' | sort -n))
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
    
    # Confirmar e instalar
    local confirmation="Ações a serem executadas:\n\n"
    for app_id in "${selected_apps[@]}"; do
        confirmation+="• ${APPS[$app_id]%%|*}\n"
    done
    confirmation+="\nDeseja continuar com a instalação?"
    
    if dialog "${DIALOG_OPTS[@]}" --title "Confirmar Instalação" --yesno "$confirmation" 15 60; then
        local sorted_apps=($(sort_installation_order "${selected_apps[@]}"))
        install_selected_apps "${sorted_apps[@]}"
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
            "5" "Voltar ao Menu Principal" \
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

# Função para gerenciar serviços
manage_services() {
    while true; do
        local menu_items=()
        local priority_order=(1 2 3 4 5 6 7 8 9 12 13 14 15)

        for app_id in "${priority_order[@]}"; do
            local service_name=$(get_service_name "$app_id")
            if [ -n "$service_name" ] && [[ "$(check_app_status "$app_id")" != "not_installed" ]]; then
                local app_name=$(echo "${APPS[$app_id]}" | cut -d'|' -f1)
                local status_icon="❌"

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

# ==============================================
# MANUTENÇÃO E RELATÓRIOS
# ==============================================

# Função para criar scripts de manutenção
create_maintenance_scripts() {
    log_message "INFO" "Criando scripts de manutenção..."

    # Script de limpeza semanal
    cat > /etc/cron.weekly/cleanup-boxserver << 'EOF'
#!/bin/bash
# Script de limpeza automática do Boxserver
apt-get autoremove --purge -y >/dev/null 2>&1
apt-get clean >/dev/null 2>&1
journalctl --vacuum-time=7d >/dev/null 2>&1
find /var/log -name "pihole*.log*" -mtime +30 -delete 2>/dev/null
df -h > /var/log/boxserver/disk-usage.log
echo "Entropia: $(cat /proc/sys/kernel/random/entropy_avail)" >> /var/log/boxserver/system-health.log
echo "Limpeza concluída em $(date)" >> /var/log/boxserver/cleanup.log
EOF

    chmod +x /etc/cron.weekly/cleanup-boxserver

    # Script de saúde do sistema
    cat > /usr/local/bin/boxserver-health << 'EOF'
#!/bin/bash
# Script de monitoramento de saúde do Boxserver
echo "==========================================="
echo "    RELATÓRIO DE SAÚDE DO BOXSERVER"
echo "==========================================="
echo "Data: $(date)"
echo
echo "=== SISTEMA ==="
echo "Uptime: $(uptime -p)"
echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
echo "Memória: $(free -h | awk 'NR==2{printf "%.1f%% (%s/%s)", $3*100/$2, $3, $2}')"
echo "Disco: $(df -h / | awk 'NR==2{printf "%s usado de %s (%s)", $3, $2, $5}')"
if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
    echo "Temperatura CPU: $(($(cat /sys/class/thermal/thermal_zone0/temp)/1000))°C"
fi
echo
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
echo "==========================================="
EOF

    chmod +x /usr/local/bin/boxserver-health
    log_message "INFO" "Scripts de manutenção criados com sucesso"
}

# Função para gerar relatório final
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

# ==============================================
# MENU PRINCIPAL
# ==============================================

# Menu principal
main_menu() {
    while true; do        
        local choice=$(dialog "${DIALOG_OPTS[@]}" --title "Boxserver TUI v2.0 - Refatorado" \
            --menu "Bem-vindo ao painel de controle do seu Boxserver.\n\nO que você gostaria de fazer?" \
            $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Instalar / Desinstalar Aplicativos" \
            "2" "Gerenciamento de Serviços" \
            "3" "Configurações Avançadas" \
            "4" "Informações do Sistema" \
            "5" "Sobre o Boxserver TUI" \
            "6" "Sair" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) select_applications ;;
            2) manage_services ;;
            3) configure_advanced_settings ;;
            4) show_system_info ;;
            5)
                dialog --title "Sobre" --msgbox "Boxserver TUI Installer v2.0 (Refatorado)\n\nInstalador automatizado para MXQ-4K\n\nMelhorias:\n• Código modular e reutilizável\n• Otimizações específicas para RK322x\n• Tratamento de erros centralizado\n• Melhor performance e eficiência" 14 70
                ;;
            6|"")
                if dialog --title "Confirmar Saída" --yesno "Deseja realmente sair?" 6 30; then
                    clear
                    echo "Obrigado por usar o Boxserver TUI Installer!"
                    exit 0
                fi
                ;;
        esac
    done
}

# ==============================================
# INÍCIO DO SCRIPT
# ==============================================

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
    
    # Configurar diretórios
    setup_directories
    
    # Log de início
    log_message "INFO" "Boxserver TUI Installer v2.0 iniciado"
    
    # Executar verificações do sistema
    run_system_checks
    
    # Mostrar tela de boas-vindas
    dialog "${DIALOG_OPTS[@]}" --title "Bem-vindo" --msgbox "Boxserver TUI Installer v2.0 (Refatorado)\n\nInstalador automatizado para MXQ-4K\n\nEste assistente irá guiá-lo através da\ninstalação e configuração do seu\nservidor doméstico.\n\nPressione ENTER para continuar..." 12 50
    
    # Iniciar menu principal
    main_menu
}

# Tratamento de sinais
trap 'clear; echo "Instalação interrompida."; exit 1' INT TERM

# Executar função principal
main "$@"
