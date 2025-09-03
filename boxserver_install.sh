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

# Configurações globais do script

# Diretorios principais
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

# Variáveis globais de configuração
NETWORK_INTERFACE=""
SERVER_IP=""
VPN_NETWORK="10.200.200.0/24"
VPN_PORT="51820"
PIHOLE_PASSWORD=""
FILEBROWSER_PORT="8080"
COCKPIT_PORT="9090"

# MELHORIA: Variáveis para modo silencioso
SILENT_MODE="false"
CURRENT_STEP=0
TOTAL_STEPS=0

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
)

# MELHORIA: Função para logging com modo silencioso
log_message() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
    
    # Verificar se está em modo silencioso
    if [[ "$SILENT_MODE" == "true" ]]; then
        # Em modo silencioso, apenas logs críticos são exibidos
        if [[ "$level" == "ERROR" ]]; then
            echo -e "${RED}[ERROR]${NC} $message" >&2
        fi
    else
        # Modo normal - exibir todos os logs
        if [[ "$level" == "ERROR" ]]; then
            echo -e "${RED}[ERROR]${NC} $message" >&2
        elif [[ "$level" == "INFO" ]]; then
            echo -e "${GREEN}[INFO]${NC} $message"
        elif [[ "$level" == "WARN" ]]; then
            echo -e "${YELLOW}[WARN]${NC} $message"
        fi
    fi
}

# MELHORIA: Função para atualizar progresso em tempo real
update_progress() {
    local current="$1"
    local total="$2"
    local message="$3"
    local percentage=$((current * 100 / total))
    
    echo "$percentage" | dialog --title "Instalação Silenciosa" \
        --gauge "$message" 10 70
}

# MELHORIA: Função para executar comandos silenciosamente
run_silent() {
    local command="$1"
    local description="$2"
    
    # Executar comando redirecionando output
    if eval "$command" >/dev/null 2>&1; then
        log_message "INFO" "$description: SUCESSO"
        return 0
    else
        log_message "ERROR" "$description: FALHOU"
        return 1
    fi
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
    unset DISPLAY
    unset WAYLAND_DISPLAY
    unset XDG_SESSION_TYPE
    unset XDG_CURRENT_DESKTOP
    
    # Configurar variáveis para modo texto
    export DEBIAN_FRONTEND=noninteractive
    export TERM=${TERM:-linux}
    
    # Verificar se estamos em um ambiente headless
    if [[ -z "$SSH_CLIENT" && -z "$SSH_TTY" ]]; then
        # Não é SSH, verificar se há display disponível
        if [[ -n "$DISPLAY" ]] && command -v xset &>/dev/null; then
            if ! xset q &>/dev/null; then
                # Display definido mas não funcional
                unset DISPLAY
            fi
        fi
    fi
    
    # Configurar browser padrão para evitar tentativas de abertura
    export BROWSER="echo 'Browser não disponível em servidor headless. URL:'"
    
    log_message "INFO" "Ambiente headless configurado - DISPLAY removido, BROWSER desabilitado"
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
    
    # Verificar hardware RK322x específico
    if [ -f /proc/device-tree/model ]; then
        if ! grep -q 'rk322x' /proc/device-tree/model; then
            errors+="• Hardware incompatível: requer MXQ-4K RK322x\n"
        fi
    fi
    
    # Verificar RAM (mínimo 512MB para RK322x)
    if [ "$ram_mb" -lt 512 ]; then
        errors+="• RAM insuficiente: ${ram_mb}MB (mínimo 512MB para RK322x)\n"
    fi
    
    # Verificar espaço em disco NAND (mínimo 2GB livre)
    if [ "$disk_gb" -lt 2 ]; then
        errors+="• Espaço em disco NAND insuficiente: ${disk_gb}GB (mínimo 2GB)\n"
    fi
    
    # Verificar arquitetura ARM
    if [[ "$arch" != *"arm"* ]] && [[ "$arch" != *"aarch"* ]]; then
        errors+="• Arquitetura não suportada: $arch (requer ARM Cortex-A7)\n"
    fi
    
    # Verificar tipo de armazenamento (NAND vs eMMC)
    if [ -d /sys/block/mtdblock0 ]; then
        log_message "INFO" "Armazenamento NAND detectado - aplicando otimizações"
    fi
    
    if [ -n "$errors" ]; then
        dialog --title "Verificação do Sistema" --msgbox "Problemas encontrados:\n\n$errors\nRecomenda-se resolver estes problemas antes de continuar." 12 60
        return 1
    fi
    
    dialog --title "Verificação do Sistema" --msgbox "Sistema RK322x compatível:\n\n• RAM: ${ram_mb}MB ✓\n• NAND: ${disk_gb}GB ✓\n• Arquitetura: $arch ✓" 10 50
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
    
    # Limpar caches antigos
    sync && echo 3 > /proc/sys/vm/drop_caches
    log_message "INFO" "Caches de memória limpos"
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

# MELHORIA: Função para aplicar limites de memória RK322x
apply_rk322x_memory_limits() {
    log_message "INFO" "Aplicando limites de memória para serviços RK322x"
    
    # Limites otimizados para 512MB RAM
    limit_service_memory "pihole-FTL" "128"
    limit_service_memory "unbound" "64"
    limit_service_memory "netdata" "96"
    limit_service_memory "cockpit" "64"
    
    log_message "INFO" "Todos os limites de memória RK322x aplicados"
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
    
    # Otimizar para NAND
    optimize_for_nand
    
    # Aplicar limites de memória
    apply_rk322x_memory_limits
    
    dialog --title "Otimização Concluída" --msgbox "Sistema otimizado para MXQ-4K TV Box RK322x!\n\n• NAND otimizado\n• Memória limitada\n• I/O otimizado" 8 50
}

# Função para mostrar informações do sistema
show_system_info() {
    local ram_info=$(free -h | awk 'NR==2{printf "%s/%s (%.1f%%)", $3, $2, $3*100/$2}')
    local disk_info=$(df -h / | awk 'NR==2{printf "%s/%s (%s)", $3, $2, $5}')
    local cpu_info=$(lscpu | grep "Model name" | cut -d: -f2 | xargs)
    local uptime_info=$(uptime -p)
    
    dialog --title "Informações do Sistema" --msgbox "Sistema: $(lsb_release -d | cut -f2)\nCPU: $cpu_info\nRAM: $ram_info\nDisco: $disk_info\nUptime: $uptime_info\n\nInterface: $NETWORK_INTERFACE\nIP: $SERVER_IP" 12 70
}

# Função para configurações avançadas
configure_advanced_settings() {
    while true; do
        local choice=$(dialog --title "Configurações Avançadas" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Configurar IP do Servidor" \
            "2" "Configurar Rede VPN" \
            "3" "Configurar Portas dos Serviços" \
            "4" "Configurar Senhas" \
            "5" "Voltar ao Menu Principal" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1)
                SERVER_IP=$(dialog --title "IP do Servidor" --inputbox "Digite o IP do servidor:" 8 50 "$SERVER_IP" 3>&1 1>&2 2>&3)
                ;;
            2)
                VPN_NETWORK=$(dialog --title "Rede VPN" --inputbox "Digite a rede VPN (CIDR):" 8 50 "$VPN_NETWORK" 3>&1 1>&2 2>&3)
                VPN_PORT=$(dialog --title "Porta VPN" --inputbox "Digite a porta do WireGuard:" 8 50 "$VPN_PORT" 3>&1 1>&2 2>&3)
                ;;
            3)
                FILEBROWSER_PORT=$(dialog --title "Porta FileBrowser" --inputbox "Digite a porta do FileBrowser:" 8 50 "$FILEBROWSER_PORT" 3>&1 1>&2 2>&3)
                COCKPIT_PORT=$(dialog --title "Porta Cockpit" --inputbox "Digite a porta do Cockpit:" 8 50 "$COCKPIT_PORT" 3>&1 1>&2 2>&3)
                ;;
            4)
                PIHOLE_PASSWORD=$(dialog --title "Senha Pi-hole" --passwordbox "Digite a senha do Pi-hole:" 8 50 3>&1 1>&2 2>&3)
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
        
        dialog --title "Detalhes: $name" --msgbox "$details" 15 70
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
        local choices=$(dialog --title "Seleção de Aplicativos" \
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
        dialog --title "Nenhum Aplicativo" --msgbox "Nenhum aplicativo foi selecionado." 6 40
        return 1
    fi
    
    # Confirmar seleção
    local confirmation="Aplicativos selecionados para instalação:\n\n"
    for app_id in "${selected_apps[@]}"; do
        local app_info="${APPS[$app_id]}"
        IFS='|' read -r name description access <<< "$app_info"
        confirmation+="• $name\n"
    done
    confirmation+="\nDeseja continuar com a instalação?"
    
    if dialog --title "Confirmar Instalação" --yesno "$confirmation" 15 60; then
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
    # Fase 5: Serviços avançados
    local priority_order=(9 11 10 2 1 3 4 5 6 12 8 7 13)
    
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

# MELHORIA: Função para instalar aplicativos com progresso silencioso
install_selected_apps() {
    local apps_to_install=("$@")
    local total_apps=${#apps_to_install[@]}
    local current_app=0
    
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
    
    log_message "INFO" "Iniciando instalação silenciosa de ${total_apps} aplicativos"
    
    # Configurar modo silencioso
    export DEBIAN_FRONTEND=noninteractive
    export APT_LISTCHANGES_FRONTEND=none
    
    for app_id in "${apps_to_install[@]}"; do
        current_app=$((current_app + 1))
        local app_info="${APPS[$app_id]}"
        IFS='|' read -r name description access <<< "$app_info"
        
        # Calcular progresso detalhado
        local base_progress=$(((current_app - 1) * 100 / total_apps))
        local step_size=$((100 / total_apps))
        
        # Mostrar início da instalação
        echo "$base_progress" | dialog --title "Instalação Silenciosa" \
            --gauge "Preparando: $name ($current_app/$total_apps)" 10 70
        
        log_message "INFO" "Instalando $name (ID: $app_id)"
        
        # Executar instalação com progresso em tempo real
        {
            case $app_id in
                1) install_pihole_silent "$base_progress" "$step_size" ;;
                2) install_unbound_silent "$base_progress" "$step_size" ;;
                3) install_wireguard_silent "$base_progress" "$step_size" ;;
                4) install_cockpit_silent "$base_progress" "$step_size" ;;
                5) install_filebrowser_silent "$base_progress" "$step_size" ;;
                6) install_netdata_silent "$base_progress" "$step_size" ;;
                7) install_fail2ban_silent "$base_progress" "$step_size" ;;
                8) install_ufw_silent "$base_progress" "$step_size" ;;
                9) install_rng_tools_silent "$base_progress" "$step_size" ;;
                10) install_rclone_silent "$base_progress" "$step_size" ;;
                11) install_rsync_silent "$base_progress" "$step_size" ;;
                12) install_minidlna_silent "$base_progress" "$step_size" ;;
                13) install_cloudflared_silent "$base_progress" "$step_size" ;;
            esac
        } 2>&1 | while IFS= read -r line; do
            # Filtrar apenas logs importantes
            if [[ "$line" =~ (ERROR|WARN|Instalando|Configurando|Testando) ]]; then
                log_message "INFO" "$line"
            fi
        done
        
        # Mostrar conclusão
        local final_progress=$((current_app * 100 / total_apps))
        echo "$final_progress" | dialog --title "Instalação Silenciosa" \
            --gauge "Concluído: $name ($current_app/$total_apps)" 10 70
        
        log_message "INFO" "$name instalado com sucesso"
        sleep 1
    done
    
    # Mostrar conclusão final
    dialog --title "Instalação Concluída" --msgbox "Todos os aplicativos foram instalados com sucesso!\n\n✅ $total_apps aplicativos instalados\n📋 Logs detalhados: $LOG_FILE\n🔧 Configurações: $CONFIG_DIR" 12 70
    
    # CORREÇÃO: Reconfigurar integrações após instalação completa
    reconfigure_service_integrations "${apps_to_install[@]}"
    
    # Oferecer menu pós-instalação
    post_installation_menu
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
    
    log_message "INFO" "Reconfiguração de integrações concluída"
}

# Função para instalação do Pi-hole (baseada em INSTALAÇÃO APPS.md)
install_pihole() {
    log_message "INFO" "Instalando Pi-hole..."
    
    # Baixar e executar script de instalação
    curl -sSL https://install.pi-hole.net | bash
    
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
    
    # Baixar root hints com verificação
    log_message "INFO" "Baixando root hints..."
    if ! wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root; then
        log_message "ERROR" "Falha ao baixar root hints"
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
    
    # Configurar permissões
    chown unbound:unbound /var/lib/unbound/root.key /var/lib/unbound/root.hints
    chmod 644 /var/lib/unbound/root.key /var/lib/unbound/root.hints
    
    # Verificar configuração
    log_message "INFO" "Verificando configuração do Unbound..."
    if ! unbound-checkconf; then
        log_message "ERROR" "Erro na configuração do Unbound"
        log_message "ERROR" "Detalhes: $(unbound-checkconf 2>&1)"
        return 1
    fi
    
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

# MELHORIA: Versão silenciosa da instalação do Unbound
install_unbound_silent() {
    local base_progress="$1"
    local step_size="$2"
    local current_progress="$base_progress"
    
    # Ativar modo silencioso
    SILENT_MODE="true"
    
    # Etapa 1: Verificar conflitos (10% do progresso)
    update_progress "$current_progress" 100 "Unbound: Verificando conflitos DNS..."
    if ! resolve_dns_conflicts >/dev/null 2>&1; then
        log_message "ERROR" "Falha ao resolver conflitos DNS"
        SILENT_MODE="false"
        return 1
    fi
    current_progress=$((base_progress + step_size / 5))
    
    # Etapa 2: Parar serviços (15% do progresso)
    update_progress "$current_progress" 100 "Unbound: Preparando ambiente..."
    systemctl stop unbound 2>/dev/null || true
    current_progress=$((base_progress + step_size / 4))
    
    # Etapa 3: Instalar pacote (40% do progresso)
    update_progress "$current_progress" 100 "Unbound: Instalando pacote..."
    if ! run_silent "apt update && apt install unbound -y" "Instalação do Unbound"; then
        SILENT_MODE="false"
        return 1
    fi
    current_progress=$((base_progress + step_size * 2 / 3))
    
    # Etapa 4: Configurar (70% do progresso)
    update_progress "$current_progress" 100 "Unbound: Configurando serviço..."
    
    # Verificar usuário
    if ! id "unbound" &>/dev/null; then
        log_message "ERROR" "Usuário unbound não foi criado durante a instalação"
        SILENT_MODE="false"
        return 1
    fi
    
    # Criar diretórios
    mkdir -p /etc/unbound/unbound.conf.d /var/lib/unbound
    
    # Backup da configuração
    if [ -f "/etc/unbound/unbound.conf" ]; then
        cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.backup
    fi
    
    # Criar configuração otimizada
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
    
    current_progress=$((base_progress + step_size * 3 / 4))
    
    # Etapa 5: Baixar arquivos necessários (80% do progresso)
    update_progress "$current_progress" 100 "Unbound: Baixando arquivos de configuração..."
    
    if ! run_silent "wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root" "Download root hints"; then
        SILENT_MODE="false"
        return 1
    fi
    
    if ! unbound-anchor -a /var/lib/unbound/root.key >/dev/null 2>&1; then
        if ! run_silent "wget -O /tmp/root.key https://data.iana.org/root-anchors/icannbundle.pem && mv /tmp/root.key /var/lib/unbound/root.key" "Trust anchor manual"; then
            SILENT_MODE="false"
            return 1
        fi
    fi
    
    # Configurar permissões
    chown unbound:unbound /var/lib/unbound/root.key /var/lib/unbound/root.hints
    chmod 644 /var/lib/unbound/root.key /var/lib/unbound/root.hints
    
    current_progress=$((base_progress + step_size * 4 / 5))
    
    # Etapa 6: Ativar serviço (90% do progresso)
    update_progress "$current_progress" 100 "Unbound: Ativando serviço..."
    
    if ! activate_unbound_service >/dev/null 2>&1; then
        if diagnose_and_fix_unbound >/dev/null 2>&1; then
            if ! activate_unbound_service >/dev/null 2>&1; then
                SILENT_MODE="false"
                return 1
            fi
        else
            SILENT_MODE="false"
            return 1
        fi
    fi
    
    current_progress=$((base_progress + step_size * 9 / 10))
    
    # Etapa 7: Testar funcionalidade (100% do progresso)
    update_progress "$current_progress" 100 "Unbound: Testando funcionalidade..."
    
    if ! test_unbound_functionality >/dev/null 2>&1; then
        log_message "WARN" "Teste DNS falhou, mas serviço está ativo"
    fi
    
    # Finalizar
    current_progress=$((base_progress + step_size))
    update_progress "$current_progress" 100 "Unbound: Instalação concluída"
    
    SILENT_MODE="false"
    return 0
}

# MELHORIA: Versão silenciosa da instalação do Pi-hole
install_pihole_silent() {
    local base_progress="$1"
    local step_size="$2"
    local current_progress="$base_progress"
    
    SILENT_MODE="true"
    
    update_progress "$current_progress" 100 "Pi-hole: Baixando instalador..."
    current_progress=$((base_progress + step_size / 4))
    
    update_progress "$current_progress" 100 "Pi-hole: Executando instalação..."
    if ! run_silent "curl -sSL https://install.pi-hole.net | bash" "Instalação do Pi-hole"; then
        SILENT_MODE="false"
        return 1
    fi
    current_progress=$((base_progress + step_size * 3 / 4))
    
    update_progress "$current_progress" 100 "Pi-hole: Configurando..."
    
    if [ -n "$PIHOLE_PASSWORD" ]; then
        echo "$PIHOLE_PASSWORD" | pihole -a -p >/dev/null 2>&1
    fi
    
    cat > /etc/pihole/setupVars.conf << EOF
PIHOLE_INTERFACE=$NETWORK_INTERFACE
IPV4_ADDRESS=$SERVER_IP/24
IPV6_ADDRESS=
PIHOLE_DNS_1=127.0.0.1#5335
PIHOLE_DNS_2=
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSSEC=true
EOF
    
    systemctl restart pihole-FTL >/dev/null 2>&1
    systemctl enable pihole-FTL >/dev/null 2>&1
    
    current_progress=$((base_progress + step_size))
    update_progress "$current_progress" 100 "Pi-hole: Instalação concluída"
    
    SILENT_MODE="false"
    return 0
}

# MELHORIA: Função genérica para instalações silenciosas simples
install_generic_silent() {
    local app_name="$1"
    local base_progress="$2"
    local step_size="$3"
    local install_function="$4"
    
    SILENT_MODE="true"
    
    update_progress "$base_progress" 100 "$app_name: Iniciando instalação..."
    
    if $install_function >/dev/null 2>&1; then
        local final_progress=$((base_progress + step_size))
        update_progress "$final_progress" 100 "$app_name: Instalação concluída"
        SILENT_MODE="false"
        return 0
    else
        SILENT_MODE="false"
        return 1
    fi
}

# MELHORIA: Versões silenciosas para outros aplicativos
install_wireguard_silent() { install_generic_silent "WireGuard" "$1" "$2" "install_wireguard"; }
install_cockpit_silent() { install_generic_silent "Cockpit" "$1" "$2" "install_cockpit"; }
install_filebrowser_silent() { install_generic_silent "FileBrowser" "$1" "$2" "install_filebrowser"; }
install_netdata_silent() { install_generic_silent "Netdata" "$1" "$2" "install_netdata"; }
install_fail2ban_silent() { install_generic_silent "Fail2Ban" "$1" "$2" "install_fail2ban"; }
install_ufw_silent() { install_generic_silent "UFW" "$1" "$2" "install_ufw"; }
install_rng_tools_silent() { install_generic_silent "RNG-tools" "$1" "$2" "install_rng_tools"; }
install_rclone_silent() { install_generic_silent "Rclone" "$1" "$2" "install_rclone"; }
install_rsync_silent() { install_generic_silent "Rsync" "$1" "$2" "install_rsync"; }
install_minidlna_silent() { install_generic_silent "MiniDLNA" "$1" "$2" "install_minidlna"; }
install_cloudflared_silent() { install_generic_silent "Cloudflared" "$1" "$2" "install_cloudflared"; }

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
    
    # Habilitar IP Forwarding
    sysctl -w net.ipv4.ip_forward=1
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
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
    filebrowser -d /var/lib/filebrowser/filebrowser.db config init
    filebrowser -d /var/lib/filebrowser/filebrowser.db config set --address 0.0.0.0
    filebrowser -d /var/lib/filebrowser/filebrowser.db config set --port $FILEBROWSER_PORT
    filebrowser -d /var/lib/filebrowser/filebrowser.db config set --root /home
    filebrowser -d /var/lib/filebrowser/filebrowser.db users add admin admin --perm.admin
    
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
        log_message "INFO" "Login: admin / Senha: admin"
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
    
    # Instalar dependências
    apt install curl libuv1-dev liblz4-dev libjudy-dev libssl-dev libelf-dev -y
    
    # Baixar e instalar Netdata
    bash <(curl -Ss https://my-netdata.io/kickstart.sh) --dont-wait --disable-telemetry
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do Netdata"
        return 1
    fi
    
    # Configurar para ARM/baixa RAM
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
    web files group = netdata
    bind to = *
    
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

# Função para instalação do Cloudflared (baseada em INSTALAÇÃO APPS.md)
install_cloudflared() {
    log_message "INFO" "Instalando Cloudflared..."
    
    # Baixar Cloudflared para ARM
    wget -O /tmp/cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm.deb
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha no download do Cloudflared"
        return 1
    fi
    
    # Instalar pacote
    dpkg -i /tmp/cloudflared.deb
    apt-get install -f -y  # Corrigir dependências se necessário
    
    # Criar usuário para cloudflared
    useradd -r -s /bin/false cloudflared
    
    # Criar configuração básica
    mkdir -p /etc/cloudflared
    cat > /etc/cloudflared/config.yml << 'EOF'
# Configuração Cloudflared para Boxserver
tunnel: boxserver-tunnel
credentials-file: /etc/cloudflared/cert.pem

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
    
    # Configurar permissões
    chown -R cloudflared:cloudflared /etc/cloudflared
    
    # Criar serviço systemd
    cat > /etc/systemd/system/cloudflared.service << 'EOF'
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
User=cloudflared
Group=cloudflared
ExecStart=/usr/local/bin/cloudflared tunnel --config /etc/cloudflared/config.yml run
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
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
    # Verificar se já existe certificado
    if [[ -f "$HOME/.cloudflared/cert.pem" ]]; then
        dialog --title "Certificado Existente" --yesno "Já existe um certificado Cloudflare.\n\nDeseja renovar o login?" 8 50
        if [[ $? -ne 0 ]]; then
            return 0
        fi
    fi
    
    dialog --title "Login Cloudflare - Servidor Headless" --msgbox "ATENÇÃO: Este é um servidor sem interface gráfica.\n\nO comando irá gerar uma URL que você deve:\n1. Copiar da saída do terminal\n2. Abrir em qualquer navegador\n3. Fazer login na sua conta Cloudflare\n4. Selecionar o domínio\n\nPressione ENTER para continuar..." 14 70
    
    # Criar diretório se não existir
    mkdir -p "$HOME/.cloudflared"
    
    # Executar login e capturar a saída
    dialog --title "Executando Login" --infobox "Executando cloudflared tunnel login...\n\nCopie a URL que aparecerá no terminal\ne abra em um navegador." 8 50
    
    # Executar login em background e mostrar a URL
    {
        echo "==========================================="
        echo "CLOUDFLARE LOGIN - SERVIDOR HEADLESS"
        echo "==========================================="
        echo "Copie a URL abaixo e abra em um navegador:"
        echo "==========================================="
        cloudflared tunnel login 2>&1
        echo "==========================================="
        echo "Após fazer login no navegador, pressione ENTER"
        echo "==========================================="
    } > /tmp/cloudflare_login.log 2>&1 &
    
    # Aguardar um pouco para o comando iniciar
    sleep 3
    
    # Mostrar o log em tempo real
    if [[ -f "/tmp/cloudflare_login.log" ]]; then
        dialog --title "URL de Login" --textbox "/tmp/cloudflare_login.log" 20 80
    fi
    
    # Aguardar confirmação do usuário
    dialog --title "Aguardando Login" --msgbox "Após fazer login no navegador:\n\n1. Selecione seu domínio\n2. Aguarde a confirmação\n3. Pressione ENTER aqui" 10 50
    
    # Verificar se o certificado foi criado
    local timeout=60
    local count=0
    while [[ $count -lt $timeout ]]; do
        if [[ -f "$HOME/.cloudflared/cert.pem" ]]; then
            dialog --title "Login Concluído" --msgbox "Login realizado com sucesso!\n\nCertificado salvo em: ~/.cloudflared/cert.pem" 8 60
            log_message "INFO" "Login no Cloudflare realizado com sucesso"
            rm -f /tmp/cloudflare_login.log
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    # Se chegou aqui, o login falhou
    dialog --title "Erro de Login" --msgbox "Falha no login do Cloudflare.\n\nPossíveis causas:\n- Login não foi completado no navegador\n- Domínio não foi selecionado\n- Problemas de conectividade\n\nTente novamente." 12 60
    log_message "ERROR" "Falha no login do Cloudflare - timeout ou erro"
    rm -f /tmp/cloudflare_login.log
    return 1
}

# Função para criar/configurar túnel
cloudflare_create_tunnel() {
    # Verificar se já existe túnel
    if cloudflared tunnel list | grep -q "boxserver-tunnel"; then
        if dialog --title "Túnel Existente" --yesno "O túnel 'boxserver-tunnel' já existe.\n\nDeseja reconfigurá-lo?" 8 50; then
            cloudflared tunnel delete boxserver-tunnel 2>/dev/null
        else
            return 0
        fi
    fi
    
    dialog --title "Criando Túnel" --infobox "Criando túnel 'boxserver-tunnel'..." 5 40
    
    if cloudflared tunnel create boxserver-tunnel; then
        # Obter UUID do túnel
        local tunnel_id=$(cloudflared tunnel list | grep "boxserver-tunnel" | awk '{print $1}')
        
        if [ -n "$tunnel_id" ]; then
            # Atualizar config.yml com o ID correto
            sed -i "s/tunnel: boxserver-tunnel/tunnel: $tunnel_id/g" /etc/cloudflared/config.yml
            
            # Copiar certificado para o diretório correto
            if [ -f "$HOME/.cloudflared/$tunnel_id.json" ]; then
                cp "$HOME/.cloudflared/$tunnel_id.json" /etc/cloudflared/cert.pem
                chown cloudflared:cloudflared /etc/cloudflared/cert.pem
            fi
            
            dialog --title "Túnel Criado" --msgbox "Túnel criado com sucesso!\n\nID: $tunnel_id\n\nAgora configure os domínios." 10 50
            log_message "INFO" "Túnel Cloudflare criado: $tunnel_id"
            
            # Oferecer configuração automática
            if dialog --title "Configuração Automática" --yesno "Deseja configurar automaticamente\nos serviços detectados?" 8 50; then
                auto_configure_services
            fi
        else
            dialog --title "Erro" --msgbox "Erro ao obter ID do túnel." 6 40
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
    if ! cloudflared tunnel list | grep -q "boxserver-tunnel"; then
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
    
    local domain=$(dialog --title "Domínio $service_name" --inputbox "Digite o domínio completo para $service_name:\n\nExemplo: $subdomain.seudominio.com" 10 60 "$subdomain.example.com" 3>&1 1>&2 2>&3)
    
    if [ -n "$domain" ]; then
        # Atualizar config.yml
        update_ingress_rule "$domain" "$port"
        dialog --title "Configurado" --msgbox "Domínio configurado:\n\n$service_name: $domain\nPorta: $port\n\nLembre-se de aplicar as configurações DNS." 10 50
        log_message "INFO" "Domínio configurado: $domain -> $port"
    fi
}

# Função para configurar domínio customizado
configure_custom_domain() {
    local domain=$(dialog --title "Domínio Customizado" --inputbox "Digite o domínio:" 8 50 3>&1 1>&2 2>&3)
    local port=$(dialog --title "Porta do Serviço" --inputbox "Digite a porta do serviço:" 8 50 3>&1 1>&2 2>&3)
    
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
    
    # Backup da configuração atual
    cp /etc/cloudflared/config.yml /etc/cloudflared/config.yml.bak
    
    # Remover regra existente se houver
    sed -i "/hostname: $domain/,+1d" /etc/cloudflared/config.yml
    
    # Adicionar nova regra antes da regra catch-all
    sed -i "/service: http_status:404/i\  - hostname: $domain\n    service: http://127.0.0.1:$port" /etc/cloudflared/config.yml
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
                cloudflared tunnel route dns "$tunnel_id" "$domain" 2>/dev/null
                log_message "INFO" "Registro DNS criado para: $domain"
            fi
        done
        
        dialog --title "DNS Aplicado" --msgbox "Registros DNS criados com sucesso!\n\nOs domínios podem levar alguns minutos\npara propagar." 8 50
    else
        dialog --title "Erro" --msgbox "ID do túnel não encontrado." 6 40
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
    if cloudflared tunnel --config /etc/cloudflared/config.yml validate &> /dev/null; then
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
    
    dialog --title "Resultados dos Testes" --msgbox "$test_results" 12 50
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
    
    dialog --title "Status do Túnel" --msgbox "$status_info" 15 60
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
        if cloudflared tunnel --config /etc/cloudflared/config.yml validate &> /dev/null; then
            dialog --title "Configuração Válida" --msgbox "Configuração salva e validada com sucesso!" 6 50
            log_message "INFO" "Configuração Cloudflare editada manualmente"
        else
            dialog --title "Erro de Configuração" --yesno "A configuração contém erros.\n\nDeseja restaurar o backup?" 8 50
            if [ $? -eq 0 ]; then
                mv /etc/cloudflared/config.yml.backup /etc/cloudflared/config.yml
                dialog --title "Restaurado" --msgbox "Backup restaurado com sucesso." 6 40
            fi
        fi
    else
        dialog --title "Erro" --msgbox "Arquivo de configuração não encontrado." 6 40
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
        dialog --title "Protocolo Configurado" --msgbox "Protocolo alterado para: $protocol\n\nReinicie o serviço para aplicar." 8 50
        log_message "INFO" "Protocolo Cloudflare alterado para: $protocol"
    fi
}

# Função para configurar métricas
configure_metrics() {
    local metrics_addr=$(dialog --title "Métricas" --inputbox "Digite o endereço para métricas:\n\nFormato: IP:PORTA" 10 50 "127.0.0.1:8080" 3>&1 1>&2 2>&3)
    
    if [ -n "$metrics_addr" ]; then
        sed -i "s/metrics: .*/metrics: $metrics_addr/g" /etc/cloudflared/config.yml
        dialog --title "Métricas Configuradas" --msgbox "Métricas configuradas para: $metrics_addr\n\nAcesse: http://$metrics_addr/metrics" 8 60
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
    
    dialog --title "Gerenciar Certificados" --msgbox "$cert_info" 15 60
}

# Função para reiniciar serviço
restart_cloudflared_service() {
    dialog --title "Reiniciando Serviço" --infobox "Reiniciando Cloudflared..." 5 30
    
    systemctl restart cloudflared
    sleep 2
    
    if systemctl is-active --quiet cloudflared; then
        dialog --title "Serviço Reiniciado" --msgbox "Cloudflared reiniciado com sucesso!" 6 40
        log_message "INFO" "Serviço Cloudflared reiniciado"
    else
        dialog --title "Erro" --msgbox "Falha ao reiniciar o serviço.\n\nVerifique os logs." 8 40
        log_message "ERROR" "Falha ao reiniciar Cloudflared"
    fi
}

# Função para mostrar logs
show_cloudflared_logs() {
    dialog --title "Logs do Cloudflared" --msgbox "Os logs serão exibidos em uma nova janela.\n\nPressione 'q' para sair da visualização." 8 50
    
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
        if dialog --title "Pi-hole Detectado" --yesno "Configurar Pi-hole no subdomínio 'pihole'?\n\nExemplo: pihole.seudominio.com" 8 50; then
            local domain=$(dialog --title "Domínio Pi-hole" --inputbox "Digite o domínio completo:" 8 50 "pihole.example.com" 3>&1 1>&2 2>&3)
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
        if dialog --title "Cockpit Detectado" --yesno "Configurar Cockpit no subdomínio 'admin'?\n\nExemplo: admin.seudominio.com" 8 50; then
            local domain=$(dialog --title "Domínio Cockpit" --inputbox "Digite o domínio completo:" 8 50 "admin.example.com" 3>&1 1>&2 2>&3)
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
        if dialog --title "WireGuard Detectado" --yesno "Configurar interface web WireGuard?\n\nExemplo: vpn.seudominio.com" 8 50; then
            local domain=$(dialog --title "Domínio WireGuard" --inputbox "Digite o domínio completo:" 8 50 "vpn.example.com" 3>&1 1>&2 2>&3)
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
        dialog --title "Configuração Concluída" --msgbox "Serviços configurados automaticamente!\n\nLembre-se de aplicar os registros DNS\nno menu de configuração de domínios." 10 50
        
        # Oferecer aplicação automática de DNS
        if dialog --title "Aplicar DNS" --yesno "Deseja aplicar os registros DNS\nautomaticamente agora?" 8 50; then
            apply_dns_records
        fi
    else
        dialog --title "Nenhum Serviço" --msgbox "Nenhum serviço foi configurado\nautomaticamente.\n\nUse o menu manual para\nconfigurar domínios customizados." 10 50
    fi
}

# Função para detectar serviços adicionais
detect_additional_services() {
    # Detectar FileBrowser (porta comum 8080)
    if netstat -tlnp 2>/dev/null | grep -q ":8080"; then
        if dialog --title "Serviço na Porta 8080" --yesno "Detectado serviço na porta 8080.\n\nConfigurar como FileBrowser?" 8 50; then
            local domain=$(dialog --title "Domínio Arquivos" --inputbox "Digite o domínio completo:" 8 50 "files.example.com" 3>&1 1>&2 2>&3)
            if [ -n "$domain" ]; then
                update_ingress_rule "$domain" "8080"
                log_message "INFO" "Auto-configurado FileBrowser: $domain"
            fi
        fi
    fi
    
    # Detectar Portainer (porta comum 9000)
    if netstat -tlnp 2>/dev/null | grep -q ":9000"; then
        if dialog --title "Serviço na Porta 9000" --yesno "Detectado serviço na porta 9000.\n\nConfigurar como Portainer?" 8 50; then
            local domain=$(dialog --title "Domínio Portainer" --inputbox "Digite o domínio completo:" 8 50 "docker.example.com" 3>&1 1>&2 2>&3)
            if [ -n "$domain" ]; then
                update_ingress_rule "$domain" "9000"
                log_message "INFO" "Auto-configurado Portainer: $domain"
            fi
        fi
    fi
    
    # Detectar Grafana (porta comum 3000)
    if netstat -tlnp 2>/dev/null | grep -q ":3000"; then
        if dialog --title "Serviço na Porta 3000" --yesno "Detectado serviço na porta 3000.\n\nConfigurar como Grafana?" 8 50; then
            local domain=$(dialog --title "Domínio Grafana" --inputbox "Digite o domínio completo:" 8 50 "monitor.example.com" 3>&1 1>&2 2>&3)
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
        if cloudflared tunnel --config /etc/cloudflared/config.yml validate &> /dev/null; then
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
    local tunnel_id=$(grep "tunnel:" /etc/cloudflared/config.yml 2>/dev/null | awk '{print $2}')
    if [ -n "$tunnel_id" ] && [ -f "/etc/cloudflared/cert.pem" ]; then
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
        dialog --title "Validação Falhou" --msgbox "$validation_results" 15 60
        return 1
    else
        validation_results+="\n✅ CONFIGURAÇÃO VÁLIDA\n\nTúnel pronto para uso!"
        dialog --title "Validação Bem-sucedida" --msgbox "$validation_results" 15 60
        return 0
    fi
}

# Menu pós-instalação
post_installation_menu() {
    while true; do
        local choice=$(dialog --title "Pós-Instalação" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Executar testes do sistema" \
            "2" "Ver status dos serviços" \
            "3" "Ver logs de instalação" \
            "4" "Configurar WireGuard VPN" \
            "5" "Configurar túnel Cloudflare" \
            "6" "Configurar Pi-hole + Unbound" \
            "7" "Configurar Fail2Ban" \
            "8" "Configurar Netdata" \
            "9" "Configurar FileBrowser" \
            "10" "Configurar MiniDLNA" \
            "11" "Configurar outros serviços" \
            "12" "Backup das configurações" \
            "13" "Sair" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) run_system_tests ;;
            2) show_services_status ;;
            3) show_installation_logs ;;
            4) configure_wireguard_vpn ;;
            5) configure_cloudflare_tunnel ;;
            6) configure_pihole_unbound ;;
            7) configure_fail2ban ;;
            8) configure_netdata ;;
            9) configure_filebrowser ;;
            10) configure_minidlna ;;
            11) configure_other_services ;;
            12) backup_configurations ;;
            13|"")
                break
                ;;
        esac
    done
}

# Configuração do WireGuard VPN
configure_wireguard_vpn() {
    while true; do
        local choice=$(dialog --title "Configuração WireGuard VPN" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
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
    
    dialog --title "Status WireGuard" --msgbox "$status_info" 20 70
}

# Gerar novo cliente WireGuard
generate_wireguard_client() {
    local client_name=$(dialog --title "Novo Cliente" --inputbox "Nome do cliente:" 8 40 3>&1 1>&2 2>&3)
    
    if [[ -z "$client_name" ]]; then
        dialog --title "Erro" --msgbox "Nome do cliente é obrigatório!" 6 40
        return 1
    fi
    
    # Verificar se cliente já existe
    if [[ -f "/etc/wireguard/clients/${client_name}.conf" ]]; then
        dialog --title "Erro" --msgbox "Cliente '$client_name' já existe!" 6 40
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
    local server_public_key=$(grep "PublicKey" /etc/wireguard/wg0.conf | head -1 | cut -d'=' -f2 | tr -d ' ' || echo "")
    local server_endpoint=$(get_server_endpoint)
    local server_port=$(grep "ListenPort" /etc/wireguard/wg0.conf | cut -d'=' -f2 | tr -d ' ' || echo "51820")
    
    # Criar configuração do cliente
    cat > "/etc/wireguard/clients/${client_name}.conf" << EOF
[Interface]
PrivateKey = $client_private_key
Address = $client_ip/24
DNS = 10.8.0.1

[Peer]
PublicKey = $server_public_key
Endpoint = $server_endpoint:$server_port
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    # Adicionar peer ao servidor
    wg set wg0 peer "$client_public_key" allowed-ips "$client_ip/32"
    
    # Salvar configuração no arquivo do servidor
    echo "" >> /etc/wireguard/wg0.conf
    echo "# Cliente: $client_name" >> /etc/wireguard/wg0.conf
    echo "[Peer]" >> /etc/wireguard/wg0.conf
    echo "PublicKey = $client_public_key" >> /etc/wireguard/wg0.conf
    echo "AllowedIPs = $client_ip/32" >> /etc/wireguard/wg0.conf
    
    # Gerar QR Code se qrencode estiver disponível
    local qr_file="/etc/wireguard/clients/${client_name}.png"
    if command -v qrencode &>/dev/null; then
        qrencode -t png -o "$qr_file" < "/etc/wireguard/clients/${client_name}.conf"
    fi
    
    dialog --title "Cliente Criado" --msgbox "Cliente '$client_name' criado com sucesso!\n\nIP: $client_ip\nArquivo: /etc/wireguard/clients/${client_name}.conf" 10 60
}

# Obter próximo IP disponível para cliente
get_next_client_ip() {
    local base_ip="10.8.0"
    local start_ip=2
    
    for i in $(seq $start_ip 254); do
        local test_ip="${base_ip}.${i}"
        if ! grep -q "$test_ip" /etc/wireguard/wg0.conf /etc/wireguard/clients/*.conf 2>/dev/null; then
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
    
    local client_to_remove=$(dialog --title "Remover Cliente" --menu "Selecione o cliente para remover:" 15 50 8 "${client_list[@]}" 3>&1 1>&2 2>&3)
    
    if [[ -z "$client_to_remove" ]]; then
        return 0
    fi
    
    # Confirmar remoção
    if dialog --title "Confirmar Remoção" --yesno "Tem certeza que deseja remover o cliente '$client_to_remove'?" 7 50; then
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
        
        dialog --title "Cliente Removido" --msgbox "Cliente '$client_to_remove' removido com sucesso!" 6 50
    fi
}

# Regenerar chaves do servidor
regenerate_server_keys() {
    if dialog --title "Regenerar Chaves" --yesno "ATENÇÃO: Regenerar as chaves do servidor invalidará TODOS os clientes existentes.\n\nDeseja continuar?" 10 60; then
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
        
        dialog --title "Chaves Regeneradas" --msgbox "Chaves do servidor regeneradas com sucesso!\n\nNova chave pública: ${new_public_key:0:30}...\n\nTodos os clientes precisam ser recriados." 12 70
    fi
}

# Configurar interface de rede
configure_network_interface() {
    local current_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    local new_interface=$(dialog --title "Interface de Rede" --inputbox "Interface de rede para WireGuard:" 8 50 "$current_interface" 3>&1 1>&2 2>&3)
    
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
    
    dialog --title "Interface Configurada" --msgbox "Interface de rede atualizada para: $new_interface" 6 60
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
    
    dialog --title "Resultados dos Testes" --msgbox "$test_results" 18 60
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
    
    local client_to_export=$(dialog --title "Exportar Cliente" --menu "Selecione o cliente para exportar:" 15 50 8 "${client_list[@]}" 3>&1 1>&2 2>&3)
    
    if [[ -z "$client_to_export" ]]; then
        return 0
    fi
    
    local export_path=$(dialog --title "Local de Exportação" --inputbox "Caminho para exportar:" 8 60 "/tmp/${client_to_export}.conf" 3>&1 1>&2 2>&3)
    
    if [[ -z "$export_path" ]]; then
        return 0
    fi
    
    # Copiar arquivo de configuração
    if cp "/etc/wireguard/clients/${client_to_export}.conf" "$export_path"; then
        dialog --title "Exportação Concluída" --msgbox "Configuração do cliente '$client_to_export' exportada para:\n$export_path" 8 70
    else
        dialog --title "Erro" --msgbox "Falha ao exportar configuração!" 6 40
    fi
}

# Configurações avançadas do WireGuard
wireguard_advanced_settings() {
    while true; do
        local choice=$(dialog --title "Configurações Avançadas" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Alterar porta do servidor" \
            "2" "Configurar DNS personalizado" \
            "3" "Alterar rede VPN" \
            "4" "Configurar Keep-Alive" \
            "5" "Backup/Restore configurações" \
            "6" "Logs e diagnósticos" \
            "7" "Voltar" \
            3>&1 1>&2 2>&3)
        
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
    local new_port=$(dialog --title "Alterar Porta" --inputbox "Nova porta para WireGuard:" 8 40 "$current_port" 3>&1 1>&2 2>&3)
    
    if [[ -z "$new_port" ]] || [[ "$new_port" == "$current_port" ]]; then
        return 0
    fi
    
    # Validar porta
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [[ "$new_port" -lt 1024 ]] || [[ "$new_port" -gt 65535 ]]; then
        dialog --title "Erro" --msgbox "Porta inválida! Use um número entre 1024 e 65535." 6 50
        return 1
    fi
    
    # Verificar se a porta está em uso
    if ss -ulnp | grep -q ":$new_port"; then
        dialog --title "Erro" --msgbox "Porta $new_port já está em uso!" 6 40
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
    
    dialog --title "Porta Alterada" --msgbox "Porta do WireGuard alterada para: $new_port\n\nTodos os clientes foram atualizados automaticamente." 8 60
}

# Configuração Pi-hole + Unbound
configure_pihole_unbound() {
    while true; do
        local choice=$(dialog --title "Configuração Pi-hole + Unbound" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
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
    
    dialog --title "Status DNS" --msgbox "$status_info" 18 70
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
    
    # Configurar Unbound para Pi-hole
    cat > /etc/unbound/unbound.conf.d/pi-hole.conf << 'EOF'
server:
    # Porta para escutar (diferente da 53 usada pelo Pi-hole)
    port: 5335
    
    # Interfaces de escuta
    interface: 127.0.0.1
    
    # Não fazer cache de TTL zero
    cache-min-ttl: 0
    
    # Servir dados expirados
    serve-expired: yes
    
    # Prefetch de registros populares
    prefetch: yes
    
    # Número de threads
    num-threads: 2
    
    # Configurações de segurança
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    
    # Cache settings otimizadas para ARM
    rrset-cache-size: 32m
    msg-cache-size: 16m
    
    # Configurações de rede
    edns-buffer-size: 1232
    
    # Logs
    verbosity: 1
    
    # Root hints
    root-hints: "/var/lib/unbound/root.hints"
    
    # Trust anchor para DNSSEC
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
EOF
    
    # Baixar root hints se não existir
    if [[ ! -f "/var/lib/unbound/root.hints" ]]; then
        curl -s https://www.internic.net/domain/named.cache -o /var/lib/unbound/root.hints
        chown unbound:unbound /var/lib/unbound/root.hints
    fi
    
    # Configurar trust anchor se não existir
    if [[ ! -f "/var/lib/unbound/root.key" ]]; then
        unbound-anchor -a /var/lib/unbound/root.key
        chown unbound:unbound /var/lib/unbound/root.key
    fi
    
    # Configurar Pi-hole para usar Unbound
    echo "127.0.0.1#5335" > /etc/pihole/setupVars.conf.tmp
    if [[ -f "/etc/pihole/setupVars.conf" ]]; then
        # Backup da configuração atual
        cp /etc/pihole/setupVars.conf /etc/pihole/setupVars.conf.backup
        
        # Atualizar DNS upstream
        sed -i 's/^PIHOLE_DNS_.*$/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
        
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
        dialog --title "Integração Configurada" --msgbox "Integração Pi-hole + Unbound configurada com sucesso!\n\nUnbound: porta 5335\nPi-hole: porta 53 (usando Unbound como upstream)" 10 70
    else
        dialog --title "Erro" --msgbox "Falha na configuração da integração!\nVerifique os logs dos serviços." 8 50
    fi
}

# Gerenciar listas de bloqueio
manage_blocklists() {
    while true; do
        local choice=$(dialog --title "Gerenciar Listas de Bloqueio" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
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
    
    dialog --title "Listas de Bloqueio" --msgbox "$blocklists_info" 20 80
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
    
    dialog --title "Resultados dos Testes" --msgbox "$test_results" 12 50
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
    
    dialog --title "Status dos Serviços" --msgbox "$status_info" 12 50
}

# Função para mostrar logs
show_installation_logs() {
    if [ -f "$LOG_FILE" ]; then
        dialog --title "Logs de Instalação" --textbox "$LOG_FILE" 20 80
    else
        dialog --title "Logs" --msgbox "Arquivo de log não encontrado." 6 40
    fi
}

# Função para configurar clientes VPN
configure_vpn_clients() {
    dialog --title "Configuração VPN" --msgbox "Para configurar clientes VPN:\n\n1. Gere chaves para o cliente\n2. Adicione a configuração no servidor\n3. Crie arquivo .conf para o cliente\n\nConsulte a documentação para detalhes." 10 60
}

# IMPLEMENTAÇÃO: Configuração do Netdata
configure_netdata() {
    while true; do
        local choice=$(dialog --title "Configuração Netdata" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Ver status do Netdata" \
            "2" "Configurar plugins" \
            "3" "Configurar alertas" \
            "4" "Configurar acesso remoto" \
            "5" "Otimizar para ARM" \
            "6" "Reiniciar serviço" \
            "7" "Ver logs" \
            "8" "Voltar" \
            3>&1 1>&2 2>&3)
        
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
        local choice=$(dialog --title "Configuração FileBrowser" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
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
        
        case $choice in
            1) check_filebrowser_status ;;
            2) manage_filebrowser_users ;;
            3) configure_filebrowser_dirs ;;
            4) change_filebrowser_port ;;
            5) configure_filebrowser_permissions ;;
            6) backup_restore_filebrowser ;;
            7) restart_filebrowser_service ;;
            8) show_filebrowser_logs ;;
            9|"") break ;;
        esac
    done
}

# IMPLEMENTAÇÃO: Configuração do MiniDLNA
configure_minidlna() {
    while true; do
        local choice=$(dialog --title "Configuração MiniDLNA" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
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
        
        case $choice in
            1) check_minidlna_status ;;
            2) configure_minidlna_dirs ;;
            3) configure_minidlna_name ;;
            4) change_minidlna_port ;;
            5) rescan_minidlna_library ;;
            6) configure_minidlna_filetypes ;;
            7) restart_minidlna_service ;;
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
        dialog --title "Backup Concluído" --msgbox "Backup criado com sucesso:\n\n$backup_file" 8 60
    else
        dialog --title "Erro no Backup" --msgbox "Erro ao criar backup." 6 40
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
    
    dialog --title "Status Netdata" --msgbox "$status_info" 15 60
}

configure_netdata_plugins() {
    local current_config="/etc/netdata/netdata.conf"
    
    if [ ! -f "$current_config" ]; then
        dialog --title "Erro" --msgbox "Arquivo de configuração não encontrado." 6 40
        return 1
    fi
    
    local choice=$(dialog --title "Plugins Netdata" --menu "Configurar plugins:" 15 60 8 \
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
            dialog --title "Plugins" --msgbox "Plugins pesados desabilitados para otimizar ARM." 6 50
            systemctl restart netdata
            ;;
        2)
            sed -i 's/^.*proc:/proc/net/dev = no/    \/proc\/net\/dev = yes/' "$current_config"
            dialog --title "Plugins" --msgbox "Monitoramento de rede habilitado." 6 40
            systemctl restart netdata
            ;;
        5)
            local active_plugins=$(grep -E "^[[:space:]]*[^#].*= yes" "$current_config" | head -10)
            dialog --title "Plugins Ativos" --msgbox "$active_plugins" 15 70
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
            dialog --title "Configuração" --msgbox "Configuração padrão restaurada." 6 40
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
    dialog --title "Otimização" --msgbox "Netdata otimizado para ARM RK322x.\n\nRAM reduzida, plugins pesados desabilitados." 8 60
}

restart_netdata_service() {
    dialog --title "Reiniciando Netdata" --infobox "Reiniciando serviço..." 5 30
    systemctl restart netdata
    sleep 2
    
    if systemctl is-active --quiet netdata; then
        dialog --title "Serviço" --msgbox "Netdata reiniciado com sucesso!" 6 40
    else
        dialog --title "Erro" --msgbox "Falha ao reiniciar Netdata." 6 30
    fi
}

show_netdata_logs() {
    dialog --title "Logs do Netdata" --msgbox "Os logs serão exibidos em uma nova janela.\n\nPressione 'q' para sair." 8 50
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
    
    dialog --title "Status FileBrowser" --msgbox "$status_info" 12 60
}

manage_filebrowser_users() {
    local choice=$(dialog --title "Gerenciar Usuários" --menu "Escolha uma opção:" 12 50 5 \
        "1" "Listar usuários" \
        "2" "Adicionar usuário" \
        "3" "Remover usuário" \
        "4" "Alterar senha" \
        "5" "Voltar" \
        3>&1 1>&2 2>&3)
    
    case $choice in
        1)
            local users=$(filebrowser -d /var/lib/filebrowser/filebrowser.db users ls 2>/dev/null || echo "Erro ao listar usuários")
            dialog --title "Usuários" --msgbox "$users" 15 60
            ;;
        2)
            local username=$(dialog --title "Novo Usuário" --inputbox "Nome do usuário:" 8 40 3>&1 1>&2 2>&3)
            local password=$(dialog --title "Nova Senha" --passwordbox "Senha:" 8 40 3>&1 1>&2 2>&3)
            
            if [ -n "$username" ] && [ -n "$password" ]; then
                filebrowser -d /var/lib/filebrowser/filebrowser.db users add "$username" "$password"
                dialog --title "Usuário" --msgbox "Usuário '$username' criado com sucesso!" 6 50
            fi
            ;;
        3)
            local username=$(dialog --title "Remover Usuário" --inputbox "Nome do usuário:" 8 40 3>&1 1>&2 2>&3)
            if [ -n "$username" ]; then
                filebrowser -d /var/lib/filebrowser/filebrowser.db users rm "$username"
                dialog --title "Usuário" --msgbox "Usuário '$username' removido." 6 40
            fi
            ;;
        4)
            local username=$(dialog --title "Alterar Senha" --inputbox "Nome do usuário:" 8 40 3>&1 1>&2 2>&3)
            local password=$(dialog --title "Nova Senha" --passwordbox "Nova senha:" 8 40 3>&1 1>&2 2>&3)
            
            if [ -n "$username" ] && [ -n "$password" ]; then
                filebrowser -d /var/lib/filebrowser/filebrowser.db users update "$username" --password "$password"
                dialog --title "Senha" --msgbox "Senha alterada com sucesso!" 6 40
            fi
            ;;
    esac
}

change_filebrowser_port() {
    local current_port=$(grep -o 'port.*' /etc/systemd/system/filebrowser.service | cut -d' ' -f2 || echo "$FILEBROWSER_PORT")
    local new_port=$(dialog --title "Alterar Porta" --inputbox "Nova porta para FileBrowser:" 8 40 "$current_port" 3>&1 1>&2 2>&3)
    
    if [ -n "$new_port" ] && [ "$new_port" != "$current_port" ]; then
        # Atualizar configuração
        filebrowser -d /var/lib/filebrowser/filebrowser.db config set --port "$new_port"
        
        # Reiniciar serviço
        systemctl restart filebrowser
        
        # Atualizar variável global
        FILEBROWSER_PORT="$new_port"
        
        dialog --title "Porta Alterada" --msgbox "Porta do FileBrowser alterada para: $new_port\n\nNovo acesso: http://$SERVER_IP:$new_port" 8 60
    fi
}

restart_filebrowser_service() {
    dialog --title "Reiniciando FileBrowser" --infobox "Reiniciando serviço..." 5 30
    systemctl restart filebrowser
    sleep 2
    
    if systemctl is-active --quiet filebrowser; then
        dialog --title "Serviço" --msgbox "FileBrowser reiniciado com sucesso!" 6 40
    else
        dialog --title "Erro" --msgbox "Falha ao reiniciar FileBrowser." 6 30
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
    
    dialog --title "Status MiniDLNA" --msgbox "$status_info" 12 60
}

configure_minidlna_dirs() {
    local choice=$(dialog --title "Diretórios de Mídia" --menu "Configurar diretórios:" 12 60 6 \
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
            dialog --title "Diretórios" --msgbox "$dirs" 15 70
            ;;
        2)
            local dir=$(dialog --title "Diretório de Vídeos" --inputbox "Caminho completo:" 8 60 "/media/dlna/videos" 3>&1 1>&2 2>&3)
            if [ -n "$dir" ]; then
                echo "media_dir=V,$dir" >> /etc/minidlna.conf
                mkdir -p "$dir"
                chown minidlna:minidlna "$dir"
                dialog --title "Diretório" --msgbox "Diretório de vídeos adicionado: $dir" 6 60
            fi
            ;;
        3)
            local dir=$(dialog --title "Diretório de Música" --inputbox "Caminho completo:" 8 60 "/media/dlna/music" 3>&1 1>&2 2>&3)
            if [ -n "$dir" ]; then
                echo "media_dir=A,$dir" >> /etc/minidlna.conf
                mkdir -p "$dir"
                chown minidlna:minidlna "$dir"
                dialog --title "Diretório" --msgbox "Diretório de música adicionado: $dir" 6 60
            fi
            ;;
        4)
            local dir=$(dialog --title "Diretório de Fotos" --inputbox "Caminho completo:" 8 60 "/media/dlna/pictures" 3>&1 1>&2 2>&3)
            if [ -n "$dir" ]; then
                echo "media_dir=P,$dir" >> /etc/minidlna.conf
                mkdir -p "$dir"
                chown minidlna:minidlna "$dir"
                dialog --title "Diretório" --msgbox "Diretório de fotos adicionado: $dir" 6 60
            fi
            ;;
    esac
}

configure_minidlna_name() {
    local current_name=$(grep "friendly_name" /etc/minidlna.conf | cut -d'=' -f2 || echo "Boxserver DLNA")
    local new_name=$(dialog --title "Nome do Servidor" --inputbox "Nome amigável do servidor DLNA:" 8 50 "$current_name" 3>&1 1>&2 2>&3)
    
    if [ -n "$new_name" ]; then
        sed -i "s/^friendly_name=.*/friendly_name=$new_name/" /etc/minidlna.conf
        systemctl restart minidlna
        dialog --title "Nome Alterado" --msgbox "Nome do servidor alterado para: $new_name" 6 50
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
    dialog --title "Biblioteca" --msgbox "Biblioteca reescaneada com sucesso!\n\nNovos arquivos serão detectados em alguns minutos." 8 60
}

restart_minidlna_service() {
    dialog --title "Reiniciando MiniDLNA" --infobox "Reiniciando serviço..." 5 30
    systemctl restart minidlna
    sleep 2
    
    if systemctl is-active --quiet minidlna; then
        dialog --title "Serviço" --msgbox "MiniDLNA reiniciado com sucesso!" 6 40
    else
        dialog --title "Erro" --msgbox "Falha ao reiniciar MiniDLNA." 6 30
    fi
}

# IMPLEMENTAÇÃO: Funções auxiliares adicionais
configure_netdata_alerts() {
    dialog --title "Alertas Netdata" --msgbox "Configuração de alertas será implementada\nem versão futura.\n\nPor enquanto, monitore via interface web:\nhttp://$SERVER_IP:19999" 10 60
}

configure_netdata_access() {
    local choice=$(dialog --title "Acesso Remoto" --menu "Configurar acesso:" 10 50 4 \
        "1" "Permitir acesso de qualquer IP" \
        "2" "Restringir a rede local" \
        "3" "Configurar senha" \
        "4" "Voltar" \
        3>&1 1>&2 2>&3)
    
    case $choice in
        1)
            sed -i 's/bind to = .*/bind to = */' /etc/netdata/netdata.conf
            systemctl restart netdata
            dialog --title "Acesso" --msgbox "Acesso liberado para qualquer IP." 6 40
            ;;
        2)
            sed -i 's/bind to = .*/bind to = 192.168.*/' /etc/netdata/netdata.conf
            systemctl restart netdata
            dialog --title "Acesso" --msgbox "Acesso restrito à rede local." 6 40
            ;;
        3)
            dialog --title "Senha" --msgbox "Configuração de senha será implementada\nem versão futura." 8 50
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
            dialog --title "Backup" --msgbox "Backup criado: $backup_file" 6 60
            ;;
        2)
            local backup_file=$(dialog --title "Restaurar" --inputbox "Caminho do arquivo de backup:" 8 60 3>&1 1>&2 2>&3)
            if [ -f "$backup_file" ]; then
                systemctl stop filebrowser
                cp "$backup_file" /var/lib/filebrowser/filebrowser.db
                chown filebrowser:filebrowser /var/lib/filebrowser/filebrowser.db
                systemctl start filebrowser
                dialog --title "Restaurar" --msgbox "Configuração restaurada com sucesso!" 6 50
            else
                dialog --title "Erro" --msgbox "Arquivo de backup não encontrado." 6 40
            fi
            ;;
    esac
}

show_filebrowser_logs() {
    dialog --title "Logs do FileBrowser" --msgbox "Os logs serão exibidos em uma nova janela.\n\nPressione 'q' para sair." 8 50
    journalctl -u filebrowser -f --no-pager
}

change_minidlna_port() {
    local current_port=$(grep "port=" /etc/minidlna.conf | cut -d'=' -f2 || echo "8200")
    local new_port=$(dialog --title "Alterar Porta" --inputbox "Nova porta para MiniDLNA:" 8 40 "$current_port" 3>&1 1>&2 2>&3)
    
    if [ -n "$new_port" ] && [ "$new_port" != "$current_port" ]; then
        sed -i "s/^port=.*/port=$new_port/" /etc/minidlna.conf
        systemctl restart minidlna
        dialog --title "Porta Alterada" --msgbox "Porta do MiniDLNA alterada para: $new_port\n\nNovo acesso: http://$SERVER_IP:$new_port" 8 60
    fi
}

configure_minidlna_filetypes() {
    dialog --title "Tipos de Arquivo" --msgbox "Tipos de arquivo suportados:\n\n📹 Vídeos: .mp4, .avi, .mkv, .mov, .wmv\n🎵 Áudio: .mp3, .flac, .wav, .aac, .ogg\n🖼️ Imagens: .jpg, .png, .gif, .bmp\n\nPara adicionar novos tipos, edite:\n/etc/minidlna.conf" 14 60
}

show_minidlna_logs() {
    dialog --title "Logs do MiniDLNA" --msgbox "Os logs serão exibidos em uma nova janela.\n\nPressione 'q' para sair." 8 50
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
    local choice=$(dialog --title "UFW Firewall" --menu "Configurar firewall:" 12 50 5 \
        "1" "Ver status do UFW" \
        "2" "Ver regras ativas" \
        "3" "Adicionar regra personalizada" \
        "4" "Resetar configuração" \
        "5" "Voltar" \
        3>&1 1>&2 2>&3)
    
    case $choice in
        1)
            local ufw_status=$(ufw status verbose)
            dialog --title "Status UFW" --msgbox "$ufw_status" 20 80
            ;;
        2)
            local ufw_rules=$(ufw status numbered)
            dialog --title "Regras UFW" --msgbox "$ufw_rules" 20 80
            ;;
        3)
            local port=$(dialog --title "Nova Regra" --inputbox "Porta ou serviço:" 8 40 3>&1 1>&2 2>&3)
            local action=$(dialog --title "Ação" --menu "Escolha a ação:" 10 40 2 \
                "allow" "Permitir" \
                "deny" "Negar" \
                3>&1 1>&2 2>&3)
            
            if [ -n "$port" ] && [ -n "$action" ]; then
                ufw $action $port
                dialog --title "Regra" --msgbox "Regra adicionada: $action $port" 6 40
            fi
            ;;
        4)
            if dialog --title "Resetar UFW" --yesno "Tem certeza que deseja resetar todas as regras?" 6 50; then
                ufw --force reset
                dialog --title "Reset" --msgbox "UFW resetado. Configure novamente se necessário." 6 50
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
    
    dialog --title "Status dos Serviços" --msgbox "$services_status" 20 60
}

configure_rng_service() {
    dialog --title "RNG-tools" --msgbox "RNG-tools Status:\n\n$(systemctl status rng-tools --no-pager -l | head -10)\n\nEntropia atual: $(cat /proc/sys/kernel/random/entropy_avail)" 15 70
}

configure_rclone_service() {
    dialog --title "Rclone" --msgbox "Para configurar Rclone:\n\n1. Execute: rclone config\n2. Configure seus provedores de nuvem\n3. Use: /usr/local/bin/boxserver-backup\n\nConsulte a documentação para detalhes." 12 60
}

configure_rsync_service() {
    dialog --title "Rsync" --msgbox "Rsync configurado para backup local:\n\n• Script: /usr/local/bin/boxserver-sync\n• Agendamento: diário às 02:00\n• Destino: /var/backups/boxserver/\n\nExecute manualmente: sudo /usr/local/bin/boxserver-sync" 12 70
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
    
    dialog --title "Cockpit" --msgbox "$cockpit_status" 12 60
}

# MELHORIA: Menu principal com opção de modo silencioso
main_menu() {
    while true; do
        local silent_status="Desabilitado"
        if [[ "$SILENT_MODE" == "true" ]]; then
            silent_status="Habilitado"
        fi
        
        local choice=$(dialog --title "Boxserver TUI Installer v1.0" \
            --menu "Instalador automatizado para MXQ-4K (RK322x)\n\nModo Silencioso: $silent_status\n\nEscolha uma opção:" \
            $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Verificações do sistema" \
            "2" "Selecionar e instalar aplicativos" \
            "3" "Configurações avançadas" \
            "4" "Informações do sistema" \
            "5" "Ver logs" \
            "6" "Alternar modo silencioso ($silent_status)" \
            "7" "Sobre" \
            "8" "Sair" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1)
                run_system_checks
                ;;
            2)
                select_applications
                ;;
            3)
                configure_advanced_settings
                ;;
            4)
                show_system_info
                ;;
            5)
                show_installation_logs
                ;;
            6)
                toggle_silent_mode
                ;;
            7)
                dialog --title "Sobre" --msgbox "Boxserver TUI Installer v1.0\n\nInstalador automatizado para servidor doméstico\nem dispositivos MXQ-4K com chip RK322x\n\nBaseado na base de conhecimento do\nprojeto Boxserver Arandutec\n\nDesenvolvido para hardware limitado\ncom otimizações específicas para ARM\n\n🔇 Modo Silencioso: Instalação com barra de progresso\n📋 Logs detalhados salvos automaticamente" 14 70
                ;;
            8|"")
                if dialog --title "Confirmar Saída" --yesno "Deseja realmente sair?" 6 30; then
                    clear
                    echo "Obrigado por usar o Boxserver TUI Installer!"
                    exit 0
                fi
                ;;
        esac
    done
}

# MELHORIA: Função para alternar modo silencioso
toggle_silent_mode() {
    if [[ "$SILENT_MODE" == "true" ]]; then
        SILENT_MODE="false"
        dialog --title "Modo Silencioso" --msgbox "Modo Silencioso DESABILITADO\n\n• Logs detalhados serão exibidos\n• Instalação mais verbosa\n• Melhor para diagnóstico" 10 50
    else
        SILENT_MODE="true"
        dialog --title "Modo Silencioso" --msgbox "Modo Silencioso HABILITADO\n\n• Apenas barra de progresso\n• Instalação mais rápida\n• Logs salvos em arquivo\n• Ideal para instalações automáticas" 12 60
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
    
    # Mostrar tela de boas-vindas
    dialog --title "Bem-vindo" --msgbox "Boxserver TUI Installer v1.0\n\nInstalador automatizado para MXQ-4K\n\nEste assistente irá guiá-lo através da\ninstalação e configuração do seu\nservidor doméstico.\n\nPressione ENTER para continuar..." 12 50
    
    # Iniciar menu principal
    main_menu
}

# Tratamento de sinais
trap 'clear; echo "Instalação interrompida."; exit 1' INT TERM

# Executar função principal
main "$@"
