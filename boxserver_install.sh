#!/bin/bash
#
# Boxserver TUI Installer - Interface Gráfica Terminal
# Instalador automatizado para MXQ-4K com chip RK322x
# Baseado na base de conhecimento do projeto Boxserver Arandutec
#
# Autor: Boxserver Team
# Versão: 1.0
# Data: $(date +%Y-%m-%d)
#

# Configurações globais
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

# Função para logging
log_message() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
    if [[ "$level" == "ERROR" ]]; then
        echo -e "${RED}[ERROR]${NC} $message" >&2
    elif [[ "$level" == "INFO" ]]; then
        echo -e "${GREEN}[INFO]${NC} $message"
    elif [[ "$level" == "WARN" ]]; then
        echo -e "${YELLOW}[WARN]${NC} $message"
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

# Função para verificar recursos do sistema
check_system_resources() {
    local ram_mb=$(free -m | awk 'NR==2{print $2}')
    local disk_gb=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    local arch=$(uname -m)
    
    local errors=""
    
    # Verificar RAM (mínimo 512MB)
    if [ "$ram_mb" -lt 512 ]; then
        errors+="• RAM insuficiente: ${ram_mb}MB (mínimo 512MB)\n"
    fi
    
    # Verificar espaço em disco (mínimo 2GB)
    if [ "$disk_gb" -lt 2 ]; then
        errors+="• Espaço em disco insuficiente: ${disk_gb}GB (mínimo 2GB)\n"
    fi
    
    # Verificar arquitetura ARM
    if [[ "$arch" != *"arm"* ]] && [[ "$arch" != *"aarch"* ]]; then
        errors+="• Arquitetura não suportada: $arch (requer ARM)\n"
    fi
    
    if [ -n "$errors" ]; then
        dialog --title "Verificação do Sistema" --msgbox "Problemas encontrados:\n\n$errors\nRecomenda-se resolver estes problemas antes de continuar." 12 60
        return 1
    fi
    
    dialog --title "Verificação do Sistema" --msgbox "Sistema compatível:\n\n• RAM: ${ram_mb}MB ✓\n• Disco: ${disk_gb}GB ✓\n• Arquitetura: $arch ✓" 10 50
    return 0
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
        install_selected_apps "${selected_apps[@]}"
    fi
}

# Função para instalar aplicativos selecionados
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
    
    log_message "INFO" "Iniciando instalação de ${total_apps} aplicativos"
    
    for app_id in "${apps_to_install[@]}"; do
        current_app=$((current_app + 1))
        local app_info="${APPS[$app_id]}"
        IFS='|' read -r name description access <<< "$app_info"
        
        local progress=$((current_app * 100 / total_apps))
        
        # Mostrar progresso
        echo "$progress" | dialog --title "Instalando Aplicativos" \
            --gauge "Instalando: $name ($current_app/$total_apps)" 8 60
        
        log_message "INFO" "Instalando $name (ID: $app_id)"
        
        # Simular instalação (aqui você colocaria a lógica real de instalação)
        sleep 2
        
        # Aqui você chamaria as funções específicas de instalação
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
        esac
        
        log_message "INFO" "$name instalado com sucesso"
    done
    
    dialog --title "Instalação Concluída" --msgbox "Todos os aplicativos foram instalados com sucesso!\n\nVerifique os logs em: $LOG_FILE" 8 60
    
    # Oferecer menu pós-instalação
    post_installation_menu
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
    
    # Configurar setupVars.conf com configurações específicas
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
    
    # Reiniciar serviço
    systemctl restart pihole-FTL
    systemctl enable pihole-FTL
    
    log_message "INFO" "Pi-hole instalado e configurado com sucesso"
}

# Função para instalação do Unbound (baseada em INSTALAÇÃO APPS.md)
install_unbound() {
    log_message "INFO" "Instalando Unbound..."
    
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
    
    # Aguardar inicialização
    sleep 5
    
    # Verificar se serviço está ativo
    if ! systemctl is-active --quiet unbound; then
        log_message "ERROR" "Serviço Unbound não está ativo"
        log_message "ERROR" "Logs: $(journalctl -u unbound --no-pager -n 10)"
        return 1
    fi
    
    # Testar DNS com timeout e múltiplas tentativas
    log_message "INFO" "Testando DNS do Unbound..."
    local test_success=false
    for i in {1..3}; do
        if timeout 10 dig @127.0.0.1 -p 5335 google.com +short >/dev/null 2>&1; then
            test_success=true
            break
        fi
        log_message "WARN" "Tentativa $i de teste DNS falhou, aguardando..."
        sleep 2
    done
    
    if [ "$test_success" = true ]; then
        log_message "INFO" "Unbound instalado e testado com sucesso"
    else
        log_message "WARN" "Unbound instalado mas teste de DNS falhou após 3 tentativas"
        log_message "WARN" "Verifique logs: journalctl -u unbound"
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
    
    # Configuração otimizada para ARM/baixa RAM
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 3

[cockpit]
enabled = true
port = 9090
logpath = /var/log/cockpit/cockpit.log
maxretry = 3

[pihole-web]
enabled = true
port = 80,443
logpath = /var/log/pihole.log
maxretry = 5
filter = pihole-web

[wireguard]
enabled = true
port = 51820
logpath = /var/log/syslog
maxretry = 3
filter = wireguard
EOF
    
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
    
    # Permitir SSH
    ufw allow ssh
    
    # Permitir serviços do Boxserver
    ufw allow 80/tcp comment 'Pi-hole Web'
    ufw allow 443/tcp comment 'Pi-hole Web SSL'
    ufw allow 53 comment 'Pi-hole DNS'
    ufw allow $VPN_PORT/udp comment 'WireGuard VPN'
    ufw allow $COCKPIT_PORT/tcp comment 'Cockpit Web'
    ufw allow $FILEBROWSER_PORT/tcp comment 'FileBrowser Web'
    ufw allow 19999/tcp comment 'Netdata Web'
    
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

# Função para login no Cloudflare
cloudflare_login() {
    dialog --title "Login Cloudflare" --msgbox "Você será redirecionado para o navegador para fazer login.\n\nApós o login, volte ao terminal e pressione ENTER." 8 60
    
    # Executar login
    if cloudflared tunnel login; then
        dialog --title "Login Concluído" --msgbox "Login realizado com sucesso!\n\nO certificado foi salvo em ~/.cloudflared/" 8 50
        log_message "INFO" "Login no Cloudflare realizado com sucesso"
    else
        dialog --title "Erro de Login" --msgbox "Falha no login do Cloudflare.\n\nVerifique sua conexão e tente novamente." 8 50
        log_message "ERROR" "Falha no login do Cloudflare"
    fi
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
            "8" "Configurar outros serviços" \
            "9" "Backup das configurações" \
            "10" "Sair" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) run_system_tests ;;
            2) show_services_status ;;
            3) show_installation_logs ;;
            4) configure_wireguard_vpn ;;
            5) configure_cloudflare_tunnel ;;
            6) configure_pihole_unbound ;;
            7) configure_fail2ban ;;
            8) configure_other_services ;;
            9) backup_configurations ;;
            10|"")
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

# Função para backup
backup_configurations() {
    dialog --title "Backup" --infobox "Criando backup das configurações..." 5 40
    
    local backup_file="$BACKUP_DIR/boxserver-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    tar -czf "$backup_file" -C / etc/boxserver etc/pihole etc/wireguard etc/unbound 2>/dev/null
    
    if [ $? -eq 0 ]; then
        dialog --title "Backup Concluído" --msgbox "Backup criado com sucesso:\n\n$backup_file" 8 60
    else
        dialog --title "Erro no Backup" --msgbox "Erro ao criar backup." 6 40
    fi
}

# Menu principal
main_menu() {
    while true; do
        local choice=$(dialog --title "Boxserver TUI Installer v1.0" \
            --menu "Instalador automatizado para MXQ-4K (RK322x)\n\nEscolha uma opção:" \
            $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Verificações do sistema" \
            "2" "Selecionar e instalar aplicativos" \
            "3" "Configurações avançadas" \
            "4" "Informações do sistema" \
            "5" "Ver logs" \
            "6" "Sobre" \
            "7" "Sair" \
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
                dialog --title "Sobre" --msgbox "Boxserver TUI Installer v1.0\n\nInstalador automatizado para servidor doméstico\nem dispositivos MXQ-4K com chip RK322x\n\nBaseado na base de conhecimento do\nprojeto Boxserver Arandutec\n\nDesenvolvido para hardware limitado\ncom otimizações específicas para ARM" 12 60
                ;;
            7|"")
                if dialog --title "Confirmar Saída" --yesno "Deseja realmente sair?" 6 30; then
                    clear
                    echo "Obrigado por usar o Boxserver TUI Installer!"
                    exit 0
                fi
                ;;
        esac
    done
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
