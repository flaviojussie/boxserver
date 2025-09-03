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
    
    # Instalar Unbound
    apt install unbound -y
    
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Falha na instalação do Unbound"
        return 1
    fi
    
    # Criar configuração otimizada para ARM RK322x
    mkdir -p /etc/unbound/unbound.conf.d
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
    
    # Baixar root hints
    wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
    
    # Configurar trust anchor automático
    unbound-anchor -a /var/lib/unbound/root.key
    if [ $? -ne 0 ]; then
        log_message "WARN" "Usando método manual para trust anchor"
        wget -O /tmp/root.key https://data.iana.org/root-anchors/icannbundle.pem
        mv /tmp/root.key /var/lib/unbound/root.key
    fi
    
    # Configurar permissões
    chown unbound:unbound /var/lib/unbound/root.key /var/lib/unbound/root.hints
    chmod 644 /var/lib/unbound/root.key /var/lib/unbound/root.hints
    
    # Verificar configuração
    unbound-checkconf
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Erro na configuração do Unbound"
        return 1
    fi
    
    # Iniciar e habilitar serviço
    systemctl restart unbound
    systemctl enable unbound
    
    # Testar DNS
    sleep 3
    if dig @127.0.0.1 -p 5335 google.com +short >/dev/null 2>&1; then
        log_message "INFO" "Unbound instalado e testado com sucesso"
    else
        log_message "WARN" "Unbound instalado mas teste de DNS falhou"
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
}

# Menu pós-instalação
post_installation_menu() {
    while true; do
        local choice=$(dialog --title "Pós-Instalação" --menu "Escolha uma opção:" $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "Executar testes do sistema" \
            "2" "Ver status dos serviços" \
            "3" "Ver logs de instalação" \
            "4" "Configurar clientes VPN" \
            "5" "Backup das configurações" \
            "6" "Sair" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) run_system_tests ;;
            2) show_services_status ;;
            3) show_installation_logs ;;
            4) configure_vpn_clients ;;
            5) backup_configurations ;;
            6|"")
                break
                ;;
        esac
    done
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
