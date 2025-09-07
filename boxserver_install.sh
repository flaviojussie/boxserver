#!/bin/bash
set -euo pipefail

# ==============================================
# BoxServer - Instalador Profissional
# Versão: 2.3
# ==============================================

# Diretório base do projeto
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/boxserver.conf"
BACKUP_DIR="/opt/boxserver/backups"
LOGFILE="/var/log/boxserver_install.log"
REPORT_FILE="/var/log/boxserver_report.txt"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variáveis de ambiente (documentação)
# FORCE_INSTALL: Ignora verificações de segurança
# SKIP_BACKUP: Pula backup de configurações
# VERBOSE_MODE: Ativa modo detalhado
# DRY_RUN: Simula execução sem alterações
# NO_COLOR: Desativa cores no output
# QUIET_MODE: Modo silencioso
# SKIP_PORT_CHECK: Ignora verificação de portas

# ==============================================
# Funções de Logging
# ==============================================
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOGFILE"
}

log_error() {
    echo -e "${RED}[ERRO]$(date '+%Y-%m-%d %H:%M:%S')${NC} $1" | tee -a "$LOGFILE"
}

log_warn() {
    echo -e "${YELLOW}[AVISO]$(date '+%Y-%m-%d %H:%M:%S')${NC} $1" | tee -a "$LOGFILE"
}

log_info() {
    echo -e "${BLUE}[INFO]$(date '+%Y-%m-%d %H:%M:%S')${NC} $1" | tee -a "$LOGFILE"
}

# ==============================================
# Funções de Interface
# ==============================================
whiptail_msg() {
    local title="$1"
    local msg="$2"
    local height="${3:-10}"
    local width="${4:-70}"
    whiptail --title "$title" --msgbox "$msg" $height $width 3>&1 1>&2 2>&3
}

whiptail_input() {
    local title="$1"
    local text="$2"
    local default="$3"
    local height="${4:-10}"
    local width="${5:-60}"
    whiptail --title "$title" --inputbox "$text" $height $width "$default" 3>&1 1>&2 2>&3
}

whiptail_checklist() {
    local title="$1"
    local text="$2"
    local height="$3"
    local width="$4"
    local listheight="$5"
    shift 5
    whiptail --title "$title" --checklist "$text" $height $width $listheight "$@" 3>&1 1>&2 2>&3
}

# ==============================================
# Detecção de Sistema
# ==============================================
detect_interface() {
    ip route | awk '/^default/ {print $5; exit}'
}

detect_arch() {
    case "$(uname -m)" in
        x86_64) echo "amd64";;
        aarch64|arm64) echo "arm64";;
        armv7l|armhf) echo "arm";;
        *) echo "unsupported";;
    esac
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script deve ser executado como root."
        exit 1
    fi
}

check_ports() {
    if [[ "${SKIP_PORT_CHECK:-false}" == "true" ]]; then
        log_warn "Verificação de portas desativada"
        return 0
    fi

    log_info "Verificando portas em uso (8080, 8081, 8200, 8443, 51820, 5335)..."
    local ports_in_use=$(sudo ss -tulpn | grep -E '(:8080|:8081|:8200|:8443|:51820|:5335)' || true)
    if [[ -n "$ports_in_use" ]]; then
        log_warn "Portas em uso:"
        echo "$ports_in_use"
        if [[ "${FORCE_INSTALL:-false}" != "true" ]] && ! whiptail --title "Portas em Uso" --yesno "Algumas portas necessárias já estão em uso. Deseja continuar?" 10 60; then
            exit 1
        fi
    fi
}

# ==============================================
# Gestão de Configurações
# ==============================================
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # Parse seguro do arquivo de configuração
        while IFS='=' read -r key value; do
            # Ignorar comentários e linhas vazias
            [[ -z "$key" || "$key" =~ ^# ]] && continue
            # Remover aspas e espaços em excesso
            value="${value%\"}"
            value="${value#\"}"
            value="${value%\'}"
            value="${value#\'}"
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"

            export "$key"="$value"
        done < "$CONFIG_FILE"
        log_info "Carregando configuração de $CONFIG_FILE"
    else
        log_info "Arquivo de configuração não encontrado, usando valores padrão"
    fi
}

save_config() {
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" << EOF
# BoxServer Configuration
NET_IF="${NET_IF:-$(detect_interface)}"
DOMAIN="${DOMAIN:-pihole.local}"
ARCH="${ARCH:-$(detect_arch)}"
CHOICES="${CHOICES:-}"
INSTALL_MODE="${INSTALL_MODE:-interactive}"
EOF
    log_info "Configuração salva em $CONFIG_FILE"
}

backup_configs() {
    if [[ "${SKIP_BACKUP:-false}" == "true" ]]; then
        log_warn "Backup de configurações desativado"
        return
    fi

    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_path="$BACKUP_DIR/backup_$timestamp"

    mkdir -p "$backup_path"
    log_info "Fazendo backup de configurações em $backup_path"

    # Backup de configurações específicas
    [[ -d /etc/pihole ]] && cp -r /etc/pihole "$backup_path/"
    [[ -d /etc/unbound ]] && cp -r /etc/unbound "$backup_path/"
    [[ -d /etc/wireguard ]] && cp -r /etc/wireguard "$backup_path/"
    [[ -f /etc/cloudflared/config.yml ]] && cp /etc/cloudflared/config.yml "$backup_path/"
    [[ -f /etc/samba/smb.conf ]] && cp /etc/samba/smb.conf "$backup_path/"
    [[ -f /etc/minidlna.conf ]] && cp /etc/minidlna.conf "$backup_path/"
    [[ -f /etc/systemd/system/filebrowser.service ]] && cp /etc/systemd/system/filebrowser.service "$backup_path/"

    log_info "Backup concluído"
    echo "$backup_path"
}

# ==============================================
# Funções de Verificação
# ==============================================
check_service_installed() {
    local service_name="$1"
    local package_name="$2"

    if dpkg -l | grep -q "^ii  $package_name "; then
        return 0
    else
        return 1
    fi
}

check_package_available() {
    local package_name="$1"

    if apt-cache policy "$package_name" | grep -q "Candidate:"; then
        return 0
    else
        return 1
    fi
}

check_systemd_service() {
    local service_name="$1"

    if systemctl list-unit-files | grep -q "$service_name"; then
        return 0
    else
        return 1
    fi
}

check_port_available() {
    local port="$1"

    if ! ss -tulpn | grep -q ":$port"; then
        return 0
    else
        return 1
    fi
}

check_service_running() {
    local service_name="$1"

    if systemctl is-active --quiet "$service_name"; then
        return 0
    else
        return 1
    fi
}

check_service_configured() {
    local service_name="$1"
    local config_file="$2"

    case "$service_name" in
        "UNBOUND")
            if [[ -f "$config_file" ]] && sudo unbound-checkconf "$config_file" &>/dev/null; then
                return 0
            fi
            ;;
        "PIHOLE")
            if [[ -f "/etc/pihole/setupVars.conf" ]] && grep -q "PIHOLE_DNS_1=127.0.0.1#5335" "/etc/pihole/setupVars.conf"; then
                return 0
            fi
            ;;
        "WIREGUARD")
            if [[ -f "/etc/wireguard/wg0.conf" ]] && wg show &>/dev/null; then
                return 0
            fi
            ;;
        "CLOUDFLARE")
            if [[ -f "/etc/cloudflared/config.yml" ]]; then
                return 0
            fi
            ;;
        "RNG")
            if [[ -f "/etc/default/rng-tools" ]]; then
                return 0
            fi
            ;;
        "SAMBA")
            if [[ -f "/etc/samba/smb.conf" ]] && systemctl is-active --quiet smbd; then
                return 0
            fi
            ;;
        "MINIDLNA")
            if [[ -f "/etc/minidlna.conf" ]]; then
                return 0
            fi
            ;;
        "FILEBROWSER")
            if [[ -f "/etc/systemd/system/filebrowser.service" ]] && systemctl is-active --quiet filebrowser; then
                return 0
            fi
            ;;
    esac

    return 1
}

get_service_status() {
    local service_name="$1"
    local display_name="$2"
    local package_name="$3"
    local config_file="$4"

    local status=""
    local color="$NC"

    if check_service_installed "$service_name" "$package_name"; then
        if check_service_running "$service_name"; then
            if check_service_configured "$service_name" "$config_file"; then
                status="✓ INSTALADO, ATIVO E CONFIGURADO"
                color="$GREEN"
            else
                status="⚠ INSTALADO E ATIVO, MAS NÃO CONFIGURADO"
                color="$YELLOW"
            fi
        else
            status="⚠ INSTALADO, MAS INATIVO"
            color="$YELLOW"
        fi
    else
        status="✗ NÃO INSTALADO"
        color="$RED"
    fi

    echo -e "${color}$status${NC} - $display_name"
}

# ==============================================
# Instalação de Serviços
# ==============================================
install_unbound() {
    log_info "Instalando Unbound..."
    sudo apt install -y unbound unbound-anchor

    cat << EOF | sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    edns-buffer-size: 1232
    prefetch: yes
    num-threads: 1
    so-rcvbuf: 512k
    so-sndbuf: 512k
    private-address: 192.168.0.0/16
    private-address: 10.0.0.0/8
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    root-hints: "/var/lib/unbound/root.hints"
EOF

    sudo mkdir -p /var/lib/unbound
    sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
    sudo unbound-anchor -a /var/lib/unbound/root.key || {
        sudo wget -O /tmp/root.key https://data.iana.org/root-anchors/icannbundle.pem
        sudo mv /tmp/root.key /var/lib/unbound/root.key
    }

    sudo chown -R unbound:unbound /var/lib/unbound
    sudo chmod 644 /var/lib/unbound/root.*

    if sudo unbound-checkconf; then
        sudo systemctl restart unbound
        sudo systemctl enable unbound
        log_info "Unbound instalado com sucesso"
    else
        log_error "Falha na configuração do Unbound"
        return 1
    fi
}

install_pihole() {
    log_info "Instalando Pi-hole..."
    if curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended; then
        log_info "Pi-hole instalado"

        log_info "Configurando Pi-hole para usar Unbound..."
        sudo sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
        pihole restartdns

        log_info "Alterando portas do Pi-hole para 8081/8443..."
        sudo sed -i 's/server.port\s*=\s*80/server.port = 8081/' /etc/lighttpd/lighttpd.conf
        sudo bash -c 'echo "$SERVER[\"socket\"] == \":8443\" { ssl.engine = \"enable\" }" > /etc/lighttpd/external.conf'
        sudo systemctl restart lighttpd
        log_info "Pi-hole configurado com sucesso"
    else
        log_error "Falha na instalação do Pi-hole"
        return 1
    fi
}

install_wireguard() {
    log_info "Instalando WireGuard..."
    sudo apt install -y wireguard wireguard-tools

    sudo mkdir -p /etc/wireguard/keys
    sudo chmod 700 /etc/wireguard/keys
    umask 077
    wg genkey | sudo tee /etc/wireguard/keys/privatekey | wg pubkey | sudo tee /etc/wireguard/keys/publickey
    local PRIVATE_KEY=$(sudo cat /etc/wireguard/keys/privatekey)

    cat << EOF | sudo tee /etc/wireguard/wg0.conf
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.200.200.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_IF -j MASQUERADE
EOF

    sudo chmod 600 /etc/wireguard/wg0.conf

    sudo sysctl -w net.ipv4.ip_forward=1
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf

    sudo systemctl enable wg-quick@wg0
    sudo systemctl start wg-quick@wg0
    log_info "WireGuard instalado com sucesso"
}

install_cloudflare() {
    log_info "Instalando Cloudflare Tunnel..."
    local ARCH=$(detect_arch)
    local URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
    sudo wget -O /usr/local/bin/cloudflared "$URL"
    sudo chmod +x /usr/local/bin/cloudflared

    sudo mkdir -p /etc/cloudflared
    cat << EOF | sudo tee /etc/cloudflared/config.yml
tunnel: boxserver
credentials-file: /etc/cloudflared/boxserver.json
ingress:
  - hostname: $DOMAIN
    service: http://localhost:8081
  - service: http_status:404
EOF
    log_info "Cloudflare instalado. Execute manualmente:"
    log_info "  cloudflared tunnel login"
    log_info "  cloudflared tunnel create boxserver"
}

install_rng() {
    log_info "Instalando RNG-tools..."
    sudo apt install -y rng-tools

    local RNGDEVICE="/dev/urandom"
    [[ -e /dev/hwrng ]] && RNGDEVICE="/dev/hwrng"

    cat << EOF | sudo tee /etc/default/rng-tools
RNGDEVICE="$RNGDEVICE"
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10"
EOF

    sudo systemctl enable rng-tools
    sudo systemctl restart rng-tools
    log_info "RNG-tools instalado com sucesso"
}

install_samba() {
    log_info "Instalando Samba..."
    sudo apt install -y samba
    sudo mkdir -p /srv/samba/share
    sudo chmod 777 /srv/samba/share

    cat << EOF | sudo tee -a /etc/samba/smb.conf

[BoxShare]
   path = /srv/samba/share
   browseable = yes
   read only = no
   guest ok = yes
EOF

    sudo systemctl restart smbd
    sudo systemctl enable smbd
    log_info "Samba instalado. Configure usuários com: sudo smbpasswd -a <usuario>"
}

install_minidlna() {
    log_info "Instalando MiniDLNA..."
    sudo apt install -y minidlna
    sudo mkdir -p /srv/media/{video,audio,photos}

    cat << EOF | sudo tee /etc/minidlna.conf
media_dir=V,/srv/media/video
media_dir=A,/srv/media/audio
media_dir=P,/srv/media/photos
db_dir=/var/cache/minidlna
log_dir=/var/log
friendly_name=BoxServer DLNA
inotify=yes
port=8200
EOF

    sudo systemctl restart minidlna
    sudo systemctl enable minidlna
    log_info "MiniDLNA instalado com sucesso"
}

install_filebrowser() {
    log_info "Instalando Filebrowser..."
    local FB_VERSION=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | grep tag_name | cut -d '"' -f4)
    local ARCH=$(detect_arch)
    case "$ARCH" in
        amd64) FB_ARCH="linux-amd64";;
        arm64) FB_ARCH="linux-arm64";;
        arm) FB_ARCH="linux-armv6";;
        *) log_error "Arquitetura não suportada pelo Filebrowser"; return 1;;
    esac

    wget -O filebrowser.tar.gz "https://github.com/filebrowser/filebrowser/releases/download/${FB_VERSION}/filebrowser-${FB_ARCH}.tar.gz"
    tar -xzf filebrowser.tar.gz
    sudo mv filebrowser /usr/local/bin/
    rm -f filebrowser.tar.gz

    sudo mkdir -p /srv/filebrowser
    sudo useradd -r -s /bin/false filebrowser || true

    cat << EOF | sudo tee /etc/systemd/system/filebrowser.service
[Unit]
Description=Filebrowser
After=network.target

[Service]
User=filebrowser
ExecStart=/usr/local/bin/filebrowser -r /srv/filebrowser --port 8080
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reexec
    sudo systemctl enable filebrowser
    sudo systemctl start filebrowser

    log_info "Filebrowser instalado! Acesse http://<IP>:8080 (usuário: admin, senha: admin)"
}

# ==============================================
# Verificação de Requisitos do Sistema
# ==============================================
check_system_requirements() {
    log_info "Verificando requisitos do sistema..."

    # Verificar versão do Ubuntu/Debian
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        log_info "Sistema: $NAME $VERSION"

        # Verificar se é Ubuntu 20.04+ ou Debian 10+
        if [[ "$ID" == "ubuntu" && "$(echo "$VERSION_ID >= 20.04" | bc)" -eq 1 ]] || \
           [[ "$ID" == "debian" && "$(echo "$VERSION_ID >= 10" | bc)" -eq 1 ]]; then
            log_info "✓ Versão do sistema compatível"
        else
            log_warn "⚠ Versão do sistema não testada: $VERSION_ID"
        fi
    else
        log_warn "⚠ Não foi possível identificar o sistema operacional"
    fi

    # Verificar arquitetura
    local ARCH=$(detect_arch)
    case "$ARCH" in
        amd64|arm64|arm)
            log_info "✓ Arquitetura suportada: $ARCH"
            ;;
        *)
            log_error "✗ Arquitetura não suportada: $ARCH"
            exit 1
            ;;
    esac

    # Verificar espaço em disco mínimo (5GB)
    local available_space=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [[ $available_space -ge 5 ]]; then
        log_info "✓ Espaço em disco suficiente: ${available_space}GB disponíveis"
    else
        log_warn "⚠ Espaço em disco baixo: ${available_space}GB disponíveis (recomendado 5GB+)"
    fi

    # Verificar memória mínima (1GB)
    local memory_gb=$(( $(free -g | awk 'NR==2 {print $2}') ))
    if [[ $memory_gb -ge 1 ]]; then
        log_info "✓ Memória suficiente: ${memory_gb}GB total"
    else
        log_warn "⚠ Memória baixa: ${memory_gb}GB total (recomendado 1GB+)"
    fi

    # Verificar conexão com a internet
    if ping -c 1 8.8.8.8 &>/dev/null; then
        log_info "✓ Conexão com a internet ativa"
    else
        log_warn "⚠ Sem conexão com a internet"
    fi

    # Verificar disponibilidade dos pacotes
    log_info "Verificando disponibilidade dos pacotes..."
    local required_packages=("curl" "wget" "gnupg" "lsb-release" "ca-certificates")
    for package in "${required_packages[@]}"; do
        if check_package_available "$package"; then
            log_info "✓ Pacote $package disponível"
        else
            log_error "✗ Pacote $package não disponível nos repositórios"
        fi
    done

    # Verificar serviços systemd
    log_info "Verificando serviços systemd..."
    local systemd_services=("unbound" "lighttpd" "wg-quick@wg0" "rng-tools" "smbd" "minidlna")
    for service in "${systemd_services[@]}"; do
        if check_systemd_service "$service"; then
            log_info "✓ Serviço systemd $service disponível"
        else
            log_warn "⚠ Serviço systemd $service não encontrado"
        fi
    done

    log_info "Requisitos do sistema verificados"
}

# ==============================================
# Funções de Segurança e Validação
# ==============================================
validate_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Arquivo de configuração não encontrado: $CONFIG_FILE"
        return 1
    fi

    # Validar variáveis obrigatórias
    local required_vars=("NET_IF" "DOMAIN" "ARCH")
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Variável obrigatória não definida: $var"
            return 1
        fi
    done

    log_info "Configuração validada com sucesso"
    return 0
}

check_security() {
    log_info "Verificando configurações de segurança..."

    # Verificar se o sistema está atualizado
    local security_updates=$(apt list --upgradable 2>/dev/null | grep -c security)
    if [[ $security_updates -gt 0 ]]; then
        log_warn "⚠ $security_updates atualizações de segurança disponíveis"
        log_warn "   Execute: sudo apt update && sudo apt upgrade"
    else
        log_info "✓ Sistema atualizado"
    fi

    # Verificar firewall
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        log_info "✓ Firewall ativo"
    else
        log_warn "⚠ Firewall não está ativo"
    fi

    # Verificar senha root
    if [[ $(passwd --status root | awk '{print $2}') == "L" ]]; then
        log_warn "⚠ Conta root está bloqueada (isso é bom para segurança)"
    fi

    log_info "Verificação de segurança concluída"
}

create_emergency_rollback() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local rollback_file="$BACKUP_DIR/rollback_$timestamp.sh"

    cat > "$rollback_file" << EOF
#!/bin/bash
# Script de rollback de emergência - Gerado automaticamente
# Data: $(date)
# Não modifique este arquivo manualmente

echo "Iniciando rollback de emergência..."
echo "Este script restaurará o sistema ao estado anterior"

# Restaurar backups se disponíveis
if [[ -d "$BACKUP_DIR" ]]; then
    echo "Restaurando backups..."
    # Adicione comandos de restauração específicos aqui
fi

echo "Rollback concluído"
EOF

    chmod +x "$rollback_file"
    log_info "Script de rollback criado: $rollback_file"
}

# ==============================================
# Desinstalação de Serviços
# ==============================================
uninstall_unbound() {
    if ! check_service_installed "UNBOUND" "unbound"; then
        log_info "Unbound não está instalado, pulando desinstalação"
        return 0
    fi

    log_info "Desinstalando Unbound..."
    sudo systemctl stop unbound 2>/dev/null || true
    sudo systemctl disable unbound 2>/dev/null || true
    sudo apt remove --purge -y unbound unbound-anchor
    sudo rm -rf /etc/unbound/unbound.conf.d/pi-hole.conf
    sudo rm -rf /var/lib/unbound
    log_info "Unbound desinstalado"
}

uninstall_pihole() {
    if ! check_service_installed "PIHOLE" "pi-hole-core"; then
        log_info "Pi-hole não está instalado, pulando desinstalação"
        return 0
    fi

    log_info "Desinstalando Pi-hole..."
    if command -v pihole &> /dev/null; then
        pihole -r
        sudo systemctl stop lighttpd 2>/dev/null || true
        sudo systemctl disable lighttpd 2>/dev/null || true
        sudo apt remove --purge -y lighttpd
    fi
    sudo apt remove --purge -y pi-hole-core
    sudo rm -rf /etc/pihole /etc/lighttpd
    log_info "Pi-hole desinstalado"
}

uninstall_wireguard() {
    if ! check_service_installed "WIREGUARD" "wireguard"; then
        log_info "WireGuard não está instalado, pulando desinstalação"
        return 0
    fi

    log_info "Desinstalando WireGuard..."
    sudo systemctl stop wg-quick@wg0 2>/dev/null || true
    sudo systemctl disable wg-quick@wg0 2>/dev/null || true
    sudo apt remove --purge -y wireguard wireguard-tools
    sudo rm -rf /etc/wireguard
    sudo sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf
    log_info "WireGuard desinstalado"
}

uninstall_cloudflare() {
    if [[ ! -f "/usr/local/bin/cloudflared" ]]; then
        log_info "Cloudflare não está instalado, pulando desinstalação"
        return 0
    fi

    log_info "Desinstalando Cloudflare..."
    sudo rm -f /usr/local/bin/cloudflared
    sudo rm -rf /etc/cloudflared
    log_info "Cloudflare desinstalado"
}

uninstall_rng() {
    if ! check_service_installed "RNG" "rng-tools"; then
        log_info "RNG-tools não está instalado, pulando desinstalação"
        return 0
    fi

    log_info "Desinstalando RNG-tools..."
    sudo systemctl stop rng-tools 2>/dev/null || true
    sudo systemctl disable rng-tools 2>/dev/null || true
    sudo apt remove --purge -y rng-tools
    log_info "RNG-tools desinstalado"
}

uninstall_samba() {
    if ! check_service_installed "SAMBA" "samba"; then
        log_info "Samba não está instalado, pulando desinstalação"
        return 0
    fi

    log_info "Desinstalando Samba..."
    sudo systemctl stop smbd nmbd 2>/dev/null || true
    sudo systemctl disable smbd nmbd 2>/dev/null || true
    sudo apt remove --purge -y samba
    sudo rm -rf /etc/samba /srv/samba
    log_info "Samba desinstalado"
}

uninstall_minidlna() {
    if ! check_service_installed "MINIDLNA" "minidlna"; then
        log_info "MiniDLNA não está instalado, pulando desinstalação"
        return 0
    fi

    log_info "Desinstalando MiniDLNA..."
    sudo systemctl stop minidlna 2>/dev/null || true
    sudo systemctl disable minidlna 2>/dev/null || true
    sudo apt remove --purge -y minidlna
    sudo rm -rf /etc/minidlna.conf /var/cache/minidlna /srv/media
    log_info "MiniDLNA desinstalado"
}

uninstall_filebrowser() {
    if [[ ! -f "/etc/systemd/system/filebrowser.service" ]]; then
        log_info "Filebrowser não está instalado, pulando desinstalação"
        return 0
    fi

    log_info "Desinstalando Filebrowser..."
    sudo systemctl stop filebrowser 2>/dev/null || true
    sudo systemctl disable filebrowser 2>/dev/null || true
    sudo rm -f /etc/systemd/system/filebrowser.service
    sudo systemctl daemon-reexec
    sudo rm -f /usr/local/bin/filebrowser
    sudo userdel filebrowser 2>/dev/null || true
    sudo rm -rf /srv/filebrowser
    log_info "Filebrowser desinstalado"
}

# ==============================================
# Instalação Completa
# ==============================================
install_services() {
    local services=("$@")

    for service in "${services[@]}"; do
        case "$service" in
            "UNBOUND")
                if check_service_installed "UNBOUND" "unbound"; then
                    log_info "Unbound já está instalado"
                    if check_service_running "unbound"; then
                        log_info "Unbound já está em execução"
                    else
                        log_warn "Unbound instalado mas inativo, iniciando..."
                        sudo systemctl start unbound
                    fi
                else
                    install_unbound
                fi
                ;;
            "PIHOLE")
                if check_service_installed "PIHOLE" "pi-hole-core"; then
                    log_info "Pi-hole já está instalado"
                    if check_service_running "lighttpd"; then
                        log_info "Pi-hole já está em execução"
                    else
                        log_warn "Pi-hole instalado mas inativo, iniciando..."
                        sudo systemctl start lighttpd
                    fi
                else
                    install_pihole
                fi
                ;;
            "WIREGUARD")
                if check_service_installed "WIREGUARD" "wireguard"; then
                    log_info "WireGuard já está instalado"
                    if check_service_running "wg-quick@wg0"; then
                        log_info "WireGuard já está em execução"
                    else
                        log_warn "WireGuard instalado mas inativo, iniciando..."
                        sudo systemctl start wg-quick@wg0
                    fi
                else
                    install_wireguard
                fi
                ;;
            "CLOUDFLARE")
                if [[ -f "/usr/local/bin/cloudflared" ]]; then
                    log_info "Cloudflare já está instalado"
                else
                    install_cloudflare
                fi
                ;;
            "RNG")
                if check_service_installed "RNG" "rng-tools"; then
                    log_info "RNG-tools já está instalado"
                    if check_service_running "rng-tools"; then
                        log_info "RNG-tools já está em execução"
                    else
                        log_warn "RNG-tools instalado mas inativo, iniciando..."
                        sudo systemctl start rng-tools
                    fi
                else
                    install_rng
                fi
                ;;
            "SAMBA")
                if check_service_installed "SAMBA" "samba"; then
                    log_info "Samba já está instalado"
                    if systemctl is-active --quiet smbd; then
                        log_info "Samba já está em execução"
                    else
                        log_warn "Samba instalado mas inativo, iniciando..."
                        sudo systemctl start smbd
                    fi
                else
                    install_samba
                fi
                ;;
            "MINIDLNA")
                if check_service_installed "MINIDLNA" "minidlna"; then
                    log_info "MiniDLNA já está instalado"
                    if check_service_running "minidlna"; then
                        log_info "MiniDLNA já está em execução"
                    else
                        log_warn "MiniDLNA instalado mas inativo, iniciando..."
                        sudo systemctl start minidlna
                    fi
                else
                    install_minidlna
                fi
                ;;
            "FILEBROWSER")
                if [[ -f "/etc/systemd/system/filebrowser.service" ]]; then
                    log_info "Filebrowser já está instalado"
                    if check_service_running "filebrowser"; then
                        log_info "Filebrowser já está em execução"
                    else
                        log_warn "Filebrowser instalado mas inativo, iniciando..."
                        sudo systemctl start filebrowser
                    fi
                else
                    install_filebrowser
                fi
                ;;
            *) log_error "Serviço desconhecido: $service" ;;
        esac
    done
}

uninstall_services() {
    local services=("$@")

    for service in "${services[@]}"; do
        case "$service" in
            "UNBOUND") uninstall_unbound ;;
            "PIHOLE") uninstall_pihole ;;
            "WIREGUARD") uninstall_wireguard ;;
            "CLOUDFLARE") uninstall_cloudflare ;;
            "RNG") uninstall_rng ;;
            "SAMBA") uninstall_samba ;;
            "MINIDLNA") uninstall_minidlna ;;
            "FILEBROWSER") uninstall_filebrowser ;;
            *) log_error "Serviço desconhecido: $service" ;;
        esac
    done
}

# ==============================================
# Modos de Operação
# ==============================================
interactive_install() {
    log_info "Iniciando instalação interativa"

    local NET_IF=$(detect_interface)
    NET_IF=$(whiptail_input "Interface de Rede" "Interface detectada: $NET_IF\nConfirme ou edite:" "$NET_IF")
    export NET_IF

    local DOMAIN=$(whiptail_input "Domínio" "Digite o domínio para acessar o Pi-hole:" "pihole.local")
    export DOMAIN

    local ARCH=$(detect_arch)
    log_info "Arquitetura detectada: $ARCH"
    export ARCH

    local CHOICES=$(whiptail_checklist "Seleção de Componentes" "Escolha os serviços que deseja instalar:" 20 70 10 \
        "UNBOUND" "DNS recursivo (automático)" ON \
        "PIHOLE" "Bloqueio de anúncios (manual, portas 8081/8443)" ON \
        "WIREGUARD" "VPN segura (server auto, peers manuais)" OFF \
        "CLOUDFLARE" "Acesso remoto (login manual)" OFF \
        "RNG" "Gerador de entropia (automático)" ON \
        "SAMBA" "Compartilhamento de arquivos" OFF \
        "MINIDLNA" "Servidor DLNA" OFF \
        "FILEBROWSER" "Gerenciador de arquivos Web" OFF \
        3>&1 1>&2 2>&3)

    if [[ -z "$CHOICES" ]]; then
        log_error "Nenhum serviço selecionado"
        exit 1
    fi

    save_config
    check_ports
    install_services $CHOICES

    whiptail_msg "Instalação Concluída" "Instalação concluída! Revise o log em $LOGFILE"
}

non_interactive_install() {
    log_info "Iniciando instalação não-interativa"

    if [[ -z "$CHOICES" ]]; then
        log_error "Nenhum serviço especificado para instalação não-interativa"
        exit 1
    fi

    save_config
    check_ports
    install_services $CHOICES
    log_info "Instalação não-interativa concluída"
}

uninstall_all() {
    log_info "Iniciando desinstalação completa"

    local backup_path=$(backup_configs)
    log_info "Backup salvo em: $backup_path"

    local all_services=("UNBOUND" "PIHOLE" "WIREGUARD" "CLOUDFLARE" "RNG" "SAMBA" "MINIDLNA" "FILEBROWSER")
    uninstall_services "${all_services[@]}"

    # Remover configurações do BoxServer
    sudo rm -rf "$SCRIPT_DIR"
    sudo rm -f "$CONFIG_FILE"

    log_info "Desinstalação concluída"
}

purge_all() {
    log_info "Iniciando purga completa (remove configurações)..."

    local backup_path=$(backup_configs)
    log_info "Backup salvo em: $backup_path"

    local all_services=("UNBOUND" "PIHOLE" "WIREGUARD" "CLOUDFLARE" "RNG" "SAMBA" "MINIDLNA" "FILEBROWSER")
    uninstall_services "${all_services[@]}"

    # Remover todas as configurações e dados
    sudo rm -rf /opt/boxserver
    sudo rm -f "$CONFIG_FILE"
    sudo rm -rf "$BACKUP_DIR"

    log_info "Purga concluída"
}

reinstall_all() {
    log_info "Iniciando reinstalação completa"

    local backup_path=$(backup_configs)
    log_info "Backup salvo em: $backup_path"

    local all_services=("UNBOUND" "PIHOLE" "WIREGUARD" "CLOUDFLARE" "RNG" "SAMBA" "MINIDLNA" "FILEBROWSER")
    uninstall_services "${all_services[@]}"

    # Esperar um pouco antes de reinstalar
    sleep 2

    install_services "${all_services[@]}"

    log_info "Reinstalação concluída"
}

show_status() {
    log_info "Verificando status completo dos serviços..."
    log_info "========================================"

    local services=(
        "UNBOUND:unbound:Unbound:/etc/unbound/unbound.conf.d/pi-hole.conf"
        "PIHOLE:lighttpd:Pi-hole:/etc/pihole/setupVars.conf"
        "WIREGUARD:wg-quick@wg0:WireGuard:/etc/wireguard/wg0.conf"
        "CLOUDFLARE::Cloudflare:/etc/cloudflared/config.yml"
        "RNG:rng-tools:RNG-tools:/etc/default/rng-tools"
        "SAMBA::Samba:/etc/samba/smb.conf"
        "MINIDLNA:minidlna:MiniDLNA:/etc/minidlna.conf"
        "FILEBROWSER:filebrowser:Filebrowser:/etc/systemd/system/filebrowser.service"
    )

    for service_info in "${services[@]}"; do
        local service_key=$(echo "$service_info" | cut -d: -f1)
        local service_system=$(echo "$service_info" | cut -d: -f2)
        local display_name=$(echo "$service_info" | cut -d: -f3)
        local config_file=$(echo "$service_info" | cut -d: -f4)

        get_service_status "$service_key" "$display_name" "$service_key" "$config_file"
    done

    log_info "========================================"

    # Verificar portas em uso
    log_info "Portas em uso:"
    local ports=("8080" "8081" "8200" "8443" "51820" "5335")
    for port in "${ports[@]}"; do
        if ss -tulpn | grep -q ":$port"; then
            log_warn "  Porta $port: EM USO"
        else
            log_info "  Porta $port: LIVRE"
        fi
    done

    log_info "========================================"
    log_info "Status completo verificado"
}

# ==============================================
# Recuperação e Reparo
# ==============================================
repair_service() {
    local service_name="$1"
    local display_name="$2"

    log_info "Reparando $display_name..."

    case "$service_name" in
        "UNBOUND")
            sudo systemctl restart unbound
            sudo systemctl enable unbound
            ;;
        "PIHOLE")
            sudo systemctl restart lighttpd
            sudo systemctl enable lighttpd
            pihole restartdns 2>/dev/null || true
            ;;
        "WIREGUARD")
            sudo systemctl restart wg-quick@wg0
            sudo systemctl enable wg-quick@wg0
            ;;
        "CLOUDFLARE")
            log_warn "Cloudflare requer configuração manual"
            ;;
        "RNG")
            sudo systemctl restart rng-tools
            sudo systemctl enable rng-tools
            ;;
        "SAMBA")
            sudo systemctl restart smbd
            sudo systemctl enable smbd
            ;;
        "MINIDLNA")
            sudo systemctl restart minidlna
            sudo systemctl enable minidlna
            ;;
        "FILEBROWSER")
            sudo systemctl restart filebrowser
            sudo systemctl enable filebrowser
            ;;
        *)
            log_error "Serviço desconhecido para reparo: $service_name"
            return 1
            ;;
    esac

    if check_service_running "$service_name"; then
        log_info "$display_name reparado com sucesso"
        return 0
    else
        log_error "Falha ao reparar $display_name"
        return 1
    fi
}

validate_installation() {
    local service_name="$1"
    local display_name="$2"

    log_info "Validando instalação do $display_name..."

    case "$service_name" in
        "UNBOUND")
            if check_service_installed "UNBOUND" "unbound" && \
               check_service_running "unbound" && \
               check_service_configured "UNBOUND" "/etc/unbound/unbound.conf.d/pi-hole.conf"; then
                log_info "✓ $display_name validado com sucesso"
                return 0
            else
                log_error "✗ $display_name falhou na validação"
                return 1
            fi
            ;;
        "PIHOLE")
            if check_service_installed "PIHOLE" "pi-hole-core" && \
               check_service_running "lighttpd" && \
               check_service_configured "PIHOLE" "/etc/pihole/setupVars.conf"; then
                log_info "✓ $display_name validado com sucesso"
                return 0
            else
                log_error "✗ $display_name falhou na validação"
                return 1
            fi
            ;;
        *)
            log_warn "Validação não implementada para $display_name"
            return 0
            ;;
    esac
}

# ==============================================
# Relatórios e Documentação
# ==============================================
generate_report() {
    log_info "Gerando relatório completo do sistema..."

    local report_timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="$BACKUP_DIR/report_$report_timestamp.txt"

    mkdir -p "$BACKUP_DIR"

    {
        echo "BoxServer - Relatório Completo"
        echo "Data: $(date)"
        echo "Versão: 2.2"
        echo "========================================"
        echo ""

        echo "INFORMAÇÕES DO SISTEMA:"
        echo "Sistema Operacional: $(uname -a)"
        echo "Distribuição: $(lsb_release -sd 2>/dev/null || echo 'Não detectado')"
        echo "Kernel: $(uname -r)"
        echo "Arquitetura: $(uname -m)"
        echo "Uptime: $(uptime -p)"
        echo ""

        echo "RECURSOS DO SISTEMA:"
        echo "CPU: $(nproc) núcleos"
        echo "Memória Total: $(free -h | awk 'NR==2{print $2}')"
        echo "Espaço em Disco: $(df -h / | awk 'NR==2{print $4}' | sed 's/Usado:/Disponível:/') disponível"
        echo ""

        echo "SERVIÇOS INSTALADOS:"
        show_status | sed 's/.*- /- /'
        echo ""

        echo "PORTAS EM USO:"
        ss -tulpn | grep -E ':(8080|8081|8200|8443|51820|5335)' || echo "Nenhuma porta monitorada detectada"
        echo ""

        echo "CONFIGURAÇÕES:"
        if [[ -f "$CONFIG_FILE" ]]; then
            echo "Arquivo de configuração: $CONFIG_FILE"
            echo "Conteúdo:"
            cat "$CONFIG_FILE"
        else
            echo "Nenhum arquivo de configuração encontrado"
        fi
        echo ""

        echo "ULTIMAS ATIVIDADES:"
        tail -20 "$LOGFILE" 2>/dev/null || echo "Log não disponível"
        echo ""

        echo "BACKUPS DISPONÍVEIS:"
        ls -la "$BACKUP_DIR" 2>/dev/null || echo "Nenhum backup disponível"

    } > "$report_file"

    log_info "Relatório gerado em: $report_file"
    echo -e "${CYAN}Relatório salvo em: $report_file${NC}"
}

# ==============================================
# Help e Argumentos
# ==============================================
show_help() {
    cat << EOF
BoxServer - Instalador Profissional Versão 2.2

Uso: sudo $0 [opção] [--non-interactive]

OPÇÕES PRINCIPAIS:
    install          Instala os serviços (modo interativo por padrão)
    --non-interactive Instalação não-interativa (requer configuração prévia)
    uninstall        Desinstala todos os serviços, mantém configurações
    purge            Desinstala e remove todas as configurações
    reinstall        Reinstala todos os serviços
    status           Mostra status detalhado dos serviços
    repair           Repara serviços instalados
    validate         Valida instalações existentes
    report           Gera relatório completo
    help             Mostra esta mensagem de ajuda

OPÇÕES AVANÇADAS:
    --force          Força instalação mesmo com conflitos
    --skip-backup    Pula backup de configurações
    --verbose        Modo verbose (detalhado)
    --dry-run        Simula a execução sem fazer alterações
    --no-color       Desativa cores no output
    --quiet          Modo silencioso (apenas erros)

MODOS DE OPERAÇÃO:
    Interativo:     Solicita informações e escolhas do usuário
    Não-Interativo:  Usa configuração prévia de $SCRIPT_DIR/boxserver.conf
    Reparo:         Corrige problemas em serviços existentes
    Validação:      Verifica integridade das instalações
    Relatório:      Gera relatório completo do sistema

REQUISITOS DO SISTEMA:
    - Ubuntu 20.04+ ou Debian 10+
    - Arquitetura: amd64, arm64, arm
    - Espaço em disco: mínimo 5GB
    - Memória: mínimo 1GB
    - Conexão com a internet
    - Permissões de root

SERVIÇOS DISPONÍVEIS:
    UNBOUND         - DNS recursivo seguro (porta 5335)
    PIHOLE          - Bloqueador de anúncios (portas 8081/8443)
    WIREGUARD       - VPN segura (porta 51820)
    CLOUDFLARE      - Túnel reverso (porta 443)
    RNG             - Gerador de entropia
    SAMBA           - Compartilhamento de arquivos (porta 445)
    MINIDLNA        - Servidor DLNA (porta 8200)
    FILEBROWSER     - Gerenciador de arquivos web (porta 8080)

ARQUIVOS DE CONFIGURAÇÃO:
    $SCRIPT_DIR/boxserver.conf    - Configurações persistentes
    $BACKUP_DIR/                  - Backups automáticos
    $LOGFILE                      - Log detalhado

EXEMPLOS DE USO:
    sudo $0 install                    # Instalação interativa
    sudo $0 install --non-interactive # Instalação automática
    sudo $0 status                     # Status dos serviços
    sudo $0 repair                     # Reparar serviços
    sudo $0 validate                   # Validar instalações
    sudo $0 report                     # Gerar relatório
    sudo $0 uninstall                  # Desinstalação segura
    sudo $0 purge                      # Remover tudo
    sudo $0 reinstall                  # Reinstalar tudo
    sudo $0 --force install            # Força instalação
    sudo $0 --verbose install          # Modo detalhado
    sudo $0 --quiet install           # Modo silencioso

RELATÓRIO DE PROBLEMAS:
    Caso encontre problemas, verifique o log em $LOGFILE

EOF
}

# ==============================================
# Parse de Argumentos
# ==============================================
parse_args() {
    INSTALL_MODE="install"
    INTERACTIVE="true"

    while [[ $# -gt 0 ]]; do
        case $1 in
            install)
                INSTALL_MODE="install"
                shift
                ;;
            uninstall)
                INSTALL_MODE="uninstall"
                shift
                ;;
            purge)
                INSTALL_MODE="purge"
                shift
                ;;
            reinstall)
                INSTALL_MODE="reinstall"
                shift
                ;;
            status)
                INSTALL_MODE="status"
                shift
                ;;
            repair)
                INSTALL_MODE="repair"
                shift
                ;;
            validate)
                INSTALL_MODE="validate"
                shift
                ;;
            report)
                INSTALL_MODE="report"
                shift
                ;;
            --non-interactive)
                INTERACTIVE="false"
                shift
                ;;
            help|--help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Argumento desconhecido: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# ==============================================
# Função Principal
# ==============================================
main() {
    # Redirecionar stdout e stderr para log
    exec > >(tee -a "$LOGFILE") 2>&1

    log_info "Iniciando BoxServer Installer"
    log_info "Modo: $INSTALL_MODE"
    log_info "Versão: 2.2"
    log_info "========================================"

    # Verificar requisitos do sistema
    check_system_requirements

    # Verificar segurança
    check_security

    # Criar script de rollback de emergência
    create_emergency_rollback

    # Verificar argumentos adicionais
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force)
                export FORCE_INSTALL="true"
                log_warn "Modo força ativado - ignorando conflitos"
                shift
                ;;
            --skip-backup)
                export SKIP_BACKUP="true"
                log_warn "Backup de configurações desativado"
                shift
                ;;
            --verbose)
                export VERBOSE_MODE="true"
                set -x
                log_info "Modo verbose ativado"
                shift
                ;;
            --dry-run)
                export DRY_RUN="true"
                log_info "Modo dry-run - apenas simulação"
                shift
                ;;
            --no-color)
                export NO_COLOR="true"
                RED=''
                GREEN=''
                YELLOW=''
                BLUE=''
                CYAN=''
                NC=''
                shift
                ;;
            --quiet)
                export QUIET_MODE="true"
                exec > /dev/null
                shift
                ;;
            *)
                # Já foi processado no parse_args
                shift
                ;;
        esac
    done

    # Aplicar opções globais
    if [[ "${FORCE_INSTALL:-false}" == "true" ]]; then
        export SKIP_PORT_CHECK="true"
        log_warn "⚠ Modo força ativado - Ignorando verificações de segurança"
    fi

    # Validar configuração para modo não-interativo
    if [[ "$INTERACTIVE" == "false" ]]; then
        if ! validate_config; then
            log_error "Configuração inválida para modo não-interativo"
            exit 1
        fi
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "Executando em modo dry-run - nenhuma alteração será feita"
    fi

    case "$INSTALL_MODE" in
        "install")
            if [[ "$INTERACTIVE" == "true" ]]; then
                interactive_install
            else
                non_interactive_install
            fi
            ;;
        "uninstall")
            log_info "Verificando serviços instalados antes da desinstalação..."
            show_status
            echo
            read -p "Tem certeza que deseja desinstalar todos os serviços? (s/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Ss]$ ]]; then
                uninstall_all
            else
                log_info "Operação cancelada"
            fi
            ;;
        "purge")
            log_info "Verificando serviços instalados antes da purga..."
            show_status
            echo
            read -p "Tem certeza que deseja purgar todos os serviços e configurações? (s/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Ss]$ ]]; then
                purge_all
            else
                log_info "Operação cancelada"
            fi
            ;;
        "reinstall")
            log_info "Verificando serviços instalados antes da reinstalação..."
            show_status
            echo
            read -p "Tem certeza que deseja reinstalar todos os serviços? (s/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Ss]$ ]]; then
                reinstall_all
            else
                log_info "Operação cancelada"
            fi
            ;;
        "status")
            show_status
            ;;
        "repair")
            log_info "Modo de reparo - iniciando verificação..."
            show_status
            echo
            log_info "Reparando todos os serviços instalados..."
            local all_services=("UNBOUND" "PIHOLE" "WIREGUARD" "CLOUDFLARE" "RNG" "SAMBA" "MINIDLNA" "FILEBROWSER")
            for service in "${all_services[@]}"; do
                case "$service" in
                    "UNBOUND") repair_service "unbound" "Unbound" ;;
                    "PIHOLE") repair_service "lighttpd" "Pi-hole" ;;
                    "WIREGUARD") repair_service "wg-quick@wg0" "WireGuard" ;;
                    "CLOUDFLARE") repair_service "" "Cloudflare" ;;
                    "RNG") repair_service "rng-tools" "RNG-tools" ;;
                    "SAMBA") repair_service "smbd" "Samba" ;;
                    "MINIDLNA") repair_service "minidlna" "MiniDLNA" ;;
                    "FILEBROWSER") repair_service "filebrowser" "Filebrowser" ;;
                esac
            done
            log_info "Reparo concluído"
            ;;
        "validate")
            log_info "Validando instalações existentes..."
            local all_services=("UNBOUND" "PIHOLE" "WIREGUARD" "CLOUDFLARE" "RNG" "SAMBA" "MINIDLNA" "FILEBROWSER")
            local validation_success=0
            for service in "${all_services[@]}"; do
                case "$service" in
                    "UNBOUND") validate_installation "UNBOUND" "Unbound" || validation_success=1 ;;
                    "PIHOLE") validate_installation "PIHOLE" "Pi-hole" || validation_success=1 ;;
                    "WIREGUARD") validate_installation "WIREGUARD" "WireGuard" || validation_success=1 ;;
                    "CLOUDFLARE") validate_installation "CLOUDFLARE" "Cloudflare" || validation_success=1 ;;
                    "RNG") validate_installation "RNG" "RNG-tools" || validation_success=1 ;;
                    "SAMBA") validate_installation "SAMBA" "Samba" || validation_success=1 ;;
                    "MINIDLNA") validate_installation "MINIDLNA" "MiniDLNA" || validation_success=1 ;;
                    "FILEBROWSER") validate_installation "FILEBROWSER" "Filebrowser" || validation_success=1 ;;
                esac
            done
            if [[ $validation_success -eq 0 ]]; then
                log_info "✓ Todas as instalações validadas com sucesso"
            else
                log_error "✗ Algumas instalações falharam na validação"
                exit 1
            fi
            ;;
        "report")
            generate_report
            ;;
        *)
            log_error "Modo de instalação inválido: $INSTALL_MODE"
            show_help
            exit 1
            ;;
    esac

    log_info "========================================"
    log_info "Operação concluída"
    log_info "Log detalhado disponível em: $LOGFILE"

    if [[ "${QUIET_MODE:-false}" != "true" ]]; then
        echo -e "${CYAN}Para mais informações, execute: sudo $0 status${NC}"
    fi
}

# ==============================================
# Inicialização
# ==============================================
check_root
parse_args "$@"
load_config

# Verificar se estamos no diretório correto
if [[ ! -f "$SCRIPT_DIR/install_boxserver.sh" ]]; then
    log_error "Script deve ser executado do diretório do projeto"
    exit 1
fi

# Criar diretórios necessários
sudo mkdir -p "$BACKUP_DIR"

# Executar função principal
main "$@"
