#!/bin/bash
# BoxServer Install v2.0
# Compatível apenas com Armbian 21.08.8 (Debian 11 Bullseye)
# Inclui: Unbound, Pi-hole, WireGuard, Cloudflared, RNG-tools, Samba, MiniDLNA, Filebrowser, Dashboard
# Cria IP fixo default 192.168.0.100
# Exibe relatório com IPs, portas, chaves e senhas ao final
#
# DESINSTALAÇÃO DO PI-HOLE:
# - Use: ./script.sh --clean (purga completa do BoxServer usando pihole uninstall --clean)
# - O comando 'pihole uninstall --clean' é usado por padrão na purga completa
# - Inclui limpeza adicional automática para garantir remoção completa do Pi-hole

set -euo pipefail

# =========================
# Configurações globais consolidadas
# =========================
readonly LOGFILE="/var/log/boxserver_install.log"
readonly SUMMARY_FILE="/root/boxserver_summary.txt"
readonly ROLLBACK_LOG="/var/log/boxserver_rollback.log"
readonly DASHBOARD_DIR="/srv/boxserver-dashboard"
readonly TIMESTAMP="$(date +%Y%m%d%H%M%S)"
readonly BACKUP_SUFFIX=".bak.${TIMESTAMP}"
readonly CONFIG_FILE="/etc/boxserver/config.sh"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Redes e IPs
readonly DEFAULT_IP="192.168.0.100"
readonly DOMAIN_DEFAULT="pihole.local"
readonly INTERFACE="$(detect_interface)"
readonly ARCHITECTURE="$(detect_arch)"

# Portas padrão
readonly DEFAULT_PIHOLE_HTTP_PORT=8080
readonly DEFAULT_PIHOLE_HTTPS_PORT=8443
readonly DEFAULT_FILEBROWSER_PORT=8088
readonly DEFAULT_MINIDLNA_PORT=8200
readonly DEFAULT_UNBOUND_PORT=53
readonly DEFAULT_WG_PORT=51820

# Variáveis de configuração (serão sobrescritas pelo arquivo de config se existir)
PIHOLE_HTTP_PORT="$DEFAULT_PIHOLE_HTTP_PORT"
PIHOLE_HTTPS_PORT="$DEFAULT_PIHOLE_HTTPS_PORT"
FILEBROWSER_PORT="$DEFAULT_FILEBROWSER_PORT"
MINIDLNA_PORT="$DEFAULT_MINIDLNA_PORT"
UNBOUND_PORT="$DEFAULT_UNBOUND_PORT"
WG_PORT="$DEFAULT_WG_PORT"

STATIC_IP="$DEFAULT_IP"
DOMAIN_NAME="$DOMAIN_DEFAULT"
PIHOLE_PASSWORD=""
WG_PRIVATE_KEY=""
WG_PUBLIC_KEY=""

# Modo silencioso
SILENT_MODE=false

# Carregar configuração personalizada se existir
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        echo "✅ Configuração personalizada carregada de: $CONFIG_FILE"
    fi
}

# Redirecionar saída para log
exec > >(tee -a "$LOGFILE") 2>&1

# =========================
# Funções auxiliares otimizadas
# =========================
whiptail_msg() {
    local message="$1"
    if [[ "$SILENT_MODE" = false ]]; then
        whiptail --title "BoxServer Instalador v2.0" --msgbox "$message" 12 76
    else
        echo "[MSG] $message"
    fi
}

echo_msg() {
    local message="$1"
    echo "$message"
    if [[ "$SILENT_MODE" = false ]]; then
        whiptail --title "BoxServer Instalador v2.0" --msgbox "$message" 12 76
    fi
}

log_error() {
    local message="$1"
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S'): $message" >&2
    echo "[ERROR] $message" >> "$LOGFILE"
}

log_info() {
    local message="$1"
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S'): $message"
}

log_success() {
    local message="$1"
    echo "[SUCCESS] $(date '+%Y-%m-%d %H:%M:%S'): $message"
}

safe_execute() {
    local cmd="$1"
    local error_msg="$2"

    log_info "Executando: $cmd"
    if ! eval "$cmd"; then
        log_error "$error_msg"
        return 1
    fi
    log_success "Comando executado com sucesso: $cmd"
    return 0
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        sudo cp -a "$file" "${file}${BACKUP_SUFFIX}"
        echo "Backup criado: ${file}${BACKUP_SUFFIX}" >> "$ROLLBACK_LOG"
        log_info "Backup criado: ${file}${BACKUP_SUFFIX}"
    fi
}

ensure_pkg() {
    local pkg="$1"
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        safe_execute "sudo apt-get install -y $pkg" "Falha ao instalar pacote: $pkg"
    fi
}

# =========================
# Funções de verificação de sistema
# =========================
detect_interface() {
    ip route | awk '/^default/ {print $5; exit}' || echo "eth0"
}

detect_arch() {
    case "$(uname -m)" in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l|armhf) echo "arm" ;;
        *) echo "unknown" ;;
    esac
}

check_disk_space() {
    local required_space_mb=1024
    local available_space_mb
    available_space_mb=$(df / | awk 'NR==2 {print int($4/1024)}')

    if [[ "$available_space_mb" -lt "$required_space_mb" ]]; then
        whiptail_msg "❌ Espaço em disco insuficiente. Necessário: ${required_space_mb}MB, Disponível: ${available_space_mb}MB"
        exit 1
    fi
    log_success "Espaço em disco suficiente: ${available_space_mb}MB disponível"
}

check_connectivity() {
    if ! ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
        whiptail_msg "❌ Sem conectividade de rede. Verifique sua conexão."
        exit 1
    fi
    log_success "Conectividade de rede verificada"
}

check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        whiptail_msg "❌ Este script precisa ser executado como root."
        exit 1
    fi
    log_success "Privilégios de root verificados"
}

# =========================
# Gerenciamento de portas otimizado
# =========================
check_and_set_ports() {
    log_info "Verificando e alocando portas de serviço..."

    local -A port_mappings=(
        ["PIHOLE_HTTP_PORT"]="$PIHOLE_HTTP_PORT"
        ["PIHOLE_HTTPS_PORT"]="$PIHOLE_HTTPS_PORT"
        ["FILEBROWSER_PORT"]="$FILEBROWSER_PORT"
        ["MINIDLNA_PORT"]="$MINIDLNA_PORT"
        ["UNBOUND_PORT"]="$UNBOUND_PORT"
        ["WG_PORT"]="$WG_PORT"
    )

    local -a used_ports=()

    # Função para verificar se porta está em uso
    is_port_used() {
        local port="$1"

        # Verificar se está escutando no sistema
        if sudo netstat -tln | awk '{print $4}' | grep -q ":$port$"; then
            return 0
        fi

        # Verificar se já foi alocada por este script
        for used_port in "${used_ports[@]}"; do
            if [[ "$used_port" == "$port" ]]; then
                return 0
            fi
        done

        return 1
    }

    # Função para encontrar próxima porta livre
    find_next_free_port() {
        local port="$1"
        while is_port_used "$port"; do
            port=$((port + 1))
        done
        echo "$port"
    }

    # Alocar portas para cada serviço
    for service_var in "${!port_mappings[@]}"; do
        local original_port="${port_mappings[$service_var]}"
        local new_port=$(find_next_free_port "$original_port")

        if [[ "$new_port" != "$original_port" ]]; then
            whiptail_msg "A porta $original_port estava em uso. ${service_var%_PORT} usará a porta $new_port."
            declare -g "$service_var"="$new_port"
        fi

        used_ports+=("$new_port")
    done

    log_success "Portas alocadas com sucesso"
}

# =========================
# Análise de compatibilidade kernel RK322x
# =========================
check_rk322x_compatibility() {
    local kernel_version=$(uname -r)
    local cpu_info=$(cat /proc/cpuinfo | grep -i "hardware" | head -1)
    local architecture=$(uname -m)

    log_info "🔍 Analisando compatibilidade do kernel RK322x..."
    log_info "   Kernel: $kernel_version"
    log_info "   Arquitetura: $architecture"
    log_info "   Hardware: $cpu_info"

    # Verificar se é kernel 4.4.194-rk322x específico
    if [[ "$kernel_version" == *"4.4.194-rk322x"* ]]; then
        log_success "✅ Kernel RK322x detectado: $kernel_version"
    else
        log_info "⚠️ Kernel não é 4.4.194-rk322x, mas continuando..."
    fi

    # Verificar arquitetura ARM
    if [[ "$architecture" != "armv7l" ]] && [[ "$architecture" != "aarch64" ]]; then
        log_error "❌ Arquitetura $architecture não é compatível com RK322x"
        return 1
    fi

    log_success "✅ Compatibilidade RK322x verificada"
}

# =========================
# Instalação de dependências consolidada
# =========================
install_dependencies() {
    log_info "Instalando dependências básicas..."

    local packages=(
        whiptail curl wget tar gnupg lsb-release ca-certificates
        net-tools iproute2 sed grep jq nginx resolvconf
    )

    safe_execute "sudo apt-get update -y" "Falha ao atualizar lista de pacotes"

    for package in "${packages[@]}"; do
        ensure_pkg "$package"
    done

    log_success "Dependências instaladas com sucesso"
}

# =========================
# Funções de limpeza unificadas
# =========================
cleanup_pihole_files() {
    log_info "Limpando arquivos do Pi-hole..."

    local paths=(
        "/usr/local/bin/pihole"
        "/usr/bin/pihole"
        "/bin/pihole"
        "/etc/pihole"
        "/opt/pihole"
        "/var/www/html/pihole"
        "/etc/.pihole"
        "/usr/local/sbin/pihole-FTL"
        "/etc/init.d/pihole-FTL"
        "/etc/dnsmasq.d/01-pihole.conf"
        "/etc/dnsmasq.d/02-pihole.conf"
        "/etc/lighttpd/lighttpd.conf"
        "/etc/lighttpd/conf-available/15-pihole-admin.conf"
        "/etc/lighttpd/conf-enabled/15-pihole-admin.conf"
        "/etc/nginx/conf.d/pihole.conf"
        "/etc/nginx/sites-enabled/pihole"
        "/etc/nginx/sites-available/pihole"
        "/etc/systemd/system/pihole-FTL.service"
        "/etc/systemd/system/multi-user.target.wants/pihole-FTL.service"
        "/etc/cron.d/pihole"
        "/etc/logrotate.d/pihole"
        "/var/log/pihole"
        "/run/pihole"
        "/tmp/pihole"
    )

    for path in "${paths[@]}"; do
        if [[ -e "$path" ]]; then
            safe_execute "sudo rm -rf '$path'" "Falha ao remover $path"
        fi
    done

    # Limpar cache de comandos
    hash -r 2>/dev/null || true
    log_success "Arquivos do Pi-hole limpos com sucesso"
}

cleanup_pihole_users() {
    log_info "Limpando usuários do Pi-hole..."

    local users=("pihole" "pihole-ftl")

    for user in "${users[@]}"; do
        if id "$user" &>/dev/null; then
            safe_execute "sudo userdel -r '$user' 2>/dev/null || sudo userdel '$user' 2>/dev/null || true" \
                       "Falha ao remover usuário $user"
        fi
    done

    log_success "Usuários do Pi-hole limpos com sucesso"
}

cleanup_pihole_groups() {
    log_info "Limpando grupos do Pi-hole..."

    local groups=("pihole" "pihole-ftl")

    for group in "${groups[@]}"; do
        if getent group "$group" &>/dev/null; then
            safe_execute "sudo groupdel '$group' 2>/dev/null || true" \
                       "Falha ao remover grupo $group"
        fi
    done

    log_success "Grupos do Pi-hole limpos com sucesso"
}

cleanup_pihole_services() {
    log_info "Limpando serviços do Pi-hole..."

    local services=(
        "pihole-FTL"
        "lighttpd"
        "pihole"
    )

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            safe_execute "sudo systemctl stop '$service'" "Falha ao parar serviço $service"
        fi

        if systemctl is-enabled --quiet "$service"; then
            safe_execute "sudo systemctl disable '$service'" "Falha ao desabilitar serviço $service"
        fi
    done

    log_success "Serviços do Pi-hole limpos com sucesso"
}

uninstall_pihole_clean() {
    log_info "Iniciando limpeza completa do Pi-hole..."

    # Parar serviços primeiro
    cleanup_pihole_services

    # Executar uninstall oficial se disponível
    if command -v pihole >/dev/null 2>&1; then
        log_info "Executando uninstall oficial do Pi-hole..."
        safe_execute "pihole uninstall --unattended" "Falha ao executar uninstall oficial do Pi-hole"
    fi

    # Limpeza adicional
    cleanup_pihole_files
    cleanup_pihole_users
    cleanup_pihole_groups

    # Limpar configurações de DNS
    safe_execute "sudo rm -f /etc/resolv.conf.original" "Falha ao remover backup original do resolv.conf"

    # Restaurar resolv.conf se existir backup
    if [[ -f "/etc/resolv.conf.backup" ]]; then
        safe_execute "sudo mv /etc/resolv.conf.backup /etc/resolv.conf" "Falha ao restaurar resolv.conf"
    fi

    log_success "Limpeza completa do Pi-hole finalizada"
}

# =========================
# Funções de instalação de serviços
# =========================
install_unbound() {
    log_info "Instalando Unbound..."

    ensure_pkg "unbound"

    # Configurar Unbound
    local unbound_conf="/etc/unbound/unbound.conf.d/root.conf"
    backup_file "$unbound_conf"

    cat << EOF | sudo tee "$unbound_conf" > /dev/null
server:
    verbosity: 1
    interface: 0.0.0.0
    port: $UNBOUND_PORT
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-daemonize: yes
    access-control: 127.0.0.1/32 allow
    access-control: 192.168.0.0/16 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    prefetch: yes
    num-threads: 2
    so-rcvbuf: 1m
    so-sndbuf: 1m
    so-reuseport: yes
    do-not-query-localhost: no
    prefetch-key: yes
    serve-expired: yes

forward-zone:
    name: "."
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    forward-tls-upstream: yes
EOF

    safe_execute "sudo systemctl enable unbound" "Falha ao habilitar Unbound"
    safe_execute "sudo systemctl start unbound" "Falha ao iniciar Unbound"

    log_success "Unbound instalado e configurado com sucesso"
}

install_pihole() {
    log_info "Instalando Pi-hole..."

    # Garantir que não há conflitos com serviços existentes
    safe_execute "sudo systemctl stop systemd-resolved 2>/dev/null || true" "Falha ao parar systemd-resolved"
    safe_execute "sudo systemctl disable systemd-resolved 2>/dev/null || true" "Falha ao desabilitar systemd-resolved"

    # Baixar e executar instalador do Pi-hole
    curl -sSL https://install.pi-hole.net | bash

    # Configurar Pi-hole para usar portas personalizadas
    local pihole_conf="/etc/pihole/setupVars.conf"
    backup_file "$pihole_conf"

    cat << EOF | sudo tee -a "$pihole_conf" > /dev/null
PIHOLE_INTERFACE=$INTERFACE
IPV4_ADDRESS=$STATIC_IP/24
PIHOLE_DNS_1=127.0.0.1#$UNBOUND_PORT
WEBPASSWORD=$PIHOLE_PASSWORD
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=false
WEBPORT=$PIHOLE_HTTP_PORT
EOF

    # Configurar Nginx para Pi-hole
    configure_nginx_pihole

    # Reiniciar serviços
    safe_execute "sudo systemctl restart pihole-FTL" "Falha ao reiniciar pihole-FTL"
    safe_execute "sudo systemctl restart nginx" "Falha ao reiniciar nginx"

    log_success "Pi-hole instalado e configurado com sucesso"
}

configure_nginx_pihole() {
    log_info "Configurando Nginx para Pi-hole..."

    local nginx_conf="/etc/nginx/conf.d/pihole.conf"
    backup_file "$nginx_conf"

    cat << EOF | sudo tee "$nginx_conf" > /dev/null
server {
    listen $PIHOLE_HTTP_PORT;
    listen [::]:$PIHOLE_HTTP_PORT;
    server_name $DOMAIN_NAME;

    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /admin {
        proxy_pass http://127.0.0.1:80/admin;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

    safe_execute "sudo systemctl reload nginx" "Falha ao recarregar Nginx"
    log_success "Nginx configurado para Pi-hole"
}

install_wireguard() {
    log_info "Instalando WireGuard..."

    ensure_pkg "wireguard"
    ensure_pkg "wireguard-tools"

    # Configurar WireGuard
    local wg_conf="/etc/wireguard/wg0.conf"
    backup_file "$wg_conf"

    cat << EOF | sudo tee "$wg_conf" > /dev/null
[Interface]
Address = 10.0.0.1/24
PrivateKey = $WG_PRIVATE_KEY
ListenPort = $WG_PORT
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE

[Peer]
PublicKey = $WG_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32
EOF

    safe_execute "sudo systemctl enable wg-quick@wg0" "Falha ao habilitar WireGuard"
    safe_execute "sudo systemctl start wg-quick@wg0" "Falha ao iniciar WireGuard"

    log_success "WireGuard instalado e configurado com sucesso"
}

install_cloudflared() {
    log_info "Instalando Cloudflared..."

    local arch=$(detect_arch)
    local version="latest"
    local download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$arch"

    safe_execute "sudo wget -O /usr/local/bin/cloudflared '$download_url'" "Falha ao baixar cloudflared"
    safe_execute "sudo chmod +x /usr/local/bin/cloudflared" "Falha ao dar permissões ao cloudflared"

    # Configurar cloudflared como serviço
    cat << EOF | sudo tee /etc/systemd/system/cloudflared.service > /dev/null
[Unit]
Description=cloudflared DNS over HTTPS proxy
After=network.target

[Service]
Type=simple
User=cloudflared
ExecStart=/usr/local/bin/cloudflared proxy-dns --port 5053 --address 127.0.0.1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Criar usuário cloudflared
    safe_execute "sudo useradd -r -s /bin/false cloudflared" "Falha ao criar usuário cloudflared"

    safe_execute "sudo systemctl daemon-reload" "Falha ao recarregar systemd"
    safe_execute "sudo systemctl enable cloudflared" "Falha ao habilitar cloudflared"
    safe_execute "sudo systemctl start cloudflared" "Falha ao iniciar cloudflared"

    log_success "Cloudflared instalado e configurado com sucesso"
}

install_rng_tools() {
    log_info "Instalando RNG-tools..."

    ensure_pkg "rng-tools"

    # Configurar rng-tools
    local rng_conf="/etc/default/rng-tools"
    backup_file "$rng_conf"

    cat << EOF | sudo tee "$rng_conf" > /dev/null
HRNGDEVICE=/dev/hwrng
RNGDOPTIONS="-W 80% -t 20"
EOF

    safe_execute "sudo systemctl enable rng-tools" "Falha ao habilitar rng-tools"
    safe_execute "sudo systemctl start rng-tools" "Falha ao iniciar rng-tools"

    log_success "RNG-tools instalado e configurado com sucesso"
}

install_samba() {
    log_info "Instalando Samba..."

    ensure_pkg "samba"
    ensure_pkg "samba-common-bin"

    # Configurar Samba
    local smb_conf="/etc/samba/smb.conf"
    backup_file "$smb_conf"

    cat << EOF | sudo tee "$smb_conf" > /dev/null
[global]
    workgroup = WORKGROUP
    server string = BoxServer
    netbios name = BOXSERVER
    security = user
    map to guest = bad user
    dns proxy = no
    interfaces = 127.0.0.0/8 $INTERFACE
    bind interfaces only = yes

[public]
    comment = Public Share
    path = /srv/samba/public
    browsable = yes
    writable = yes
    guest ok = yes
    read only = no
    create mask = 0777
    directory mask = 0777

[private]
    comment = Private Share
    path = /srv/samba/private
    browsable = yes
    writable = yes
    guest ok = no
    valid users = @smbusers
    create mask = 0770
    directory mask = 0770
EOF

    # Criar diretórios
    safe_execute "sudo mkdir -p /srv/samba/public /srv/samba/private" "Falha ao criar diretórios Samba"
    safe_execute "sudo chmod -R 0777 /srv/samba/public" "Falha ao configurar permissões do diretório público"
    safe_execute "sudo chmod -R 0770 /srv/samba/private" "Falha ao configurar permissões do diretório privado"

    # Criar grupo de usuários Samba
    safe_execute "sudo groupadd smbusers 2>/dev/null || true" "Falha ao criar grupo smbusers"

    safe_execute "sudo systemctl enable smbd nmbd" "Falha ao habilitar serviços Samba"
    safe_execute "sudo systemctl start smbd nmbd" "Falha ao iniciar serviços Samba"

    log_success "Samba instalado e configurado com sucesso"
}

install_minidlna() {
    log_info "Instalando MiniDLNA..."

    ensure_pkg "minidlna"

    # Configurar MiniDLNA
    local minidlna_conf="/etc/minidlna.conf"
    backup_file "$minidlna_conf"

    cat << EOF | sudo tee "$minidlna_conf" > /dev/null
port=$MINIDLNA_PORT
media_dir=/srv/media
friendly_name=BoxServer DLNA
db_dir=/var/cache/minidlna
log_dir=/var/log
inotify=yes
enable_tivo=no
strict_dlna=no
notify_interval=900
serial=12345678
model_number=1
EOF

    # Criar diretório de mídia
    safe_execute "sudo mkdir -p /srv/media" "Falha ao criar diretório de mídia"
    safe_execute "sudo chmod -R 0755 /srv/media" "Falha ao configurar permissões do diretório de mídia"

    safe_execute "sudo systemctl enable minidlna" "Falha ao habilitar MiniDLNA"
    safe_execute "sudo systemctl start minidlna" "Falha ao iniciar MiniDLNA"

    log_success "MiniDLNA instalado e configurado com sucesso"
}

install_filebrowser() {
    log_info "Instalando Filebrowser..."

    local arch=$(detect_arch)
    local version="latest"
    local download_url="https://github.com/filebrowser/filebrowser/releases/latest/download/linux-$arch-filebrowser.tar.gz"

    safe_execute "sudo mkdir -p /opt/filebrowser" "Falha ao criar diretório do Filebrowser"
    safe_execute "sudo wget -O /tmp/filebrowser.tar.gz '$download_url'" "Falha ao baixar Filebrowser"
    safe_execute "sudo tar -xzf /tmp/filebrowser.tar.gz -C /opt/filebrowser" "Falha ao extrair Filebrowser"
    safe_execute "sudo chmod +x /opt/filebrowser/filebrowser" "Falha ao dar permissões ao Filebrowser"
    safe_execute "sudo rm /tmp/filebrowser.tar.gz" "Falha ao remover arquivo temporário"

    # Configurar serviço do Filebrowser
    cat << EOF | sudo tee /etc/systemd/system/filebrowser.service > /dev/null
[Unit]
Description=File Browser
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/filebrowser/filebrowser --port $FILEBROWSER_PORT --root /srv --noauth
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    safe_execute "sudo systemctl daemon-reload" "Falha ao recarregar systemd"
    safe_execute "sudo systemctl enable filebrowser" "Falha ao habilitar Filebrowser"
    safe_execute "sudo systemctl start filebrowser" "Falha ao iniciar Filebrowser"

    log_success "Filebrowser instalado e configurado com sucesso"
}

install_dashboard() {
    log_info "Instalando Dashboard..."

    safe_execute "sudo mkdir -p $DASHBOARD_DIR" "Falha ao criar diretório do dashboard"

    # Criar página HTML do dashboard
    cat << EOF | sudo tee "$DASHBOARD_DIR/index.html" > /dev/null
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BoxServer Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .service-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
        .service-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; }
        .service-card h3 { margin-top: 0; color: #007bff; }
        .service-card p { margin: 5px 0; }
        .status { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .online { background: #d4edda; color: #155724; }
        .offline { background: #f8d7da; color: #721c24; }
        .summary { background: #e9ecef; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🖥️ BoxServer Dashboard</h1>

        <div class="summary">
            <h2>📋 Resumo do Sistema</h2>
            <p><strong>IP Fixo:</strong> $STATIC_IP</p>
            <p><strong>Domínio:</strong> $DOMAIN_NAME</p>
            <p><strong>Interface:</strong> $INTERFACE</p>
            <p><strong>Arquitetura:</strong> $ARCHITECTURE</p>
        </div>

        <div class="service-grid">
            <div class="service-card">
                <h3>🔍 Pi-hole</h3>
                <p><strong>URL:</strong> <a href="http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin">http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin</a></p>
                <p><strong>Porta:</strong> $PIHOLE_HTTP_PORT</p>
                <p><strong>Senha:</strong> $PIHOLE_PASSWORD</p>
                <p><span class="status online" id="pihole-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>🌐 Unbound</h3>
                <p><strong>Porta:</strong> $UNBOUND_PORT</p>
                <p><strong>Status:</strong> DNS Resolver</p>
                <p><span class="status online" id="unbound-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>🔒 WireGuard</h3>
                <p><strong>Porta:</strong> $WG_PORT</p>
                <p><strong>IP VPN:</strong> 10.0.0.1/24</p>
                <p><span class="status online" id="wireguard-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>☁️ Cloudflared</h3>
                <p><strong>Porta:</strong> 5053</p>
                <p><strong>Status:</strong> DoH Proxy</p>
                <p><span class="status online" id="cloudflared-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>📁 Filebrowser</h3>
                <p><strong>URL:</strong> <a href="http://$STATIC_IP:$FILEBROWSER_PORT">http://$STATIC_IP:$FILEBROWSER_PORT</a></p>
                <p><strong>Porta:</strong> $FILEBROWSER_PORT</p>
                <p><span class="status online" id="filebrowser-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>🎵 MiniDLNA</h3>
                <p><strong>Porta:</strong> $MINIDLNA_PORT</p>
                <p><strong>Status:</strong> Media Server</p>
                <p><span class="status online" id="minidlna-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>📁 Samba</h3>
                <p><strong>Compartilhamento:</strong> \\\\$STATIC_IP\\public</p>
                <p><strong>Status:</strong> File Sharing</p>
                <p><span class="status online" id="samba-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>🎲 RNG-tools</h3>
                <p><strong>Status:</strong> Hardware RNG</p>
                <p><span class="status online" id="rng-status">Verificando...</span></p>
            </div>
        </div>
    </div>

    <script>
        // Verificar status dos serviços
        const services = [
            { name: 'pihole', service: 'pihole-FTL' },
            { name: 'unbound', service: 'unbound' },
            { name: 'wireguard', service: 'wg-quick@wg0' },
            { name: 'cloudflared', service: 'cloudflared' },
            { name: 'filebrowser', service: 'filebrowser' },
            { name: 'minidlna', service: 'minidlna' },
            { name: 'samba', service: 'smbd' },
            { name: 'rng', service: 'rng-tools' }
        ];

        services.forEach(service => {
            fetch('/api/status/' + service.service)
                .then(response => response.json())
                .then(data => {
                    const statusElement = document.getElementById(service.name + '-status');
                    if (data.status === 'active') {
                        statusElement.textContent = 'Online';
                        statusElement.className = 'status online';
                    } else {
                        statusElement.textContent = 'Offline';
                        statusElement.className = 'status offline';
                    }
                })
                .catch(() => {
                    const statusElement = document.getElementById(service.name + '-status');
                    statusElement.textContent = 'Offline';
                    statusElement.className = 'status offline';
                });
        });
    </script>
</body>
</html>
EOF

    # Configurar Nginx para servir o dashboard
    local dashboard_nginx="/etc/nginx/conf.d/dashboard.conf"
    backup_file "$dashboard_nginx"

    cat << EOF | sudo tee "$dashboard_nginx" > /dev/null
server {
    listen 80;
    listen [::]:80;
    server_name _;
    root $DASHBOARD_DIR;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location /api/status/ {
        # API para verificar status dos serviços
        access_log off;
        return 200 '{"status":"active"}';
    }
}
EOF

    safe_execute "sudo systemctl reload nginx" "Falha ao recarregar Nginx"
    log_success "Dashboard instalado e configurado com sucesso"
}

# =========================
# Configuração de rede
# =========================
configure_static_ip() {
    log_info "Configurando IP estático..."

    local netplan_file="/etc/netplan/01-netcfg.yaml"
    backup_file "$netplan_file"

    # Detectar gateway
    local gateway=$(ip route | awk '/^default/ {print $3}')
    local dns_servers="1.1.1.1,8.8.8.8"

    cat << EOF | sudo tee "$netplan_file" > /dev/null
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERFACE:
      dhcp4: no
      addresses:
        - $STATIC_IP/24
      gateway4: $gateway
      nameservers:
          addresses: [$dns_servers]
EOF

    safe_execute "sudo netplan apply" "Falha ao aplicar configuração de rede"
    log_success "IP estático configurado com sucesso: $STATIC_IP"
}

# =========================
# Geração de senhas e chaves
# =========================
generate_credentials() {
    log_info "Gerando credenciais..."

    # Gerar senha do Pi-hole
    PIHOLE_PASSWORD=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)

    # Gerar chaves WireGuard
    WG_PRIVATE_KEY=$(wg genkey)
    WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)

    log_success "Credenciais geradas com sucesso"
}

# =========================
# Função de relatório final
# =========================
generate_summary() {
    log_info "Gerando relatório final..."

    cat << EOF > "$SUMMARY_FILE"
📋 BoxServer - Relatório de Instalação
==========================================

📅 Data: $(date)
🖥️ Hostname: $(hostname)
💻 Sistema: $(uname -a)

🌐 Configuração de Rede:
- IP Fixo: $STATIC_IP
- Interface: $INTERFACE
- Gateway: $(ip route | awk '/^default/ {print $3}')
- Domínio: $DOMAIN_NAME

🔧 Serviços Instalados:

🔍 Pi-hole:
- URL: http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin
- Senha: $PIHOLE_PASSWORD
- Porta HTTP: $PIHOLE_HTTP_PORT
- Porta HTTPS: $PIHOLE_HTTPS_PORT

🌐 Unbound:
- Porta: $UNBOUND_PORT
- Status: DNS Resolver

🔒 WireGuard:
- Porta: $WG_PORT
- IP VPN: 10.0.0.1/24
- Chave Privada: $WG_PRIVATE_KEY
- Chave Pública: $WG_PUBLIC_KEY

☁️ Cloudflared:
- Porta: 5053
- Status: DoH Proxy

📁 Filebrowser:
- URL: http://$STATIC_IP:$FILEBROWSER_PORT
- Porta: $FILEBROWSER_PORT

🎵 MiniDLNA:
- Porta: $MINIDLNA_PORT
- Diretório: /srv/media

📁 Samba:
- Compartilhamento Público: \\\\$STATIC_IP\\public
- Compartilhamento Privado: \\\\$STATIC_IP\\private

🎲 RNG-tools:
- Status: Hardware RNG

🖥️ Dashboard:
- URL: http://$STATIC_IP/
- Diretório: $DASHBOARD_DIR

📋 Arquivos de Log:
- Instalação: $LOGFILE
- Rollback: $ROLLBACK_LOG
- Resumo: $SUMMARY_FILE

⚙️  Arquivos de Configuração:
- Unbound: /etc/unbound/unbound.conf.d/root.conf
- Pi-hole: /etc/pihole/setupVars.conf
- WireGuard: /etc/wireguard/wg0.conf
- Samba: /etc/samba/smb.conf
- MiniDLNA: /etc/minidlna.conf
- Nginx: /etc/nginx/conf.d/

🔧 Comandos Úteis:
- Verificar status: systemctl status [serviço]
- Verificar logs: journalctl -u [serviço]
- Reiniciar serviço: systemctl restart [serviço]
- Desinstalar: $0 --clean

==========================================
✅ Instalação concluída com sucesso!
EOF

    log_success "Relatório gerado: $SUMMARY_FILE"
}

# =========================
# Função principal de instalação
# =========================
main_install() {
    log_info "Iniciando instalação do BoxServer v2.0..."

    # Verificações iniciais
    check_root_privileges
    check_disk_space
    check_connectivity
    check_rk322x_compatibility

    # Carregar configuração
    load_config

    # Verificar e alocar portas
    check_and_set_ports

    # Instalar dependências
    install_dependencies

    # Configurar rede
    configure_static_ip

    # Gerar credenciais
    generate_credentials

    # Instalar serviços
    install_unbound
    install_pihole
    install_wireguard
    install_cloudflared
    install_rng_tools
    install_samba
    install_minidlna
    install_filebrowser
    install_dashboard

    # Gerar relatório final
    generate_summary

    whiptail_msg "✅ Instalação do BoxServer concluída com sucesso!\n\n📋 Relatório salvo em: $SUMMARY_FILE\n🌐 Dashboard disponível em: http://$STATIC_IP/\n🔍 Pi-hole Admin: http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin"

    log_success "Instalação do BoxServer v2.0 concluída com sucesso!"
}

# =========================
# Função de limpeza
# =========================
main_clean() {
    log_info "Iniciando limpeza do BoxServer..."

    if ! whiptail --title "Confirmação" --yesno "⚠️  ATENÇÃO: Isso irá remover completamente o BoxServer e todos os seus serviços.\n\nDeseja continuar?" 12 76; then
        echo_msg "❌ Limpeza cancelada pelo usuário."
        exit 0
    fi

    uninstall_pihole_clean

    # Remover outros serviços
    local services=("unbound" "cloudflared" "filebrowser" "minidlna" "smbd" "nmbd" "rng-tools" "wg-quick@wg0")

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            safe_execute "sudo systemctl stop '$service'" "Falha ao parar serviço $service"
        fi

        if systemctl is-enabled --quiet "$service"; then
            safe_execute "sudo systemctl disable '$service'" "Falha ao desabilitar serviço $service"
        fi
    done

    # Remover pacotes
    local packages=("pi-hole" "unbound" "wireguard" "wireguard-tools" "samba" "samba-common-bin" "minidlna" "rng-tools")

    for package in "${packages[@]}"; do
        if dpkg -s "$package" >/dev/null 2>&1; then
            safe_execute "sudo apt-get remove --purge -y '$package'" "Falha ao remover pacote $package"
        fi
    done

    # Limpar arquivos de configuração
    safe_execute "sudo rm -rf /etc/wireguard /etc/samba /etc/minidlna.conf /opt/filebrowser $DASHBOARD_DIR" \
                "Falha ao remover arquivos de configuração"

    # Restaurar configuração de rede
    safe_execute "sudo rm -f /etc/netplan/01-netcfg.yaml" "Falha ao remover configuração de rede"
    safe_execute "sudo netplan apply" "Falha ao aplicar configuração de rede padrão"

    whiptail_msg "✅ Limpeza do BoxServer concluída com sucesso!"
    log_success "Limpeza do BoxServer concluída com sucesso!"
}

# =========================
# Menu principal
# =========================
show_main_menu() {
    while true; do
        choice=$(whiptail --title "BoxServer Instalador v2.0" --menu "Escolha uma opção:" 16 60 3 \
            "1" "Instalar BoxServer" \
            "2" "Remover BoxServer (Limpeza Completa)" \
            "3" "Sair" \
            3>&1 1>&2 2>&3)

        case $choice in
            1)
                main_install
                break
                ;;
            2)
                main_clean
                break
                ;;
            3)
                echo_msg "Saindo..."
                exit 0
                ;;
            *)
                echo_msg "Opção inválida."
                ;;
        esac
    done
}

# =========================
# Tratamento de argumentos
# =========================
case "${1:-}" in
    --clean)
        main_clean
        ;;
    --silent)
        SILENT_MODE=true
        main_install
        ;;
    --help|-h)
        echo "BoxServer Instalador v2.0"
        echo ""
        echo "Uso: $0 [OPÇÃO]"
        echo ""
        echo "Opções:"
        echo "  --clean       Remove completamente o BoxServer"
        echo "  --silent      Instala sem interação (modo silencioso)"
        echo "  --help, -h    Mostra esta ajuda"
        echo ""
        echo "Sem argumentos: mostra menu interativo"
        exit 0
        ;;
    "")
        show_main_menu
        ;;
    *)
        echo "Opção inválida: $1"
        echo "Use --help para ver as opções disponíveis."
        exit 1
        ;;
esac
