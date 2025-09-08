#!/bin/bash
# BoxServer Installer V2 - Refactored Version
# Compatível apenas com Armbian 21.08.8 (Debian 11 Bullseye)
# Inclui: Unbound, Pi-hole, WireGuard, Cloudflared, RNG-tools, Samba, MiniDLNA, Filebrowser, Dashboard
# Cria IP fixo default 192.168.0.100
# Exibe relatório com IPs, portas, chaves e senhas ao final

set -euo pipefail

# =========================
# Configurações Globais Centralizadas
# =========================
readonly LOGFILE="/var/log/boxserver_install.log"
readonly SUMMARY_FILE="/root/boxserver_summary.txt"
readonly ROLLBACK_LOG="/var/log/boxserver_rollback.log"
readonly DASHBOARD_DIR="/srv/boxserver-dashboard"
readonly TIMESTAMP="$(date +%Y%m%d%H%M%S)"
readonly BACKUP_SUFFIX=".bak.${TIMESTAMP}"
readonly REQUIRED_DISK_SPACE_MB=1024

# Portas otimizadas para evitar conflitos
declare -A DEFAULT_PORTS=(
    ["UNBOUND"]=5335
    ["PIHOLE_HTTP"]=8081
    ["PIHOLE_HTTPS"]=8443
    ["FILEBROWSER"]=8080
    ["MINIDLNA"]=8200
    ["WIREGUARD"]=51820
    ["DASHBOARD"]=8082
)

# Serviços e pacotes
declare -a BASE_PACKAGES=("whiptail" "curl" "wget" "tar" "gnupg" "lsb-release" "ca-certificates" "net-tools" "iproute2" "sed" "grep" "jq")
declare -a OPTIONAL_PACKAGES=("nginx" "lighttpd" "samba" "minidlna" "rng-tools")

# Variáveis de estado
SILENT_MODE=false
STATIC_IP_CONFIGURED=false
declare -A SERVICE_PORTS
declare -a BACKUP_FILES=()

# =========================
# Sistema de Backup Centralizado
# =========================
backup_manager_init() {
    mkdir -p "$(dirname "$ROLLBACK_LOG")"
    echo "=== Backup Session $TIMESTAMP ===" > "$ROLLBACK_LOG"
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_path="${file}${BACKUP_SUFFIX}"
        sudo cp -a "$file" "$backup_path"
        echo "Backup criado: $backup_path" >> "$ROLLBACK_LOG"
        BACKUP_FILES+=("$file:$backup_path")
        log_info "Backup criado: $backup_path"
        return 0
    fi
    return 1
}

restore_backups() {
    log_info "Restaurando backups..."
    while IFS=':' read -r original backup; do
        if [[ -f "$backup" ]]; then
            sudo mv "$backup" "$original"
            log_info "Restaurado: $original"
        fi
    done <<< "$(printf '%s\n' "${BACKUP_FILES[@]}")"
}

# =========================
# Logging Centralizado
# =========================
log_info() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $message" | tee -a "$LOGFILE"
}

log_error() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $message" | tee -a "$LOGFILE" >&2
}

log_warn() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $message" | tee -a "$LOGFILE"
}

show_message() {
    local message="$1"
    echo "$message"
    if [[ "$SILENT_MODE" == false ]]; then
        whiptail --title "BoxServer Instalador V2" --msgbox "$message" 12 76
    fi
}

# =========================
# Sistema de Portas Unificado
# =========================
is_port_available() {
    local port="$1"
    # Verificar se a porta está em uso no sistema
    if sudo netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -q ":$port$"; then
        return 1
    fi
    # Verificar se já foi alocada por nós
    for allocated_port in "${SERVICE_PORTS[@]}"; do
        if [[ "$allocated_port" == "$port" ]]; then
            return 1
        fi
    done
    return 0
}

find_available_port() {
    local start_port="$1"
    local port="$start_port"
    while ! is_port_available "$port"; do
        port=$((port + 1))
        if [[ $port -gt $((start_port + 100)) ]]; then
            log_error "Não foi possível encontrar porta disponível próxima a $start_port"
            return 1
        fi
    done
    echo "$port"
}

allocate_ports() {
    log_info "Alocando portas para os serviços..."
    for service in "${!DEFAULT_PORTS[@]}"; do
        local default_port="${DEFAULT_PORTS[$service]}"
        local allocated_port
        allocated_port=$(find_available_port "$default_port")
        if [[ -n "$allocated_port" ]]; then
            SERVICE_PORTS["$service"]="$allocated_port"
            if [[ "$allocated_port" != "$default_port" ]]; then
                log_warn "Porta $default_port em uso, usando $allocated_port para $service"
                show_message "Porta $default_port em uso, $service usará porta $allocated_port"
            fi
        else
            log_error "Falha ao alocar porta para $service"
            exit 1
        fi
    done
}

# =========================
# Sistema de Pacotes Unificado
# =========================
install_packages() {
    local packages=("$@")
    local to_install=()

    for pkg in "${packages[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            to_install+=("$pkg")
        fi
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        log_info "Instalando pacotes: ${to_install[*]}"
        sudo apt-get update -y
        sudo apt-get install -y "${to_install[@]}"
    else
        log_info "Todos os pacotes já estão instalados"
    fi
}

remove_packages() {
    local packages=("$@")
    local to_remove=()

    for pkg in "${packages[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            to_remove+=("$pkg")
        fi
    done

    if [[ ${#to_remove[@]} -gt 0 ]]; then
        log_info "Removendo pacotes: ${to_remove[*]}"
        sudo apt-get remove --purge -y "${to_remove[@]}" 2>/dev/null || true
        sudo apt-get autoremove -y 2>/dev/null || true
    fi
}

# =========================
# Sistema de Limpeza Unificado
# =========================
clean_service() {
    local service_name="$1"
    local packages=("${@:2}")

    log_info "Limpando serviço: $service_name"

    # Parar serviços
    for pkg in "${packages[@]}"; do
        sudo systemctl stop "$pkg" 2>/dev/null || true
        sudo systemctl disable "$pkg" 2>/dev/null || true
    done

    # Remover pacotes
    remove_packages "${packages[@]}"

    # Remover arquivos de configuração
    case "$service_name" in
        "pihole")
            clean_pihole
            ;;
        "unbound")
            clean_unbound
            ;;
        "wireguard")
            clean_wireguard
            ;;
        "samba")
            clean_samba
            ;;
        "minidlna")
            clean_minidlna
            ;;
        "filebrowser")
            clean_filebrowser
            ;;
        "dashboard")
            clean_dashboard
            ;;
    esac
}

clean_pihole() {
    log_info "Limpando Pi-hole..."
    sudo pihole uninstall --unattended 2>/dev/null || true
    sudo rm -rf /etc/pihole /opt/pihole /var/www/html/admin /etc/dnsmasq.d 2>/dev/null || true
    sudo rm -f /etc/cron.d/pihole /etc/logrotate.d/pihole 2>/dev/null || true
}

clean_unbound() {
    log_info "Limpando Unbound..."
    sudo systemctl stop unbound 2>/dev/null || true
    sudo systemctl disable unbound 2>/dev/null || true
    sudo rm -rf /etc/unbound /var/lib/unbound 2>/dev/null || true
    remove_packages unbound unbound-host
}

clean_wireguard() {
    log_info "Limpando WireGuard..."
    sudo systemctl stop wg-quick@wg0 2>/dev/null || true
    sudo systemctl disable wg-quick@wg0 2>/dev/null || true
    sudo rm -f /etc/wireguard/wg0.conf 2>/dev/null || true
    remove_packages wireguard wireguard-tools
}

clean_samba() {
    log_info "Limpando Samba..."
    sudo systemctl stop smbd nmbd 2>/dev/null || true
    sudo systemctl disable smbd nmbd 2>/dev/null || true
    sudo rm -f /etc/samba/smb.conf 2>/dev/null || true
    remove_packages samba samba-common-bin
}

clean_minidlna() {
    log_info "Limpando MiniDLNA..."
    sudo systemctl stop minidlna 2>/dev/null || true
    sudo systemctl disable minidlna 2>/dev/null || true
    sudo rm -f /etc/minidlna.conf 2>/dev/null || true
    remove_packages minidlna
}

clean_filebrowser() {
    log_info "Limpando Filebrowser..."
    sudo systemctl stop filebrowser 2>/dev/null || true
    sudo systemctl disable filebrowser 2>/dev/null || true
    sudo rm -f /usr/local/bin/filebrowser /etc/systemd/system/filebrowser.service 2>/dev/null || true
    sudo systemctl daemon-reload 2>/dev/null || true
}

clean_dashboard() {
    log_info "Limpando Dashboard..."
    sudo systemctl stop boxserver-dashboard 2>/dev/null || true
    sudo systemctl disable boxserver-dashboard 2>/dev/null || true
    sudo rm -rf "$DASHBOARD_DIR" 2>/dev/null || true
    sudo rm -f /etc/systemd/system/boxserver-dashboard.service /etc/nginx/sites-available/boxserver-dashboard 2>/dev/null || true
    sudo systemctl daemon-reload 2>/dev/null || true
}

# =========================
# Funções de Verificação do Sistema
# =========================
check_system_compatibility() {
    log_info "Verificando compatibilidade do sistema..."

    local kernel_version=$(uname -r)
    local architecture=$(uname -m)

    log_info "Kernel: $kernel_version"
    log_info "Arquitetura: $architecture"

    # Verificar arquitetura ARM
    if [[ "$architecture" != "armv7l" ]] && [[ "$architecture" != "aarch64" ]]; then
        log_error "Arquitetura $architecture não é suportada"
        exit 1
    fi

    # Verificar espaço em disco
    local available_space_mb
    available_space_mb=$(df / | awk 'NR==2 {print int($4/1024)}')
    if [[ "$available_space_mb" -lt "$REQUIRED_DISK_SPACE_MB" ]]; then
        log_error "Espaço insuficiente. Necessário: ${REQUIRED_DISK_SPACE_MB}MB, Disponível: ${available_space_mb}MB"
        exit 1
    fi

    # Verificar conectividade
    if ! ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
        log_error "Sem conectividade de rede"
        exit 1
    fi

    log_info "Sistema compatível verificado"
}

# =========================
# Funções de Instalação dos Serviços
# =========================
install_unbound_service() {
    log_info "Instalando Unbound..."

    backup_file /etc/unbound/unbound.conf.d/pi-hole.conf
    install_packages unbound unbound-host

    sudo mkdir -p /etc/unbound/unbound.conf.d
    sudo mkdir -p /var/lib/unbound

    # Configurar Unbound
    cat << EOF | sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    port: ${SERVICE_PORTS[UNBOUND]}
    verbosity: 1
    root-hints: "/usr/share/dns/root.hints"
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    edns-buffer-size: 1472
    prefetch: yes
    num-threads: 1
    interface: 127.0.0.1
    access-control: 127.0.0.1/32 allow
    private-address: 192.168.0.0/16
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 169.254.0.0/16
    private-address: 127.0.0.0/8
    private-address: ::ffff:0:0/96
    private-address: ::1/128
EOF

    sudo chown -R unbound:unbound /var/lib/unbound
    sudo systemctl enable unbound
    sudo systemctl start unbound

    log_info "Unbound instalado com sucesso"
}

install_pihole_service() {
    log_info "Instalando Pi-hole..."

    backup_file /etc/pihole/setupVars.conf
    backup_file /etc/dnsmasq.d/02-pihole.conf

    # Instalar Pi-hole
    curl -sSL https://install.pi-hole.net | bash

    # Configurar Pi-hole para usar Unbound
    cat << EOF | sudo tee /etc/pihole/setupVars.conf
PIHOLE_INTERFACE=$(detect_interface)
IPV4_ADDRESS=192.168.0.100/24
IPV6_ADDRESS=
PIHOLE_DNS_1=127.0.0.1#${SERVICE_PORTS[UNBOUND]}
PIHOLE_DNS_2=
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSMASQ_LISTENING=all
WEBPORT=${SERVICE_PORTS[PIHOLE_HTTP]}
WEBTHEME=default-light
WEBPASSWORD=$(openssl rand -base64 12)
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNSSEC=true
EOF

    sudo pihole -g
    sudo systemctl restart pihole-FTL

    log_info "Pi-hole instalado com sucesso"
}

install_wireguard_service() {
    log_info "Instalando WireGuard..."

    backup_file /etc/wireguard/wg0.conf
    install_packages wireguard wireguard-tools

    sudo mkdir -p /etc/wireguard

    # Gerar chaves
    local private_key=$(wg genkey)
    local public_key=$(echo "$private_key" | wg pubkey)

    # Configurar WireGuard
    cat << EOF | sudo tee /etc/wireguard/wg0.conf
[Interface]
Address = 10.8.0.1/24
PrivateKey = $private_key
ListenPort = ${SERVICE_PORTS[WIREGUARD]}
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $(detect_interface) -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $(detect_interface) -j MASQUERADE
EOF

    sudo systemctl enable wg-quick@wg0
    sudo systemctl start wg-quick@wg0

    # Habilitar IP forwarding
    echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p

    log_info "WireGuard instalado com sucesso"
    log_info "Chave pública: $public_key"
}

install_cloudflared_service() {
    log_info "Instalando Cloudflared..."

    backup_file /etc/cloudflared/config.yml
    backup_file /etc/systemd/system/cloudflared.service

    local arch=$(detect_arch)
    curl -L -o cloudflared.deb "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$arch.deb"
    sudo dpkg -i cloudflared.deb || sudo apt-get install -f -y
    rm cloudflared.deb

    sudo mkdir -p /etc/cloudflared
    cat << EOF | sudo tee /etc/cloudflared/config.yml
proxy-dns: true
proxy-port: 5054
upstream:
  - https://1.1.1.1/dns-query
  - https://1.0.0.1/dns-query
EOF

    sudo systemctl enable cloudflared
    sudo systemctl start cloudflared

    log_info "Cloudflared instalado com sucesso"
}

install_samba_service() {
    log_info "Instalando Samba..."

    backup_file /etc/samba/smb.conf
    install_packages samba samba-common-bin

    sudo mkdir -p /srv/samba/shared
    sudo chmod 777 /srv/samba/shared

    cat << EOF | sudo tee /etc/samba/smb.conf
[global]
   workgroup = WORKGROUP
   server string = BoxServer Samba
   netbios name = boxserver
   security = user
   map to guest = bad user
   dns proxy = no

[shared]
   path = /srv/samba/shared
   browsable = yes
   writable = yes
   guest ok = yes
   read only = no
   create mask = 0777
   directory mask = 0777
EOF

    sudo systemctl enable smbd nmbd
    sudo systemctl restart smbd nmbd

    log_info "Samba instalado com sucesso"
}

install_minidlna_service() {
    log_info "Instalando MiniDLNA..."

    backup_file /etc/minidlna.conf
    install_packages minidlna

    sudo mkdir -p /srv/media
    sudo chmod 777 /srv/media

    cat << EOF | sudo tee /etc/minidlna.conf
media_dir=/srv/media
port=${SERVICE_PORTS[MINIDLNA]}
network_interface=eth0
friendly_name=BoxServer DLNA
inotify=yes
enable_tivo=no
strict_dlna=no
notify_interval=300
serial=12345678
model_number=1
EOF

    sudo systemctl enable minidlna
    sudo systemctl restart minidlna

    log_info "MiniDLNA instalado com sucesso"
}

install_filebrowser_service() {
    log_info "Instalando Filebrowser..."

    backup_file /etc/systemd/system/filebrowser.service

    local arch=$(detect_arch)
    curl -L -o filebrowser.tar.gz "https://github.com/filebrowser/filebrowser/releases/latest/download/linux-$arch-filebrowser.tar.gz"
    sudo tar -xvzf filebrowser.tar.gz -C /usr/local/bin
    rm filebrowser.tar.gz

    sudo mkdir -p /srv/files
    sudo chmod 777 /srv/files

    cat << EOF | sudo tee /etc/systemd/system/filebrowser.service
[Unit]
Description=Filebrowser
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/filebrowser --root /srv/files --port ${SERVICE_PORTS[FILEBROWSER]} --noauth
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable filebrowser
    sudo systemctl start filebrowser

    log_info "Filebrowser instalado com sucesso"
}

install_dashboard_service() {
    log_info "Instalando Dashboard..."

    backup_file "$DASHBOARD_DIR/index.html"
    backup_file /etc/nginx/sites-available/boxserver-dashboard

    install_packages nginx

    sudo mkdir -p "$DASHBOARD_DIR"

    cat << EOF | sudo tee "$DASHBOARD_DIR/index.html"
<!DOCTYPE html>
<html>
<head>
    <title>BoxServer Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .service { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .status { color: green; font-weight: bold; }
        .port { color: blue; }
    </style>
</head>
<body>
    <h1>BoxServer Dashboard</h1>
    <div class="service">
        <h3>Pi-hole</h3>
        <p>Status: <span class="status">Ativo</span></p>
        <p>Porta: <span class="port">${SERVICE_PORTS[PIHOLE_HTTP]}</span></p>
        <p><a href="http://192.168.0.100:${SERVICE_PORTS[PIHOLE_HTTP]}/admin">Acessar Admin</a></p>
    </div>
    <div class="service">
        <h3>Filebrowser</h3>
        <p>Status: <span class="status">Ativo</span></p>
        <p>Porta: <span class="port">${SERVICE_PORTS[FILEBROWSER]}</span></p>
        <p><a href="http://192.168.0.100:${SERVICE_PORTS[FILEBROWSER]}">Acessar Filebrowser</a></p>
    </div>
    <div class="service">
        <h3>MiniDLNA</h3>
        <p>Status: <span class="status">Ativo</span></p>
        <p>Porta: <span class="port">${SERVICE_PORTS[MINIDLNA]}</span></p>
    </div>
    <div class="service">
        <h3>WireGuard</h3>
        <p>Status: <span class="status">Ativo</span></p>
        <p>Porta: <span class="port">${SERVICE_PORTS[WIREGUARD]}</span></p>
    </div>
</body>
</html>
EOF

    cat << EOF | sudo tee /etc/nginx/sites-available/boxserver-dashboard
server {
    listen ${SERVICE_PORTS[DASHBOARD]};
    server_name _;
    root $DASHBOARD_DIR;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    sudo ln -sf /etc/nginx/sites-available/boxserver-dashboard /etc/nginx/sites-enabled/
    sudo rm -f /etc/nginx/sites-enabled/default

    sudo systemctl enable nginx
    sudo systemctl restart nginx

    log_info "Dashboard instalado com sucesso"
}

# =========================
# Funções Utilitárias
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

configure_static_ip() {
    log_info "Configurando IP estático..."

    backup_file /etc/netplan/01-boxserver.yaml

    local interface=$(detect_interface)
    cat << EOF | sudo tee /etc/netplan/01-boxserver.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    $interface:
      dhcp4: no
      addresses: [192.168.0.100/24]
      gateway4: 192.168.0.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
EOF

    sudo netplan apply
    STATIC_IP_CONFIGURED=true

    log_info "IP estático configurado: 192.168.0.100"
}

generate_summary() {
    log_info "Gerando resumo da instalação..."

    cat << EOF > "$SUMMARY_FILE"
=== BoxServer Installation Summary ===
Data: $(date)
IP: 192.168.0.100

Portas Configuradas:
- Unbound: ${SERVICE_PORTS[UNBOUND]}
- Pi-hole HTTP: ${SERVICE_PORTS[PIHOLE_HTTP]}
- Pi-hole HTTPS: ${SERVICE_PORTS[PIHOLE_HTTPS]}
- Filebrowser: ${SERVICE_PORTS[FILEBROWSER]}
- MiniDLNA: ${SERVICE_PORTS[MINIDLNA]}
- WireGuard: ${SERVICE_PORTS[WIREGUARD]}
- Dashboard: ${SERVICE_PORTS[DASHBOARD]}

Serviços Instalados:
- Unbound (DNS recursivo)
- Pi-hole (bloqueador de anúncios)
- WireGuard (VPN)
- Cloudflared (DNS sobre HTTPS)
- Samba (compartilhamento de arquivos)
- MiniDLNA (servidor de mídia)
- Filebrowser (gerenciador de arquivos web)
- Dashboard (painel de controle)

Acessos:
- Pi-hole Admin: http://192.168.0.100:${SERVICE_PORTS[PIHOLE_HTTP]}/admin
- Filebrowser: http://192.168.0.100:${SERVICE_PORTS[FILEBROWSER]}
- Dashboard: http://192.168.0.100:${SERVICE_PORTS[DASHBOARD]}
- Samba: \\\\192.168.0.100\\shared
- MiniDLNA: Disponível na rede local

Logs:
- Instalação: $LOGFILE
- Rollback: $ROLLBACK_LOG
EOF

    log_info "Resumo gerado em: $SUMMARY_FILE"
}

# =========================
# Função Principal
# =========================
main() {
    # Inicializar sistemas
    backup_manager_init
    exec > >(tee -a "$LOGFILE") 2>&1

    # Processar argumentos
    while [[ $# -gt 0 ]]; do
        case $1 in
            --clean)
                log_info "Iniciando limpeza completa..."
                clean_service "pihole" "pihole" "pihole-ftl" "lighttpd"
                clean_service "unbound" "unbound" "unbound-host"
                clean_service "wireguard" "wireguard" "wireguard-tools"
                clean_service "samba" "samba" "samba-common-bin"
                clean_service "minidlna" "minidlna"
                clean_service "filebrowser"
                clean_service "dashboard" "nginx"
                log_info "Limpeza completa finalizada"
                exit 0
                ;;
            --silent)
                SILENT_MODE=true
                shift
                ;;
            *)
                log_error "Opção desconhecida: $1"
                exit 1
                ;;
        esac
    done

    # Iniciar instalação
    show_message "BoxServer Installer V2 - Iniciando instalação..."

    # Verificar sistema
    check_system_compatibility

    # Instalar pacotes base
    install_packages "${BASE_PACKAGES[@]}"

    # Alocar portas
    allocate_ports

    # Configurar IP estático
    configure_static_ip

    # Instalar serviços
    install_unbound_service
    install_pihole_service
    install_wireguard_service
    install_cloudflared_service
    install_samba_service
    install_minidlna_service
    install_filebrowser_service
    install_dashboard_service

    # Gerar resumo
    generate_summary

    show_message "Instalação concluída com sucesso! Verifique $SUMMARY_FILE para detalhes."
    log_info "Instalação concluída com sucesso"
}

# Executar função principal
main "$@"
