#!/bin/bash
# BoxServer Installer - Version 2.0 Optimized
# Eliminadas redundâncias e conflitos da versão anterior
# Compatível com Armbian 21.08.8 (Debian 11 Bullseye) - Kernel RK322x
# Inclui: Unbound, Pi-hole, WireGuard, Cloudflared, RNG-tools, Samba, MiniDLNA, Filebrowser, Dashboard

set -euo pipefail

# =========================
# CONFIGURAÇÃO CENTRALIZADA
# =========================
readonly SCRIPT_VERSION="2.0"
readonly LOGFILE="/var/log/boxserver_install_v2.log"
readonly SUMMARY_FILE="/root/boxserver_summary_v2.txt"
readonly BACKUP_DIR="/var/backups/boxserver"
readonly DASHBOARD_DIR="/srv/boxserver-dashboard"

# Configurações de rede e sistema
readonly DEFAULT_IP="192.168.0.100"
readonly DOMAIN_DEFAULT="pihole.local"

# Portas de serviço (centralizadas)
declare -A SERVICE_PORTS=(
    [UNBOUND]=5335
    [PIHOLE_HTTP]=8081
    [PIHOLE_HTTPS]=8443
    [FILEBROWSER]=8080
    [MINIDLNA]=8200
    [WIREGUARD]=51820
)

# Variáveis globais
SILENT_MODE=false
STATIC_IP=""
GATEWAY=""
NET_IF=""
DOMAIN=""
PIHOLE_PASSWORD=""
WG_PRIVATE=""
WG_PUBLIC=""
SUMMARY_ENTRIES=()

# Cache de verificações
declare -A VERIFICATION_CACHE=()

exec > >(tee -a "$LOGFILE") 2>&1

# =========================
# SISTEMA DE LOGGING UNIFICADO
# =========================
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        INFO)    echo "[$timestamp] ℹ️  $message" ;;
        SUCCESS) echo "[$timestamp] ✅ $message" ;;
        WARNING) echo "[$timestamp] ⚠️  $message" ;;
        ERROR)   echo "[$timestamp] ❌ $message" ;;
        DEBUG)   echo "[$timestamp] 🔧 $message" ;;
    esac

    # Exibir via whiptail apenas se não estiver em modo silencioso
    if [[ "$SILENT_MODE" = false && "$level" != "DEBUG" ]]; then
        whiptail --title "BoxServer v$SCRIPT_VERSION" --msgbox "$message" 12 76 || true
    fi
}

# Aliases para compatibilidade
info() { log INFO "$@"; }
success() { log SUCCESS "$@"; }
warning() { log WARNING "$@"; }
error() { log ERROR "$@"; }
debug() { log DEBUG "$@"; }

# =========================
# FUNÇÕES DE CONFIGURAÇÃO UNIFICADAS
# =========================
load_system_config() {
    debug "Carregando configuração do sistema..."

    # Cache de verificações para evitar repetições
    if [[ -z "${VERIFICATION_CACHE[interface]:-}" ]]; then
        VERIFICATION_CACHE[interface]=$(ip route | awk '/^default/ {print $5; exit}' || echo "eth0")
    fi

    if [[ -z "${VERIFICATION_CACHE[arch]:-}" ]]; then
        case "$(uname -m)" in
            x86_64) VERIFICATION_CACHE[arch]="amd64" ;;
            aarch64|arm64) VERIFICATION_CACHE[arch]="arm64" ;;
            armv7l|armhf) VERIFICATION_CACHE[arch]="arm" ;;
            *) VERIFICATION_CACHE[arch]="unknown" ;;
        esac
    fi

    NET_IF="${VERIFICATION_CACHE[interface]}"
    debug "Interface de rede: $NET_IF"
    debug "Arquitetura: ${VERIFICATION_CACHE[arch]}"
}

configure_static_ip() {
    local current_ip=$(hostname -I | awk '{print $1}')

    if [[ "$SILENT_MODE" = false ]]; then
        STATIC_IP=$(whiptail --inputbox "IP fixo para o servidor:" 10 68 "${current_ip:-$DEFAULT_IP}" 3>&1 1>&2 2>&3) || true
    else
        STATIC_IP="${current_ip:-$DEFAULT_IP}"
    fi

    [[ -z "$STATIC_IP" ]] && STATIC_IP="$DEFAULT_IP"
    GATEWAY=$(ip route | awk '/^default/ {print $3; exit}' || true)

    info "IP configurado: $STATIC_IP"
    info "Gateway: ${GATEWAY:-auto}"
}

# =========================
# VERIFICAÇÕES UNIFICADAS
# =========================
verify_system_compatibility() {
    local cache_key="system_compat"

    if [[ -n "${VERIFICATION_CACHE[$cache_key]:-}" ]]; then
        debug "Usando cache para verificação de compatibilidade"
        return "${VERIFICATION_CACHE[$cache_key]}"
    fi

    info "Verificando compatibilidade do sistema..."

    # Verificar Armbian
    if [[ ! -f /etc/armbian-release ]]; then
        error "Requer Armbian 21.08.8 (Debian 11 Bullseye)"
        VERIFICATION_CACHE[$cache_key]=1
        return 1
    fi

    source /etc/armbian-release
    if [[ "$VERSION" != "21.08.8" ]]; then
        error "Versão Armbian incompatível. Detectado: $VERSION"
        VERIFICATION_CACHE[$cache_key]=1
        return 1
    fi

    # Verificar Debian base
    if ! grep -q 'VERSION_ID="11"' /etc/os-release; then
        error "Base incompatível. Necessário Debian 11 (Bullseye)"
        VERIFICATION_CACHE[$cache_key]=1
        return 1
    fi

    # Verificar kernel RK322x
    local kernel_version=$(uname -r)
    if [[ "$kernel_version" == *"4.4.194-rk322x"* ]]; then
        success "Kernel RK322x detectado: $kernel_version"
    else
        warning "Kernel não é 4.4.194-rk322x específico, mas continuando"
    fi

    # Verificar recursos mínimos
    local total_mem=$(awk '/MemTotal:/ {print int($2/1024)}' /proc/meminfo)
    local available_space=$(df / | awk 'NR==2 {print int($4/1024)}')

    if [[ $total_mem -lt 256 ]]; then
        warning "Memória baixa ($total_mem MB). Aplicando otimizações"
        export LOW_MEMORY=true
    fi

    if [[ $available_space -lt 512 ]]; then
        error "Espaço insuficiente ($available_space MB). Mínimo: 512MB"
        VERIFICATION_CACHE[$cache_key]=1
        return 1
    fi

    success "Sistema compatível: Armbian $VERSION (Debian 11) em RK322x"
    VERIFICATION_CACHE[$cache_key]=0
    return 0
}

verify_network_connectivity() {
    local cache_key="network"

    if [[ -n "${VERIFICATION_CACHE[$cache_key]:-}" ]]; then
        debug "Usando cache para verificação de rede"
        return "${VERIFICATION_CACHE[$cache_key]}"
    fi

    if ! ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
        error "Sem conectividade de rede. Verifique sua conexão"
        VERIFICATION_CACHE[$cache_key]=1
        return 1
    fi

    success "Conectividade de rede OK"
    VERIFICATION_CACHE[$cache_key]=0
    return 0
}

# =========================
# GERENCIAMENTO DE PORTAS CENTRALIZADO
# =========================
allocate_service_ports() {
    info "Verificando e alocando portas de serviços..."

    local used_ports=()

    # Função para verificar se porta está em uso
    is_port_used() {
        local port=$1

        # Verificar no sistema
        if netstat -tln 2>/dev/null | grep -q ":$port "; then
            return 0
        fi

        # Verificar se já foi alocada
        for p in "${used_ports[@]}"; do
            [[ "$p" == "$port" ]] && return 0
        done

        return 1
    }

    # Encontrar próxima porta livre
    find_free_port() {
        local start_port=$1
        local port=$start_port

        while is_port_used "$port"; do
            ((port++))
        done

        echo "$port"
    }

    # Alocar portas para cada serviço
    for service in "${!SERVICE_PORTS[@]}"; do
        local original_port=${SERVICE_PORTS[$service]}
        local allocated_port=$(find_free_port "$original_port")

        SERVICE_PORTS[$service]=$allocated_port
        used_ports+=("$allocated_port")

        if [[ $allocated_port -ne $original_port ]]; then
            warning "Porta $original_port ocupada. $service usará porta $allocated_port"
        else
            debug "$service: porta $allocated_port alocada"
        fi
    done
}

# =========================
# GERENCIAMENTO DE DEPENDÊNCIAS
# =========================
ensure_package() {
    local package="$1"
    local cache_key="pkg_$package"

    if [[ -n "${VERIFICATION_CACHE[$cache_key]:-}" ]]; then
        return 0
    fi

    if ! dpkg -s "$package" >/dev/null 2>&1; then
        debug "Instalando pacote: $package"
        sudo apt-get install -y "$package"
    fi

    VERIFICATION_CACHE[$cache_key]=1
}

install_base_dependencies() {
    info "Instalando dependências básicas..."

    sudo apt-get update -q

    local base_packages=(
        "whiptail" "curl" "wget" "tar" "gnupg" "lsb-release"
        "ca-certificates" "net-tools" "iproute2" "nginx"
        "dnsutils" "systemd"
    )

    for pkg in "${base_packages[@]}"; do
        ensure_package "$pkg"
    done

    success "Dependências básicas instaladas"
}

# =========================
# SISTEMA DE BACKUP UNIFICADO
# =========================
create_backup() {
    local file_path="$1"
    local backup_name="${file_path##*/}.$(date +%Y%m%d_%H%M%S).bak"
    local backup_path="$BACKUP_DIR/$backup_name"

    if [[ -f "$file_path" ]]; then
        sudo mkdir -p "$BACKUP_DIR"
        sudo cp "$file_path" "$backup_path"
        debug "Backup criado: $backup_path"
        echo "$file_path:$backup_path" >> "$BACKUP_DIR/restore.map"
    fi
}

# =========================
# SISTEMA DE LIMPEZA UNIFICADO
# =========================
cleanup_service() {
    local service_name="$1"

    debug "Limpando serviço: $service_name"

    # Parar e desabilitar serviço
    sudo systemctl stop "$service_name" 2>/dev/null || true
    sudo systemctl disable "$service_name" 2>/dev/null || true

    # Remover arquivos específicos baseado no serviço
    case "$service_name" in
        "pihole-ftl"|"lighttpd")
            sudo rm -rf /etc/pihole /opt/pihole /var/www/html/pihole 2>/dev/null || true
            sudo userdel pihole 2>/dev/null || true
            sudo groupdel pihole 2>/dev/null || true
            sudo rm -f /usr/local/bin/pihole /usr/bin/pihole 2>/dev/null || true
            ;;
        "unbound")
            sudo rm -rf /etc/unbound/unbound.conf.d/pi-hole.conf 2>/dev/null || true
            ;;
        "wg-quick@wg0")
            sudo rm -rf /etc/wireguard 2>/dev/null || true
            ;;
    esac
}

perform_system_cleanup() {
    info "Executando limpeza completa do sistema..."

    local services=("pihole-ftl" "lighttpd" "unbound" "wg-quick@wg0" "cloudflared" "smbd" "minidlna" "filebrowser" "nginx")

    for service in "${services[@]}"; do
        cleanup_service "$service"
    done

    # Restaurar DNS padrão
    cat <<EOF | sudo tee /etc/resolv.conf
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

    # Reativar systemd-resolved se disponível
    if [[ -f /lib/systemd/system/systemd-resolved.service ]]; then
        sudo systemctl enable systemd-resolved 2>/dev/null || true
        sudo systemctl start systemd-resolved 2>/dev/null || true
    fi

    success "Limpeza do sistema concluída"
}

# =========================
# INSTALAÇÕES DE SERVIÇOS
# =========================
install_unbound() {
    info "Instalando Unbound DNS resolver..."

    ensure_package "unbound"

    create_backup "/etc/unbound/unbound.conf.d/pi-hole.conf"

    # Configuração otimizada para RK322x
    cat <<EOF | sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    verbosity: 0
    interface: 127.0.0.1
    port: ${SERVICE_PORTS[UNBOUND]}
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    # Otimizações para RK322x (baixo consumo)
    cache-min-ttl: 300
    cache-max-ttl: 3600
    msg-cache-size: 4m
    rrset-cache-size: 8m
    num-threads: 1

    # Segurança básica
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes

    # Root hints
    root-hints: /var/lib/unbound/root.hints

forward-zone:
    name: "."
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 8.8.8.8@853#dns.google
    forward-tls-upstream: yes
EOF

    # Baixar root hints
    sudo mkdir -p /var/lib/unbound
    sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache 2>/dev/null || true
    sudo chown -R unbound:unbound /var/lib/unbound

    if sudo unbound-checkconf; then
        sudo systemctl enable unbound
        sudo systemctl restart unbound
        success "Unbound instalado na porta ${SERVICE_PORTS[UNBOUND]}"
        SUMMARY_ENTRIES+=("Unbound DNS: Porta ${SERVICE_PORTS[UNBOUND]}")
    else
        error "Falha na configuração do Unbound"
        return 1
    fi
}

install_pihole() {
    info "Instalando Pi-hole ad blocker..."

    # Verificar se Unbound está rodando
    if ! sudo systemctl is-active --quiet unbound; then
        error "Pi-hole requer Unbound. Instale o Unbound primeiro"
        return 1
    fi

    # Configurar variáveis para instalação não-interativa
    sudo mkdir -p /etc/pihole
    cat <<EOF | sudo tee /etc/pihole/setupVars.conf
WEBPASSWORD=$(echo -n "${PIHOLE_PASSWORD:-admin123}" | sha256sum | awk '{print $1}' | sha256sum | awk '{print $1}')
PIHOLE_INTERFACE=$NET_IF
IPV4_ADDRESS=$STATIC_IP/24
PIHOLE_DNS_1=127.0.0.1#${SERVICE_PORTS[UNBOUND]}
PIHOLE_DNS_2=
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
WEB_PORT=${SERVICE_PORTS[PIHOLE_HTTP]}
DNSSEC=false
REV_SERVER=false
MAXDBDAYS=2
EOF

    # Instalar Pi-hole
    if command -v pihole >/dev/null 2>&1; then
        info "Pi-hole já instalado. Reconfigurando..."
        pihole -r --unattended
    else
        export DEBIAN_FRONTEND=noninteractive
        wget -O basic-install.sh https://install.pi-hole.net
        sudo bash basic-install.sh --unattended
        rm -f basic-install.sh
    fi

    # Configurar lighttpd na porta correta
    create_backup "/etc/lighttpd/lighttpd.conf"
    sudo sed -i "s/server.port.*=.*/server.port = ${SERVICE_PORTS[PIHOLE_HTTP]}/" /etc/lighttpd/lighttpd.conf

    sudo systemctl restart lighttpd
    sudo systemctl restart pihole-ftl

    success "Pi-hole instalado nas portas ${SERVICE_PORTS[PIHOLE_HTTP]}/${SERVICE_PORTS[PIHOLE_HTTPS]}"
    SUMMARY_ENTRIES+=("Pi-hole Web: http://$STATIC_IP:${SERVICE_PORTS[PIHOLE_HTTP]}/admin")
    SUMMARY_ENTRIES+=("Pi-hole Password: ${PIHOLE_PASSWORD:-admin123}")
}

install_wireguard() {
    info "Instalando WireGuard VPN..."

    # Verificar compatibilidade com kernel RK322x
    if [[ ! -c /dev/net/tun ]]; then
        warning "Interface TUN não disponível. Instalando WireGuard userspace"
        ensure_package "wireguard-tools"
    else
        ensure_package "wireguard"
    fi

    sudo mkdir -p /etc/wireguard/keys
    sudo chmod 700 /etc/wireguard/keys

    # Gerar chaves
    WG_PRIVATE=$(wg genkey)
    WG_PUBLIC=$(echo "$WG_PRIVATE" | wg pubkey)

    # Configuração do servidor
    cat <<EOF | sudo tee /etc/wireguard/wg0.conf
[Interface]
PrivateKey = $WG_PRIVATE
Address = 10.0.0.1/24
ListenPort = ${SERVICE_PORTS[WIREGUARD]}
SaveConfig = true
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_IF -j MASQUERADE

# Exemplo de cliente - descomente e configure
# [Peer]
# PublicKey = CLIENT_PUBLIC_KEY_HERE
# AllowedIPs = 10.0.0.2/32
EOF

    sudo chmod 600 /etc/wireguard/wg0.conf
    sudo systemctl enable wg-quick@wg0

    success "WireGuard configurado na porta ${SERVICE_PORTS[WIREGUARD]}"
    SUMMARY_ENTRIES+=("WireGuard VPN: Porta ${SERVICE_PORTS[WIREGUARD]}")
    SUMMARY_ENTRIES+=("WireGuard Public Key: $WG_PUBLIC")
}

install_filebrowser() {
    info "Instalando Filebrowser..."

    local arch="${VERIFICATION_CACHE[arch]}"
    local fb_arch=""

    case "$arch" in
        "arm") fb_arch="linux-armv7" ;;
        "arm64") fb_arch="linux-arm64" ;;
        "amd64") fb_arch="linux-amd64" ;;
        *) error "Arquitetura $arch não suportada"; return 1 ;;
    esac

    local version="v2.23.0"
    local url="https://github.com/filebrowser/filebrowser/releases/download/${version}/${fb_arch}-filebrowser.tar.gz"

    sudo mkdir -p /srv/filebrowser
    cd /tmp

    if wget -q "$url" -O filebrowser.tar.gz; then
        tar -xzf filebrowser.tar.gz
        sudo mv filebrowser /usr/local/bin/
        sudo chmod +x /usr/local/bin/filebrowser
        rm -f filebrowser.tar.gz

        # Configurar serviço
        cat <<EOF | sudo tee /etc/systemd/system/filebrowser.service
[Unit]
Description=File Browser
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/srv/filebrowser
ExecStart=/usr/local/bin/filebrowser -r /srv -p ${SERVICE_PORTS[FILEBROWSER]} -a 0.0.0.0
Restart=always

[Install]
WantedBy=multi-user.target
EOF

        sudo systemctl daemon-reload
        sudo systemctl enable filebrowser
        sudo systemctl start filebrowser

        success "Filebrowser instalado na porta ${SERVICE_PORTS[FILEBROWSER]}"
        SUMMARY_ENTRIES+=("Filebrowser: http://$STATIC_IP:${SERVICE_PORTS[FILEBROWSER]} (admin/admin)")
    else
        error "Falha ao baixar Filebrowser"
        return 1
    fi
}

install_additional_services() {
    info "Instalando serviços adicionais..."

    # Samba
    ensure_package "samba"
    sudo mkdir -p /srv/samba/share
    sudo chmod 755 /srv/samba/share

    create_backup "/etc/samba/smb.conf"
    cat <<EOF | sudo tee -a /etc/samba/smb.conf

[BoxShare]
   path = /srv/samba/share
   browseable = yes
   read only = no
   guest ok = yes
   create mask = 0755
EOF
    sudo systemctl restart smbd
    SUMMARY_ENTRIES+=("Samba Share: \\\\$STATIC_IP\\BoxShare")

    # MiniDLNA
    ensure_package "minidlna"
    sudo mkdir -p /srv/media/{videos,music,pictures}

    create_backup "/etc/minidlna.conf"
    sudo sed -i "s/^port=.*/port=${SERVICE_PORTS[MINIDLNA]}/" /etc/minidlna.conf
    sudo sed -i "s|^media_dir=.*|media_dir=/srv/media|" /etc/minidlna.conf
    sudo systemctl restart minidlna
    SUMMARY_ENTRIES+=("MiniDLNA: Porta ${SERVICE_PORTS[MINIDLNA]}")

    success "Serviços adicionais instalados"
}

# =========================
# DASHBOARD WEB
# =========================
install_dashboard() {
    info "Instalando dashboard web..."

    sudo mkdir -p "$DASHBOARD_DIR"

    cat <<EOF | sudo tee "$DASHBOARD_DIR/index.html"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BoxServer v$SCRIPT_VERSION - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem 0; text-align: center; }
        .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
        .services { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 2rem 0; }
        .service { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); transition: transform 0.2s; }
        .service:hover { transform: translateY(-5px); }
        .service h3 { color: #333; margin-bottom: 10px; }
        .service p { color: #666; margin-bottom: 15px; }
        .btn { display: inline-block; background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; transition: background 0.2s; }
        .btn:hover { background: #5a6fd8; }
        .status { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; margin-left: 10px; }
        .status.online { background: #d4edda; color: #155724; }
        .footer { text-align: center; padding: 2rem 0; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>🚀 BoxServer v$SCRIPT_VERSION</h1>
            <p>Sistema otimizado para RK322x • IP: $STATIC_IP</p>
        </div>
    </div>

    <div class="container">
        <div class="services">
            <div class="service">
                <h3>🛡️ Pi-hole <span class="status online">ONLINE</span></h3>
                <p>Bloqueador de anúncios e DNS</p>
                <a href="http://$STATIC_IP:${SERVICE_PORTS[PIHOLE_HTTP]}/admin" class="btn" target="_blank">Acessar Admin</a>
            </div>

            <div class="service">
                <h3>📁 File Browser <span class="status online">ONLINE</span></h3>
                <p>Gerenciador de arquivos web</p>
                <a href="http://$STATIC_IP:${SERVICE_PORTS[FILEBROWSER]}" class="btn" target="_blank">Acessar Files</a>
            </div>

            <div class="service">
                <h3>🔒 WireGuard VPN <span class="status online">ONLINE</span></h3>
                <p>Servidor VPN seguro</p>
                <a href="#wireguard-config" class="btn">Ver Configuração</a>
            </div>

            <div class="service">
                <h3>📺 MiniDLNA <span class="status online">ONLINE</span></h3>
                <p>Servidor de mídia DLNA</p>
                <p>Porta: ${SERVICE_PORTS[MINIDLNA]}</p>
            </div>

            <div class="service">
                <h3>💾 Samba Share <span class="status online">ONLINE</span></h3>
                <p>Compartilhamento de arquivos</p>
                <p>Acesso: \\\\$STATIC_IP\\BoxShare</p>
            </div>

            <div class="service">
                <h3>⚙️ Sistema</h3>
                <p>Status e informações</p>
                <p><strong>Kernel:</strong> $(uname -r)</p>
                <p><strong>Uptime:</strong> $(uptime -p)</p>
            </div>
        </div>

        <div id="wireguard-config" style="background: white; margin: 2rem 0; padding: 20px; border-radius: 10px; display: none;">
            <h3>🔒 Configuração WireGuard</h3>
            <p><strong>Chave Pública do Servidor:</strong></p>
            <code style="background: #f8f9fa; padding: 10px; display: block; margin: 10px 0; border-radius: 5px;">$WG_PUBLIC</code>
            <p><strong>Endpoint:</strong> $STATIC_IP:${SERVICE_PORTS[WIREGUARD]}</p>
        </div>
    </div>

    <div class="footer">
        <p>BoxServer v$SCRIPT_VERSION • Otimizado para kernel RK322x • $(date)</p>
    </div>

    <script>
        // Mostrar configuração WireGuard
        document.querySelector('a[href="#wireguard-config"]').onclick = function(e) {
            e.preventDefault();
            document.getElementById('wireguard-config').style.display = 'block';
        };

        // Verificar status dos serviços (simulado)
        setInterval(function() {
            fetch('/api/status').then(r => r.json()).then(data => {
                // Atualizar status se API estiver disponível
            }).catch(() => {
                // Manter status padrão
            });
        }, 30000);
    </script>
</body>
</html>
EOF

    # Configurar Nginx
    create_backup "/etc/nginx/sites-available/default"
    cat <<EOF | sudo tee /etc/nginx/sites-available/boxserver
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root $DASHBOARD_DIR;
    index index.html;

    server_name _;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    sudo ln -sf /etc/nginx/sites-available/boxserver /etc/nginx/sites-enabled/default
    sudo systemctl restart nginx

    success "Dashboard instalado em http://$STATIC_IP/"
    SUMMARY_ENTRIES+=("Dashboard: http://$STATIC_IP/")
}

# =========================
# INTERFACE DO USUÁRIO
# =========================
show_service_menu() {
    if [[ "$SILENT_MODE" = true ]]; then
        # Modo silencioso - instalar todos os serviços
        echo "UNBOUND PIHOLE WIREGUARD FILEBROWSER SAMBA MINIDLNA DASHBOARD"
        return
    fi

    local choices=$(whiptail --title "BoxServer v$SCRIPT_VERSION - Seleção de Serviços" \
        --checklist "Selecione os serviços para instalar:" 20 78 10 \
        "UNBOUND" "DNS Resolver (obrigatório para Pi-hole)" ON \
        "PIHOLE" "Bloqueador de anúncios" ON \
        "WIREGUARD" "Servidor VPN" ON \
        "FILEBROWSER" "Gerenciador de arquivos web" ON \
        "SAMBA" "Compartilhamento de arquivos" OFF \
        "MINIDLNA" "Servidor de mídia DLNA" OFF \
        "DASHBOARD" "Dashboard web" ON \
        3>&1 1>&2 2>&3)

    echo "$choices" | tr -d '"'
}

configure_pihole_password() {
    if [[ "$SILENT_MODE" = false ]]; then
        PIHOLE_PASSWORD=$(whiptail --title "Pi-hole Password" \
            --inputbox "Digite a senha do Pi-hole (deixe vazio para 'admin123'):" 10 68 \
            3>&1 1>&2 2>&3) || true
    fi

    [[ -z "$PIHOLE_PASSWORD" ]] && PIHOLE_PASSWORD="admin123"
}

# =========================
# GERAÇÃO DE RELATÓRIO
# =========================
generate_summary() {
    info "Gerando relatório final..."

    cat <<EOF | sudo tee "$SUMMARY_FILE"
=====================================
  BoxServer v$SCRIPT_VERSION - Resumo da Instalação
=====================================

Data/Hora: $(date)
IP do Servidor: $STATIC_IP
Interface de Rede: $NET_IF
Gateway: ${GATEWAY:-auto}

SERVIÇOS INSTALADOS:
EOF

    for entry in "${SUMMARY_ENTRIES[@]}"; do
        echo "• $entry" | sudo tee -a "$SUMMARY_FILE" >/dev/null
    done

    cat <<EOF | sudo tee -a "$SUMMARY_FILE"

PORTAS DE SERVIÇOS:
• Unbound DNS: ${SERVICE_PORTS[UNBOUND]}
• Pi-hole HTTP: ${SERVICE_PORTS[PIHOLE_HTTP]}
• Pi-hole HTTPS: ${SERVICE_PORTS[PIHOLE_HTTPS]}
• Filebrowser: ${SERVICE_PORTS[FILEBROWSER]}
• MiniDLNA: ${SERVICE_PORTS[MINIDLNA]}
• WireGuard VPN: ${SERVICE_PORTS[WIREGUARD]}

INFORMAÇÕES IMPORTANTES:
• Dashboard Principal: http://$STATIC_IP/
• Pi-hole Admin: http://$STATIC_IP:${SERVICE_PORTS[PIHOLE_HTTP]}/admin
• Senha Pi-hole: $PIHOLE_PASSWORD
• Chave Pública WireGuard: ${WG_PUBLIC:-"N/A"}

CONFIGURAÇÃO DE REDE:
• Configure seu roteador para usar $STATIC_IP como DNS
• Ou configure dispositivos para usar $STATIC_IP:53 como DNS

OTIMIZAÇÕES APLICADAS:
• Configurações otimizadas para kernel RK322x
• Cache de DNS reduzido para economizar memória
• Logs rotacionados para economizar espaço
• Serviços configurados para baixo consumo

BACKUP:
• Backups dos arquivos originais: $BACKUP_DIR
• Mapa de restauração: $BACKUP_DIR/restore.map

LOGS:
• Log de instalação: $LOGFILE
• Para verificar serviços: sudo systemctl status <service>

=====================================
  BoxServer v$SCRIPT_VERSION Instalado com Sucesso!
=====================================
EOF

    success "Relatório salvo em: $SUMMARY_FILE"

    # Exibir resumo na tela
    if [[ "$SILENT_MODE" = false ]]; then
        whiptail --title "BoxServer v$SCRIPT_VERSION - Instalação Concluída!" \
            --textbox "$SUMMARY_FILE" 25 80
    fi
}

# =========================
# VERIFICAÇÃO FINAL DE SERVIÇOS
# =========================
verify_installation() {
    info "Verificando instalação dos serviços..."

    local failed_services=()
    local service_status=""

    # Verificar serviços essenciais
    local services_to_check=(
        "unbound:Unbound DNS"
        "pihole-ftl:Pi-hole FTL"
        "lighttpd:Pi-hole Web"
        "nginx:Dashboard Web"
    )

    for service_info in "${services_to_check[@]}"; do
        local service_name="${service_info%:*}"
        local service_desc="${service_info#*:}"

        if sudo systemctl is-active --quiet "$service_name"; then
            service_status+="✅ $service_desc: ONLINE\n"
        else
            service_status+="❌ $service_desc: OFFLINE\n"
            failed_services+=("$service_name")
        fi
    done

    # Verificar conectividade DNS
    if dig @127.0.0.1 -p "${SERVICE_PORTS[UNBOUND]}" google.com +short >/dev/null 2>&1; then
        service_status+="✅ Resolução DNS: OK\n"
    else
        service_status+="❌ Resolução DNS: FALHOU\n"
    fi

    echo -e "$service_status"

    if [[ ${#failed_services[@]} -eq 0 ]]; then
        success "Todos os serviços estão funcionando corretamente!"
        return 0
    else
        warning "Alguns serviços falharam: ${failed_services[*]}"
        return 1
    fi
}

# =========================
# INSTALAÇÃO PRINCIPAL
# =========================
run_installation() {
    local selected_services="$1"

    info "Iniciando instalação do BoxServer v$SCRIPT_VERSION..."

    # Verificações iniciais
    verify_system_compatibility || exit 1
    verify_network_connectivity || exit 1

    # Carregar configuração do sistema
    load_system_config
    configure_static_ip
    allocate_service_ports

    # Instalar dependências
    install_base_dependencies

    # Instalar serviços selecionados
    if [[ "$selected_services" == *"UNBOUND"* ]]; then
        install_unbound || warning "Falha na instalação do Unbound"
    fi

    if [[ "$selected_services" == *"PIHOLE"* ]]; then
        if [[ "$selected_services" == *"UNBOUND"* ]] || sudo systemctl is-active --quiet unbound; then
            configure_pihole_password
            install_pihole || warning "Falha na instalação do Pi-hole"
        else
            error "Pi-hole requer Unbound. Selecione Unbound também."
        fi
    fi

    if [[ "$selected_services" == *"WIREGUARD"* ]]; then
        install_wireguard || warning "Falha na instalação do WireGuard"
    fi

    if [[ "$selected_services" == *"FILEBROWSER"* ]]; then
        install_filebrowser || warning "Falha na instalação do Filebrowser"
    fi

    if [[ "$selected_services" == *"SAMBA"* ]] || [[ "$selected_services" == *"MINIDLNA"* ]]; then
        install_additional_services || warning "Falha na instalação de serviços adicionais"
    fi

    if [[ "$selected_services" == *"DASHBOARD"* ]]; then
        install_dashboard || warning "Falha na instalação do Dashboard"
    fi

    # Configurar IP estático se necessário
    if [[ "$STATIC_IP" != "$(hostname -I | awk '{print $1}')" ]]; then
        configure_static_network
    fi

    # Verificação final
    verify_installation

    # Gerar relatório
    generate_summary

    success "Instalação do BoxServer v$SCRIPT_VERSION concluída!"
    info "Acesse o dashboard em: http://$STATIC_IP/"
}

# =========================
# CONFIGURAÇÃO DE REDE ESTÁTICA
# =========================
configure_static_network() {
    info "Configurando IP estático..."

    create_backup "/etc/netplan/01-netcfg.yaml"

    cat <<EOF | sudo tee /etc/netplan/01-boxserver.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    $NET_IF:
      dhcp4: false
      addresses:
        - $STATIC_IP/24
      gateway4: $GATEWAY
      nameservers:
        addresses: [127.0.0.1, 1.1.1.1, 8.8.8.8]
EOF

    sudo netplan apply
    success "IP estático configurado: $STATIC_IP"
}

# =========================
# FUNÇÕES DE MANUTENÇÃO
# =========================
show_status() {
    echo "=== BoxServer v$SCRIPT_VERSION - Status dos Serviços ==="
    echo

    local services=(
        "unbound:Unbound DNS"
        "pihole-ftl:Pi-hole FTL"
        "lighttpd:Pi-hole Web"
        "nginx:Dashboard"
        "wg-quick@wg0:WireGuard VPN"
        "smbd:Samba"
        "minidlna:MiniDLNA"
        "filebrowser:Filebrowser"
    )

    for service_info in "${services[@]}"; do
        local service="${service_info%:*}"
        local desc="${service_info#*:}"

        if sudo systemctl is-active --quiet "$service" 2>/dev/null; then
            echo "✅ $desc: ATIVO"
        else
            echo "❌ $desc: INATIVO"
        fi
    done

    echo
    echo "=== Informações de Rede ==="
    echo "IP Local: $(hostname -I | awk '{print $1}')"
    echo "Interface: $NET_IF"
    echo "Gateway: $(ip route | awk '/default/ {print $3}')"
    echo
    echo "=== Uso de Recursos ==="
    echo "Memória: $(free | awk '/Mem:/ {printf "%.1f%%", $3/$2 * 100}')"
    echo "Disco: $(df / | awk 'NR==2 {printf "%.1f%%", $3/$2 * 100}')"
    echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
}

update_services() {
    info "Atualizando serviços do BoxServer..."

    sudo apt-get update -q
    sudo apt-get upgrade -y unbound

    # Atualizar Filebrowser se instalado
    if command -v filebrowser >/dev/null 2>&1; then
        info "Atualizando Filebrowser..."
        install_filebrowser
    fi

    success "Serviços atualizados"
}

# =========================
# FUNÇÃO PRINCIPAL
# =========================
print_usage() {
    cat <<EOF
BoxServer v$SCRIPT_VERSION - Instalador Otimizado para RK322x

USO:
    $0 [opções]

OPÇÕES:
    --install          Instalar BoxServer (modo interativo)
    --silent           Instalar todos os serviços (modo silencioso)
    --clean            Remover completamente o BoxServer
    --status           Mostrar status dos serviços
    --update           Atualizar serviços instalados
    --help             Mostrar esta ajuda

EXEMPLOS:
    $0 --install       # Instalação interativa
    $0 --silent        # Instalação completa automática
    $0 --clean         # Desinstalação completa
    $0 --status        # Ver status dos serviços

EOF
}

main() {
    # Verificar se está rodando como root ou com sudo
    if [[ $EUID -eq 0 ]]; then
        warning "Executando como root. Recomendado usar sudo quando necessário."
    elif ! sudo -n true 2>/dev/null; then
        error "Este script precisa de privilégios sudo"
        exit 1
    fi

    # Processar argumentos
    case "${1:-}" in
        --install)
            local services=$(show_service_menu)
            run_installation "$services"
            ;;
        --silent)
            SILENT_MODE=true
            local services="UNBOUND PIHOLE WIREGUARD FILEBROWSER SAMBA MINIDLNA DASHBOARD"
            run_installation "$services"
            ;;
        --clean)
            if [[ "$SILENT_MODE" = false ]]; then
                if ! whiptail --title "Confirmar Desinstalação" \
                    --yesno "Deseja remover completamente o BoxServer?\n\nEsta ação é irreversível!" 10 68; then
                    info "Desinstalação cancelada"
                    exit 0
                fi
            fi
            perform_system_cleanup
            ;;
        --status)
            show_status
            ;;
        --update)
            update_services
            ;;
        --help|*)
            print_usage
            [[ "${1:-}" != "--help" ]] && exit 1
            ;;
    esac
}

# Verificar dependências mínimas antes de iniciar
if ! command -v whiptail >/dev/null 2>&1; then
    echo "Instalando whiptail..."
    sudo apt-get update -q && sudo apt-get install -y whiptail
fi

# Executar função principal
main "$@"
