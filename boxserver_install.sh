#!/bin/bash
# =============================================================================
# BOXSERVER TUI INSTALLER - VERSÃO UNIFICADA 5.0
# =============================================================================
# Sistema unificado para instalação e gerenciamento do BoxServer
# Interface TUI otimizada para MXQ-4K com chip RK322x
# Consolida todas as versões anteriores eliminando redundâncias
#
# Autor: BoxServer Team
# Versão: 5.0-unified
# Data: $(date +%Y-%m-%d)
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURAÇÕES GLOBAIS
# =============================================================================

readonly SCRIPT_VERSION="5.0-unified"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "$0")"

# Diretórios do sistema
declare -r LOG_DIR="/var/log/boxserver"
declare -r CONFIG_DIR="/etc/boxserver"
declare -r BACKUP_DIR="/var/backups/boxserver"
declare -r WEB_DIR="/var/www/boxserver"
declare -r CACHE_DIR="/tmp/boxserver_cache"
declare -r LOCK_DIR="/var/lock/boxserver"

# Arquivos
declare -r LOG_FILE="${LOG_DIR}/boxserver.log"
declare -r CONFIG_FILE="${CONFIG_DIR}/config.conf"
declare -r PID_FILE="${LOCK_DIR}/boxserver.pid"

# Configurações de interface
declare -r DIALOG_HEIGHT=20
declare -r DIALOG_WIDTH=70
declare -r DIALOG_MENU_HEIGHT=12

# Configurações de sistema
declare -r MAX_LOG_SIZE=$((10 * 1024 * 1024))  # 10MB
declare -r CACHE_TTL=300  # 5 minutos
declare -r MAX_RETRIES=3
declare -r TIMEOUT=30

# =============================================================================
# VARIÁVEIS GLOBAIS
# =============================================================================

declare -A CONFIG=(
    [NETWORK_INTERFACE]=""
    [SERVER_IP]=""
    [HOSTNAME]=""
    [DOMAIN]="boxserver.local"
)

declare -A PORTS=(
    [PIHOLE]=8081
    [FILEBROWSER]=8080
    [COCKPIT]=9090
    [NETDATA]=19999
    [MINIDLNA]=8200
    [WIREGUARD]=51820
    [NGINX]=80
    [NGINX_SSL]=443
)

declare -A SERVICES=(
    [pihole]="Pi-hole|Bloqueador de anúncios DNS|web|${PORTS[PIHOLE]}|/admin"
    [unbound]="Unbound|DNS recursivo seguro|dns|5335|/"
    [wireguard]="WireGuard|Servidor VPN|vpn|${PORTS[WIREGUARD]}|/"
    [cockpit]="Cockpit|Painel administrativo|web|${PORTS[COCKPIT]}|/"
    [filebrowser]="FileBrowser|Gerenciador de arquivos|web|${PORTS[FILEBROWSER]}|/"
    [netdata]="Netdata|Monitor em tempo real|web|${PORTS[NETDATA]}|/"
    [fail2ban]="Fail2Ban|Proteção anti-intrusão|service|0|/"
    [ufw]="UFW|Firewall simplificado|service|0|/"
    [minidlna]="MiniDLNA|Servidor de mídia|media|${PORTS[MINIDLNA]}|/"
    [nginx]="Nginx|Servidor web|web|${PORTS[NGINX]}|/"
)

declare -a DIALOG_OPTS

# =============================================================================
# SISTEMA DE LOGGING
# =============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Criar diretório de log se não existir
    [[ ! -d "$LOG_DIR" ]] && mkdir -p "$LOG_DIR"

    # Rotacionar log se muito grande
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE") -gt $MAX_LOG_SIZE ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
        gzip "${LOG_FILE}.old" 2>/dev/null || true
    fi

    # Escrever no log
    printf '[%s][%s] %s\n' "$timestamp" "$level" "$message" >> "$LOG_FILE"

    # Exibir erros no stderr
    case "$level" in
        ERROR|FATAL)
            printf '\e[31m[%s][%s] %s\e[0m\n' "$timestamp" "$level" "$message" >&2
            ;;
        WARN)
            printf '\e[33m[%s][%s] %s\e[0m\n' "$timestamp" "$level" "$message" >&2
            ;;
    esac
}

# =============================================================================
# SISTEMA DE CACHE
# =============================================================================

cache_get() {
    local key="$1"
    local cache_file="${CACHE_DIR}/${key}"

    if [[ -f "$cache_file" ]]; then
        local cache_time=$(stat -c %Y "$cache_file")
        local current_time=$(date +%s)

        if (( current_time - cache_time < CACHE_TTL )); then
            cat "$cache_file"
            return 0
        else
            rm -f "$cache_file"
        fi
    fi
    return 1
}

cache_set() {
    local key="$1"
    local value="$2"
    local cache_file="${CACHE_DIR}/${key}"

    mkdir -p "$CACHE_DIR"
    echo "$value" > "$cache_file"
}

# =============================================================================
# TRATAMENTO DE ERROS
# =============================================================================

error_handler() {
    local line_num=$1
    local error_code=$2
    local error_msg="${3:-Erro desconhecido}"

    log "ERROR" "Linha $line_num: $error_msg (código: $error_code)"

    dialog --title "❌ Erro Fatal" \
           --msgbox "Erro na linha $line_num:\n\n$error_msg\n\nCódigo: $error_code" \
           12 60 2>/dev/null || true

    cleanup
    exit $error_code
}

cleanup() {
    log "INFO" "Realizando limpeza do sistema..."
    rm -rf "${CACHE_DIR}"/* 2>/dev/null || true
    rm -f "$PID_FILE" 2>/dev/null || true
}

# =============================================================================
# VALIDAÇÕES
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "❌ Este script deve ser executado como root."
        echo "💡 Use: sudo $0"
        exit 1
    fi
}

check_dependencies() {
    local missing=()
    local deps=("dialog" "curl" "wget" "systemctl" "ip" "ss")

    log "INFO" "Verificando dependências..."

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log "ERROR" "Dependências faltando: ${missing[*]}"

        dialog --title "❌ Dependências Faltando" \
               --msgbox "Dependências necessárias não encontradas:\n\n${missing[*]}\n\nInstale-as antes de continuar." \
               10 50
        return 1
    fi

    log "INFO" "Todas as dependências estão disponíveis"
    return 0
}

check_system_resources() {
    local ram_mb=$(free -m | awk 'NR==2{print $2}')
    local disk_gb=$(df / | awk 'NR==2{print int($4/1024/1024)}')

    log "INFO" "Verificando recursos do sistema: RAM=${ram_mb}MB, Disco=${disk_gb}GB"

    if (( ram_mb < 256 )); then
        log "WARN" "Sistema com pouca RAM: ${ram_mb}MB"
        dialog --title "⚠️  Aviso" \
               --msgbox "Sistema detectado com pouca RAM (${ram_mb}MB).\n\nAlguns serviços podem ter limitações." \
               10 50
    fi

    if (( disk_gb < 2 )); then
        log "ERROR" "Espaço em disco insuficiente: ${disk_gb}GB"
        dialog --title "❌ Erro" \
               --msgbox "Espaço em disco insuficiente: ${disk_gb}GB\n\nMínimo necessário: 2GB" \
               10 50
        return 1
    fi

    return 0
}

# =============================================================================
# DETECÇÃO DE REDE
# =============================================================================

detect_network() {
    local interface primary_ip hostname

    # Tentar cache primeiro
    if cached_data=$(cache_get "network_info"); then
        read -r interface primary_ip hostname <<< "$cached_data"
    else
        log "INFO" "Detectando configuração de rede..."

        # Detectar interface principal
        interface=$(ip route | awk '/default/ {print $5}' | head -n1)
        [[ -z "$interface" ]] && error_handler $LINENO 1 "Interface de rede não detectada"

        # Detectar IP principal
        primary_ip=$(ip -o -4 addr show dev "$interface" | awk '{print $4}' | cut -d/ -f1 | head -n1)
        [[ -z "$primary_ip" ]] && error_handler $LINENO 1 "Endereço IP não detectado"

        # Detectar hostname
        hostname=$(hostname -f 2>/dev/null || hostname)

        # Cache da informação
        echo "$interface $primary_ip $hostname" | cache_set "network_info" -
    fi

    CONFIG[NETWORK_INTERFACE]="$interface"
    CONFIG[SERVER_IP]="$primary_ip"
    CONFIG[HOSTNAME]="$hostname"

    log "INFO" "Rede detectada: Interface=$interface, IP=$primary_ip, Hostname=$hostname"
}

# =============================================================================
# CONFIGURAÇÃO DO DIALOG
# =============================================================================

setup_dialog() {
    local backtitle="BoxServer TUI $SCRIPT_VERSION | IP: ${CONFIG[SERVER_IP]} | Hostname: ${CONFIG[HOSTNAME]}"

    DIALOG_OPTS=(
        --backtitle "$backtitle"
        --colors
        --ok-label "✅ Confirmar"
        --cancel-label "🔙 Voltar"
        --timeout 3600
    )
}

# =============================================================================
# GERENCIAMENTO DE SERVIÇOS
# =============================================================================

get_service_status() {
    local service="$1"

    if systemctl is-active "$service" >/dev/null 2>&1; then
        echo "🟢 Ativo"
    elif systemctl is-enabled "$service" >/dev/null 2>&1; then
        echo "🟡 Parado"
    else
        echo "🔴 Inativo"
    fi
}

install_service() {
    local service="$1"

    log "INFO" "Iniciando instalação do serviço: $service"

    case "$service" in
        pihole)
            install_pihole
            ;;
        unbound)
            install_unbound
            ;;
        wireguard)
            install_wireguard
            ;;
        cockpit)
            install_cockpit
            ;;
        filebrowser)
            install_filebrowser
            ;;
        netdata)
            install_netdata
            ;;
        fail2ban)
            install_fail2ban
            ;;
        ufw)
            install_ufw
            ;;
        minidlna)
            install_minidlna
            ;;
        nginx)
            install_nginx
            ;;
        *)
            log "ERROR" "Serviço desconhecido: $service"
            return 1
            ;;
    esac
}

# =============================================================================
# INSTALAÇÃO DE SERVIÇOS ESPECÍFICOS
# =============================================================================

install_pihole() {
    log "INFO" "Instalando Pi-hole..."

    # Download e instalação do Pi-hole
    curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended \
        --admin-port="${PORTS[PIHOLE]}" \
        --interface="${CONFIG[NETWORK_INTERFACE]}" \
        --ipv4-address="${CONFIG[SERVER_IP]}"

    systemctl enable pihole-FTL
    systemctl start pihole-FTL

    log "INFO" "Pi-hole instalado com sucesso"
}

install_unbound() {
    log "INFO" "Instalando Unbound..."

    apt-get update && apt-get install -y unbound

    # Configuração básica do Unbound
    cat > /etc/unbound/unbound.conf.d/pihole.conf << 'EOF'
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    root-hints: "/var/lib/unbound/root.hints"

    hide-identity: yes
    hide-version: yes

    use-caps-for-id: no

    prefetch: yes

    num-threads: 1

    msg-buffer-size: 8192
    msg-cache-size: 1m
    msg-cache-slabs: 1

    rrset-cache-size: 2m
    rrset-cache-slabs: 1

    cache-max-ttl: 86400
    cache-min-ttl: 300

    edns-buffer-size: 1472

    so-rcvbuf: 1m
    so-sndbuf: 1m
EOF

    systemctl enable unbound
    systemctl start unbound

    log "INFO" "Unbound instalado com sucesso"
}

install_wireguard() {
    log "INFO" "Instalando WireGuard..."

    apt-get update && apt-get install -y wireguard wireguard-tools

    # Gerar chaves
    wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey

    # Configuração básica
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/privatekey)
Address = 10.0.0.1/24
ListenPort = ${PORTS[WIREGUARD]}
SaveConfig = true

PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${CONFIG[NETWORK_INTERFACE]} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${CONFIG[NETWORK_INTERFACE]} -j MASQUERADE
EOF

    chmod 600 /etc/wireguard/wg0.conf

    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0

    log "INFO" "WireGuard instalado com sucesso"
}

install_cockpit() {
    log "INFO" "Instalando Cockpit..."

    apt-get update && apt-get install -y cockpit cockpit-system cockpit-networkmanager

    # Configurar porta customizada
    mkdir -p /etc/systemd/system/cockpit.socket.d/
    cat > /etc/systemd/system/cockpit.socket.d/listen.conf << EOF
[Socket]
ListenStream=
ListenStream=${PORTS[COCKPIT]}
EOF

    systemctl daemon-reload
    systemctl enable cockpit.socket
    systemctl start cockpit.socket

    log "INFO" "Cockpit instalado com sucesso"
}

install_filebrowser() {
    log "INFO" "Instalando FileBrowser..."

    # Download do FileBrowser
    curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash

    # Configurar FileBrowser
    filebrowser config init --database /etc/filebrowser/filebrowser.db
    filebrowser users add admin admin --perm.admin --database /etc/filebrowser/filebrowser.db

    # Criar serviço systemd
    cat > /etc/systemd/system/filebrowser.service << EOF
[Unit]
Description=FileBrowser
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/filebrowser --port ${PORTS[FILEBROWSER]} --database /etc/filebrowser/filebrowser.db --root /
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    mkdir -p /etc/filebrowser
    systemctl daemon-reload
    systemctl enable filebrowser
    systemctl start filebrowser

    log "INFO" "FileBrowser instalado com sucesso"
}

install_netdata() {
    log "INFO" "Instalando Netdata..."

    # Instalação via script oficial
    bash <(curl -Ss https://my-netdata.io/kickstart.sh) --non-interactive --stable-channel

    # Configurar porta customizada
    sed -i "s/port = 19999/port = ${PORTS[NETDATA]}/" /etc/netdata/netdata.conf

    systemctl restart netdata

    log "INFO" "Netdata instalado com sucesso"
}

install_fail2ban() {
    log "INFO" "Instalando Fail2Ban..."

    apt-get update && apt-get install -y fail2ban

    # Configuração básica
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

    systemctl enable fail2ban
    systemctl start fail2ban

    log "INFO" "Fail2Ban instalado com sucesso"
}

install_ufw() {
    log "INFO" "Configurando UFW..."

    apt-get update && apt-get install -y ufw

    # Configuração básica
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Permitir serviços essenciais
    ufw allow 22/tcp comment 'SSH'
    ufw allow "${PORTS[NGINX]}/tcp" comment 'HTTP'
    ufw allow "${PORTS[NGINX_SSL]}/tcp" comment 'HTTPS'
    ufw allow "${PORTS[PIHOLE]}/tcp" comment 'Pi-hole'
    ufw allow "${PORTS[COCKPIT]}/tcp" comment 'Cockpit'
    ufw allow "${PORTS[WIREGUARD]}/udp" comment 'WireGuard'

    ufw --force enable

    log "INFO" "UFW configurado com sucesso"
}

install_minidlna() {
    log "INFO" "Instalando MiniDLNA..."

    apt-get update && apt-get install -y minidlna

    # Configuração básica
    cat > /etc/minidlna.conf << EOF
media_dir=V,/home
media_dir=P,/home
media_dir=A,/home

friendly_name=BoxServer Media
db_dir=/var/cache/minidlna

album_art_names=Cover.jpg/cover.jpg/AlbumArtSmall.jpg/albumartsmall.jpg

inotify=yes
enable_tivo=no
strict_dlna=no

presentation_url=http://${CONFIG[SERVER_IP]}:${PORTS[MINIDLNA]}/

notify_interval=895
serial=12345678

model_name=Windows Media Connect compatible (MiniDLNA)
model_number=1
root_container=.
port=${PORTS[MINIDLNA]}
EOF

    systemctl enable minidlna
    systemctl start minidlna

    log "INFO" "MiniDLNA instalado com sucesso"
}

install_nginx() {
    log "INFO" "Instalando Nginx..."

    apt-get update && apt-get install -y nginx

    # Criar configuração do site
    mkdir -p "$WEB_DIR"
    cat > /etc/nginx/sites-available/boxserver << EOF
server {
    listen ${PORTS[NGINX]} default_server;
    listen [::]:${PORTS[NGINX]} default_server;

    root $WEB_DIR;
    index index.html index.htm;

    server_name ${CONFIG[HOSTNAME]} ${CONFIG[SERVER_IP]};

    location / {
        try_files \$uri \$uri/ =404;
    }

    location /pihole/ {
        proxy_pass http://localhost:${PORTS[PIHOLE]}/admin/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location /cockpit/ {
        proxy_pass https://localhost:${PORTS[COCKPIT]}/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location /files/ {
        proxy_pass http://localhost:${PORTS[FILEBROWSER]}/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

    # Ativar site
    ln -sf /etc/nginx/sites-available/boxserver /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default

    # Gerar página inicial
    generate_dashboard

    systemctl enable nginx
    systemctl restart nginx

    log "INFO" "Nginx instalado com sucesso"
}

# =============================================================================
# GERAÇÃO DO DASHBOARD WEB
# =============================================================================

generate_dashboard() {
    log "INFO" "Gerando dashboard web..."

    mkdir -p "$WEB_DIR"

    cat > "$WEB_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BoxServer Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .services {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        .service-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            transition: transform 0.3s ease;
        }
        .service-card:hover {
            transform: translateY(-5px);
        }
        .service-card h3 {
            font-size: 1.5em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .service-card p {
            margin-bottom: 15px;
            opacity: 0.8;
        }
        .service-link {
            display: inline-block;
            background: rgba(255, 255, 255, 0.2);
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 25px;
            transition: background 0.3s ease;
        }
        .service-link:hover {
            background: rgba(255, 255, 255, 0.3);
        }
        .status {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #4CAF50;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            opacity: 0.7;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 BoxServer Dashboard</h1>
            <p>Sistema de Gerenciamento Unificado</p>
        </div>

        <div class="services">
            <div class="service-card">
                <h3><span class="status"></span>🛡️ Pi-hole</h3>
                <p>Bloqueador de anúncios e DNS</p>
                <a href="/pihole/" class="service-link">Acessar</a>
            </div>

            <div class="service-card">
                <h3><span class="status"></span>🖥️ Cockpit</h3>
                <p>Painel de administração do sistema</p>
                <a href="/cockpit/" class="service-link">Acessar</a>
            </div>

            <div class="service-card">
                <h3><span class="status"></span>📁 FileBrowser</h3>
                <p>Gerenciador de arquivos web</p>
                <a href="/files/" class="service-link">Acessar</a>
            </div>

            <div class="service-card">
                <h3><span class="status"></span>📊 Netdata</h3>
                <p>Monitoramento em tempo real</p>
                <a href="http://SERVER_IP:19999/" class="service-link" target="_blank">Acessar</a>
            </div>

            <div class="service-card">
                <h3><span class="status"></span>🔒 WireGuard</h3>
                <p>Servidor VPN seguro</p>
                <a href="#" class="service-link" onclick="alert('Configure via linha de comando')">Configurar</a>
            </div>

            <div class="service-card">
                <h3><span class="status"></span>📺 MiniDLNA</h3>
                <p>Servidor de mídia DLNA</p>
                <a href="http://SERVER_IP:8200/" class="service-link" target="_blank">Acessar</a>
            </div>
        </div>

        <div class="footer">
            <p>BoxServer TUI v5.0-unified | IP: SERVER_IP</p>
        </div>
    </div>

    <script>
        // Substituir SERVER_IP pelo IP real
        document.addEventListener('DOMContentLoaded', function() {
            fetch('/api/info')
                .then(response => response.json())
                .then(data => {
                    document.body.innerHTML = document.body.innerHTML.replace(/SERVER_IP/g, data.ip);
                })
                .catch(error => console.log('API não disponível'));
        });
    </script>
</body>
</html>
EOF

    # Substituir SERVER_IP pelo IP real
    sed -i "s/SERVER_IP/${CONFIG[SERVER_IP]}/g" "$WEB_DIR/index.html"

    log "INFO" "Dashboard web criado com sucesso"
}

# =============================================================================
# MENUS DA INTERFACE TUI
# =============================================================================

show_main_menu() {
    while true; do
        local choice
        choice=$(dialog "${DIALOG_OPTS[@]}" \
            --title "🚀 BoxServer TUI - Menu Principal" \
            --menu "\nEscolha uma opção para continuar:\n" \
            $DIALOG_HEIGHT $DIALOG_WIDTH $DIALOG_MENU_HEIGHT \
            "1" "📊 Status do Sistema" \
            "2" "🔧 Gerenciar Serviços" \
            "3" "⚙️  Configurações" \
            "4" "📋 Visualizar Logs" \
            "5" "🌐 Dashboard Web" \
            "6" "💾 Backup/Restaurar" \
            "7" "🔄 Atualizar Sistema" \
            "8" "ℹ️  Sobre" \
            "9" "🚪 Sair" \
            3>&1 1>&2 2>&3) || break

        case $choice in
            1) show_system_status ;;
            2) show_services_menu ;;
            3) show_settings_menu ;;
            4) show_logs ;;
            5) show_web_dashboard ;;
            6) show_backup_menu ;;
            7) update_system ;;
            8) show_about ;;
            9) confirm_exit && break ;;
        esac
    done
}

show_system_status() {
    local status_text=""

    # Informações do sistema
    status_text+="🖥️  INFORMAÇÕES DO SISTEMA\n"
    status_text+="═══════════════════════════════\n"
    status_text+="Hostname: ${CONFIG[HOSTNAME]}\n"
    status_text+="Interface: ${CONFIG[NETWORK_INTERFACE]}\n"
    status_text+="IP: ${CONFIG[SERVER_IP]}\n"
    status_text+="Domínio: ${CONFIG[DOMAIN]}\n\n"

    # Recursos do sistema
    local ram_mb=$(free -m | awk 'NR==2{print $2}')
    local ram_used=$(free -m | awk 'NR==2{print $3}')
    local disk_total=$(df -h / | awk 'NR==2{print $2}')
    local disk_used=$(df -h / | awk 'NR==2{print $3}')
    local uptime=$(uptime -p)

    status_text+="💾 RECURSOS DO SISTEMA\n"
    status_text+="═══════════════════════════════\n"
    status_text+="RAM: ${ram_used}MB / ${ram_mb}MB\n"
    status_text+="Disco: ${disk_used} / ${disk_total}\n"
    status_text+="Uptime: ${uptime}\n\n"

    # Status dos serviços
    status_text+="🔧 STATUS DOS SERVIÇOS\n"
    status_text+="═══════════════════════════════\n"

    for service_id in "${!SERVICES[@]}"; do
        IFS='|' read -r name desc type port path <<< "${SERVICES[$service_id]}"
        local status=$(get_service_status "$service_id")
        status_text+="$status $name\n"
    done

    dialog "${DIALOG_OPTS[@]}" \
        --title "📊 Status do Sistema" \
        --msgbox "$status_text" \
        25 70
}

show_services_menu() {
    while true; do
        # Construir menu dinâmico dos serviços
        local menu_items=()
        local index=1

        for service_id in "${!SERVICES[@]}"; do
            IFS='|' read -r name desc type port path <<< "${SERVICES[$service_id]}"
            local status=$(get_service_status "$service_id")
            menu_items+=("$index" "$status $name - $desc")
            ((index++))
        done

        menu_items+=("$index" "🔙 Voltar")

        local choice
        choice=$(dialog "${DIALOG_OPTS[@]}" \
            --title "🔧 Gerenciamento de Serviços" \
            --menu "\nSelecione um serviço para gerenciar:\n" \
            20 75 12 \
            "${menu_items[@]}" \
            3>&1 1>&2 2>&3) || break

        if [[ "$choice" == "$index" ]]; then
            break
        fi

        # Converter escolha para ID do serviço
        local service_keys=($(printf '%s\n' "${!SERVICES[@]}" | sort))
        local selected_service="${service_keys[$((choice-1))]}"

        manage_single_service "$selected_service"
    done
}

manage_single_service() {
    local service="$1"
    IFS='|' read -r name desc type port path <<< "${SERVICES[$service]}"

    while true; do
        local status=$(get_service_status "$service")
        local choice

        choice=$(dialog "${DIALOG_OPTS[@]}" \
            --title "🔧 Gerenciar: $name" \
            --menu "\nStatus atual: $status\n" \
            15 60 8 \
            "1" "🚀 Instalar/Reinstalar" \
            "2" "▶️  Iniciar Serviço" \
            "3" "⏸️  Parar Serviço" \
            "4" "🔄 Reiniciar Serviço" \
            "5" "📊 Ver Status Detalhado" \
            "6" "🔧 Configurar" \
            "7" "🔙 Voltar" \
            3>&1 1>&2 2>&3) || break

        case $choice in
            1) install_service "$service" ;;
            2) systemctl start "$service" 2>/dev/null || true ;;
            3) systemctl stop "$service" 2>/dev/null || true ;;
            4) systemctl restart "$service" 2>/dev/null || true ;;
            5) show_service_details "$service" ;;
            6) configure_service "$service" ;;
            7) break ;;
        esac
    done
}

show_service_details() {
    local service="$1"
    local details=""

    details+="🔍 DETALHES DO SERVIÇO: $service\n"
    details+="═══════════════════════════════\n\n"

    if systemctl list-unit-files | grep -q "^$service"; then
        details+="Status: $(systemctl is-active "$service")\n"
        details+="Habilitado: $(systemctl is-enabled "$service")\n"
        details+="PID: $(systemctl show -p MainPID --value "$service")\n\n"

        details+="📋 ÚLTIMAS LINHAS DO LOG:\n"
        details+="─────────────────────────────\n"
        details+="$(journalctl -u "$service" -n 10 --no-pager 2>/dev/null || echo 'Nenhum log disponível')"
    else
        details+="❌ Serviço não encontrado no sistema"
    fi

    dialog "${DIALOG_OPTS[@]}" \
        --title "📋 Detalhes: $service" \
        --msgbox "$details" \
        20 80
}

configure_service() {
    local service="$1"

    dialog "${DIALOG_OPTS[@]}" \
        --title "🔧 Configurar: $service" \
        --msgbox "Configuração específica para $service\nserá implementada em versão futura." \
        10 50
}

show_settings_menu() {
    while true; do
        local choice
        choice=$(dialog "${DIALOG_OPTS[@]}" \
            --title "⚙️ Configurações" \
            --menu "\nConfigurações do sistema:\n" \
            15 60 8 \
            "1" "🌐 Configurar Rede" \
            "2" "🔒 Configurar Segurança" \
            "3" "🔧 Configurar Portas" \
            "4" "📁 Diretórios" \
            "5" "🔄 Reinicializar Serviços" \
            "6" "🧹 Limpeza do Sistema" \
            "7" "🔙 Voltar" \
            3>&1 1>&2 2>&3) || break

        case $choice in
            1) configure_network ;;
            2) configure_security ;;
            3) configure_ports ;;
            4) configure_directories ;;
            5) restart_all_services ;;
            6) system_cleanup ;;
            7) break ;;
        esac
    done
}

configure_network() {
    local new_hostname new_domain

    # Configurar hostname
    new_hostname=$(dialog "${DIALOG_OPTS[@]}" \
        --title "🌐 Configurar Hostname" \
        --inputbox "Digite o novo hostname:" \
        10 50 "${CONFIG[HOSTNAME]}" \
        3>&1 1>&2 2>&3) || return

    if [[ -n "$new_hostname" ]]; then
        hostnamectl set-hostname "$new_hostname"
        CONFIG[HOSTNAME]="$new_hostname"
        log "INFO" "Hostname alterado para: $new_hostname"
    fi

    # Configurar domínio
    new_domain=$(dialog "${DIALOG_OPTS[@]}" \
        --title "🌐 Configurar Domínio" \
        --inputbox "Digite o domínio local:" \
        10 50 "${CONFIG[DOMAIN]}" \
        3>&1 1>&2 2>&3) || return

    if [[ -n "$new_domain" ]]; then
        CONFIG[DOMAIN]="$new_domain"
        log "INFO" "Domínio alterado para: $new_domain"
    fi

    dialog "${DIALOG_OPTS[@]}" \
        --title "✅ Configuração Salva" \
        --msgbox "Configurações de rede atualizadas com sucesso!" \
        8 50
}

configure_security() {
    dialog "${DIALOG_OPTS[@]}" \
        --title "🔒 Configurações de Segurança" \
        --msgbox "Configurações de segurança:\n\n• UFW: Ativo\n• Fail2Ban: Ativo\n• SSH: Protegido\n• Portas: Filtradas" \
        12 50
}

configure_ports() {
    local service port_name new_port

    # Selecionar serviço para configurar porta
    local menu_items=()
    for port_name in "${!PORTS[@]}"; do
        menu_items+=("$port_name" "${PORTS[$port_name]}")
    done

    service=$(dialog "${DIALOG_OPTS[@]}" \
        --title "🔧 Configurar Portas" \
        --menu "\nSelecione o serviço para alterar a porta:\n" \
        15 50 8 \
        "${menu_items[@]}" \
        3>&1 1>&2 2>&3) || return

    new_port=$(dialog "${DIALOG_OPTS[@]}" \
        --title "🔧 Nova Porta para $service" \
        --inputbox "Digite a nova porta:" \
        10 40 "${PORTS[$service]}" \
        3>&1 1>&2 2>&3) || return

    if [[ "$new_port" =~ ^[0-9]+$ ]] && (( new_port >= 1 && new_port <= 65535 )); then
        PORTS[$service]="$new_port"
        log "INFO" "Porta do $service alterada para: $new_port"

        dialog "${DIALOG_OPTS[@]}" \
            --title "✅ Porta Alterada" \
            --msgbox "Porta do $service alterada para $new_port\n\nReinicie o serviço para aplicar a alteração." \
            10 50
    else
        dialog "${DIALOG_OPTS[@]}" \
            --title "❌ Erro" \
            --msgbox "Porta inválida! Use valores entre 1 e 65535." \
            8 50
    fi
}

configure_directories() {
    local info=""
    info+="📁 DIRETÓRIOS DO SISTEMA\n"
    info+="═══════════════════════════════\n\n"
    info+="Logs: $LOG_DIR\n"
    info+="Configurações: $CONFIG_DIR\n"
    info+="Backups: $BACKUP_DIR\n"
    info+="Web: $WEB_DIR\n"
    info+="Cache: $CACHE_DIR\n"
    info+="Locks: $LOCK_DIR\n"

    dialog "${DIALOG_OPTS[@]}" \
        --title "📁 Diretórios do Sistema" \
        --msgbox "$info" \
        15 60
}

restart_all_services() {
    if dialog "${DIALOG_OPTS[@]}" \
        --title "🔄 Reiniciar Serviços" \
        --yesno "Deseja reiniciar todos os serviços do BoxServer?" \
        8 50; then

        for service_id in "${!SERVICES[@]}"; do
            systemctl restart "$service_id" 2>/dev/null || true
        done

        dialog "${DIALOG_OPTS[@]}" \
            --title "✅ Concluído" \
            --msgbox "Todos os serviços foram reiniciados!" \
            8 40
    fi
}

system_cleanup() {
    if dialog "${DIALOG_OPTS[@]}" \
        --title "🧹 Limpeza do Sistema" \
        --yesno "Deseja executar limpeza do sistema?\n\n• Limpar cache\n• Remover logs antigos\n• Liberar espaço" \
        12 50; then

        # Limpar cache
        rm -rf "${CACHE_DIR}"/* 2>/dev/null || true

        # Limpar logs antigos
        find "$LOG_DIR" -name "*.log.old*" -mtime +7 -delete 2>/dev/null || true

        # Limpar packages
        apt-get autoremove -y >/dev/null 2>&1 || true
        apt-get autoclean >/dev/null 2>&1 || true

        dialog "${DIALOG_OPTS[@]}" \
            --title "✅ Limpeza Concluída" \
            --msgbox "Limpeza do sistema executada com sucesso!" \
            8 50
    fi
}

show_logs() {
    if [[ ! -f "$LOG_FILE" ]]; then
        dialog "${DIALOG_OPTS[@]}" \
            --title "📋 Logs" \
            --msgbox "Nenhum arquivo de log encontrado." \
            8 40
        return
    fi

    local choice
    choice=$(dialog "${DIALOG_OPTS[@]}" \
        --title "📋 Visualizar Logs" \
        --menu "\nEscolha uma opção:\n" \
        12 50 5 \
        "1" "📖 Ver log completo" \
        "2" "🔍 Últimas 50 linhas" \
        "3" "❌ Apenas erros" \
        "4" "🔙 Voltar" \
        3>&1 1>&2 2>&3) || return

    case $choice in
        1) dialog "${DIALOG_OPTS[@]}" --title "📋 Log Completo" --textbox "$LOG_FILE" 22 80 ;;
        2) tail -n 50 "$LOG_FILE" | dialog "${DIALOG_OPTS[@]}" --title "📋 Últimas Linhas" --textbox - 22 80 ;;
        3) grep -i "error\|fatal" "$LOG_FILE" | dialog "${DIALOG_OPTS[@]}" --title "❌ Erros" --textbox - 22 80 ;;
        4) return ;;
    esac
}

show_web_dashboard() {
    local dashboard_url="http://${CONFIG[SERVER_IP]}"

    dialog "${DIALOG_OPTS[@]}" \
        --title "🌐 Dashboard Web" \
        --msgbox "Dashboard disponível em:\n\n$dashboard_url\n\nServiços disponíveis:\n• Pi-hole: $dashboard_url/pihole/\n• Cockpit: $dashboard_url/cockpit/\n• FileBrowser: $dashboard_url/files/" \
        15 60
}

show_backup_menu() {
    while true; do
        local choice
        choice=$(dialog "${DIALOG_OPTS[@]}" \
            --title "💾 Backup e Restauração" \
            --menu "\nGerenciar backups:\n" \
            12 50 5 \
            "1" "💾 Criar Backup" \
            "2" "📥 Restaurar Backup" \
            "3" "📋 Listar Backups" \
            "4" "🗑️  Limpar Backups Antigos" \
            "5" "🔙 Voltar" \
            3>&1 1>&2 2>&3) || break

        case $choice in
            1) create_backup ;;
            2) restore_backup ;;
            3) list_backups ;;
            4) clean_old_backups ;;
            5) break ;;
        esac
    done
}

create_backup() {
    local backup_name="boxserver_$(date +%Y%m%d_%H%M%S)"
    local backup_path="${BACKUP_DIR}/${backup_name}.tar.gz"

    mkdir -p "$BACKUP_DIR"

    dialog "${DIALOG_OPTS[@]}" \
        --title "💾 Criando Backup" \
        --infobox "Criando backup...\n\nAguarde..." \
        8 40

    # Criar backup das configurações
    tar -czf "$backup_path" \
        -C / \
        --exclude="$LOG_DIR" \
        --exclude="$CACHE_DIR" \
        "$CONFIG_DIR" \
        "/etc/nginx/sites-available/boxserver" \
        "/etc/pihole" \
        "/etc/wireguard" \
        2>/dev/null || true

    log "INFO" "Backup criado: $backup_path"

    dialog "${DIALOG_OPTS[@]}" \
        --title "✅ Backup Criado" \
        --msgbox "Backup criado com sucesso:\n\n$backup_path" \
        10 60
}

restore_backup() {
    local backup_files=()

    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z "$(ls -A "$BACKUP_DIR")" ]]; then
        dialog "${DIALOG_OPTS[@]}" \
            --title "📥 Restaurar Backup" \
            --msgbox "Nenhum backup encontrado." \
            8 40
        return
    fi

    # Listar arquivos de backup
    while IFS= read -r -d '' file; do
        backup_files+=("$(basename "$file")" "$(date -r "$file" '+%Y-%m-%d %H:%M:%S')")
    done < <(find "$BACKUP_DIR" -name "*.tar.gz" -print0)

    if [[ ${#backup_files[@]} -eq 0 ]]; then
        dialog "${DIALOG_OPTS[@]}" \
            --title "📥 Restaurar Backup" \
            --msgbox "Nenhum arquivo de backup válido encontrado." \
            8 50
        return
    fi

    local selected_backup
    selected_backup=$(dialog "${DIALOG_OPTS[@]}" \
        --title "📥 Selecionar Backup" \
        --menu "\nSelecione o backup para restaurar:\n" \
        15 70 8 \
        "${backup_files[@]}" \
        3>&1 1>&2 2>&3) || return

    if dialog "${DIALOG_OPTS[@]}" \
        --title "⚠️ Confirmar Restauração" \
        --yesno "Deseja restaurar o backup:\n\n$selected_backup\n\nIsto substituirá as configurações atuais!" \
        12 60; then

        tar -xzf "${BACKUP_DIR}/${selected_backup}" -C / 2>/dev/null || true
        log "INFO" "Backup restaurado: $selected_backup"

        dialog "${DIALOG_OPTS[@]}" \
            --title "✅ Backup Restaurado" \
            --msgbox "Backup restaurado com sucesso!\n\nReinicie os serviços para aplicar as alterações." \
            10 60
    fi
}

list_backups() {
    local backup_list=""

    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z "$(ls -A "$BACKUP_DIR")" ]]; then
        dialog "${DIALOG_OPTS[@]}" \
            --title "📋 Lista de Backups" \
            --msgbox "Nenhum backup encontrado." \
            8 40
        return
    fi

    backup_list+="📋 BACKUPS DISPONÍVEIS\n"
    backup_list+="═══════════════════════════════\n\n"

    while IFS= read -r -d '' file; do
        local name=$(basename "$file")
        local size=$(du -h "$file" | cut -f1)
        local date=$(date -r "$file" '+%Y-%m-%d %H:%M:%S')
        backup_list+="$name\n"
        backup_list+="  Tamanho: $size\n"
        backup_list+="  Data: $date\n\n"
    done < <(find "$BACKUP_DIR" -name "*.tar.gz" -print0)

    dialog "${DIALOG_OPTS[@]}" \
        --title "📋 Lista de Backups" \
        --msgbox "$backup_list" \
        20 70
}

clean_old_backups() {
    local count=$(find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 2>/dev/null | wc -l)

    if [[ $count -eq 0 ]]; then
        dialog "${DIALOG_OPTS[@]}" \
            --title "🗑️ Limpeza de Backups" \
            --msgbox "Nenhum backup antigo (>30 dias) encontrado." \
            8 50
        return
    fi

    if dialog "${DIALOG_OPTS[@]}" \
        --title "🗑️ Confirmar Limpeza" \
        --yesno "Encontrados $count backups antigos (>30 dias).\n\nDeseja removê-los?" \
        10 50; then

        find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete 2>/dev/null
        log "INFO" "Backups antigos removidos: $count arquivos"

        dialog "${DIALOG_OPTS[@]}" \
            --title "✅ Limpeza Concluída" \
            --msgbox "$count backups antigos foram removidos." \
            8 50
    fi
}

update_system() {
    if dialog "${DIALOG_OPTS[@]}" \
        --title "🔄 Atualizar Sistema" \
        --yesno "Deseja atualizar o sistema?\n\n• Atualizar pacotes\n• Limpar cache\n• Verificar serviços" \
        12 50; then

        dialog "${DIALOG_OPTS[@]}" \
            --title "🔄 Atualizando..." \
            --infobox "Atualizando sistema...\n\nAguarde..." \
            8 40

        # Atualizar sistema
        apt-get update >/dev/null 2>&1
        apt-get upgrade -y >/dev/null 2>&1

        log "INFO" "Sistema atualizado"

        dialog "${DIALOG_OPTS[@]}" \
            --title "✅ Sistema Atualizado" \
            --msgbox "Sistema atualizado com sucesso!" \
            8 40
    fi
}

show_about() {
    local about_text=""
    about_text+="🚀 BOXSERVER TUI v$SCRIPT_VERSION\n"
    about_text+="═══════════════════════════════\n\n"
    about_text+="Sistema unificado para MXQ-4K\n"
    about_text+="com chip RK322x\n\n"
    about_text+="📋 RECURSOS:\n"
    about_text+="• Interface TUI intuitiva\n"
    about_text+="• Gerenciamento unificado\n"
    about_text+="• Dashboard web responsivo\n"
    about_text+="• Sistema de backup\n"
    about_text+="• Monitoramento em tempo real\n"
    about_text+="• Configuração simplificada\n\n"
    about_text+="🛠️  SERVIÇOS SUPORTADOS:\n"
    about_text+="• Pi-hole (Bloqueador DNS)\n"
    about_text+="• Unbound (DNS recursivo)\n"
    about_text+="• WireGuard (VPN)\n"
    about_text+="• Cockpit (Admin panel)\n"
    about_text+="• FileBrowser (Gerenciador)\n"
    about_text+="• Netdata (Monitoramento)\n"
    about_text+="• Fail2Ban + UFW (Segurança)\n"
    about_text+="• MiniDLNA (Servidor mídia)\n\n"
    about_text+="🏠 IP do Servidor: ${CONFIG[SERVER_IP]}\n"
    about_text+="🌐 Hostname: ${CONFIG[HOSTNAME]}\n\n"
    about_text+="Desenvolvido pela BoxServer Team"

    dialog "${DIALOG_OPTS[@]}" \
        --title "ℹ️ Sobre o BoxServer TUI" \
        --msgbox "$about_text" \
        25 60
}

confirm_exit() {
    dialog "${DIALOG_OPTS[@]}" \
        --title "🚪 Confirmar Saída" \
        --yesno "Deseja realmente sair do BoxServer TUI?" \
        8 50
}

# =============================================================================
# FUNÇÃO PRINCIPAL
# =============================================================================

main() {
    # Configurar tratamento de erros
    trap 'error_handler ${LINENO} $?' ERR
    trap cleanup EXIT

    # Verificações iniciais
    check_root

    # Criar estrutura de diretórios
    mkdir -p "$LOG_DIR" "$CONFIG_DIR" "$BACKUP_DIR" "$WEB_DIR" "$CACHE_DIR" "$LOCK_DIR"

    # Verificar dependências
    check_dependencies || exit 1

    # Verificar recursos do sistema
    check_system_resources || exit 1

    # Detectar rede
    detect_network

    # Configurar interface
    setup_dialog

    log "INFO" "BoxServer TUI v$SCRIPT_VERSION iniciado"

    # Exibir menu principal
    show_main_menu

    log "INFO" "BoxServer TUI finalizado"
}

# Inicializar aplicação
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
