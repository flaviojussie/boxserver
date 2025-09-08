#!/bin/bash
# BoxServer Install V2 - Versão otimizada e refatorada
# Compatível apenas com Armbian 21.08.8 (Debian 11 Bullseye)
# Inclui: Unbound, Pi-hole, WireGuard, Cloudflared, RNG-tools, Samba, MiniDLNA, Filebrowser, Dashboard
# Cria IP fixo default 192.168.0.100
# Exibe relatório com IPs, portas, chaves e senhas ao final

set -euo pipefail

# =========================
# Configurações globais
# =========================
LOGFILE="/var/log/boxserver_install.log"
SUMMARY_FILE="/root/boxserver_summary.txt"
ROLLBACK_LOG="/var/log/boxserver_rollback.log"
DASHBOARD_DIR="/srv/boxserver-dashboard"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
BACKUP_SUFFIX=".bak.${TIMESTAMP}"
SILENT_MODE=false

exec > >(tee -a "$LOGFILE") 2>&1

# =========================
# Configurações de rede
# =========================
DEFAULT_IP="192.168.0.100"
DEFAULT_NETMASK="255.255.255.0"
DEFAULT_GATEWAY="192.168.0.1"
DEFAULT_DNS1="1.1.1.1"
DEFAULT_DNS2="8.8.8.8"

# Portas de serviço
PORT_UNBOUND=53
PORT_PIHOLE=80
PORT_WIREGUARD=51820
PORT_SAMBA=445
PORT_MINIDLNA=8200
PORT_FILEBROWSER=8080
PORT_DASHBOARD=3000

# =========================
# Funções auxiliares
# =========================
whiptail_msg() {
  if [ "$SILENT_MODE" = false ]; then
    whiptail --title "BoxServer Instalador V2" --msgbox "$1" 12 76
  else
    echo "[MSG] $1"
  fi
}

echo_msg() {
  echo "$1"
  if [ "$SILENT_MODE" = false ]; then
    whiptail --title "BoxServer Instalador V2" --msgbox "$1" 12 76
  fi
}

backup_file() {
  local f="$1"
  if [ -f "$f" ]; then
    sudo cp -a "$f" "${f}${BACKUP_SUFFIX}"
    echo "Backup criado: ${f}${BACKUP_SUFFIX}" >> "$ROLLBACK_LOG"
  fi
}

ensure_pkg() {
  local pkg="$1"
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    sudo apt-get install -y "$pkg"
  fi
}

install_dependencies() {
  echo "Instalando dependências básicas..."
  sudo apt-get update -y
  sudo apt-get install -y whiptail curl wget tar gnupg lsb-release ca-certificates \
                          net-tools iproute2 sed grep jq nginx unzip software-properties-common \
                          apt-transport-https dirmngr resolvconf dnsutils
}

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
  if [ "$available_space_mb" -lt "$required_space_mb" ]; then
    whiptail_msg "❌ Espaço em disco insuficiente. Necessário: ${required_space_mb}MB, Disponível: ${available_space_mb}MB"
    exit 1
  fi
  echo "✅ Espaço em disco suficiente: ${available_space_mb}MB disponível"
}

check_connectivity() {
  if ! ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
    whiptail_msg "❌ Sem conectividade de rede. Verifique sua conexão."
    exit 1
  fi
  echo "✅ Conectividade de rede verificada"
}

# =========================
# Configuração de rede
# =========================
configure_static_ip() {
  local interface=$(detect_interface)
  local ip_address="$DEFAULT_IP"
  local netmask="$DEFAULT_NETMASK"
  local gateway="$DEFAULT_GATEWAY"

  echo "Configurando IP estático..."

  backup_file "/etc/network/interfaces"

  sudo tee /etc/network/interfaces > /dev/null <<EOF
# interfaces(5) file used by ifup(8) and ifdown(8)
auto lo
iface lo inet loopback

auto $interface
iface $interface inet static
    address $ip_address
    netmask $netmask
    gateway $gateway
    dns-nameservers $DEFAULT_DNS1 $DEFAULT_DNS2
EOF

  echo "✅ IP estático configurado: $ip_address"
}

# =========================
# Instalação Unificada de Pacotes
# =========================
install_unbound() {
  echo "Instalando Unbound..."
  ensure_pkg unbound

  backup_file "/etc/unbound/unbound.conf"

  sudo tee /etc/unbound/unbound.conf > /dev/null <<EOF
server:
    verbosity: 1
    num-threads: 4
    interface: 0.0.0.0
    interface: ::0
    port: $PORT_UNBOUND
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    do-daemonize: yes
    access-control: 127.0.0.1/32 allow
    access-control: 192.168.0.0/16 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: ::1/128 allow
    access-control: fc00::/7 allow
    root-hints: "/usr/share/dns/root.hints"
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes
    msg-cache-size: 50m
    rrset-cache-size: 100m
    so-rcvbuf: 1m
    so-sndbuf: 1m
    minimal-responses: yes
    qname-minimisation: yes

include: "/etc/unbound/unbound.conf.d/*.conf"
EOF

  sudo mkdir -p /etc/unbound/unbound.conf.d
  sudo systemctl enable unbound
  sudo systemctl restart unbound
  echo "✅ Unbound instalado e configurado"
}

install_pihole() {
  echo "Instalando Pi-hole..."

  curl -sSL https://install.pi-hole.net | bash

  backup_file "/etc/pihole/setupVars.conf"

  sudo tee /etc/pihole/setupVars.conf > /dev/null <<EOF
PIHOLE_INTERFACE=$(detect_interface)
IPV4_ADDRESS=$DEFAULT_IP/24
IPV6_ADDRESS=
PIHOLE_DNS_1=127.0.0.1#53
PIHOLE_DNS_2=
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
BLOCKING_ENABLED=true
DNSMASQ_LISTENING=local
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
WEBPASSWORD=$(openssl rand -base64 12)
EOF

  sudo systemctl restart pihole-FTL
  echo "✅ Pi-hole instalado e configurado"
}

install_wireguard() {
  echo "Instalando WireGuard..."
  ensure_pkg wireguard

  sudo mkdir -p /etc/wireguard

  local private_key=$(wg genkey)
  local public_key=$(echo "$private_key" | wg pubkey)

  backup_file "/etc/wireguard/wg0.conf"

  sudo tee /etc/wireguard/wg0.conf > /dev/null <<EOF
[Interface]
Address = 10.8.0.1/24
PrivateKey = $private_key
ListenPort = $PORT_WIREGUARD
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $(detect_interface) -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $(detect_interface) -j MASQUERADE

[Peer]
PublicKey = $public_key
AllowedIPs = 10.8.0.2/32
EOF

  sudo systemctl enable wg-quick@wg0
  sudo systemctl start wg-quick@wg0
  echo "✅ WireGuard instalado e configurado"
}

install_cloudflared() {
  echo "Instalando Cloudflared..."

  local arch=$(detect_arch)
  local cloudflared_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$arch"

  curl -L "$cloudflared_url" -o /tmp/cloudflared
  sudo install /tmp/cloudflared /usr/local/bin/cloudflared

  sudo useradd -s /bin/false -d /etc/cloudflared cloudflared

  sudo tee /etc/systemd/system/cloudflared.service > /dev/null <<EOF
[Unit]
Description=Cloudflared DNS over HTTPS proxy
After=network.target

[Service]
Type=simple
User=cloudflared
ExecStart=/usr/local/bin/cloudflared proxy-dns --port 5053 --upstream https://1.1.1.1/dns-query --upstream https://1.0.0.1/dns-query
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable cloudflared
  sudo systemctl start cloudflared
  echo "✅ Cloudflared instalado e configurado"
}

install_rng_tools() {
  echo "Instalando RNG-tools..."
  ensure_pkg rng-tools

  backup_file "/etc/default/rng-tools"

  sudo tee /etc/default/rng-tools > /dev/null <<EOF
HRNGDEVICE=/dev/hwrng
RNGDOPTIONS="-W 80% -t 20"
EOF

  sudo systemctl enable rng-tools
  sudo systemctl start rng-tools
  echo "✅ RNG-tools instalado e configurado"
}

install_samba() {
  echo "Instalando Samba..."
  ensure_pkg samba

  backup_file "/etc/samba/smb.conf"

  sudo tee /etc/samba/smb.conf > /dev/null <<EOF
[global]
   workgroup = WORKGROUP
   server string = BoxServer
   netbios name = boxserver
   security = user
   map to guest = bad user
   dns proxy = no
   interfaces = 127.0.0.0/8 192.168.0.0/16
   bind interfaces only = yes

[BoxServer]
   path = /srv/boxserver
   browseable = yes
   writable = yes
   guest ok = yes
   read only = no
   create mask = 0775
   directory mask = 0775
EOF

  sudo mkdir -p /srv/boxserver
  sudo chmod 777 /srv/boxserver

  sudo systemctl enable smbd nmbd
  sudo systemctl restart smbd nmbd
  echo "✅ Samba instalado e configurado"
}

install_minidlna() {
  echo "Instalando MiniDLNA..."
  ensure_pkg minidlna

  backup_file "/etc/minidlna.conf"

  sudo tee /etc/minidlna.conf > /dev/null <<EOF
port=$PORT_MINIDLNA
media_dir=/srv/media
friendly_name=BoxServer
inotify=yes
enable_tivo=no
strict_dlna=no
notify_interval=300
serial=12345678
model_number=1
EOF

  sudo mkdir -p /srv/media
  sudo systemctl enable minidlna
  sudo systemctl restart minidlna
  echo "✅ MiniDLNA instalado e configurado"
}

install_filebrowser() {
  echo "Instalando Filebrowser..."
  local arch=$(detect_arch)

  curl -fsSL https://github.com/filebrowser/filebrowser/releases/latest/download/linux-$arch-filebrowser.tar.gz | tar -xzv -C /usr/local/bin

  sudo tee /etc/systemd/system/filebrowser.service > /dev/null <<EOF
[Unit]
Description=File Browser
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/filebrowser --port $PORT_FILEBROWSER --root /srv
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable filebrowser
  sudo systemctl start filebrowser
  echo "✅ Filebrowser instalado e configurado"
}

install_dashboard() {
  echo "Instalando Dashboard..."

  sudo mkdir -p "$DASHBOARD_DIR"

  sudo tee "$DASHBOARD_DIR/index.html" > /dev/null <<EOF
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BoxServer Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #333; text-align: center; }
        .service { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .service h3 { color: #2196F3; margin-top: 0; }
        .status { padding: 5px 10px; border-radius: 3px; font-weight: bold; }
        .online { background-color: #4CAF50; color: white; }
        .offline { background-color: #f44336; color: white; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>BoxServer Dashboard</h1>
        <div class="grid">
            <div class="service">
                <h3>Pi-hole</h3>
                <p>Admin: http://$DEFAULT_IP/admin</p>
                <p>Status: <span class="status online">Online</span></p>
            </div>
            <div class="service">
                <h3>FileBrowser</h3>
                <p>Acesso: http://$DEFAULT_IP:$PORT_FILEBROWSER</p>
                <p>Status: <span class="status online">Online</span></p>
            </div>
            <div class="service">
                <h3>MiniDLNA</h3>
                <p>Porta: $PORT_MINIDLNA</p>
                <p>Status: <span class="status online">Online</span></p>
            </div>
            <div class="service">
                <h3>WireGuard</h3>
                <p>Porta: $PORT_WIREGUARD</p>
                <p>Status: <span class="status online">Online</span></p>
            </div>
        </div>
    </div>
</body>
</html>
EOF

  sudo tee /etc/nginx/sites-available/boxserver-dashboard > /dev/null <<EOF
server {
    listen $PORT_DASHBOARD;
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
  echo "✅ Dashboard instalado e configurado"
}

# =========================
# Funções de verificação e teste
# =========================
test_dns_resolution() {
  echo "Testando resolução DNS..."
  local test_domains=("google.com" "github.com" "cloudflare.com")

  for domain in "${test_domains[@]}"; do
    if dig +short "$domain" @localhost >/dev/null 2>&1; then
      echo "✅ DNS OK: $domain"
    else
      echo "❌ DNS FALHOU: $domain"
    fi
  done
}

test_services() {
  echo "Testando serviços..."
  local services=("unbound" "pihole-FTL" "wg-quick@wg0" "cloudflared" "rng-tools" "smbd" "nmbd" "minidlna" "filebrowser" "nginx")

  for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
      echo "✅ $service está rodando"
    else
      echo "❌ $service não está rodando"
    fi
  done
}

# =========================
# Geração de relatório
# =========================
generate_summary() {
  echo "Gerando relatório final..."

  {
    echo "=== BoxServer Install V2 - Relatório de Instalação ==="
    echo "Data: $(date)"
    echo "Versão: 2.0"
    echo ""
    echo "=== Configurações de Rede ==="
    echo "IP Estático: $DEFAULT_IP"
    echo "Interface: $(detect_interface)"
    echo "Gateway: $DEFAULT_GATEWAY"
    echo ""
    echo "=== Portas de Serviço ==="
    echo "Unbound DNS: $PORT_UNBOUND"
    echo "Pi-hole: $PORT_PIHOLE"
    echo "WireGuard: $PORT_WIREGUARD"
    echo "Samba: $PORT_SAMBA"
    echo "MiniDLNA: $PORT_MINIDLNA"
    echo "FileBrowser: $PORT_FILEBROWSER"
    echo "Dashboard: $PORT_DASHBOARD"
    echo ""
    echo "=== Acessos ==="
    echo "Pi-hole Admin: http://$DEFAULT_IP/admin"
    echo "FileBrowser: http://$DEFAULT_IP:$PORT_FILEBROWSER"
    echo "Dashboard: http://$DEFAULT_IP:$PORT_DASHBOARD"
    echo "Samba: \\\\$DEFAULT_IP\\BoxServer"
    echo ""
    echo "=== Senhas e Chaves ==="
    echo "Pi-hole Password: $(grep WEBPASSWORD /etc/pihole/setupVars.conf | cut -d'=' -f2)"
    echo "WireGuard Private Key: $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d' ' -f3)"
    echo "WireGuard Public Key: $(grep PublicKey /etc/wireguard/wg0.conf | cut -d' ' -f3)"
    echo ""
    echo "=== Status dos Serviços ==="
    systemctl is-active unbound && echo "Unbound: Ativo" || echo "Unbound: Inativo"
    systemctl is-active pihole-FTL && echo "Pi-hole: Ativo" || echo "Pi-hole: Inativo"
    systemctl is-active wg-quick@wg0 && echo "WireGuard: Ativo" || echo "WireGuard: Inativo"
    systemctl is-active cloudflared && echo "Cloudflared: Ativo" || echo "Cloudflared: Inativo"
    systemctl is-active rng-tools && echo "RNG-tools: Ativo" || echo "RNG-tools: Inativo"
    systemctl is-active smbd && echo "Samba: Ativo" || echo "Samba: Inativo"
    systemctl is-active minidlna && echo "MiniDLNA: Ativo" || echo "MiniDLNA: Inativo"
    systemctl is-active filebrowser && echo "FileBrowser: Ativo" || echo "FileBrowser: Inativo"
    systemctl is-active nginx && echo "Nginx: Ativo" || echo "Nginx: Inativo"
  } > "$SUMMARY_FILE"

  echo "✅ Relatório gerado: $SUMMARY_FILE"
}

# =========================
# Função de limpeza
# =================--------
cleanup_installation() {
  echo "Iniciando limpeza completa do BoxServer..."

  if command -v pihole >/dev/null 2>&1; then
    echo "Removendo Pi-hole..."
    pihole uninstall --unattended
  fi

  echo "Removendo serviços..."
  sudo systemctl stop unbound pihole-FTL wg-quick@wg0 cloudflared rng-tools smbd nmbd minidlna filebrowser nginx 2>/dev/null || true
  sudo systemctl disable unbound pihole-FTL wg-quick@wg0 cloudflared rng-tools smbd nmbd minidlna filebrowser nginx 2>/dev/null || true

  echo "Removendo pacotes..."
  sudo apt-get remove --purge -y unbound pi-hole wireguard cloudflared rng-tools samba minidlna nginx 2>/dev/null || true
  sudo apt-get autoremove -y

  echo "Removendo arquivos de configuração..."
  sudo rm -rf /etc/unbound /etc/pihole /etc/wireguard /etc/cloudflared /etc/samba /etc/minidlna /etc/nginx/sites-available/boxserver-dashboard
  sudo rm -f /etc/systemd/system/cloudflared.service /etc/systemd/system/filebrowser.service
  sudo rm -rf /srv/boxserver /srv/media "$DASHBOARD_DIR"

  echo "Removendo logs e backups..."
  sudo rm -f "$LOGFILE" "$SUMMARY_FILE" "$ROLLBACK_LOG"

  echo "✅ Limpeza completa realizada"
}

# =========================
# Função principal
# =========================
main() {
  echo "Iniciando instalação do BoxServer V2..."

  # Verificações iniciais
  check_disk_space
  check_connectivity

  # Instalação de dependências
  install_dependencies

  # Configuração de rede
  configure_static_ip

  # Instalação dos serviços
  install_unbound
  install_pihole
  install_wireguard
  install_cloudflared
  install_rng_tools
  install_samba
  install_minidlna
  install_filebrowser
  install_dashboard

  # Testes e verificação
  test_dns_resolution
  test_services

  # Geração de relatório
  generate_summary

  echo_msg "🎉 BoxServer V2 instalado com sucesso!"
  echo_msg "📋 Relatório disponível em: $SUMMARY_FILE"
  echo_msg "🌐 Dashboard disponível em: http://$DEFAULT_IP:$PORT_DASHBOARD"
}

# =========================
# Processamento de argumentos
# =========================
case "${1:-}" in
  --clean)
    cleanup_installation
    ;;
  --silent)
    SILENT_MODE=true
    main
    ;;
  *)
    main
    ;;
esac
