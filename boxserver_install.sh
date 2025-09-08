#!/bin/bash
# BoxServer Installer - Final Version with Enhanced Features
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
# Funções auxiliares
# =========================
whiptail_msg() {
  if [ "$SILENT_MODE" = false ]; then
    whiptail --title "BoxServer Instalador" --msgbox "$1" 12 76
  else
    echo "[MSG] $1"
  fi
}

echo_msg() {
  echo "$1"
  if [ "$SILENT_MODE" = false ]; then
    whiptail --title "BoxServer Instalador" --msgbox "$1" 12 76
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

ensure_deps() {
  echo "Instalando dependências básicas..."
  sudo apt-get update -y
  sudo apt-get install -y whiptail curl wget tar gnupg lsb-release ca-certificates \
                          net-tools iproute2 sed grep jq nginx
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

find_free_port() {
  local port=$1
  while sudo netstat -tln | awk '{print $4}' | grep -q ":$port$"; do
    port=$((port + 1))
  done
  echo "$port"
}

check_and_set_ports() {
  echo "Verificando e alocando portas de serviço..."
  local original_port

  original_port=$PIHOLE_HTTP_PORT
  PIHOLE_HTTP_PORT=$(find_free_port "$PIHOLE_HTTP_PORT")
  if [ "$PIHOLE_HTTP_PORT" != "$original_port" ]; then
    whiptail_msg "A porta $original_port estava em uso. Pi-hole HTTP usará a porta $PIHOLE_HTTP_PORT."
  fi

  original_port=$PIHOLE_HTTPS_PORT
  PIHOLE_HTTPS_PORT=$(find_free_port "$PIHOLE_HTTPS_PORT")
  if [ "$PIHOLE_HTTPS_PORT" != "$original_port" ]; then
    whiptail_msg "A porta $original_port estava em uso. Pi-hole HTTPS usará a porta $PIHOLE_HTTPS_PORT."
  fi

  original_port=$FILEBROWSER_PORT
  FILEBROWSER_PORT=$(find_free_port "$FILEBROWSER_PORT")
  if [ "$FILEBROWSER_PORT" != "$original_port" ]; then
    whiptail_msg "A porta $original_port estava em uso. Filebrowser usará a porta $FILEBROWSER_PORT."
  fi

  original_port=$MINIDLNA_PORT
  MINIDLNA_PORT=$(find_free_port "$MINIDLNA_PORT")
  if [ "$MINIDLNA_PORT" != "$original_port" ]; then
    whiptail_msg "A porta $original_port estava em uso. MiniDLNA usará a porta $MINIDLNA_PORT."
  fi
}

# =========================
# Verificação do sistema
# =========================
check_system() {
  if [ ! -f /etc/armbian-release ]; then
    whiptail_msg "❌ Este instalador requer Armbian 21.08.8 (Debian 11 Bullseye).
Arquivo /etc/armbian-release não encontrado."
    exit 1
  fi

  . /etc/armbian-release
  if [ "$VERSION" != "21.08.8" ]; then
    whiptail_msg "❌ Este instalador é exclusivo para Armbian 21.08.8.
Detectado: $VERSION"
    exit 1
  fi

  if ! grep -q 'VERSION_ID="11"' /etc/os-release; then
    whiptail_msg "❌ Base incompatível. É necessário Debian 11 (Bullseye)."
    exit 1
  fi

  echo "✅ Sistema compatível: Armbian $VERSION (Debian 11 Bullseye)"
}

# =========================
# Configurações globais
# =========================
DEFAULT_IP="192.168.0.100"
STATIC_IP=""
GATEWAY=""
NET_IF=""
DOMAIN_DEFAULT="pihole.local"
DOMAIN=""
UNBOUND_PORT=5335
PIHOLE_HTTP_PORT=8081
PIHOLE_HTTPS_PORT=8443
FILEBROWSER_PORT=8080
MINIDLNA_PORT=8200
WG_PORT=51820
SUMMARY_ENTRIES=()
WG_PRIVATE=""
WG_PUBLIC=""

# =========================
# Funções de rollback
# =========================
rollback_changes() {
  echo "Executando rollback das alterações..."
  if [ -f "$ROLLBACK_LOG" ]; then
    while IFS= read -r line; do
      if [[ $line == "Backup criado: "* ]]; then
        backup_file="${line#Backup criado: }"
        original_file="${backup_file%$BACKUP_SUFFIX}"
        if [ -f "$backup_file" ]; then
          sudo mv "$backup_file" "$original_file"
          echo "Restaurado: $original_file"
        fi
      fi
    done < "$ROLLBACK_LOG"
  fi

  # Parar e desabilitar serviços instalados
  local services=("unbound" "pihole-ftl" "wg-quick@wg0" "cloudflared" "rng-tools" "smbd" "minidlna" "filebrowser" "nginx")
  for service in "${services[@]}"; do
    if systemctl list-units --type=service | grep -q "$service"; then
      sudo systemctl stop "$service" 2>/dev/null || true
      sudo systemctl disable "$service" 2>/dev/null || true
    fi
  done

  # Remover arquivos e diretórios criados
  sudo rm -rf /srv/boxserver-dashboard \
              /etc/wireguard \
              /etc/cloudflared \
              /srv/filebrowser \
              /srv/samba/share \
              /srv/media \
              /etc/unbound/unbound.conf.d/pi-hole.conf \
              /etc/systemd/system/filebrowser.service \
              /etc/systemd/system/cloudflared.service \
              /etc/netplan/01-boxserver.yaml \
              "$SUMMARY_FILE" \
              "$ROLLBACK_LOG" \
              2>/dev/null || true

  echo "Rollback concluído."
}

# =========================
# Configuração IP fixo
# =========================
ask_static_ip() {
  NET_IF=$(detect_interface)
  local current_ip
  current_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [ -z "$current_ip" ] && current_ip="$DEFAULT_IP"

  if [ "$SILENT_MODE" = false ]; then
    STATIC_IP=$(whiptail --inputbox "Informe o IP fixo para este servidor:" 10 68 "$current_ip" 3>&1 1>&2 2>&3)
  else
    STATIC_IP="$current_ip"
  fi

  [ -z "$STATIC_IP" ] && STATIC_IP="$DEFAULT_IP"

  GATEWAY=$(ip route | awk '/^default/ {print $3; exit}' || true)
  [ -z "$GATEWAY" ] && GATEWAY="192.168.0.1"

  if [ -d /etc/netplan ]; then
    sudo mkdir -p /etc/netplan
    backup_file /etc/netplan/01-boxserver.yaml || true
    cat <<EOF | sudo tee /etc/netplan/01-boxserver.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    $NET_IF:
      dhcp4: no
      addresses: [$STATIC_IP/24]
      gateway4: $GATEWAY
      nameservers:
        addresses: [1.1.1.1,8.8.8.8]
EOF
    sudo netplan apply || echo "⚠️ Falha ao aplicar netplan, configure manualmente."
    SUMMARY_ENTRIES+=("IP Fixo: $STATIC_IP (interface $NET_IF)")
  else
    SUMMARY_ENTRIES+=("IP Fixo solicitado: $STATIC_IP (configure manualmente)")
  fi
}

# =========================
# Seleção de serviços
# =========================
choose_services() {
  if [ "$SILENT_MODE" = false ]; then
    CHOICES=$(whiptail --title "Seleção de Componentes" --checklist \
    "Selecione os serviços a instalar:" 20 80 12 \
    "UNBOUND" "Unbound DNS recursivo" ON \
    "PIHOLE" "Pi-hole (8081/8443)" ON \
    "WIREGUARD" "VPN WireGuard" ON \
    "CLOUDFLARE" "Cloudflared tunnel" ON \
    "RNG" "rng-tools" ON \
    "SAMBA" "Samba share" ON \
    "MINIDLNA" "MiniDLNA media" ON \
    "FILEBROWSER" "Filebrowser" ON \
    "DASHBOARD" "Dashboard web (nginx)" ON \
    3>&1 1>&2 2>&3)
    CHOICES="${CHOICES//\"/}"
  else
    # Modo silencioso - instala todos os serviços
    CHOICES="UNBOUND PIHOLE WIREGUARD CLOUDFLARE RNG SAMBA MINIDLNA FILEBROWSER DASHBOARD"
  fi
}

# =========================
# Funções de atualização
# =========================
update_services() {
  echo "Atualizando serviços..."

  # Atualizar Pi-hole
  if command -v pihole &> /dev/null; then
    echo "Atualizando Pi-hole..."
    sudo pihole -up
  fi

  # Atualizar Unbound
  if dpkg -l | grep -q "^ii.*unbound"; then
    echo "Atualizando Unbound..."
    sudo apt-get update
    sudo apt-get install --only-upgrade -y unbound
  fi

  # Atualizar Filebrowser
  if command -v filebrowser &> /dev/null; then
    echo "Atualizando Filebrowser..."
    FB_VERSION=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | grep tag_name | cut -d '"' -f4)
    ARCH=$(detect_arch)
    case "$ARCH" in
      amd64) FB_ARCH="linux-amd64";;
      arm64) FB_ARCH="linux-arm64";;
      arm) FB_ARCH="linux-armv7";;
      *) echo "Arquitetura não suportada pelo Filebrowser"; return;;
    esac

    if wget -O filebrowser.tar.gz https://github.com/filebrowser/filebrowser/releases/download/${FB_VERSION}/${FB_ARCH}-filebrowser.tar.gz; then
      tar -xzf filebrowser.tar.gz
      sudo mv filebrowser /usr/local/bin/
      rm -f filebrowser.tar.gz
      sudo systemctl restart filebrowser
    fi
  fi

  # Atualizar Cloudflared
  if command -v cloudflared &> /dev/null; then
    echo "Atualizando Cloudflared..."
    ARCH=$(detect_arch)
    URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
    if sudo wget -O /usr/local/bin/cloudflared "$URL"; then
      sudo chmod +x /usr/local/bin/cloudflared
      sudo systemctl restart cloudflared
    fi
  fi

  echo "Atualização concluída."
}

# =========================
# Funções de instalação
# =========================
install_unbound() {
  echo_msg "Instalando/reconfigurando Unbound..."
  SUMMARY_ENTRIES+=("Unbound DNS: Porta $UNBOUND_PORT")

  # Verificar se Unbound já está instalado
  if dpkg -l | grep -q "^ii.*unbound"; then
    echo_msg "Unbound já está instalado. Reconfigurando..."
  else
    echo_msg "Instalando Unbound..."
    sudo apt install -y unbound
  fi

  sudo mkdir -p /etc/unbound/unbound.conf.d /var/lib/unbound

  backup_file /etc/unbound/unbound.conf.d/pi-hole.conf
  cat <<EOF | sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    interface: 127.0.0.1
    port: $UNBOUND_PORT
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    harden-glue: yes
    harden-dnssec-stripped: yes
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

  # Baixar root hints se não existirem
  if [ ! -f /var/lib/unbound/root.hints ]; then
    sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
  fi

  # Configurar trust anchor se não existir
  if [ ! -f /var/lib/unbound/root.key ]; then
    sudo unbound-anchor -a /var/lib/unbound/root.key || true
  fi

  sudo systemctl enable --now unbound

  # Verificar se o serviço está rodando
  if sudo systemctl is-active --quiet unbound; then
    echo_msg "✅ Unbound instalado/reconfigurado e em execução"
  else
    echo_msg "⚠️  Unbound instalado/reconfigurado, mas pode não estar em execução"
  fi
}

install_pihole() {
  echo_msg "Instalando/reconfigurando Pi-hole..."
  SUMMARY_ENTRIES+=("Pi-hole: Portas $PIHOLE_HTTP_PORT/$PIHOLE_HTTPS_PORT")

  # Verificar se o Pi-hole já está instalado
  if command -v pihole &> /dev/null; then
    echo_msg "Pi-hole já está instalado. Reconfigurando..."
  else
    # Instalar lighttpd explicitamente antes do Pi-hole
    echo_msg "Instalando lighttpd como dependência do Pi-hole..."
    if ! sudo apt install -y lighttpd; then
      echo_msg "❌ Falha ao instalar lighttpd"
      return 1
    fi

    # Executar o instalador do Pi-hole em modo não interativo
    echo_msg "Executando instalador do Pi-hole..."
    if ! curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended; then
      echo_msg "❌ Falha na instalação do Pi-hole"
      return 1
    fi
  fi

  # Configurar o Pi-hole
  sudo mkdir -p /etc/pihole
  sudo touch /etc/pihole/setupVars.conf
  if grep -q '^PIHOLE_DNS_1=' /etc/pihole/setupVars.conf; then
    sudo sed -i "s/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#$UNBOUND_PORT/" /etc/pihole/setupVars.conf
  else
    echo "PIHOLE_DNS_1=127.0.0.1#$UNBOUND_PORT" | sudo tee -a /etc/pihole/setupVars.conf
  fi

  # Reiniciar o DNS do Pi-hole
  if command -v pihole &> /dev/null; then
    sudo pihole restartdns
  else
    # Se o comando pihole não estiver disponível, reiniciar o serviço diretamente
    sudo systemctl restart pihole-ftl
  fi

  echo_msg "Alterando Pi-hole para rodar em $PIHOLE_HTTP_PORT/$PIHOLE_HTTPS_PORT..."

  # Verificar se o lighttpd está instalado, se não, instalar
  if ! dpkg -s "lighttpd" >/dev/null 2>&1; then
    echo_msg "lighttpd não está instalado. Instalando agora..."
    if ! sudo apt-get install -y lighttpd; then
        echo_msg "❌ Falha ao instalar lighttpd. A configuração do Pi-hole não pode continuar."
        return 1
    fi
    # Recarregar systemd para garantir que o novo serviço seja encontrado
    sudo systemctl daemon-reload
  fi

  backup_file /etc/lighttpd/lighttpd.conf
  if [ -f /etc/lighttpd/lighttpd.conf ]; then
    sudo sed -i "s/server.port\s*=\s*80/server.port = $PIHOLE_HTTP_PORT/" /etc/lighttpd/lighttpd.conf
  else
    # Criar arquivo de configuração básico se não existir
    sudo mkdir -p /etc/lighttpd
    cat <<EOF | sudo tee /etc/lighttpd/lighttpd.conf
server.modules = (
    "mod_access",
    "mod_alias",
    "mod_compress",
    "mod_redirect",
)

server.document-root        = "/var/www/html"
server.upload-dirs          = ( "/var/cache/lighttpd/uploads" )
server.errorlog             = "/var/log/lighttpd/error.log"
server.pid-file             = "/var/run/lighttpd.pid"
server.username             = "www-data"
server.groupname            = "www-data"
server.port                 = $PIHOLE_HTTP_PORT

# SSL configuration
$SERVER["socket"] == ":$PIHOLE_HTTPS_PORT" {
    ssl.engine = "enable"
    ssl.pemfile = "/etc/lighttpd/server.pem"
}
EOF
  fi

  # Garantir que o diretório /etc/lighttpd exista
  sudo mkdir -p /etc/lighttpd

  # Criar o arquivo external.conf corretamente
  backup_file /etc/lighttpd/external.conf
  cat <<EOF | sudo tee /etc/lighttpd/external.conf
\$SERVER["socket"] == ":$PIHOLE_HTTPS_PORT" \{ ssl.engine = "enable" \}
EOF

  # Garante que o systemd está atualizado e tenta reiniciar o lighttpd
  sudo systemctl daemon-reload
  if ! sudo systemctl restart lighttpd >/dev/null 2>&1; then
    echo_msg "Não foi possível reiniciar o lighttpd. Tentando reinstalar..."
    if ! sudo apt-get install --reinstall -y lighttpd; then
        echo_msg "❌ Falha ao reinstalar lighttpd. A configuração do Pi-hole não pode continuar."
        return 1
    fi
    # Tenta iniciar novamente após a reinstalação
    if ! sudo systemctl enable --now lighttpd; then
        echo_msg "❌ Mesmo após a reinstalação, não foi possível iniciar o lighttpd."
        return 1
    fi
  fi

  # Verificação final
  if sudo systemctl is-active --quiet lighttpd; then
    echo_msg "✅ Pi-hole instalado/reconfigurado e em execução nas portas $PIHOLE_HTTP_PORT/$PIHOLE_HTTPS_PORT"
  else
    echo_msg "⚠️  Pi-hole instalado/reconfigurado, mas o serviço lighttpd pode não estar em execução corretamente."
  fi
}

install_wireguard() {
  echo_msg "Instalando/reconfigurando WireGuard..."
  SUMMARY_ENTRIES+=("WireGuard: Porta UDP $WG_PORT")

  # Verificar se WireGuard já está instalado
  if dpkg -l | grep -q "^ii.*wireguard"; then
    echo_msg "WireGuard já está instalado. Reconfigurando..."
  else
    echo_msg "Instalando WireGuard..."
    sudo apt install -y wireguard wireguard-tools
  fi

  sudo mkdir -p /etc/wireguard/keys
  sudo chmod 700 /etc/wireguard/keys
  umask 077

  # Verificar se as chaves já existem
  if [ ! -f /etc/wireguard/keys/privatekey ] || [ ! -f /etc/wireguard/keys/publickey ]; then
    wg genkey | sudo tee /etc/wireguard/keys/privatekey | wg pubkey | sudo tee /etc/wireguard/keys/publickey
  fi

  WG_PRIVATE=$(sudo cat /etc/wireguard/keys/privatekey)
  WG_PUBLIC=$(sudo cat /etc/wireguard/keys/publickey)

  backup_file /etc/wireguard/wg0.conf
  cat <<EOF | sudo tee /etc/wireguard/wg0.conf
[Interface]
PrivateKey = $WG_PRIVATE
Address = 10.200.200.1/24
ListenPort = $WG_PORT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_IF -j MASQUERADE
EOF

  sudo chmod 600 /etc/wireguard/wg0.conf
  echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
  sudo sysctl -p
  sudo systemctl enable --now wg-quick@wg0

  # Verificar se o serviço está rodando
  if sudo systemctl is-active --quiet wg-quick@wg0; then
    echo_msg "✅ WireGuard instalado/reconfigurado e em execução"
  else
    echo_msg "⚠️  WireGuard instalado/reconfigurado, mas pode não estar em execução"
  fi
}

install_cloudflared() {
  echo_msg "Instalando/reconfigurando Cloudflare Tunnel..."
  SUMMARY_ENTRIES+=("Cloudflared: Domínio $DOMAIN (requer autenticação manual)")
  ARCH=$(detect_arch)
  URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"

  # Baixar e instalar cloudflared
  if sudo wget -O /usr/local/bin/cloudflared "$URL"; then
    sudo chmod +x /usr/local/bin/cloudflared
    sudo mkdir -p /etc/cloudflared

    backup_file /etc/cloudflared/config.yml
    cat <<EOF | sudo tee /etc/cloudflared/config.yml
tunnel: boxserver
credentials-file: /etc/cloudflared/boxserver.json
ingress:
  - hostname: $DOMAIN
    service: http://localhost:$PIHOLE_HTTP_PORT
  - service: http_status:404
EOF

    # Criar serviço systemd para cloudflared
    backup_file /etc/systemd/system/cloudflared.service
    cat <<EOF | sudo tee /etc/systemd/system/cloudflared.service
[Unit]
Description=cloudflared
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/cloudflared --config /etc/cloudflared/config.yml tunnel run
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable cloudflared

    # Verificar se já existe autenticação
    if [ -f "/etc/cloudflared/boxserver.json" ]; then
      sudo systemctl start cloudflared
      if sudo systemctl is-active --quiet cloudflared; then
        echo_msg "✅ Cloudflare Tunnel instalado/reconfigurado e em execução"
      else
        echo_msg "⚠️  Cloudflare Tunnel configurado mas falhou ao iniciar. Verifique as credenciais."
      fi
    else
      # Modo interativo: guiar usuário através da autenticação
      if [ "$SILENT_MODE" = false ]; then
        whiptail_msg "🔐 Cloudflare Tunnel requer autenticação manual:\n\n1. Execute: sudo cloudflared tunnel login\n2. Siga as instruções no navegador\n3. Execute: sudo cloudflared tunnel create boxserver\n4. Execute: sudo systemctl start cloudflared"
      else
        echo_msg "⚠️  Cloudflare Tunnel instalado mas requer autenticação manual:"
        echo_msg "  1. Execute: sudo cloudflared tunnel login"
        echo_msg "  2. Siga as instruções no navegador"
        echo_msg "  3. Execute: sudo cloudflared tunnel create boxserver"
        echo_msg "  4. Execute: sudo systemctl start cloudflared"
      fi
    fi
  else
    echo_msg "❌ Falha ao baixar Cloudflare Tunnel"
  fi
}

install_rng() {
  echo_msg "Instalando/reconfigurando RNG-tools..."
  SUMMARY_ENTRIES+=("RNG-tools: Configurado")

  # Verificar se RNG-tools já está instalado
  if dpkg -l | grep -q "^ii.*rng-tools"; then
    echo_msg "RNG-tools já está instalado. Reconfigurando..."
  else
    echo_msg "Instalando RNG-tools..."
    sudo apt install -y rng-tools
  fi

  sudo mkdir -p /etc/default

  if [ -e /dev/hwrng ]; then
    RNGDEVICE="/dev/hwrng"
  else
    RNGDEVICE="/dev/urandom"
  fi

  backup_file /etc/default/rng-tools
  cat <<EOF | sudo tee /etc/default/rng-tools
RNGDEVICE="$RNGDEVICE"
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10"
EOF
  sudo systemctl enable --now rng-tools

  # Verificar se o serviço está rodando
  if sudo systemctl is-active --quiet rng-tools; then
    echo_msg "✅ RNG-tools instalado/reconfigurado e em execução"
  else
    echo_msg "⚠️  RNG-tools instalado/reconfigurado, mas pode não estar em execução"
  fi
}

install_samba() {
  echo_msg "Instalando/reconfigurando Samba..."
  SUMMARY_ENTRIES+=("Samba: Compartilhamento BoxShare em /srv/samba/share")

  # Verificar se Samba já está instalado
  if dpkg -l | grep -q "^ii.*samba"; then
    echo_msg "Samba já está instalado. Reconfigurando..."
  else
    echo_msg "Instalando Samba..."
    sudo apt install -y samba
  fi

  sudo mkdir -p /srv/samba/share
  sudo chmod 777 /srv/samba/share

  # Verificar se o arquivo smb.conf existe
  if [ ! -f /etc/samba/smb.conf ]; then
    sudo touch /etc/samba/smb.conf
  fi

  # Adicionar configuração do BoxShare se não existir
  if ! grep -q "BoxShare" /etc/samba/smb.conf; then
    backup_file /etc/samba/smb.conf
    cat <<EOF | sudo tee -a /etc/samba/smb.conf

[BoxShare]
   path = /srv/samba/share
   browseable = yes
   read only = no
   guest ok = yes
EOF
  fi

  sudo systemctl enable --now smbd

  # Verificar se o serviço está rodando
  if sudo systemctl is-active --quiet smbd; then
    echo_msg "✅ Samba instalado/reconfigurado e em execução"
  else
    echo_msg "⚠️  Samba instalado/reconfigurado, mas pode não estar em execução"
  fi
}

install_minidlna() {
  echo_msg "Instalando/reconfigurando MiniDLNA..."
  SUMMARY_ENTRIES+=("MiniDLNA: Porta $MINIDLNA_PORT, Pastas em /srv/media")

  # Verificar se MiniDLNA já está instalado
  if dpkg -l | grep -q "^ii.*minidlna"; then
    echo_msg "MiniDLNA já está instalado. Reconfigurando..."
  else
    echo_msg "Instalando MiniDLNA..."
    sudo apt install -y minidlna
  fi

  sudo mkdir -p /srv/media/{video,audio,photos}

  # Verificar se o arquivo minidlna.conf existe
  if [ ! -f /etc/minidlna.conf ]; then
    sudo touch /etc/minidlna.conf
  fi

  # Criar ou atualizar configuração do MiniDLNA
  backup_file /etc/minidlna.conf
  cat <<EOF | sudo tee /etc/minidlna.conf
media_dir=V,/srv/media/video
media_dir=A,/srv/media/audio
media_dir=P,/srv/media/photos
friendly_name=BoxServer DLNA
inotify=yes
port=$MINIDLNA_PORT
EOF

  sudo systemctl enable --now minidlna

  # Verificar se o serviço está rodando
  if sudo systemctl is-active --quiet minidlna; then
    echo_msg "✅ MiniDLNA instalado/reconfigurado e em execução"
  else
    echo_msg "⚠️  MiniDLNA instalado/reconfigurado, mas pode não estar em execução"
  fi
}

install_filebrowser() {
  echo_msg "Instalando/reconfigurando Filebrowser..."
  SUMMARY_ENTRIES+=("Filebrowser: Porta $FILEBROWSER_PORT, Pasta /srv/filebrowser")
  FB_VERSION=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | grep tag_name | cut -d '"' -f4)
  ARCH=$(detect_arch)
  case "$ARCH" in
    amd64) FB_ARCH="linux-amd64";;
    arm64) FB_ARCH="linux-arm64";;
    arm) FB_ARCH="linux-armv7";;
    *) echo_msg "Arquitetura não suportada pelo Filebrowser"; return;;
  esac

  # Baixar e instalar Filebrowser
  if wget -O filebrowser.tar.gz https://github.com/filebrowser/filebrowser/releases/download/${FB_VERSION}/${FB_ARCH}-filebrowser.tar.gz; then
    tar -xzf filebrowser.tar.gz
    sudo mv filebrowser /usr/local/bin/
    rm -f filebrowser.tar.gz
    sudo mkdir -p /srv/filebrowser
    sudo useradd -r -s /bin/false filebrowser || true

    backup_file /etc/systemd/system/filebrowser.service
    cat <<EOF | sudo tee /etc/systemd/system/filebrowser.service
[Unit]
Description=Filebrowser
After=network.target

[Service]
User=filebrowser
ExecStart=/usr/local/bin/filebrowser -r /srv/filebrowser --port $FILEBROWSER_PORT
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reexec
    sudo systemctl enable --now filebrowser

    # Verificar se o serviço está rodando
    if sudo systemctl is-active --quiet filebrowser; then
      echo_msg "✅ Filebrowser instalado/reconfigurado e em execução"
    else
      echo_msg "⚠️  Filebrowser instalado/reconfigurado, mas pode não estar em execução"
    fi
  else
    echo_msg "❌ Falha ao baixar Filebrowser"
  fi
}

# =========================
# DASHBOARD WEB
# =========================
install_dashboard() {
  echo_msg "Instalando/reconfigurando Dashboard Web..."
  SUMMARY_ENTRIES+=("Dashboard: http://$STATIC_IP/")
  sudo mkdir -p "$DASHBOARD_DIR"

  backup_file "$DASHBOARD_DIR/index.html"
  cat <<EOF | sudo tee "$DASHBOARD_DIR/index.html"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BoxServer Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #1e1e1e;
            color: #eee;
            text-align: center;
            margin: 0;
            padding: 20px;
        }
        h1 {
            margin: 20px;
            color: #0078d7;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .service-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 30px 0;
        }
        .service-card {
            background: #2d2d2d;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #444;
        }
        .service-card h3 {
            margin-top: 0;
            color: #0078d7;
        }
        a.btn {
            display: inline-block;
            padding: 12px 20px;
            margin: 8px;
            border-radius: 8px;
            background: #0078d7;
            color: #fff;
            text-decoration: none;
            transition: background 0.3s;
        }
        a.btn:hover {
            background: #005a9e;
        }
        .info-box {
            background: #2d2d2d;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            text-align: left;
        }
        code {
            background: #1a1a1a;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 BoxServer Dashboard</h1>

        <div class="service-grid">
            <div class="service-card">
                <h3>🛡️ Pi-hole</h3>
                <a href="http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin" class="btn" target="_blank">Painel Admin</a>
                <a href="https://$STATIC_IP:$PIHOLE_HTTPS_PORT/admin" class="btn" target="_blank">Painel SSL</a>
            </div>

            <div class="service-card">
                <h3>🗂️ Filebrowser</h3>
                <a href="http://$STATIC_IP:$FILEBROWSER_PORT" class="btn" target="_blank">Acessar</a>
                <p>Usuário: admin<br>Senha: admin</p>
            </div>

            <div class="service-card">
                <h3>📺 MiniDLNA</h3>
                <a href="http://$STATIC_IP:$MINIDLNA_PORT" class="btn" target="_blank">Status</a>
                <p>Porta: $MINIDLNA_PORT</p>
            </div>

            <div class="service-card">
                <h3>📂 Samba</h3>
                <p>Compartilhamento: <code>smb://$STATIC_IP/BoxShare</code></p>
                <p>Pasta: <code>/srv/samba/share</code></p>
            </div>
        </div>

        <div class="info-box">
            <h3>🔑 WireGuard</h3>
            <p>Configuração: <code>/etc/wireguard/wg0.conf</code></p>
            <p>Porta UDP: $WG_PORT</p>
            <p>Chave Pública: <code>$WG_PUBLIC</code></p>
        </div>

        <div class="info-box">
            <h3>☁️ Cloudflare Tunnel</h3>
            <p>Configuração: <code>/etc/cloudflared/config.yml</code></p>
            <p>Domínio: <code>$DOMAIN</code></p>
            <p><strong>⚠️ Requer autenticação manual:</strong></p>
            <p>1. <code>sudo cloudflared tunnel login</code></p>
            <p>2. <code>sudo cloudflared tunnel create boxserver</code></p>
            <p>3. <code>sudo systemctl start cloudflared</code></p>
        </div>

        <div class="info-box">
            <h3>🌐 DNS Recursivo</h3>
            <p>Unbound rodando em: <code>127.0.0.1:$UNBOUND_PORT</code></p>
        </div>
    </div>
</body>
</html>
EOF

  # Parar serviços que possam estar usando a porta 80
  sudo systemctl stop apache2 || true  # Apache se estiver instalado

  # Configurar nginx para servir o dashboard
  backup_file /etc/nginx/sites-available/boxserver-dashboard
  cat <<EOF | sudo tee /etc/nginx/sites-available/boxserver-dashboard
server {
    listen 80;
    server_name $STATIC_IP localhost;
    root $DASHBOARD_DIR;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

  sudo ln -sf /etc/nginx/sites-available/boxserver-dashboard /etc/nginx/sites-enabled/
  sudo rm -f /etc/nginx/sites-enabled/default
  sudo systemctl restart nginx

  # Verificar se o serviço está rodando
  if sudo systemctl is-active --quiet nginx; then
    echo_msg "✅ Dashboard instalado/reconfigurado e acessível em http://$STATIC_IP/"
  else
    echo_msg "⚠️  Dashboard instalado/reconfigurado, mas o Nginx pode não estar em execução"
  fi
}

# =========================
# Resumo final
# =========================
show_summary() {
  {
    echo "=== BoxServer Installation Summary ==="
    echo "Data: ${TIMESTAMP}"
    echo "Rede:"
    echo "  IP: $STATIC_IP"
    echo "  Interface: $NET_IF"
    echo "  Gateway: $GATEWAY"
    echo "Serviços:"
    for s in "${SUMMARY_ENTRIES[@]}"; do
      echo "  - $s"
    done
    echo "WireGuard keys:"
    echo "  Private: $WG_PRIVATE"
    echo "  Public: $WG_PUBLIC"
  } | sudo tee "$SUMMARY_FILE" >/dev/null

  # Adicionar instruções específicas do Cloudflare Tunnel se estiver instalado
  if [[ "$CHOICES" == *CLOUDFLARE* ]]; then
    {
      echo ""
      echo "=== INSTRUÇÕES CLOUDFLARED ==="
      echo "Para completar a configuração do Cloudflare Tunnel:"
      echo "1. Execute: sudo cloudflared tunnel login"
      echo "2. Siga as instruções no navegador para autenticar"
      echo "3. Execute: sudo cloudflared tunnel create boxserver"
      echo "4. Execute: sudo systemctl start cloudflared"
      echo "5. Configure o DNS no painel Cloudflare para apontar para o tunnel"
      echo ""
      echo "Arquivo de configuração: /etc/cloudflared/config.yml"
      echo "Credenciais: /etc/cloudflared/boxserver.json (será criado após autenticação)"
    } | sudo tee -a "$SUMMARY_FILE" >/dev/null
  fi

  sudo chmod 600 "$SUMMARY_FILE"
  if [ "$SILENT_MODE" = false ]; then
    whiptail --title "Resumo da instalação" --textbox "$SUMMARY_FILE" 30 80
  else
    echo "Resumo da instalação salvo em: $SUMMARY_FILE"
  fi
}

# =========================
# Função de uso
# =========================
usage() {
  echo "Uso: $0 [OPÇÕES]"
  echo "Opções:"
  echo "  -s, --silent    Modo silencioso (sem interface whiptail)"
  echo "  -u, --update    Atualizar serviços já instalados"
  echo "  -r, --rollback  Reverter alterações"
  echo "  -h, --help      Mostrar esta ajuda"
  exit 1
}

# =========================
# Processamento de argumentos
# =========================
while [[ $# -gt 0 ]]; do
  case $1 in
    -s|--silent)
      SILENT_MODE=true
      shift
      ;;
    -u|--update)
      check_system
      check_connectivity
      update_services
      exit 0
      ;;
    -r|--rollback)
      rollback_changes
      exit 0
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Opção desconhecida: $1"
      usage
      ;;
  esac
done

# =========================
# Fluxo principal
# =========================
main() {
  check_system
  check_disk_space
  check_connectivity
  if [ "$SILENT_MODE" = false ]; then
    whiptail_msg "Bem-vindo ao instalador BoxServer (Armbian 21.08.8 Debian 11 Bullseye)."
  else
    echo "Bem-vindo ao instalador BoxServer (Armbian 21.08.8 Debian 11 Bullseye)."
  fi
  ensure_deps
  ask_static_ip
  check_and_set_ports
  if [ "$SILENT_MODE" = false ]; then
    DOMAIN=$(whiptail --inputbox "Informe o domínio para o Pi-hole:" 10 68 "$DOMAIN_DEFAULT" 3>&1 1>&2 2>&3)
  else
    DOMAIN="$DOMAIN_DEFAULT"
  fi
  [ -z "$DOMAIN" ] && DOMAIN="$DOMAIN_DEFAULT"
  choose_services

  [[ "$CHOICES" == *UNBOUND* ]] && install_unbound
  [[ "$CHOICES" == *PIHOLE* ]] && install_pihole
  [[ "$CHOICES" == *WIREGUARD* ]] && install_wireguard
  [[ "$CHOICES" == *CLOUDFLARE* ]] && install_cloudflared
  [[ "$CHOICES" == *RNG* ]] && install_rng
  [[ "$CHOICES" == *SAMBA* ]] && install_samba
  [[ "$CHOICES" == *MINIDLNA* ]] && install_minidlna
  [[ "$CHOICES" == *FILEBROWSER* ]] && install_filebrowser
  [[ "$CHOICES" == *DASHBOARD* ]] && install_dashboard

  show_summary
}

main "$@"
