#!/bin/bash
# install_boxserver_refactor_v1.sh
# Versão refatorada: semi-automática, cria configs padrão, faz backups, exibe chaves/senhas/ports no final.
set -euo pipefail

LOGFILE="/var/log/boxserver_install.log"
SUMMARY_FILE="/root/boxserver_summary.txt"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
BACKUP_SUFFIX=".bak.${TIMESTAMP}"

exec > >(tee -a "$LOGFILE") 2>&1

# -------------------------
# Utilitários
# -------------------------
whiptail_msg() {
  whiptail --title "BoxServer Instalador" --msgbox "$1" 12 76
}

whiptail_yesno() {
  whiptail --title "BoxServer Instalador" --yesno "$1" 12 76
}

backup_file() {
  local f="$1"
  if [ -f "$f" ]; then
    sudo cp -a "$f" "${f}${BACKUP_SUFFIX}"
    echo "Backup criado: ${f}${BACKUP_SUFFIX}"
  fi
}

ensure_pkg() {
  # Ensure package installed (apt)
  local pkg="$1"
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    sudo apt-get install -y "$pkg"
  fi
}

ensure_deps() {
  echo "Instalando dependências básicas..."
  sudo apt-get update -y
  sudo apt-get install -y whiptail curl wget tar gnupg lsb-release ca-certificates net-tools sed grep ss jq
  # nginx may be installed later if dashboard selected; install here to be safe
  ensure_pkg nginx
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

port_in_use() {
  local port="$1"
  ss -tulpn | awk '{print $5}' | grep -E "(:|\\b)${port}(\$| )" >/dev/null 2>&1
}

check_ports_prompt() {
  # ports to check array (strings)
  local ports_to_check=("$@")
  local inuse=()
  for p in "${ports_to_check[@]}"; do
    if port_in_use "$p"; then
      inuse+=("$p")
    fi
  done
  if [ "${#inuse[@]}" -gt 0 ]; then
    whiptail --title "Portas em uso" --msgbox "As seguintes portas parecem estar em uso: ${inuse[*]}\n\nO instalador pode tentar continuar, mas pode haver conflitos. Revise antes de prosseguir." 12 80
    return 0
  fi
  return 0
}

# -------------------------
# Defaults & variables
# -------------------------
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

# Keep WireGuard keys variables to show later
WG_PRIVATE=""
WG_PUBLIC=""

# -------------------------
# Configure static IP (Netplan) - semi-automatic (asks user, default provided)
# -------------------------
ask_static_ip() {
  NET_IF=$(detect_interface)
  local current_ip
  current_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [ -z "$current_ip" ] && current_ip="$DEFAULT_IP"
  STATIC_IP=$(whiptail --inputbox "Informe o IP fixo para este servidor (atenção: aplicar IP pode desconectar SSH):" 10 68 "${current_ip:-$DEFAULT_IP}" 3>&1 1>&2 2>&3)
  if [ -z "$STATIC_IP" ]; then
    STATIC_IP="$DEFAULT_IP"
  fi

  # gateway detection
  GATEWAY=$(ip route | awk '/^default/ {print $3; exit}' || true)
  if [ -z "$GATEWAY" ]; then
    GATEWAY=$(whiptail --inputbox "Gateway padrão não detectado automaticamente. Informe o gateway (ex: 192.168.0.1):" 10 68 "" 3>&1 1>&2 2>&3)
  fi

  # Use Netplan if present
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
    echo "Aplicando netplan..."
    sudo netplan apply || echo "netplan apply retornou não-zero (ok se você estiver em ambiente que bloqueia mudança), verifique manualmente"
    SUMMARY_ENTRIES+=("IP Fixo: $STATIC_IP (via netplan / interface $NET_IF)")
  else
    whiptail_msg "Netplan não encontrado em /etc/netplan. O script irá criar arquivos e avisá-lo para configurar IP fixo manualmente se necessário."
    SUMMARY_ENTRIES+=("IP Fixo (solicitado): $STATIC_IP (netplan ausente - configure manualmente se necessário)")
  fi
}

# -------------------------
# Services selection
# -------------------------
choose_services() {
  CHOICES=$(whiptail --title "Seleção de Componentes" --checklist \
  "Selecione os serviços a instalar (espaço para marcar/desmarcar):" 20 80 12 \
  "UNBOUND" "Unbound (DNS recursivo local)" ON \
  "PIHOLE" "Pi-hole (blocker) - ports 8081/8443" ON \
  "WIREGUARD" "WireGuard (VPN server — peers manuais)" OFF \
  "CLOUDFLARE" "Cloudflared tunnel (login manual)" OFF \
  "RNG" "rng-tools (entropia)" ON \
  "SAMBA" "Samba (file share)" OFF \
  "MINIDLNA" "MiniDLNA (DLNA/UPnP media)" OFF \
  "FILEBROWSER" "Filebrowser (web file manager)" OFF \
  "DASHBOARD" "Dashboard web (nginx, index com atalhos)" ON \
  3>&1 1>&2 2>&3)

  # normalize choice packaging (remove quotes)
  CHOICES="${CHOICES//\"/}"
}

# -------------------------
# Install functions
# -------------------------
install_unbound() {
  echo "==> Unbound"
  ensure_pkg unbound
  sudo mkdir -p /etc/unbound/unbound.conf.d /var/lib/unbound
  backup_file /etc/unbound/unbound.conf.d/pi-hole.conf || true

  cat <<EOF | sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    verbosity: 1
    interface: 127.0.0.1
    port: ${UNBOUND_PORT}
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

  # root hints and anchor
  if ! sudo wget -q -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root; then
    echo "Falha ao baixar root.hints"
  fi
  sudo chown -R unbound:unbound /var/lib/unbound || true
  # Try anchor - may fail on some minimal systems but ok
  sudo unbound-anchor -a /var/lib/unbound/root.key || true
  sudo chmod 644 /var/lib/unbound/root.hints /var/lib/unbound/root.key || true
  sudo systemctl enable --now unbound || true
  SUMMARY_ENTRIES+=("Unbound: 127.0.0.1:${UNBOUND_PORT}")
}

install_pihole() {
  echo "==> Pi-hole"
  # Pi-hole interactive installer: we run official script (user will interact within it)
  ensure_pkg curl
  whiptail_msg "Vai iniciar o instalador oficial do Pi-hole (interativo). Siga as instruções no prompt. Após a instalação o script continuará e ajustará o setupVars.conf e portas."
  curl -sSL https://install.pi-hole.net | bash

  sudo mkdir -p /etc/pihole
  # ensure file exists, create if not
  sudo touch /etc/pihole/setupVars.conf
  if grep -q '^PIHOLE_DNS_1=' /etc/pihole/setupVars.conf 2>/dev/null; then
    backup_file /etc/pihole/setupVars.conf || true
    sudo sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#'"${UNBOUND_PORT}"'/' /etc/pihole/setupVars.conf
  else
    echo "PIHOLE_DNS_1=127.0.0.1#${UNBOUND_PORT}" | sudo tee -a /etc/pihole/setupVars.conf
  fi
  # Set lighttpd port change carefully
  if [ -f /etc/lighttpd/lighttpd.conf ]; then
    backup_file /etc/lighttpd/lighttpd.conf || true
    sudo sed -i 's/^\s*server.port\s*=.*/server.port = '"${PIHOLE_HTTP_PORT}"'/' /etc/lighttpd/lighttpd.conf || true
    # set external.conf for https socket
    sudo bash -c "cat > /etc/lighttpd/external.conf <<EOL
\$SERVER[\"socket\"] == \":${PIHOLE_HTTPS_PORT}\" {
  ssl.engine = \"enable\"
}
EOL"
    sudo systemctl restart lighttpd || true
  fi

  SUMMARY_ENTRIES+=("Pi-hole: http://${STATIC_IP}:${PIHOLE_HTTP_PORT}/admin  https://${STATIC_IP}:${PIHOLE_HTTPS_PORT}/admin")
}

install_wireguard() {
  echo "==> WireGuard"
  ensure_pkg wireguard
  ensure_pkg wireguard-tools
  sudo mkdir -p /etc/wireguard/keys
  sudo chmod 700 /etc/wireguard/keys
  umask 077
  # generate keys
  if ! command -v wg >/dev/null 2>&1; then
    echo "wg (wireguard) não disponível; pulando geração de chaves"
  else
    wg genkey | sudo tee /etc/wireguard/keys/privatekey >/dev/null
    sudo chmod 600 /etc/wireguard/keys/privatekey
    sudo sh -c 'cat /etc/wireguard/keys/privatekey | wg pubkey > /etc/wireguard/keys/publickey'
    WG_PRIVATE=$(sudo cat /etc/wireguard/keys/privatekey)
    WG_PUBLIC=$(sudo cat /etc/wireguard/keys/publickey)
  fi

  backup_file /etc/wireguard/wg0.conf || true
  cat <<EOF | sudo tee /etc/wireguard/wg0.conf
[Interface]
PrivateKey = ${WG_PRIVATE:-REGENERAR}
Address = 10.200.200.1/24
ListenPort = ${WG_PORT}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${NET_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${NET_IF} -j MASQUERADE
EOF
  sudo chmod 600 /etc/wireguard/wg0.conf || true
  # Enable IP forward
  if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null; then
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
  fi
  sudo sysctl -p || true
  sudo systemctl enable --now wg-quick@wg0 || true
  SUMMARY_ENTRIES+=("WireGuard: /etc/wireguard/wg0.conf (port ${WG_PORT})")
}

install_cloudflared() {
  echo "==> Cloudflared"
  ARCH=$(detect_arch)
  if [ "$ARCH" = "unknown" ]; then
    whiptail_msg "Arquitetura não detectada, pulando instalação do cloudflared."
    return
  fi
  URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
  sudo wget -q -O /usr/local/bin/cloudflared "$URL" || { echo "Falha ao baixar cloudflared"; return; }
  sudo chmod +x /usr/local/bin/cloudflared
  sudo mkdir -p /etc/cloudflared
  backup_file /etc/cloudflared/config.yml || true
  cat <<EOF | sudo tee /etc/cloudflared/config.yml
tunnel: boxserver
credentials-file: /etc/cloudflared/boxserver.json
ingress:
  - hostname: ${DOMAIN:-$DOMAIN_DEFAULT}
    service: http://localhost:${PIHOLE_HTTP_PORT}
  - service: http_status:404
EOF
  SUMMARY_ENTRIES+=("Cloudflared: installed (login manual required). Config: /etc/cloudflared/config.yml")
}

install_rng() {
  echo "==> rng-tools"
  ensure_pkg rng-tools
  backup_file /etc/default/rng-tools || true
  # fallback detection
  if [ -e /dev/hwrng ]; then
    RNG_DEVICE="/dev/hwrng"
  else
    RNG_DEVICE="/dev/urandom"
  fi
  cat <<EOF | sudo tee /etc/default/rng-tools
RNGDEVICE="${RNG_DEVICE}"
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10"
EOF
  sudo systemctl enable --now rng-tools || true
  SUMMARY_ENTRIES+=("rng-tools: using ${RNG_DEVICE}")
}

install_samba() {
  echo "==> Samba"
  ensure_pkg samba
  sudo mkdir -p /srv/samba/share
  # less permissive by default
  sudo chmod 2775 /srv/samba/share
  backup_file /etc/samba/smb.conf || true
  # append share only if not existing
  if ! grep -q '\[BoxShare\]' /etc/samba/smb.conf 2>/dev/null; then
    cat <<EOF | sudo tee -a /etc/samba/smb.conf

[BoxShare]
   path = /srv/samba/share
   browseable = yes
   read only = no
   guest ok = yes
EOF
  fi
  sudo systemctl enable --now smbd || true
  SUMMARY_ENTRIES+=("Samba: smb://$STATIC_IP/BoxShare  (path: /srv/samba/share)")
}

install_minidlna() {
  echo "==> MiniDLNA"
  ensure_pkg minidlna
  sudo mkdir -p /srv/media/{video,audio,photos}
  backup_file /etc/minidlna.conf || true
  cat <<EOF | sudo tee /etc/minidlna.conf
media_dir=V,/srv/media/video
media_dir=A,/srv/media/audio
media_dir=P,/srv/media/photos
db_dir=/var/cache/minidlna
log_dir=/var/log
friendly_name=BoxServer DLNA
inotify=yes
port=${MINIDLNA_PORT}
EOF
  sudo systemctl enable --now minidlna || true
  SUMMARY_ENTRIES+=("MiniDLNA: http://${STATIC_IP}:${MINIDLNA_PORT} (status) + SSDP 1900/udp")
}

install_filebrowser() {
  echo "==> Filebrowser"
  FB_VER=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | jq -r .tag_name 2>/dev/null || true)
  [ -z "$FB_VER" ] && FB_VER=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | grep tag_name | head -n1 | cut -d '"' -f4 || true)
  ARCH=$(detect_arch)
  case "$ARCH" in
    amd64) FB_ARCH="linux-amd64";;
    arm64) FB_ARCH="linux-arm64";;
    arm) FB_ARCH="linux-armv6";;
    *) whiptail_msg "Arquitetura não suportada pelo filebrowser: $ARCH"; return;;
  esac

  # download binary tar.gz
  wget -q -O /tmp/filebrowser.tar.gz "https://github.com/filebrowser/filebrowser/releases/download/${FB_VER}/filebrowser-${FB_ARCH}.tar.gz" || { echo "Falha download filebrowser"; return; }
  tar -xzf /tmp/filebrowser.tar.gz -C /tmp
  sudo mv /tmp/filebrowser /usr/local/bin/filebrowser || true
  rm -f /tmp/filebrowser.tar.gz

  sudo mkdir -p /srv/filebrowser
  if ! id -u filebrowser >/dev/null 2>&1; then
    sudo useradd -r -s /bin/false filebrowser || true
  fi

  backup_file /etc/systemd/system/filebrowser.service || true
  cat <<EOF | sudo tee /etc/systemd/system/filebrowser.service
[Unit]
Description=Filebrowser
After=network.target

[Service]
User=filebrowser
ExecStart=/usr/local/bin/filebrowser -r /srv/filebrowser --port ${FILEBROWSER_PORT}
Restart=on-failure
WorkingDirectory=/srv/filebrowser

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable --now filebrowser || true
  # default admin credentials in filebrowser are admin:admin — but user should change
  SUMMARY_ENTRIES+=("Filebrowser: http://${STATIC_IP}:${FILEBROWSER_PORT} (default login admin:admin)")
}

install_dashboard() {
  echo "==> Dashboard (nginx)"
  ensure_pkg nginx
  sudo mkdir -p /srv/boxserver-dashboard
  backup_file /etc/nginx/sites-enabled/default || true
  # generate index.html with dynamic IP substitutions
  cat <<HTML | sudo tee /srv/boxserver-dashboard/index.html
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8"/>
  <title>BoxServer Dashboard</title>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <style>
    body { font-family: Arial, sans-serif; background: #0b1220; color: #e6eef8; padding: 20px; }
    .card { display:inline-block; margin:8px; padding:14px 18px; border-radius:8px; background:#132036; box-shadow:0 6px 18px rgba(0,0,0,0.4); }
    a { color:#fff; text-decoration:none; font-weight:600; }
    h1 { margin-bottom:14px; }
    .small { font-size:0.9em; color:#c6d7ea; }
  </style>
</head>
<body>
  <h1>BoxServer Dashboard</h1>
  <div class="card"><a href="http://${STATIC_IP}:${PIHOLE_HTTP_PORT}/admin" target="_blank">Pi-hole (HTTP)</a><div class="small">http://${STATIC_IP}:${PIHOLE_HTTP_PORT}/admin</div></div>
  <div class="card"><a href="https://${STATIC_IP}:${PIHOLE_HTTPS_PORT}/admin" target="_blank">Pi-hole (HTTPS)</a><div class="small">https://${STATIC_IP}:${PIHOLE_HTTPS_PORT}/admin</div></div>
  <div class="card"><a href="http://${STATIC_IP}:${FILEBROWSER_PORT}" target="_blank">Filebrowser</a><div class="small">http://${STATIC_IP}:${FILEBROWSER_PORT}</div></div>
  <div class="card"><a href="http://${STATIC_IP}:${MINIDLNA_PORT}" target="_blank">MiniDLNA (status)</a><div class="small">http://${STATIC_IP}:${MINIDLNA_PORT}</div></div>
  <div class="card"><a href="smb://${STATIC_IP}/BoxShare">Samba Share</a><div class="small">smb://${STATIC_IP}/BoxShare</div></div>
  <div style="margin-top:18px" class="small">WireGuard: /etc/wireguard/wg0.conf | Cloudflared: /etc/cloudflared/config.yml</div>
</body>
</html>
HTML

  # nginx site config pointing to /srv/boxserver-dashboard
  cat <<NGINX | sudo tee /etc/nginx/sites-available/boxserver-dashboard
server {
  listen 80 default_server;
  listen [::]:80 default_server;
  server_name _;

  root /srv/boxserver-dashboard;
  index index.html;
  location / {
    try_files \$uri \$uri/ =404;
  }
}
NGINX

  sudo ln -sf /etc/nginx/sites-available/boxserver-dashboard /etc/nginx/sites-enabled/boxserver-dashboard
  # disable default if exists and not same
  [ -f /etc/nginx/sites-enabled/default ] && sudo rm -f /etc/nginx/sites-enabled/default || true
  sudo nginx -t || true
  sudo systemctl enable --now nginx || true
  SUMMARY_ENTRIES+=("Dashboard: http://${STATIC_IP}/")
}

# -------------------------
# Final summary & output
# -------------------------
show_summary() {
  echo "Gerando resumo em $SUMMARY_FILE"
  sudo chmod 600 "$SUMMARY_FILE" 2>/dev/null || true
  {
    echo "=== BoxServer Installation Summary ==="
    echo "Timestamp: ${TIMESTAMP}"
    echo ""
    echo "Network:"
    echo "  IP Fixo: ${STATIC_IP}"
    echo "  Interface: ${NET_IF}"
    echo "  Gateway: ${GATEWAY}"
    echo ""
    echo "Domain:"
    echo "  Pi-hole domain: ${DOMAIN:-$DOMAIN_DEFAULT}"
    echo ""
    echo "Services summary:"
    for s in "${SUMMARY_ENTRIES[@]}"; do
      echo "  - $s"
    done
    echo ""
    echo "WireGuard keys (server):"
    if [ -f /etc/wireguard/keys/privatekey ]; then
      echo "  Private: $(sudo cat /etc/wireguard/keys/privatekey)"
      echo "  Public:  $(sudo cat /etc/wireguard/keys/publickey)"
    else
      echo "  WireGuard keys not present or generation failed."
    fi
    echo ""
    echo "Filebrowser default creds: admin / admin (alterar imediatamente)"
    echo ""
    echo "Notes:"
    echo " - Pi-hole installer is interactive and may have asked questions during installation."
    echo " - For Cloudflared: run 'cloudflared tunnel login' manually to complete tunnel setup."
    echo " - If netplan not present, IP fixo may need manual configuration."
  } | sudo tee "$SUMMARY_FILE" >/dev/null

  sudo chmod 600 "$SUMMARY_FILE"
  whiptail --title "Instalação concluída - resumo" --textbox "$SUMMARY_FILE" 25 80
  echo "Resumo gravado em $SUMMARY_FILE (permissões 600)"
}

# -------------------------
# Main flow
# -------------------------
main() {
  whiptail_msg "Bem-vindo ao instalador semi-automático do BoxServer.\nEste script criará configurações padrão e fará backups antes de alterar arquivos."
  ensure_deps

  # Ask static IP (default 192.168.0.100)
  DEFAULT_IP="${DEFAULT_IP:-192.168.0.100}"
  # pre-fill prompt with default if no current IP
  ask_static_ip

  DOMAIN=$(whiptail --inputbox "Informe o domínio para o Pi-hole (usado no cloudflared se instalado):" 10 68 "${DOMAIN_DEFAULT}" 3>&1 1>&2 2>&3)
  [ -z "$DOMAIN" ] && DOMAIN="$DOMAIN_DEFAULT"

  choose_services

  # ports to check before installing (union of ports we will use)
  check_ports_prompt "${PIHOLE_HTTP_PORT}" "${PIHOLE_HTTPS_PORT}" "${FILEBROWSER_PORT}" "${MINIDLNA_PORT}" "${UNBOUND_PORT}" "${WG_PORT}"

  # Run installs based on choices
  # Use substring match to detect chosen items
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

# run
main "$@"
