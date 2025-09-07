#!/usr/bin/env bash
# ------------------------------------------------------------------
# BoxServer – interactive installer (Debian/Ubuntu)
# ------------------------------------------------------------------
set -euo pipefail

LOGFILE="/var/log/boxserver_install.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------
msg() {
  # $1 = text
  whiptail --title "BoxServer Instalador" --msgbox "$1" 10 70
}

detect_interface() {
  ip route | awk '$1=="default"{print $5; exit}'
}

detect_arch() {
  case "$(uname -m)" in
    x86_64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armhf)  echo "arm" ;;
    *)       echo "unsupported" ;;
  esac
}

check_ports() {
  msg "Verificando portas em uso (8080, 8081, 8200, 8443, 51820, 5335)..."
  sudo ss -tulpn | grep -E ':(8080|8081|8200|8443|51820|5335)\b' || true
}

# ------------------------------------------------------------------
# Pre-requisites
# ------------------------------------------------------------------
pre_reqs() {
  msg "Atualizando sistema e instalando pacotes básicos..."
  sudo apt-get update -qq
  sudo apt-get install -y curl wget gnupg lsb-release ca-certificates whiptail
}

# ------------------------------------------------------------------
# Collect user choices
# ------------------------------------------------------------------
ask_questions() {
  NET_IF=$(detect_interface)
  NET_IF=$(whiptail --inputbox \
          "Interface de rede detectada: $NET_IF\nConfirme ou edite:" \
          10 60 "$NET_IF" 3>&1 1>&2 2>&3)
  export NET_IF

  DOMAIN=$(whiptail --inputbox \
         "Domínio para acessar o Pi-hole (ex: pihole.local):" \
         10 60 "pihole.local" 3>&1 1>&2 2>&3)
  export DOMAIN

  ARCH=$(detect_arch)
  msg "Arquitetura detectada: $ARCH"
  export ARCH
}

choose_services() {
  CHOICES=$(whiptail --title "Seleção de Componentes" --checklist \
  "Escolha os serviços que deseja instalar:" 20 70 10 \
  "UNBOUND"     "DNS recursivo (automático)" ON \
  "PIHOLE"      "Bloqueio de anúncios (portas 8081/8443)" ON \
  "WIREGUARD"   "VPN segura (server auto, peers manuais)" OFF \
  "CLOUDFLARE"  "Acesso remoto (login manual)" OFF \
  "RNG"         "Gerador de entropia (automático)" ON \
  "SAMBA"       "Compartilhamento de arquivos" OFF \
  "MINIDLNA"    "Servidor DLNA" OFF \
  "FILEBROWSER" "Gerenciador de arquivos Web" OFF \
  3>&1 1>&2 2>&3)
  export CHOICES
}

# ------------------------------------------------------------------
# Individual installers
# ------------------------------------------------------------------
install_unbound() {
  msg "Instalando Unbound..."
  sudo apt-get install -y unbound

  sudo mkdir -p /etc/unbound/unbound.conf.d
  sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf >/dev/null <<'EOF'
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
  sudo wget -qO /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
  if ! sudo unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null; then
    sudo wget -qO /var/lib/unbound/root.key https://data.iana.org/root-anchors/icannbundle.pem
  fi
  sudo chown -R unbound:unbound /var/lib/unbound
  sudo chmod 644 /var/lib/unbound/root.*

  sudo unbound-checkconf
  sudo systemctl enable --now unbound
}

install_pihole() {
  msg "Instalando Pi-hole (interativo oficial)..."
  curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended

  sudo sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
  pihole restartdns

  # Move Pi-hole to 8081/8443
  sudo sed -i 's/^server.port\s*=.*/server.port = 8081/' /etc/lighttpd/lighttpd.conf
  echo '$SERVER["socket"] == ":8443" { ssl.engine = "enable" }' | \
       sudo tee /etc/lighttpd/external.conf >/dev/null
  sudo systemctl restart lighttpd
}

install_wireguard() {
  msg "Instalando WireGuard..."
  sudo apt-get install -y wireguard wireguard-tools

  sudo mkdir -p /etc/wireguard/keys
  sudo chmod 700 /etc/wireguard/keys
  umask 077
  wg genkey | sudo tee /etc/wireguard/keys/privatekey | wg pubkey | sudo tee /etc/wireguard/keys/publickey
  PRIVATE_KEY=$(sudo cat /etc/wireguard/keys/privatekey)

  sudo tee /etc/wireguard/wg0.conf >/dev/null <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.200.200.1/24
ListenPort = 51820
PostUp   = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_IF -j MASQUERADE
EOF
  sudo chmod 600 /etc/wireguard/wg0.conf

  echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-boxserver.conf >/dev/null
  sudo sysctl -p /etc/sysctl.d/99-boxserver.conf

  sudo systemctl enable --now wg-quick@wg0
  msg "WireGuard ativo. Adicione peers editando /etc/wireguard/wg0.conf"
}

install_cloudflare() {
  msg "Instalando Cloudflare Tunnel..."
  ARCH=$(detect_arch)
  [[ $ARCH == "unsupported" ]] && { msg "Arquitetura não suportada"; return; }
  URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
  sudo wget -qO /usr/local/bin/cloudflared "$URL"
  sudo chmod +x /usr/local/bin/cloudflared

  sudo mkdir -p /etc/cloudflared
  sudo tee /etc/cloudflared/config.yml >/dev/null <<EOF
tunnel: boxserver
credentials-file: /etc/cloudflared/boxserver.json
ingress:
  - hostname: $DOMAIN
    service: http://localhost:8081
  - service: http_status:404
EOF
  msg "Cloudflare instalado. Execute:\n  cloudflared tunnel login\n  cloudflared tunnel create boxserver"
}

install_rng() {
  msg "Instalando RNG-tools..."
  sudo apt-get install -y rng-tools

  RNGDEVICE="/dev/urandom"
  [[ -e /dev/hwrng ]] && RNGDEVICE="/dev/hwrng"

  echo "RNGDEVICE=\"$RNGDEVICE\"" | sudo tee /etc/default/rng-tools >/dev/null
  sudo systemctl enable --now rng-tools
}

install_samba() {
  msg "Instalando Samba..."
  sudo apt-get install -y samba
  sudo mkdir -p /srv/samba/share
  sudo chmod 777 /srv/samba/share

  echo "
[BoxShare]
   path = /srv/samba/share
   browseable = yes
   read only = no
   guest ok = yes
" | sudo tee -a /etc/samba/smb.conf >/dev/null

  sudo systemctl enable --now smbd
  msg "Samba instalado. Crie usuários com: sudo smbpasswd -a <usuario>"
}

install_minidlna() {
  msg "Instalando MiniDLNA..."
  sudo apt-get install -y minidlna
  sudo mkdir -p /srv/media/{video,audio,photos}

  sudo tee /etc/minidlna.conf >/dev/null <<EOF
media_dir=V,/srv/media/video
media_dir=A,/srv/media/audio
media_dir=P,/srv/media/photos
db_dir=/var/cache/minidlna
log_dir=/var/log
friendly_name=BoxServer DLNA
inotify=yes
port=8200
EOF
  sudo systemctl enable --now minidlna
}

install_filebrowser() {
  msg "Instalando Filebrowser..."
  ARCH=$(detect_arch)
  case "$ARCH" in
    amd64)  FB_ARCH="linux-amd64" ;;
    arm64)  FB_ARCH="linux-arm64" ;;
    arm)    FB_ARCH="linux-armv6" ;;
    *) msg "Arquitetura não suportada pelo Filebrowser"; return ;;
  esac

  FB_VERSION=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | jq -r .tag_name)
  wget -qO filebrowser.tar.gz "https://github.com/filebrowser/filebrowser/releases/download/${FB_VERSION}/filebrowser-${FB_ARCH}.tar.gz"
  tar -xzf filebrowser.tar.gz
  sudo mv filebrowser /usr/local/bin/
  rm -f filebrowser.tar.gz

  sudo mkdir -p /srv/filebrowser
  sudo useradd -r -s /bin/false filebrowser 2>/dev/null || true

  sudo tee /etc/systemd/system/filebrowser.service >/dev/null <<EOF
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
  sudo systemctl daemon-reload
  sudo systemctl enable --now filebrowser
  msg "Filebrowser rodando! Acesse http://<IP>:8080  (admin/admin)"
}

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
main() {
  [[ $EUID -ne 0 ]] && { echo "Execute com sudo"; exit 1; }
  whiptail --title "BoxServer Instalador" --msgbox "Bem-vindo ao Instalador Interativo do BoxServer!" 10 70

  pre_reqs
  ask_questions
  choose_services

  [[ $CHOICES == *"UNBOUND"* ]]     && install_unbound
  [[ $CHOICES == *"PIHOLE"* ]]      && install_pihole
  [[ $CHOICES == *"WIREGUARD"* ]]   && install_wireguard
  [[ $CHOICES == *"CLOUDFLARE"* ]]  && install_cloudflare
  [[ $CHOICES == *"RNG"* ]]         && install_rng
  [[ $CHOICES == *"SAMBA"* ]]       && install_samba
  [[ $CHOICES == *"MINIDLNA"* ]]    && install_minidlna
  [[ $CHOICES == *"FILEBROWSER"* ]] && install_filebrowser

  check_ports
  msg "Instalação concluída! Revise o log em $LOGFILE"
}

main "$@"
