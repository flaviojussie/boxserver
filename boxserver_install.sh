#!/bin/bash
set -euo pipefail

LOGFILE="/var/log/boxserver_install.log"
exec > >(tee -a "$LOGFILE") 2>&1

# =========================
# Funções auxiliares
# =========================
msg() {
  whiptail --title "BoxServer Instalador" --msgbox "$1" 10 70
}

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

check_ports() {
  msg "Verificando portas em uso (8080, 8081, 8200, 8443, 51820, 5335)..."
  sudo ss -tulpn | grep -E '(:8080|:8081|:8200|:8443|:51820|:5335)' || true
}

# =========================
# Etapas de instalação
# =========================
pre_reqs() {
  msg "Atualizando sistema e instalando pacotes básicos..."
  sudo apt update
  sudo apt install -y curl wget gnupg lsb-release ca-certificates whiptail
}

ask_questions() {
  NET_IF=$(detect_interface)
  NET_IF=$(whiptail --inputbox "Interface de rede detectada: $NET_IF\nConfirme ou edite:" 10 60 "$NET_IF" 3>&1 1>&2 2>&3)

  DOMAIN=$(whiptail --inputbox "Digite o domínio para acessar o Pi-hole (ex: pihole.local):" 10 60 "pihole.local" 3>&1 1>&2 2>&3)

  ARCH=$(detect_arch)
  msg "Arquitetura detectada: $ARCH"
}

choose_services() {
  CHOICES=$(whiptail --title "Seleção de Componentes" --checklist \
  "Escolha os serviços que deseja instalar:" 20 70 10 \
  "UNBOUND" "DNS recursivo (automático)" ON \
  "PIHOLE" "Bloqueio de anúncios (manual, portas 8081/8443)" ON \
  "WIREGUARD" "VPN segura (server auto, peers manuais)" OFF \
  "CLOUDFLARE" "Acesso remoto (login manual)" OFF \
  "RNG" "Gerador de entropia (automático)" ON \
  "SAMBA" "Compartilhamento de arquivos" OFF \
  "MINIDLNA" "Servidor DLNA" OFF \
  "FILEBROWSER" "Gerenciador de arquivos Web" OFF \
  3>&1 1>&2 2>&3)

  echo "Selecionados: $CHOICES"
}

# --- Unbound ---
install_unbound() {
  msg "Instalando Unbound..."
  sudo apt install -y unbound

  cat <<EOF | sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf
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

  sudo unbound-checkconf
  sudo systemctl restart unbound
  sudo systemctl enable unbound
}


 # --- Pi-hole ---
  install_pihole() {
    msg "Instalando Pi-hole (interativo oficial)..."
    curl -sSL https://install.pi-hole.net | bash
  
    msg "Verificando e configurando o arquivo de configuração do Pi-hole..."
  
    # Verifica se o arquivo existe e cria se necessário
    if [ ! -f /etc/pihole/setupVars.conf ]; then
      sudo touch /etc/pihole/setupVars.conf
    fi
  
    msg "Ajustando Pi-hole para usar Unbound (127.0.0.1#5335)..."
    # Usa echo e tee para adicionar ou modificar a configuração
    if grep -q "^PIHOLE_DNS_1=" /etc/pihole/setupVars.conf; then
      sudo sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
    else
      echo "PIHOLE_DNS_1=127.0.0.1#5335" | sudo tee -a /etc/pihole/setupVars.conf > /dev/null
    fi
  
    pihole restartdns
  
    msg "Alterando Pi-hole para rodar em 8081/8443..."
    sudo sed -i 's/server.port\s*=\s*80/server.port = 8081/' /etc/lighttpd/lighttpd.conf
    sudo bash -c 'echo "\$SERVER[\"socket\"] == \":8443\" { ssl.engine = \"enable\" }" > /etc/lighttpd/external.conf'
    sudo systemctl restart lighttpd
  }


# --- WireGuard ---
install_wireguard() {
  msg "Instalando WireGuard..."
  sudo apt install -y wireguard wireguard-tools

  sudo mkdir -p /etc/wireguard/keys
  sudo chmod 700 /etc/wireguard/keys
  umask 077
  wg genkey | sudo tee /etc/wireguard/keys/privatekey | wg pubkey | sudo tee /etc/wireguard/keys/publickey
  PRIVATE_KEY=$(sudo cat /etc/wireguard/keys/privatekey)

  cat <<EOF | sudo tee /etc/wireguard/wg0.conf
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

  msg "WireGuard instalado. Adicione os peers manualmente em /etc/wireguard/wg0.conf"
}

# --- Cloudflare ---
install_cloudflare() {
  msg "Instalando Cloudflare Tunnel..."
  ARCH=$(detect_arch)
  URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
  sudo wget -O /usr/local/bin/cloudflared "$URL"
  sudo chmod +x /usr/local/bin/cloudflared

  cat <<EOF | sudo tee /etc/cloudflared/config.yml
tunnel: boxserver
credentials-file: /etc/cloudflared/boxserver.json
ingress:
  - hostname: $DOMAIN
    service: http://localhost:8081
  - service: http_status:404
EOF

  msg "Cloudflare instalado. Agora execute manualmente:
    cloudflared tunnel login
    cloudflared tunnel create boxserver
  "
}

# --- RNG-tools ---
install_rng() {
  msg "Instalando RNG-tools..."
  sudo apt install -y rng-tools

  if [ -e /dev/hwrng ]; then
    RNGDEVICE="/dev/hwrng"
  else
    RNGDEVICE="/dev/urandom"
  fi

  cat <<EOF | sudo tee /etc/default/rng-tools
RNGDEVICE="$RNGDEVICE"
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10"
EOF

  sudo systemctl enable rng-tools
  sudo systemctl restart rng-tools
}

# --- Samba ---
install_samba() {
  msg "Instalando Samba..."
  sudo apt install -y samba
  sudo mkdir -p /srv/samba/share
  sudo chmod 777 /srv/samba/share

  cat <<EOF | sudo tee -a /etc/samba/smb.conf

[BoxShare]
   path = /srv/samba/share
   browseable = yes
   read only = no
   guest ok = yes
EOF

  sudo systemctl restart smbd
  sudo systemctl enable smbd
  msg "Samba instalado. Configure usuários com: sudo smbpasswd -a <usuario>"
}

# --- MiniDLNA ---
install_minidlna() {
  msg "Instalando MiniDLNA..."
  sudo apt install -y minidlna
  sudo mkdir -p /srv/media/{video,audio,photos}

  cat <<EOF | sudo tee /etc/minidlna.conf
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
}

# --- Filebrowser ---
install_filebrowser() {
  msg "Instalando Filebrowser..."
  FB_VERSION=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | grep tag_name | cut -d '"' -f4)
  ARCH=$(detect_arch)
  case "$ARCH" in
    amd64) FB_ARCH="linux-amd64";;
    arm64) FB_ARCH="linux-arm64";;
    arm) FB_ARCH="linux-armv6";;
    *) msg "Arquitetura não suportada pelo Filebrowser"; return;;
  esac

  wget -O filebrowser.tar.gz https://github.com/filebrowser/filebrowser/releases/download/${FB_VERSION}/filebrowser-${FB_ARCH}.tar.gz
  tar -xzf filebrowser.tar.gz
  sudo mv filebrowser /usr/local/bin/
  rm -f filebrowser.tar.gz

  sudo mkdir -p /srv/filebrowser
  sudo useradd -r -s /bin/false filebrowser || true

  cat <<EOF | sudo tee /etc/systemd/system/filebrowser.service
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

  msg "Filebrowser instalado! Acesse http://<IP>:8080 (usuário: admin, senha: admin)"
}

# =========================
# Fluxo principal
# =========================
main() {
  whiptail --title "BoxServer Instalador" --msgbox "Bem-vindo ao Instalador Interativo do BoxServer!" 10 70

  pre_reqs
  ask_questions
  choose_services

  [[ $CHOICES == *"UNBOUND"* ]] && install_unbound
  [[ $CHOICES == *"PIHOLE"* ]] && install_pihole
  [[ $CHOICES == *"WIREGUARD"* ]] && install_wireguard
  [[ $CHOICES == *"CLOUDFLARE"* ]] && install_cloudflare
  [[ $CHOICES == *"RNG"* ]] && install_rng
  [[ $CHOICES == *"SAMBA"* ]] && install_samba
  [[ $CHOICES == *"MINIDLNA"* ]] && install_minidlna
  [[ $CHOICES == *"FILEBROWSER"* ]] && install_filebrowser

  check_ports
  msg "Instalação concluída! Revise o log em $LOGFILE"
}

main "$@"
