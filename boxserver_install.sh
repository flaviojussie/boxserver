#!/bin/bash
set -euo pipefail

# =========================
# CONFIGURAÇÕES GLOBAIS
# =========================
LOGFILE="/var/log/boxserver_install.log"
DASHBOARD_DIR="/srv/boxserver-dashboard"
STATIC_IP="192.168.0.100"

# =========================
# FUNÇÕES AUXILIARES
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
    msg "Verificando portas em uso..."
    sudo ss -tulpn | grep -E '(:8080|:8081|:8200|:8443|:51820|:5335|:80)' || true
}

# =========================
# PRÉ-REQUISITOS
# =========================
pre_reqs() {
    msg "Atualizando sistema e instalando pacotes básicos..."
    sudo apt update
    sudo apt install -y curl wget gnupg lsb-release ca-certificates whiptail nginx
}

# =========================
# CONFIGURAR IP FIXO
# =========================
ask_static_ip() {
    CURRENT_IP=$(hostname -I | awk '{print $1}')
    STATIC_IP=$(whiptail --inputbox "Digite o IP fixo para este servidor:" 10 60 "$STATIC_IP" 3>&1 1>&2 2>&3)
    GATEWAY=$(ip route | awk '/^default/ {print $3; exit}')
    DNS="1.1.1.1"
    NET_IF=$(detect_interface)

    if [ -d /etc/netplan ]; then
        sudo mkdir -p /etc/netplan
        cat <<EOF | sudo tee /etc/netplan/01-boxserver.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    $NET_IF:
      dhcp4: no
      addresses:
        - $STATIC_IP/24
      gateway4: $GATEWAY
      nameservers:
        addresses: [$DNS]
EOF
        sudo netplan apply || true
    fi
}

# =========================
# SELEÇÃO DE SERVIÇOS
# =========================
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
}

# =========================
# INSTALAÇÃO DOS SERVIÇOS
# =========================
install_unbound() {
    msg "Instalando Unbound..."
    sudo apt install -y unbound
    sudo mkdir -p /etc/unbound/unbound.conf.d /var/lib/unbound

    cat <<EOF | sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    interface: 127.0.0.1
    port: 5335
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

    sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
    sudo unbound-anchor -a /var/lib/unbound/root.key || true
    sudo systemctl enable --now unbound
}

install_pihole() {
    msg "Instalando Pi-hole..."
    curl -sSL https://install.pi-hole.net | bash

    sudo mkdir -p /etc/pihole
    sudo touch /etc/pihole/setupVars.conf
    if grep -q '^PIHOLE_DNS_1=' /etc/pihole/setupVars.conf; then
        sudo sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
    else
        echo "PIHOLE_DNS_1=127.0.0.1#5335" | sudo tee -a /etc/pihole/setupVars.conf
    fi
    pihole restartdns

    msg "Alterando Pi-hole para rodar em 8081/8443..."
    if [ -f /etc/lighttpd/lighttpd.conf ]; then
        sudo sed -i 's/server.port\s*=\s*80/server.port = 8081/' /etc/lighttpd/lighttpd.conf
    fi
    sudo bash -c 'echo "\$SERVER[\"socket\"] == \":8443\" { ssl.engine = \"enable\" }" > /etc/lighttpd/external.conf'
    sudo systemctl restart lighttpd
}

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
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
    sudo systemctl enable --now wg-quick@wg0
}

install_cloudflare() {
    msg "Instalando Cloudflare Tunnel..."
    ARCH=$(detect_arch)
    URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
    sudo wget -O /usr/local/bin/cloudflared "$URL"
    sudo chmod +x /usr/local/bin/cloudflared
    sudo mkdir -p /etc/cloudflared

    cat <<EOF | sudo tee /etc/cloudflared/config.yml
tunnel: boxserver
credentials-file: /etc/cloudflared/boxserver.json
ingress:
  - hostname: $DOMAIN
    service: http://localhost:8081
  - service: http_status:404
EOF
}

install_rng() {
    msg "Instalando RNG-tools..."
    sudo apt install -y rng-tools
    sudo mkdir -p /etc/default

    if [ -e /dev/hwrng ]; then
        RNGDEVICE="/dev/hwrng"
    else
        RNGDEVICE="/dev/urandom"
    fi

    cat <<EOF | sudo tee /etc/default/rng-tools
RNGDEVICE="$RNGDEVICE"
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10"
EOF
    sudo systemctl enable --now rng-tools
}

install_samba() {
    msg "Instalando Samba..."
    sudo apt install -y samba
    sudo mkdir -p /srv/samba/share
    sudo chmod 777 /srv/samba/share
    sudo touch /etc/samba/smb.conf

    cat <<EOF | sudo tee -a /etc/samba/smb.conf

[BoxShare]
   path = /srv/samba/share
   browseable = yes
   read only = no
   guest ok = yes
EOF
    sudo systemctl enable --now smbd
}

install_minidlna() {
    msg "Instalando MiniDLNA..."
    sudo apt install -y minidlna
    sudo mkdir -p /srv/media/{video,audio,photos}
    sudo touch /etc/minidlna.conf

    cat <<EOF | sudo tee /etc/minidlna.conf
media_dir=V,/srv/media/video
media_dir=A,/srv/media/audio
media_dir=P,/srv/media/photos
friendly_name=BoxServer DLNA
inotify=yes
port=8200
EOF
    sudo systemctl enable --now minidlna
}

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
    sudo systemctl enable --now filebrowser
}

# =========================
# DASHBOARD WEB
# =========================
install_dashboard() {
    msg "Instalando Dashboard Web..."
    sudo mkdir -p "$DASHBOARD_DIR"

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
                <a href="http://$STATIC_IP:8081/admin" class="btn" target="_blank">Painel Admin</a>
                <a href="https://$STATIC_IP:8443/admin" class="btn" target="_blank">Painel SSL</a>
            </div>

            <div class="service-card">
                <h3>🗂️ Filebrowser</h3>
                <a href="http://$STATIC_IP:8080" class="btn" target="_blank">Acessar</a>
                <p>Usuário: admin<br>Senha: admin</p>
            </div>

            <div class="service-card">
                <h3>📺 MiniDLNA</h3>
                <a href="http://$STATIC_IP:8200" class="btn" target="_blank">Status</a>
                <p>Porta: 8200</p>
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
            <p>Porta UDP: 51820</p>
            <p>Chave Pública: <code>$(sudo cat /etc/wireguard/keys/publickey 2>/dev/null || echo "Não instalado")</code></p>
        </div>

        <div class="info-box">
            <h3>☁️ Cloudflare Tunnel</h3>
            <p>Configuração: <code>/etc/cloudflared/config.yml</code></p>
            <p>Domínio: <code>$DOMAIN</code></p>
        </div>

        <div class="info-box">
            <h3>🌐 DNS Recursivo</h3>
            <p>Unbound rodando em: <code>127.0.0.1:5335</code></p>
        </div>
    </div>
</body>
</html>
EOF

    # Configurar nginx para servir o dashboard
    cat <<EOF | sudo tee /etc/nginx/sites-available/boxserver-dashboard
server {
    listen 80;
    server_name $STATIC_IP;
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
}

# =========================
# RELATÓRIO FINAL
# =========================
show_summary() {
    SUMMARY="/root/boxserver_summary.txt"
    cat <<EOF > $SUMMARY
=== RESUMO DA INSTALAÇÃO BOXSERVER ===

📌 CONFIGURAÇÃO DE REDE
IP Fixo: $STATIC_IP
Interface: $NET_IF
Gateway: $GATEWAY
DNS: $DNS

🛡️ PI-HOLE
Painel Admin: http://$STATIC_IP:8081/admin
Painel SSL: https://$STATIC_IP:8443/admin
DNS Interno: 127.0.0.1#5335
Domínio: $DOMAIN

🔑 WIREGUARD
Chave Privada: $(sudo cat /etc/wireguard/keys/privatekey 2>/dev/null || echo "Não instalado")
Chave Pública: $(sudo cat /etc/wireguard/keys/publickey 2>/dev/null || echo "Não instalado")
Porta UDP: 51820
Arquivo de Configuração: /etc/wireguard/wg0.conf

📂 SAMBA
Compartilhamento: smb://$STATIC_IP/BoxShare
Pasta Local: /srv/samba/share
Para adicionar usuários: sudo smbpasswd -a <usuário>

🗂️ FILEBROWSER
URL: http://$STATIC_IP:8080
Usuário: admin
Senha: admin
Pasta Raiz: /srv/filebrowser

📺 MINIDLNA
Status: http://$STATIC_IP:8200
Porta: 8200
Pastas de Mídia: /srv/media/{video,audio,photos}

🌐 UNBOUND DNS
Porta: 5335
Configuração: /etc/unbound/unbound.conf.d/pi-hole.conf

☁️ CLOUDFLARE TUNNEL
Configuração: /etc/cloudflared/config.yml
Para configurar: cloudflared tunnel login
Domínio: $DOMAIN

⚙️ RNG-TOOLS
Dispositivo: $(grep RNGDEVICE /etc/default/rng-tools 2>/dev/null | cut -d= -f2 || echo "Não configurado")

🚀 DASHBOARD WEB
URL: http://$STATIC_IP/
Local: $DASHBOARD_DIR

📋 LOG DA INSTALAÇÃO
Arquivo: $LOGFILE

=== FIM DO RELATÓRIO ===
EOF

    whiptail --title "Resumo da Instalação" --textbox $SUMMARY 30 80
}

# =========================
# FLUXO PRINCIPAL
# =========================
main() {
    exec > >(tee -a "$LOGFILE") 2>&1

    whiptail --title "BoxServer Instalador" --msgbox "Bem-vindo ao Instalador Interativo do BoxServer!" 10 70

    pre_reqs
    ask_static_ip
    DOMAIN=$(whiptail --inputbox "Digite o domínio para o Pi-hole:" 10 60 "pihole.local" 3>&1 1>&2 2>&3)
    choose_services

    [[ $CHOICES == *"UNBOUND"* ]] && install_unbound
    [[ $CHOICES == *"PIHOLE"* ]] && install_pihole
    [[ $CHOICES == *"WIREGUARD"* ]] && install_wireguard
    [[ $CHOICES == *"CLOUDFLARE"* ]] && install_cloudflare
    [[ $CHOICES == *"RNG"* ]] && install_rng
    [[ $CHOICES == *"SAMBA"* ]] && install_samba
    [[ $CHOICES == *"MINIDLNA"* ]] && install_minidlna
    [[ $CHOICES == *"FILEBROWSER"* ]] && install_filebrowser

    install_dashboard
    check_ports
    show_summary

    msg "✅ Instalação concluída com sucesso!\n\nAcesse o Dashboard em: http://$STATIC_IP/\n\nLog completo em: $LOGFILE\nRelatório em: /root/boxserver_summary.txt"
}

main "$@"
