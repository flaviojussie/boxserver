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

    # Validar formato do IP
    if ! echo "$STATIC_IP" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        msg "❌ IP inválido: $STATIC_IP. Usando IP atual: $CURRENT_IP"
        STATIC_IP="$CURRENT_IP"
    fi

    GATEWAY=$(ip route | awk '/^default/ {print $3; exit}')
    # Se não encontrar gateway, usar padrão baseado no IP
    if [ -z "$GATEWAY" ]; then
        GATEWAY=$(echo "$STATIC_IP" | sed 's/\.[0-9]*$/.1/')
        msg "⚠️  Gateway não detectado. Usando gateway padrão: $GATEWAY"
    fi

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
        # Aplicar Netplan de forma não-bloqueante com timeout
        msg "Aplicando configuração de rede..."
        timeout 30s sudo netplan apply >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            msg "✅ IP fixo configurado com sucesso: $STATIC_IP"
        else
            msg "⚠️  Netplan está demorando. A configuração de IP será aplicada após reiniciar o sistema."
        fi
    else
        msg "⚠️  Este sistema não usa Netplan. Configure manualmente o IP fixo $STATIC_IP"
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
    msg "Instalando/reconfigurando Unbound..."
    
    # Verificar se Unbound já está instalado
    if dpkg -l | grep -q "^ii.*unbound"; then
        msg "Unbound já está instalado. Reconfigurando..."
    else
        msg "Instalando Unbound..."
        sudo apt install -y unbound
    fi
    
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
        msg "✅ Unbound instalado/reconfigurado e em execução"
    else
        msg "⚠️  Unbound instalado/reconfigurado, mas pode não estar em execução"
    fi
}

install_pihole() {
    msg "Instalando/reconfigurando Pi-hole..."
    
    # Verificar se o Pi-hole já está instalado
    if command -v pihole &> /dev/null; then
        msg "Pi-hole já está instalado. Reconfigurando..."
    else
        # Instalar lighttpd explicitamente antes do Pi-hole
        msg "Instalando lighttpd como dependência do Pi-hole..."
        if ! sudo apt install -y lighttpd; then
            msg "❌ Falha ao instalar lighttpd"
            return 1
        fi

        # Executar o instalador do Pi-hole em modo não interativo
        msg "Executando instalador do Pi-hole..."
        if ! curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended; then
            msg "❌ Falha na instalação do Pi-hole"
            return 1
        fi
    fi

    # Configurar o Pi-hole
    sudo mkdir -p /etc/pihole
    sudo touch /etc/pihole/setupVars.conf
    if grep -q '^PIHOLE_DNS_1=' /etc/pihole/setupVars.conf; then
        sudo sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
    else
        echo "PIHOLE_DNS_1=127.0.0.1#5335" | sudo tee -a /etc/pihole/setupVars.conf
    fi
    
    # Reiniciar o DNS do Pi-hole
    if command -v pihole &> /dev/null; then
        sudo pihole restartdns
    else
        # Se o comando pihole não estiver disponível, reiniciar o serviço diretamente
        sudo systemctl restart pihole-ftl
    fi

    msg "Alterando Pi-hole para rodar em 8081/8443..."
    
    # Verificar se o arquivo de configuração do lighttpd existe
    if [ ! -f /etc/lighttpd/lighttpd.conf ]; then
        # Se não existir, instalar lighttpd
        sudo apt install -y lighttpd
    fi
    
    if [ -f /etc/lighttpd/lighttpd.conf ]; then
        sudo sed -i 's/server.port\s*=\s*80/server.port = 8081/' /etc/lighttpd/lighttpd.conf
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
server.port                 = 8081

# SSL configuration
\$SERVER["socket"] == ":8443" {
    ssl.engine = "enable"
    ssl.pemfile = "/etc/lighttpd/server.pem"
}
EOF
    fi
    
    # Garantir que o diretório /etc/lighttpd exista
    sudo mkdir -p /etc/lighttpd
    
    # Criar o arquivo external.conf corretamente
    cat <<EOF | sudo tee /etc/lighttpd/external.conf
\$SERVER["socket"] == ":8443" { ssl.engine = "enable" }
EOF
    
    # Verificar se o serviço lighttpd existe
    if systemctl list-units --type=service --all | grep -q 'lighttpd.service'; then
        # Habilitar e iniciar o serviço lighttpd
        sudo systemctl enable lighttpd
        sudo systemctl restart lighttpd
        
        # Verificar se o serviço está rodando
        if sudo systemctl is-active --quiet lighttpd; then
            msg "✅ Pi-hole instalado/reconfigurado e em execução nas portas 8081/8443"
        else
            msg "⚠️  Pi-hole instalado/reconfigurado, mas o serviço lighttpd pode não estar em execução corretamente"
        fi
    else
        msg "⚠️  Serviço lighttpd não encontrado. Verifique se ele foi instalado corretamente."
    fi
}

install_wireguard() {
    msg "Instalando/reconfigurando WireGuard..."
    
    # Verificar se WireGuard já está instalado
    if dpkg -l | grep -q "^ii.*wireguard"; then
        msg "WireGuard já está instalado. Reconfigurando..."
    else
        msg "Instalando WireGuard..."
        sudo apt install -y wireguard wireguard-tools
    fi
    
    sudo mkdir -p /etc/wireguard/keys
    sudo chmod 700 /etc/wireguard/keys
    umask 077
    
    # Verificar se as chaves já existem
    if [ ! -f /etc/wireguard/keys/privatekey ] || [ ! -f /etc/wireguard/keys/publickey ]; then
        wg genkey | sudo tee /etc/wireguard/keys/privatekey | wg pubkey | sudo tee /etc/wireguard/keys/publickey
    fi
    
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
    
    # Verificar se o serviço está rodando
    if sudo systemctl is-active --quiet wg-quick@wg0; then
        msg "✅ WireGuard instalado/reconfigurado e em execução"
    else
        msg "⚠️  WireGuard instalado/reconfigurado, mas pode não estar em execução"
    fi
}

install_cloudflare() {
    msg "Instalando/reconfigurando Cloudflare Tunnel..."
    ARCH=$(detect_arch)
    URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
    
    # Baixar e instalar cloudflared
    if sudo wget -O /usr/local/bin/cloudflared "$URL"; then
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
        
        # Criar serviço systemd para cloudflared
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
        sudo systemctl enable --now cloudflared
        
        # Verificar se o serviço está rodando
        if sudo systemctl is-active --quiet cloudflared; then
            msg "✅ Cloudflare Tunnel instalado/reconfigurado e em execução"
        else
            msg "⚠️  Cloudflare Tunnel instalado/reconfigurado, execute 'cloudflared tunnel login' para autenticar"
        fi
    else
        msg "❌ Falha ao baixar Cloudflare Tunnel"
    fi
}

install_rng() {
    msg "Instalando/reconfigurando RNG-tools..."
    
    # Verificar se RNG-tools já está instalado
    if dpkg -l | grep -q "^ii.*rng-tools"; then
        msg "RNG-tools já está instalado. Reconfigurando..."
    else
        msg "Instalando RNG-tools..."
        sudo apt install -y rng-tools
    fi
    
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
    
    # Verificar se o serviço está rodando
    if sudo systemctl is-active --quiet rng-tools; then
        msg "✅ RNG-tools instalado/reconfigurado e em execução"
    else
        msg "⚠️  RNG-tools instalado/reconfigurado, mas pode não estar em execução"
    fi
}

install_samba() {
    msg "Instalando/reconfigurando Samba..."
    
    # Verificar se Samba já está instalado
    if dpkg -l | grep -q "^ii.*samba"; then
        msg "Samba já está instalado. Reconfigurando..."
    else
        msg "Instalando Samba..."
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
        msg "✅ Samba instalado/reconfigurado e em execução"
    else
        msg "⚠️  Samba instalado/reconfigurado, mas pode não estar em execução"
    fi
}

install_minidlna() {
    msg "Instalando/reconfigurando MiniDLNA..."
    
    # Verificar se MiniDLNA já está instalado
    if dpkg -l | grep -q "^ii.*minidlna"; then
        msg "MiniDLNA já está instalado. Reconfigurando..."
    else
        msg "Instalando MiniDLNA..."
        sudo apt install -y minidlna
    fi
    
    sudo mkdir -p /srv/media/{video,audio,photos}
    
    # Verificar se o arquivo minidlna.conf existe
    if [ ! -f /etc/minidlna.conf ]; then
        sudo touch /etc/minidlna.conf
    fi

    # Criar ou atualizar configuração do MiniDLNA
    cat <<EOF | sudo tee /etc/minidlna.conf
media_dir=V,/srv/media/video
media_dir=A,/srv/media/audio
media_dir=P,/srv/media/photos
friendly_name=BoxServer DLNA
inotify=yes
port=8200
EOF
    
    sudo systemctl enable --now minidlna
    
    # Verificar se o serviço está rodando
    if sudo systemctl is-active --quiet minidlna; then
        msg "✅ MiniDLNA instalado/reconfigurado e em execução"
    else
        msg "⚠️  MiniDLNA instalado/reconfigurado, mas pode não estar em execução"
    fi
}

install_filebrowser() {
    msg "Instalando/reconfigurando Filebrowser..."
    FB_VERSION=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | grep tag_name | cut -d '"' -f4)
    ARCH=$(detect_arch)
    case "$ARCH" in
        amd64) FB_ARCH="linux-amd64";;
        arm64) FB_ARCH="linux-arm64";;
        arm) FB_ARCH="linux-armv6";;
        *) msg "Arquitetura não suportada pelo Filebrowser"; return;;
    esac

    # Baixar e instalar Filebrowser
    if wget -O filebrowser.tar.gz https://github.com/filebrowser/filebrowser/releases/download/${FB_VERSION}/filebrowser-${FB_ARCH}.tar.gz; then
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
        
        # Verificar se o serviço está rodando
        if sudo systemctl is-active --quiet filebrowser; then
            msg "✅ Filebrowser instalado/reconfigurado e em execução"
        else
            msg "⚠️  Filebrowser instalado/reconfigurado, mas pode não estar em execução"
        fi
    else
        msg "❌ Falha ao baixar Filebrowser"
    fi
}

# =========================
# DASHBOARD WEB
# =========================
install_dashboard() {
    msg "Instalando/reconfigurando Dashboard Web..."
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

    # Parar serviços que possam estar usando a porta 80
    sudo systemctl stop apache2 || true  # Apache se estiver instalado
    
    # Configurar nginx para servir o dashboard
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
        msg "✅ Dashboard instalado/reconfigurado e acessível em http://$STATIC_IP/"
    else
        msg "⚠️  Dashboard instalado/reconfigurado, mas o Nginx pode não estar em execução"
    fi
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

    # Instalar serviços principais primeiro
    [[ $CHOICES == *"UNBOUND"* ]] && install_unbound
    [[ $CHOICES == *"PIHOLE"* ]] && install_pihole
    
    # Instalar serviços adicionais
    [[ $CHOICES == *"WIREGUARD"* ]] && install_wireguard
    [[ $CHOICES == *"CLOUDFLARE"* ]] && install_cloudflare
    [[ $CHOICES == *"RNG"* ]] && install_rng
    [[ $CHOICES == *"SAMBA"* ]] && install_samba
    [[ $CHOICES == *"MINIDLNA"* ]] && install_minidlna
    [[ $CHOICES == *"FILEBROWSER"* ]] && install_filebrowser

    # Instalar dashboard por último para evitar conflitos
    install_dashboard
    check_ports
    show_summary

    FINAL_MSG="✅ Instalação/reconfiguração concluída com sucesso!\n\n"
    FINAL_MSG+="IP Configurado: $STATIC_IP\n"
    FINAL_MSG+="Gateway: $GATEWAY\n"
    FINAL_MSG+="Interface: $NET_IF\n\n"
    FINAL_MSG+="Acesse o Dashboard em: http://$STATIC_IP/\n\n"
    FINAL_MSG+="Log completo em: $LOGFILE\n"
    FINAL_MSG+="Relatório em: /root/boxserver_summary.txt\n\n"
    FINAL_MSG+="⚠️  ATENÇÃO: Se o IP fixo não estiver funcionando, reinicie o sistema ou execute:\n"
    FINAL_MSG+="sudo netplan apply"

    msg "$FINAL_MSG"
}

main "$@"
