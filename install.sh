#!/bin/bash
set -e

echo "🚀 Iniciando instalação do servidor doméstico..."

# ========================
# 1. Atualizar sistema
# ========================
apt update && apt upgrade -y
apt install -y \
    build-essential iproute2 iptables \
    curl wget git unzip ufw dnsutils avahi-daemon \
    php php-cli php-fpm php-gd php-mbstring php-xml php-zip composer \
    nginx mariadb-server mariadb-client \
    samba samba-common-bin \
    minidlna syncthing transmission-daemon \
    mosquitto mosquitto-clients \
    fail2ban unbound wireguard wireguard-tools

# ========================
# 2. Heimdall (porta 80)
# ========================
echo "==> Instalando Heimdall Dashboard..."
cd /var/www
rm -rf Heimdall
git clone https://github.com/linuxserver/Heimdall.git
cd Heimdall
composer install --no-dev
chown -R www-data:www-data /var/www/Heimdall

cat <<EOF >/etc/nginx/sites-available/heimdall
server {
    listen 80;
    root /var/www/Heimdall/public;
    index index.php index.html;
    server_name _;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php7.4-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}
EOF

ln -sf /etc/nginx/sites-available/heimdall /etc/nginx/sites-enabled/heimdall
rm -f /etc/nginx/sites-enabled/default
systemctl restart php7.4-fpm nginx

# ========================
# 3. Pi-hole + Unbound
# ========================
echo "==> Instalando Pi-hole..."
curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended

# Configurar Pi-hole na porta 8080
sed -i 's/80/8080/g' /etc/lighttpd/lighttpd.conf
systemctl restart lighttpd

# Configurar Unbound
cat <<EOF >/etc/unbound/unbound.conf.d/pi-hole.conf
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    root-hints: "/var/lib/unbound/root.hints"
    harden-glue: yes
    harden-dnssec-stripped: yes
    cache-min-ttl: 3600
    cache-max-ttl: 86400
EOF

wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache
systemctl enable unbound
systemctl restart unbound

# ========================
# 4. Filebrowser (porta 8082)
# ========================
echo "==> Instalando Filebrowser..."
cd /usr/local/bin
wget -O filebrowser.tar.gz https://github.com/filebrowser/filebrowser/releases/download/v2.42.0/linux-armv7-filebrowser.tar.gz
tar -xvzf filebrowser.tar.gz
mv filebrowser /usr/local/bin/filebrowser
chmod +x /usr/local/bin/filebrowser
rm filebrowser.tar.gz

mkdir -p /srv/filebrowser

cat <<EOF >/etc/systemd/system/filebrowser.service
[Unit]
Description=Filebrowser
After=network.target

[Service]
ExecStart=/usr/local/bin/filebrowser -r /srv/filebrowser --address 0.0.0.0 --port 8082
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reexec
systemctl enable filebrowser
systemctl start filebrowser

# ========================
# 5. Cloudflared DoH (porta 5054)
# ========================
echo "==> Instalando Cloudflared..."
wget -O /usr/local/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm
chmod +x /usr/local/bin/cloudflared

cat <<EOF >/etc/systemd/system/cloudflared.service
[Unit]
Description=Cloudflared DNS over HTTPS Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/cloudflared proxy-dns --address 127.0.0.1 --port 5054
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reexec
systemctl enable cloudflared
systemctl start cloudflared

# ========================
# 6. WireGuard + WireGuard-UI
# ========================
echo "==> Instalando WireGuard-UI..."
cd /usr/local/bin
wget -O wireguard-ui.tar.gz https://github.com/ngoduykhanh/wireguard-ui/releases/download/v0.5.4/wireguard-ui-linux-armv7.tar.gz
tar -xvzf wireguard-ui.tar.gz
mv wireguard-ui /usr/local/bin/wireguard-ui
chmod +x /usr/local/bin/wireguard-ui
rm wireguard-ui.tar.gz

mkdir -p /etc/wireguard-ui

cat <<EOF >/etc/systemd/system/wireguard-ui.service
[Unit]
Description=WireGuard UI
After=network.target

[Service]
ExecStart=/usr/local/bin/wireguard-ui --data-dir /etc/wireguard-ui --port 5000
WorkingDirectory=/etc/wireguard-ui
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reexec
systemctl enable wireguard-ui
systemctl start wireguard-ui

# ========================
# 7. Configurar serviços locais
# ========================
# Transmission
sed -i 's/"rpc-enabled":.*/"rpc-enabled": true,/' /etc/transmission-daemon/settings.json
sed -i 's/"rpc-port":.*/"rpc-port": 9091,/' /etc/transmission-daemon/settings.json
systemctl restart transmission-daemon

# Syncthing
systemctl enable syncthing@$USER
systemctl start syncthing@$USER

# MiniDLNA
sed -i 's/#friendly_name=.*/friendly_name=MiniDLNA Server/' /etc/minidlna.conf
systemctl enable minidlna
systemctl restart minidlna

# Samba
mkdir -p /srv/samba/publico
chmod 777 /srv/samba/publico
cat <<EOF >>/etc/samba/smb.conf
[Publico]
   path = /srv/samba/publico
   browseable = yes
   read only = no
   guest ok = yes
EOF
systemctl restart smbd nmbd

# Fail2Ban
systemctl enable fail2ban
systemctl start fail2ban

# ========================
# 8. Firewall UFW
# ========================
echo "==> Configurando Firewall..."
ufw allow 22/tcp
ufw allow 80/tcp   # Heimdall
ufw allow 8080/tcp # Pi-hole
ufw allow 8082/tcp # Filebrowser
ufw allow 8200/tcp # MiniDLNA
ufw allow 9091/tcp # Transmission
ufw allow 8384/tcp # Syncthing
ufw allow 1883/tcp # Mosquitto
ufw allow 5000/tcp # WireGuard-UI
ufw allow 51820/udp # WireGuard VPN
ufw allow 5054/tcp # Cloudflared DoH
ufw --force enable

echo "✅ Instalação concluída!"
echo "Heimdall:        http://192.168.0.100/"
echo "Pi-hole:         http://192.168.0.100:8080/admin/"
echo "Filebrowser:     http://192.168.0.100:8082/"
echo "Transmission:    http://192.168.0.100:9091/"
echo "Syncthing:       http://192.168.0.100:8384/"
echo "MiniDLNA:        http://192.168.0.100:8200/"
echo "WireGuard-UI:    http://192.168.0.100:5000/"
echo "Cloudflared DoH: 127.0.0.1:5054"
