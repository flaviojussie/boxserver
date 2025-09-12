#!/bin/bash
set -e

echo "🚀 Iniciando instalação do servidor doméstico..."

# =========================
# 1. Corrigir repositórios
# =========================
sed -i '/bullseye-backports/d' /etc/apt/sources.list
apt update -y

# =========================
# 2. Instalar pacotes principais
# =========================
apt install -y \
  unbound \
  wireguard wireguard-tools \
  samba samba-common-bin \
  minidlna \
  syncthing \
  transmission-daemon \
  mosquitto mosquitto-clients \
  fail2ban \
  avahi-daemon \
  ufw curl wget unzip git nginx php-fpm php-cli php-xml php-zip php-mbstring php-gd mariadb-server mariadb-client composer

# =========================
# 3. Instalar Filebrowser
# =========================
FB_VERSION=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | grep tag_name | cut -d '"' -f 4)
wget -O /usr/local/bin/filebrowser https://github.com/filebrowser/filebrowser/releases/download/${FB_VERSION}/linux-armv7-filebrowser
chmod +x /usr/local/bin/filebrowser

cat >/etc/systemd/system/filebrowser.service <<EOF
[Unit]
Description=Filebrowser
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/filebrowser -a 0.0.0.0 -p 8081 -r /srv
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl enable filebrowser
systemctl start filebrowser

# =========================
# 4. Instalar Cloudflared
# =========================
CLOUDFLARED_DEB="cloudflared-stable-linux-arm.deb"
wget -O /tmp/${CLOUDFLARED_DEB} https://github.com/cloudflare/cloudflared/releases/latest/download/${CLOUDFLARED_DEB}
dpkg -i /tmp/${CLOUDFLARED_DEB} || apt -f install -y

cat >/etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflared DNS over HTTPS
After=network.target

[Service]
ExecStart=/usr/local/bin/cloudflared proxy-dns --port 5053 --upstream https://1.1.1.1/dns-query
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
EOF

systemctl enable cloudflared
systemctl start cloudflared

# =========================
# 5. Heimdall Dashboard (porta 80)
# =========================
echo "🌐 Instalando Heimdall Dashboard..."

cd /var/www
git clone https://github.com/linuxserver/Heimdall.git heimdall
cd heimdall
composer install --no-dev

chown -R www-data:www-data /var/www/heimdall

cat >/etc/nginx/sites-available/heimdall <<EOF
server {
    listen 80 default_server;
    server_name _;

    root /var/www/heimdall/public;
    index index.php index.html;

    location / {
        try_files \$uri /index.php?\$query_string;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.ht {
        deny all;
    }
}
EOF

ln -sf /etc/nginx/sites-available/heimdall /etc/nginx/sites-enabled/
systemctl reload nginx

# =========================
# 6. Ajustar Pi-hole (porta 8080)
# =========================
echo "🔧 Ajustando Pi-hole para usar porta 8080..."
if [ -f /etc/lighttpd/lighttpd.conf ]; then
  sed -i 's/server.port *=.*/server.port = 8080/' /etc/lighttpd/lighttpd.conf
  systemctl restart lighttpd || true
fi

# =========================
# 7. Serviços adicionais
# =========================
systemctl enable minidlna
systemctl restart minidlna

systemctl enable transmission-daemon
systemctl restart transmission-daemon

systemctl enable syncthing@root
systemctl start syncthing@root

systemctl enable mosquitto
systemctl start mosquitto

mkdir -p /srv/samba/share
chmod 777 /srv/samba/share
grep -q "\[Compartilhado\]" /etc/samba/smb.conf || cat >>/etc/samba/smb.conf <<EOF

[Compartilhado]
   path = /srv/samba/share
   browseable = yes
   writable = yes
   guest ok = yes
   read only = no
EOF
systemctl restart smbd

# =========================
# 8. Firewall
# =========================
ufw allow 22/tcp
ufw allow 80/tcp       # Heimdall
ufw allow 8080/tcp     # Pi-hole
ufw allow 53/udp
ufw allow 5053/udp
ufw allow 51820/udp
ufw allow 137,138/udp
ufw allow 139,445/tcp
ufw allow 8200/tcp
ufw allow 8081/tcp
ufw allow 9091/tcp
ufw allow 8384/tcp
ufw allow 1883/tcp
ufw --force enable

# =========================
# 9. Finalização
# =========================
echo "✅ Instalação concluída!"
echo "----------------------------------"
echo " Heimdall:      http://192.168.0.100/"
echo " Pi-hole:       http://192.168.0.100:8080/admin"
echo " Filebrowser:   http://192.168.0.100:8081"
echo " Transmission:  http://192.168.0.100:9091"
echo " Syncthing:     http://192.168.0.100:8384"
echo " Samba:         \\\\192.168.0.100\\Compartilhado"
echo " MiniDLNA:      via DLNA (porta 8200)"
echo " MQTT:          tcp://192.168.0.100:1883"
echo " WireGuard:     Porta 51820/UDP"
echo "----------------------------------"

---

👉 Quer que eu prepare também a configuração inicial do **Heimdall** já com os atalhos de todos os serviços que você instalou?
