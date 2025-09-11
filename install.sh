#!/bin/bash
set -e

# ===== VARIÁVEIS =====
INTERFACE=$(ip route | awk '/default/ {print $5; exit}')
LAN_IP="192.168.0.100"
GATEWAY=$(ip route | awk '/default/ {print $3; exit}')
SAMBA_USER="boxserver_user"
FILEBROWSER_PASS="senha_forte"

# ===== 1. Atualização e pacotes base =====
apt update && apt upgrade -y
apt install -y curl wget git ufw iptables iproute2 dnsutils samba \
               php php-fpm php-xml php-mbstring php-cli php-zip php-gd \
               nginx unzip build-essential pkg-config avahi-daemon \
               network-manager

# ===== 2. Configurar IP fixo =====
nmcli con mod "$INTERFACE" ipv4.addresses $LAN_IP/24
nmcli con mod "$INTERFACE" ipv4.gateway $GATEWAY
nmcli con mod "$INTERFACE" ipv4.method manual
nmcli con up "$INTERFACE"

# ===== 3. Swapfile (caso não exista) =====
if [ ! -f /swapfile ]; then
  fallocate -l 1G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo "/swapfile none swap sw 0 0" | tee -a /etc/fstab
fi

# ===== 4. WireGuard =====
apt install -y wireguard-tools
umask 077
wg genkey | tee /etc/wireguard/privatekey | wg pubkey | tee /etc/wireguard/publickey

cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = 10.252.1.1/24
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/privatekey)
MTU = 1450
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.252.1.0/24 -o $INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.252.1.0/24 -o $INTERFACE -j MASQUERADE
EOF

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

ufw allow 51820/udp
ufw allow OpenSSH
ufw --force enable

# ===== 5. Pi-hole =====
curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
sed -i "s/PIHOLE_INTERFACE=.*/PIHOLE_INTERFACE=$INTERFACE/" /etc/pihole/setupVars.conf
sed -i "s/IPV4_ADDRESS=.*/IPV4_ADDRESS=$LAN_IP\/24/" /etc/pihole/setupVars.conf
sed -i "s/DNSMASQ_LISTENING=.*/DNSMASQ_LISTENING=all/" /etc/pihole/setupVars.conf
sed -i 's/server.port.*/server.port = 8081/' /etc/lighttpd/lighttpd.conf
systemctl restart lighttpd

# ===== 6. Unbound =====
apt install -y unbound
cat > /etc/unbound/unbound.conf.d/pi-hole.conf << 'EOF'
server:
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    root-hints: "/var/lib/unbound/root.hints"
    prefetch: yes
    num-threads: 1
    so-reuseport: yes
    private-address: 192.168.0.0/16
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
EOF
wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache
systemctl enable --now unbound

# ===== 7. Samba =====
cat >> /etc/samba/smb.conf << 'EOF'
[shared]
path = /srv/samba/shared
browsable = yes
writable = yes
guest ok = no
read only = no
valid users = boxserver_user
create mask = 0775
directory mask = 0775
EOF

mkdir -p /srv/samba/shared
adduser --gecos "" --disabled-password $SAMBA_USER || true
smbpasswd -a $SAMBA_USER
chown $SAMBA_USER:$SAMBA_USER /srv/samba/shared
chmod 775 /srv/samba/shared
systemctl restart smbd nmbd
ufw allow Samba

# ===== 8. Filebrowser =====
curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash
mkdir -p /etc/filebrowser
filebrowser config init -d /etc/filebrowser/filebrowser.db
filebrowser config set -a 0.0.0.0 -p 8082 -r /srv/samba/shared -d /etc/filebrowser/filebrowser.db
filebrowser users add admin $FILEBROWSER_PASS --perm.admin -d /etc/filebrowser/filebrowser.db

cat > /etc/systemd/system/filebrowser.service << 'EOF'
[Unit]
Description=File Browser
After=network.target
[Service]
ExecStart=/usr/local/bin/filebrowser -d /etc/filebrowser/filebrowser.db
WorkingDirectory=/etc/filebrowser
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now filebrowser
ufw allow 8082/tcp

# ===== 9. Heimdall =====
mkdir -p /var/www/heimdall
cd /var/www/heimdall
wget https://github.com/linuxserver/Heimdall/archive/refs/tags/v2.6.1.tar.gz
tar -xvzf v2.6.1.tar.gz --strip-components=1
chown -R www-data:www-data /var/www/heimdall

cat > /etc/nginx/sites-available/heimdall << 'EOF'
server {
    listen 80;
    server_name _;
    root /var/www/heimdall/public;
    index index.php;
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php7.4-fpm.sock;
    }
}
EOF

ln -sf /etc/nginx/sites-available/heimdall /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
systemctl enable php7.4-fpm
systemctl restart php7.4-fpm

# ===== 10. Mosquitto (MQTT) =====
apt install -y mosquitto mosquitto-clients
systemctl enable --now mosquitto
ufw allow 1883/tcp

# ===== 11. Syncthing =====
curl -s https://syncthing.net/release-key.txt | apt-key add -
echo "deb https://apt.syncthing.net/ syncthing stable" | tee /etc/apt/sources.list.d/syncthing.list
apt update && apt install -y syncthing
systemctl enable --now syncthing@$USER
ufw allow 8384/tcp
ufw allow 22000/tcp
ufw allow 21027/udp

# ===== 12. Transmission-daemon =====
apt install -y transmission-daemon
systemctl stop transmission-daemon
sed -i 's/"rpc-enabled":.*/"rpc-enabled": true,/' /etc/transmission-daemon/settings.json
sed -i 's/"rpc-port":.*/"rpc-port": 9092,/' /etc/transmission-daemon/settings.json
sed -i 's/"rpc-whitelist-enabled":.*/"rpc-whitelist-enabled": false,/' /etc/transmission-daemon/settings.json
systemctl start transmission-daemon
systemctl enable transmission-daemon
ufw allow 9092/tcp
ufw allow 51413/tcp
ufw allow 51413/udp

# ===== 13. Fail2Ban =====
apt install -y fail2ban
systemctl enable --now fail2ban

# ===== 14. Final =====
echo "===== INSTALAÇÃO FINALIZADA ====="
echo "IP Fixo:       $LAN_IP"
echo "Pi-hole Web:   http://$LAN_IP:8081/admin"
echo "Filebrowser:   http://$LAN_IP:8082 (admin / $FILEBROWSER_PASS)"
echo "Heimdall:      http://$LAN_IP/"
echo "Samba Share:   //$LAN_IP/shared"
echo "WireGuard:     Porta 51820/UDP"
echo "Mosquitto:     Porta 1883/TCP"
echo "Syncthing:     http://$LAN_IP:8384"
echo "Transmission:  http://$LAN_IP:9092"
