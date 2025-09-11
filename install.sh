#!/bin/bash
set -e

INTERFACE=$(ip link | awk -F: '$0 !~ "lo|wg0|docker|br-|^[^0-9]"{print $2;getline}' | head -n 1)
LAN_IP="192.168.0.100"
PUBLIC_IP=$(curl -s http://icanhazip.com)
SAMBA_USER="boxserver_user"
FILEBROWSER_PASS="senha_forte"

# 1. Configurar IP estático
tee -a /etc/network/interfaces << EOF
auto $INTERFACE
iface $INTERFACE inet static
    address $LAN_IP
    netmask 255.255.255.0
    gateway 192.168.0.1
    dns-nameservers 127.0.0.1
EOF
ifdown $INTERFACE && ifup $INTERFACE

# 2. Atualizar sistema
apt update && apt upgrade -y
apt install -y curl wget git ufw iptables iproute2 dnsutils samba php php-fpm nginx
fallocate -l 1G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo "/swapfile none swap sw 0 0" | tee -a /etc/fstab

# 3. Instalar WireGuard
apt install -y wireguard wireguard-tools
modprobe wireguard || (apt install -y linux-headers-$(uname -r); git clone https://git.zx2c4.com/wireguard-linux-compat; cd wireguard-linux-compat/src; make; make install; modprobe wireguard)
umask 077
wg genkey | tee /etc/wireguard/privatekey | wg pubkey | tee /etc/wireguard/publickey

# 4. Instalar WireGuard-UI
cd /opt
wget https://github.com/ngoduykhanh/wireguard-ui/releases/latest/download/wireguard-ui-linux-arm64.tar.gz
tar -xvzf wireguard-ui-linux-arm64.tar.gz
mv wireguard-ui /usr/local/bin/
mkdir -p /etc/wireguard-ui
tee /etc/systemd/system/wireguard-ui.service << 'EOF'
[Unit]
Description=WireGuard UI
After=network.target
[Service]
ExecStart=/usr/local/bin/wireguard-ui -bind-address 0.0.0.0:5000 -data-dir /etc/wireguard-ui
WorkingDirectory=/etc/wireguard-ui
Restart=always
[Install]
WantedBy=multi-user.target
EOF
tee /etc/systemd/system/wireguard-ui.path << 'EOF'
[Path]
PathModified=/etc/wireguard/wg0.conf
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now wireguard-ui wireguard-ui.path

# 5. Configurar WireGuard
tee /etc/wireguard/wg0.conf << EOF
[Interface]
Address = 10.252.1.1/24
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/privatekey)
MTU = 1450
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.252.1.0/24 -o $INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.252.1.0/24 -o $INTERFACE -j MASQUERADE
EOF
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# 6. Ativar roteamento e NAT
echo "net.ipv4.ip_forward=1" | tee -a /etc/sysctl.conf
sysctl -p
ufw allow 51820/udp
ufw route allow in on wg0 out on $INTERFACE
ufw allow from 10.252.1.0/24 to any
ufw enable
ufw reload

# 7. Instalar Pi-hole
curl -sSL https://install.pi-hole.net | bash
sed -i "s/PIHOLE_INTERFACE=.*/PIHOLE_INTERFACE=$INTERFACE/" /etc/pihole/setupVars.conf
sed -i "s/IPV4_ADDRESS=.*/IPV4_ADDRESS=$LAN_IP\/24/" /etc/pihole/setupVars.conf
sed -i "s/DNSMASQ_LISTENING=.*/DNSMASQ_LISTENING=all/" /etc/pihole/setupVars.conf
echo "WEB_PORT=8082" >> /etc/pihole/setupVars.conf
echo "DBINTERVAL=0" >> /etc/pihole/pihole-FTL.conf
pihole restartdns

# 8. Instalar Unbound
apt install -y unbound
tee /etc/unbound/unbound.conf.d/pi-hole.conf << 'EOF'
server:
    verbosity: 0
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    root-hints: "/var/lib/unbound/root.hints"
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    edns-buffer-size: 1232
    prefetch: yes
    num-threads: 1
    so-reuseport: yes
    so-rcvbuf: 1m
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
EOF
wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache
echo "0 0 1 * * wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache && systemctl restart unbound" | crontab -
systemctl enable --now unbound

# 9. Instalar Samba
tee -a /etc/samba/smb.conf << 'EOF'
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
adduser --gecos "" --disabled-password $SAMBA_USER
echo -e "$SAMBA_USER\n$SAMBA_USER" | smbpasswd -a $SAMBA_USER
chown $SAMBA_USER:$SAMBA_USER /srv/samba/shared
chmod 775 /srv/samba/shared
systemctl enable smbd nmbd
systemctl start smbd nmbd
ufw allow Samba
ufw allow from 10.252.1.0/24 to any port 137:139
ufw allow from 10.252.1.0/24 to any port 445
ufw reload

# 10. Instalar File Browser
curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash
mkdir -p /etc/filebrowser
filebrowser config init -d /etc/filebrowser/filebrowser.db
filebrowser config set -a 0.0.0.0 -p 8080 -r /srv/samba/shared -d /etc/filebrowser/filebrowser.db
filebrowser users add admin $FILEBROWSER_PASS --perm.admin -d /etc/filebrowser/filebrowser.db
tee /etc/systemd/system/filebrowser.service << 'EOF'
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
ufw allow from 10.252.1.0/24 to any port 8080
ufw reload

# 11. Instalar Heimdall
mkdir -p /var/www/heimdall
cd /var/www/heimdall
wget https://github.com/linuxserver/Heimdall/archive/refs/tags/v2.6.1.tar.gz
tar -xvzf v2.6.1.tar.gz --strip-components=1
chown -R www-data:www-data /var/www/heimdall
chmod -R 755 /var/www/heimdall
tee /etc/nginx/sites-available/heimdall << 'EOF'
server {
    listen 80;
    server_name 192.168.0.100;
    root /var/www/heimdall/public;
    index index.php;
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
EOF
ln -s /etc/nginx/sites-available/heimdall /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
systemctl enable php-fpm
systemctl start php-fpm
ufw allow from 10.252.1.0/24 to any port 80
ufw reload

# 12. Testes
echo "Testes no servidor:"
wg show
ss -lunp | grep 51820
dig @127.0.0.1 -p 5335 google.com
smbclient -L //192.168.0.100 -U $SAMBA_USER
curl http://192.168.0.100
curl http://192.168.0.100:8080
curl http://192.168.0.100:8082/admin
echo "Monitore RAM/CPU com: htop"
echo "Configure um cliente VPN e teste:"
echo "ping 10.252.1.1"
echo "dig @10.252.1.1 google.com"
echo "curl http://10.252.1.1"
echo "Acesse \\10.252.1.1\shared"
echo "Configure Heimdall em http://192.168.0.100 (admin/heimdall)"
