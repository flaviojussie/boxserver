#!/bin/bash
set -e

### ==========================
### 1. Configuração de IP fixo
### ==========================
echo "[INFO] Configurando IP fixo em eth0 (192.168.0.100)..."
nmcli con delete static-ip 2>/dev/null || true
nmcli con add type ethernet ifname eth0 con-name static-ip \
  ip4 192.168.0.100/24 gw4 192.168.0.1
nmcli con mod static-ip ipv4.dns "127.0.0.1,8.8.8.8"
nmcli con up static-ip

### ==========================
### 2. Atualizações do sistema
### ==========================
echo "[INFO] Atualizando pacotes..."
apt update && apt upgrade -y

### ==========================
### 3. Instalação de serviços
### ==========================
echo "[INFO] Instalando pacotes..."
apt install -y \
  unbound \
  wireguard \
  cloudflared \
  samba \
  minidlna \
  filebrowser \
  mosquitto \
  transmission-daemon \
  syncthing \
  fail2ban \
  lighttpd \
  curl git net-tools

### ==========================
### 4. Configuração do Pi-hole
### ==========================
echo "[INFO] Instalando Pi-hole..."
curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended

# Pi-hole usa lighttpd → mover painel para porta 8081
sed -i 's/server.port\s*=\s*80/server.port = 8081/' /etc/lighttpd/lighttpd.conf
systemctl restart lighttpd

### ==========================
### 5. Configuração do Unbound
### ==========================
echo "[INFO] Configurando Unbound..."
cat >/etc/unbound/unbound.conf.d/pi-hole.conf <<EOF
server:
    verbosity: 0
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    root-hints: "/var/lib/unbound/root.hints"
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    edns-buffer-size: 1232
    prefetch: yes
    cache-min-ttl: 3600
EOF
wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
systemctl enable unbound --now

### ==========================
### 6. WireGuard
### ==========================
echo "[INFO] Configurando WireGuard..."
mkdir -p /etc/wireguard
umask 077
wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey

cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/privatekey)
Address = 10.252.1.1/24
ListenPort = 51820
SaveConfig = true

[Peer]
# Exemplo de cliente (substituir pela sua chave pública)
PublicKey = CLIENT_PUBLIC_KEY
AllowedIPs = 10.252.1.2/32
EOF

systemctl enable wg-quick@wg0 --now

### ==========================
### 7. Cloudflared (DoH)
### ==========================
echo "[INFO] Configurando Cloudflared..."
cat >/etc/default/cloudflared <<EOF
CLOUDFLARED_OPTS="proxy-dns --port 5053 --upstream https://1.1.1.1/dns-query"
EOF
systemctl enable cloudflared --now

### ==========================
### 8. Samba
### ==========================
echo "[INFO] Configurando Samba..."
cat >>/etc/samba/smb.conf <<EOF

[Public]
   path = /srv/samba/public
   browseable = yes
   read only = no
   guest ok = yes
EOF
mkdir -p /srv/samba/public
chmod 777 /srv/samba/public
systemctl restart smbd

### ==========================
### 9. MiniDLNA
### ==========================
echo "[INFO] Configurando MiniDLNA..."
mkdir -p /srv/media
sed -i 's|#media_dir=/var/lib/minidlna|media_dir=/srv/media|' /etc/minidlna.conf
systemctl enable minidlna --now

### ==========================
### 10. Filebrowser
### ==========================
echo "[INFO] Configurando Filebrowser..."
mkdir -p /srv/filebrowser
filebrowser config init
filebrowser config set -a 0.0.0.0 -p 8082
filebrowser users add admin admin --perm.admin

### ==========================
### 11. Mosquitto (MQTT)
### ==========================
echo "[INFO] Configurando Mosquitto..."
systemctl enable mosquitto --now

### ==========================
### 12. Transmission
### ==========================
echo "[INFO] Configurando Transmission..."
systemctl stop transmission-daemon
sed -i 's/"rpc-whitelist-enabled": true/"rpc-whitelist-enabled": false/' /etc/transmission-daemon/settings.json
sed -i 's/"rpc-authentication-required": true/"rpc-authentication-required": false/' /etc/transmission-daemon/settings.json
sed -i 's/"rpc-port": [0-9]\+/"rpc-port": 9092/' /etc/transmission-daemon/settings.json
systemctl enable transmission-daemon --now

### ==========================
### 13. Syncthing
### ==========================
echo "[INFO] Configurando Syncthing..."
systemctl enable syncthing@root --now

### ==========================
### 14. Fail2Ban
### ==========================
echo "[INFO] Configurando Fail2Ban..."
systemctl enable fail2ban --now

### ==========================
### Fim
### ==========================
echo "[OK] Servidor doméstico configurado com sucesso!"
echo "Acesse:"
echo "- Pi-hole: http://192.168.0.100:8081/admin"
echo "- Filebrowser: http://192.168.0.100:8082 (admin/admin)"
echo "- Transmission: http://192.168.0.100:9092"
echo "- Syncthing: http://192.168.0.100:8384"
