#!/bin/bash
# BoxServer Installer - Final Version with Enhanced Features
# Compatível apenas com Armbian 21.08.8 (Debian 11 Bullseye)
# Inclui: Unbound, Pi-hole, WireGuard, Cloudflared, RNG-tools, Samba, MiniDLNA, Filebrowser, Dashboard
# Cria IP fixo default 192.168.0.100
# Exibe relatório com IPs, portas, chaves e senhas ao final

set -euo pipefail

# =========================
# Configurações globais
# =========================
LOGFILE="/var/log/boxserver_install.log"
SUMMARY_FILE="/root/boxserver_summary.txt"
ROLLBACK_LOG="/var/log/boxserver_rollback.log"
DASHBOARD_DIR="/srv/boxserver-dashboard"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
BACKUP_SUFFIX=".bak.${TIMESTAMP}"
SILENT_MODE=false

exec > >(tee -a "$LOGFILE") 2>&1

# =========================
# Funções auxiliares
# =========================
whiptail_msg() {
  if [ "$SILENT_MODE" = false ]; then
    whiptail --title "BoxServer Instalador" --msgbox "$1" 12 76
  else
    echo "[MSG] $1"
  fi
}

echo_msg() {
  echo "$1"
  if [ "$SILENT_MODE" = false ]; then
    whiptail --title "BoxServer Instalador" --msgbox "$1" 12 76
  fi
}

backup_file() {
  local f="$1"
  if [ -f "$f" ]; then
    sudo cp -a "$f" "${f}${BACKUP_SUFFIX}"
    echo "Backup criado: ${f}${BACKUP_SUFFIX}" >> "$ROLLBACK_LOG"
  fi
}

ensure_pkg() {
  local pkg="$1"
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    sudo apt-get install -y "$pkg"
  fi
}

ensure_deps() {
  echo "Instalando dependências básicas..."
  sudo apt-get update -y
  sudo apt-get install -y whiptail curl wget tar gnupg lsb-release ca-certificates \
                          net-tools iproute2 sed grep jq nginx
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

check_disk_space() {
  local required_space_mb=1024
  local available_space_mb
  available_space_mb=$(df / | awk 'NR==2 {print int($4/1024)}')

  if [ "$available_space_mb" -lt "$required_space_mb" ]; then
    whiptail_msg "❌ Espaço em disco insuficiente. Necessário: ${required_space_mb}MB, Disponível: ${available_space_mb}MB"
    exit 1
  fi
  echo "✅ Espaço em disco suficiente: ${available_space_mb}MB disponível"
}

check_connectivity() {
  if ! ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
    whiptail_msg "❌ Sem conectividade de rede. Verifique sua conexão."
    exit 1
  fi
  echo "✅ Conectividade de rede verificada"
}

check_and_set_ports() {
  echo "Verificando e alocando portas de serviço..."
  local original_port
  local -a used_ports=() # Array to hold ports we've assigned

  # Helper to check if a port is in use by the system OR already assigned by us
  is_port_used() {
    local port_to_check=$1
    # Check if listening on the system
    if sudo netstat -tln | awk '{print $4}' | grep -q ":$port_to_check$"; then
      return 0 # 0 means true (is used)
    fi
    # Check if already assigned by this script
    for p in "${used_ports[@]}"; do
      if [[ "$p" == "$port_to_check" ]]; then
        return 0 # 0 means true (is used)
      fi
    done
    return 1 # 1 means false (is not used)
  }

  # Helper to find the next free port
  find_next_free_port() {
    local port=$1
    while is_port_used "$port"; do
      port=$((port + 1))
    done
    echo "$port"
  }

  # --- Assign ports sequentially, reserving each one ---

  original_port=$PIHOLE_HTTP_PORT
  PIHOLE_HTTP_PORT=$(find_next_free_port "$original_port")
  used_ports+=("$PIHOLE_HTTP_PORT")
  if [ "$PIHOLE_HTTP_PORT" != "$original_port" ]; then
    whiptail_msg "A porta $original_port estava em uso. Pi-hole HTTP usará a porta $PIHOLE_HTTP_PORT."
  fi

  original_port=$PIHOLE_HTTPS_PORT
  PIHOLE_HTTPS_PORT=$(find_next_free_port "$original_port")
  used_ports+=("$PIHOLE_HTTPS_PORT")
  if [ "$PIHOLE_HTTPS_PORT" != "$original_port" ]; then
    whiptail_msg "A porta $original_port estava em uso. Pi-hole HTTPS usará a porta $PIHOLE_HTTPS_PORT."
  fi

  original_port=$FILEBROWSER_PORT
  FILEBROWSER_PORT=$(find_next_free_port "$original_port")
  used_ports+=("$FILEBROWSER_PORT")
  if [ "$FILEBROWSER_PORT" != "$original_port" ]; then
    whiptail_msg "A porta $original_port estava em uso. Filebrowser usará a porta $FILEBROWSER_PORT."
  fi

  original_port=$MINIDLNA_PORT
  MINIDLNA_PORT=$(find_next_free_port "$original_port")
  used_ports+=("$MINIDLNA_PORT")
  if [ "$MINIDLNA_PORT" != "$original_port" ]; then
    whiptail_msg "A porta $original_port estava em uso. MiniDLNA usará a porta $MINIDLNA_PORT."
  fi

  original_port=$UNBOUND_PORT
  UNBOUND_PORT=$(find_next_free_port "$original_port")
  used_ports+=("$UNBOUND_PORT")
  if [ "$UNBOUND_PORT" != "$original_port" ]; then
    whiptail_msg "A porta $original_port estava em uso. Unbound usará a porta $UNBOUND_PORT."
  fi

  original_port=$WG_PORT
  WG_PORT=$(find_next_free_port "$original_port")
  used_ports+=("$WG_PORT")
  if [ "$WG_PORT" != "$original_port" ]; then
    whiptail_msg "A porta $original_port estava em uso. WireGuard usará a porta $WG_PORT."
  fi
}

# =========================
# Análise de compatibilidade kernel RK322x
# =========================
check_rk322x_compatibility() {
  local kernel_version=$(uname -r)
  local cpu_info=$(cat /proc/cpuinfo | grep -i "hardware" | head -1)
  local architecture=$(uname -m)

  echo "🔍 Analisando compatibilidade do kernel RK322x..."
  echo "   Kernel: $kernel_version"
  echo "   Arquitetura: $architecture"
  echo "   Hardware: $cpu_info"

  # Verificar se é kernel 4.4.194-rk322x específico
  if [[ "$kernel_version" == *"4.4.194-rk322x"* ]]; then
    echo "✅ Kernel RK322x detectado: $kernel_version"
  else
    echo "⚠️ Kernel não é 4.4.194-rk322x, mas continuando..."
  fi

  # Verificar arquitetura ARM
  if [[ "$architecture" != "armv7l" ]] && [[ "$architecture" != "aarch64" ]]; then
    echo "❌ Arquitetura $architecture não é compatível com RK322x"
    return 1
  fi

  # Verificar módulos críticos do kernel
  echo "🔧 Verificando módulos do kernel disponíveis..."

  # Verificar suporte a iptables/netfilter
  if [ ! -f /proc/net/ip_tables_names ] && ! lsmod | grep -q "ip_tables"; then
    echo "⚠️ Módulos iptables podem não estar disponíveis"
    if ! modprobe ip_tables 2>/dev/null; then
      echo "❌ Falha ao carregar módulos iptables críticos"
      return 1
    fi
  fi

  # Verificar suporte a TUN/TAP para VPN
  if [ ! -c /dev/net/tun ]; then
    echo "⚠️ Interface TUN/TAP não disponível para VPN"
    if ! modprobe tun 2>/dev/null; then
      echo "❌ Módulo TUN não disponível - VPN será desabilitada"
      export DISABLE_VPN=true
    fi
  fi

  # Verificar suporte a criptografia
  local crypto_modules=("crypto_user" "af_alg" "algif_hash" "algif_skcipher")
  for module in "${crypto_modules[@]}"; do
    if ! lsmod | grep -q "$module" && ! modprobe "$module" 2>/dev/null; then
      echo "⚠️ Módulo de criptografia $module não disponível"
    fi
  done

  # Verificar limitações de memória
  local total_mem=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
  echo "💾 Memória total: ${total_mem}MB"

  if [ "$total_mem" -lt 512 ]; then
    echo "⚠️ Memória baixa ($total_mem MB) - ajustando configurações"
    export LOW_MEMORY=true
  fi

  # Verificar espaço de armazenamento
  local available_space=$(df / | awk 'NR==2 {print int($4/1024)}')
  echo "💽 Espaço disponível: ${available_space}MB"

  if [ "$available_space" -lt 500 ]; then
    echo "❌ Espaço insuficiente ($available_space MB) - mínimo 500MB"
    return 1
  fi

  echo "✅ Análise de compatibilidade RK322x concluída"
  return 0
}

# =========================
# Verificação do sistema
# =========================
check_system() {
  # Primeiro verificar compatibilidade RK322x
  if ! check_rk322x_compatibility; then
    whiptail_msg "❌ Sistema não compatível com kernel RK322x.
Verifique os requisitos de hardware e kernel."
    exit 1
  fi

  if [ ! -f /etc/armbian-release ]; then
    whiptail_msg "❌ Este instalador requer Armbian 21.08.8 (Debian 11 Bullseye).
Arquivo /etc/armbian-release não encontrado."
    exit 1
  fi

  . /etc/armbian-release
  if [ "$VERSION" != "21.08.8" ]; then
    whiptail_msg "❌ Este instalador é exclusivo para Armbian 21.08.8.
Detectado: $VERSION"
    exit 1
  fi

  if ! grep -q 'VERSION_ID="11"' /etc/os-release; then
    whiptail_msg "❌ Base incompatível. É necessário Debian 11 (Bullseye)."
    exit 1
  fi

  echo "✅ Sistema compatível: Armbian $VERSION (Debian 11 Bullseye) em kernel RK322x"
}

# =========================
# Configurações globais
# =========================
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
WG_PRIVATE=""
WG_PUBLIC=""

# =========================
# Funções de rollback
# =========================
rollback_changes() {
  echo "Executando rollback das alterações..."
  if [ -f "$ROLLBACK_LOG" ]; then
    while IFS= read -r line; do
      if [[ $line == "Backup criado: "* ]]; then
        backup_file="${line#Backup criado: }"
        original_file="${backup_file%$BACKUP_SUFFIX}"
        if [ -f "$backup_file" ]; then
          sudo mv "$backup_file" "$original_file"
          echo "Restaurado: $original_file"
        fi
      fi
    done < "$ROLLBACK_LOG"
  fi

  # Parar e desabilitar serviços instalados
  local services=("unbound" "pihole-ftl" "wg-quick@wg0" "cloudflared" "rng-tools" "smbd" "minidlna" "filebrowser" "nginx")
  for service in "${services[@]}"; do
    if systemctl list-units --type=service | grep -q "$service"; then
      sudo systemctl stop "$service" 2>/dev/null || true
      sudo systemctl disable "$service" 2>/dev/null || true
    fi
  done

  # Remover arquivos e diretórios criados
  sudo rm -rf /srv/boxserver-dashboard \
              /etc/wireguard \
              /etc/cloudflared \
              /srv/filebrowser \
              /srv/samba/share \
              /srv/media \
              /etc/unbound/unbound.conf.d/pi-hole.conf \
              /etc/systemd/system/filebrowser.service \
              /etc/systemd/system/cloudflared.service \
              /etc/netplan/01-boxserver.yaml \
              "$SUMMARY_FILE" \
              "$ROLLBACK_LOG" \
              2>/dev/null || true

  echo "Rollback concluído."
}

# =========================
# Função de purga completa
# =========================
purge_existing_installations() {
  whiptail_msg "🧹 Iniciando purga completa de todas as instalações BoxServer..."
  echo "=========================================="
  echo "PURGA COMPLETA DO BOXSERVER - $(date)"
  echo "=========================================="

  # === FASE 1: PARAR TODOS OS SERVIÇOS ===
  echo "📛 FASE 1: Parando todos os serviços..."
  local all_services=(
    # Serviços principais
    "unbound" "pihole-ftl" "lighttpd" "wg-quick@wg0"
    "cloudflared" "rng-tools" "smbd" "nmbd" "minidlna"
    "filebrowser" "nginx" "apache2"
    # Serviços adicionais que podem existir
    "dnsmasq" "bind9" "named" "systemd-resolved"
    "openvpn" "strongswan" "ipsec"
  )

  for service in "${all_services[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
      echo "   Parando $service..."
      sudo systemctl stop "$service" 2>/dev/null || true
    fi
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
      echo "   Desabilitando $service..."
      sudo systemctl disable "$service" 2>/dev/null || true
    fi
  done

  # === FASE 2: DESINSTALAR PI-HOLE OFICIALMENTE ===
  echo "🕳️ FASE 2: Desinstalando Pi-hole..."
  if command -v pihole >/dev/null 2>&1; then
    echo "   Executando desinstalador oficial do Pi-hole..."
    sudo pihole uninstall --unattended 2>/dev/null || true
    # Garantir remoção de restos
    sudo rm -f /usr/local/bin/pihole 2>/dev/null || true
  fi

  # === FASE 3: REMOVER INTERFACES DE REDE VIRTUAIS ===
  echo "🌐 FASE 3: Removendo interfaces virtuais..."
  # WireGuard
  if ip link show wg0 >/dev/null 2>&1; then
    echo "   Removendo interface wg0..."
    sudo ip link delete wg0 2>/dev/null || true
  fi
  # Outras interfaces VPN possíveis
  for iface in wg1 wg2 tun0 tap0; do
    if ip link show "$iface" >/dev/null 2>&1; then
      echo "   Removendo interface $iface..."
      sudo ip link delete "$iface" 2>/dev/null || true
    fi
  done

  # === FASE 4: PURGAR PACOTES COMPLETAMENTE ===
  echo "📦 FASE 4: Purgando pacotes..."

  # Lista completa de pacotes a verificar e purgar
  local all_packages=(
    # DNS e Pi-hole
    "pihole-ftl" "lighttpd" "php*" "dnsutils" "dnsmasq*"
    # Unbound
    "unbound" "unbound-*"
    # VPN
    "wireguard" "wireguard-*" "openvpn*" "strongswan*"
    # Samba
    "samba" "samba-*" "smbclient" "cifs-utils"
    # Media
    "minidlna" "dlna*"
    # Web servers
    "nginx" "nginx-*" "apache2*"
    # Outros
    "rng-tools" "haveged"
  )

  echo "   Atualizando cache de pacotes..."
  sudo apt-get update -qq 2>/dev/null || true

  for pkg_pattern in "${all_packages[@]}"; do
    # Usar dpkg para listar pacotes que correspondem ao padrão
    local matching_packages
    matching_packages=$(dpkg -l | awk '/^ii/ {print $2}' | grep -E "^${pkg_pattern//\*/.*}$" 2>/dev/null || true)

    if [ -n "$matching_packages" ]; then
      echo "   Purgando pacotes: $matching_packages"
      for pkg in $matching_packages; do
        sudo apt-get purge -y "$pkg" 2>/dev/null || echo "     Aviso: Não foi possível purgar $pkg"
      done
    fi
  done

  # Limpeza final de pacotes
  echo "   Removendo pacotes órfãos..."
  sudo apt-get autoremove -y --purge 2>/dev/null || true
  sudo apt-get autoclean 2>/dev/null || true

  # === FASE 5: REMOVER USUÁRIOS E GRUPOS ===
  echo "👥 FASE 5: Removendo usuários e grupos..."
  local users_to_remove=("pihole" "unbound" "filebrowser" "minidlna" "debian-samba")
  local groups_to_remove=("pihole" "unbound" "filebrowser" "minidlna" "samba")

  for user in "${users_to_remove[@]}"; do
    if id "$user" >/dev/null 2>&1; then
      echo "   Removendo usuário $user..."
      sudo userdel -r "$user" 2>/dev/null || sudo userdel "$user" 2>/dev/null || true
    fi
  done

  for group in "${groups_to_remove[@]}"; do
    if getent group "$group" >/dev/null 2>&1; then
      echo "   Removendo grupo $group..."
      sudo groupdel "$group" 2>/dev/null || true
    fi
  done

  # === FASE 6: REMOVER BINÁRIOS MANUAIS ===
  echo "🗂️ FASE 6: Removendo binários manuais..."
  local manual_binaries=(
    "/usr/local/bin/cloudflared"
    "/usr/local/bin/filebrowser"
    "/usr/local/bin/pihole"
    "/opt/pihole"
    "/usr/bin/wg"
    "/usr/bin/wg-quick"
  )

  for binary in "${manual_binaries[@]}"; do
    if [ -e "$binary" ]; then
      echo "   Removendo $binary..."
      sudo rm -rf "$binary" 2>/dev/null || true
    fi
  done

  # === FASE 7: REMOVER SERVIÇOS SYSTEMD MANUAIS ===
  echo "⚙️ FASE 7: Removendo serviços systemd manuais..."
  local service_files=(
    "/etc/systemd/system/cloudflared.service"
    "/etc/systemd/system/filebrowser.service"
    "/etc/systemd/system/pihole-ftl.service"
    "/lib/systemd/system/pihole-ftl.service"
    "/etc/systemd/system/multi-user.target.wants/pihole-ftl.service"
    "/etc/systemd/system/wg-quick@.service"
    "/lib/systemd/system/wg-quick@.service"
  )

  for service_file in "${service_files[@]}"; do
    if [ -f "$service_file" ]; then
      echo "   Removendo $service_file..."
      sudo rm -f "$service_file" 2>/dev/null || true
    fi
  done

  sudo systemctl daemon-reload 2>/dev/null || true

  # === FASE 8: REMOVER CONFIGURAÇÕES E DADOS ===
  echo "📁 FASE 8: Removendo configurações e dados..."
  local config_directories=(
    # Pi-hole
    "/etc/pihole" "/var/www/html/admin" "/var/log/pihole*"
    "/etc/lighttpd" "/var/log/lighttpd"
    # Unbound
    "/etc/unbound" "/var/lib/unbound" "/var/log/unbound*"
    # WireGuard
    "/etc/wireguard" "/var/log/wireguard*"
    # Cloudflared
    "/etc/cloudflared" "/root/.cloudflared" "/home/*/.cloudflared"
    # Samba
    "/etc/samba" "/var/lib/samba" "/var/log/samba"
    # MiniDLNA
    "/etc/minidlna" "/var/lib/minidlna" "/var/log/minidlna*"
    # Nginx/Apache
    "/etc/nginx/sites-available/boxserver*" "/etc/nginx/sites-enabled/boxserver*"
    "/etc/apache2/sites-available/boxserver*" "/etc/apache2/sites-enabled/boxserver*"
    # BoxServer específicos
    "/srv/boxserver-dashboard" "/srv/filebrowser" "/srv/samba" "/srv/media"
    "/var/log/boxserver*" "/root/boxserver*" "/tmp/boxserver*"
  )

  for dir_pattern in "${config_directories[@]}"; do
    # Expandir padrões com glob
    for dir in $dir_pattern; do
      if [ -e "$dir" ]; then
        echo "   Removendo $dir..."
        sudo rm -rf "$dir" 2>/dev/null || true
      fi
    done
  done

  # === FASE 9: LIMPAR CONFIGURAÇÕES DE REDE ===
  echo "🔌 FASE 9: Limpando configurações de rede..."

  # Remover configurações netplan do BoxServer
  if [ -f "/etc/netplan/01-boxserver.yaml" ]; then
    echo "   Removendo configuração netplan BoxServer..."
    sudo rm -f "/etc/netplan/01-boxserver.yaml" 2>/dev/null || true
    sudo netplan apply 2>/dev/null || true
  fi

  # Limpar iptables rules do WireGuard
  echo "   Limpando regras iptables..."
  sudo iptables -t nat -D POSTROUTING -o "$NET_IF" -j MASQUERADE 2>/dev/null || true
  sudo iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
  sudo iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true

  # Restaurar IP forwarding se desejado
  if grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "   Desabilitando IP forwarding..."
    sudo sed -i 's/^net.ipv4.ip_forward=1/#net.ipv4.ip_forward=1/' /etc/sysctl.conf 2>/dev/null || true
    echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null 2>&1 || true
  fi

  # === FASE 10: LIMPAR DNS E RESOLVER ===
  echo "🌍 FASE 10: Restaurando configurações DNS..."

  # Restaurar systemd-resolved se foi desabilitado
  if [ -f /lib/systemd/system/systemd-resolved.service ]; then
    echo "   Reabilitando systemd-resolved..."
    sudo systemctl enable systemd-resolved 2>/dev/null || true
    sudo systemctl start systemd-resolved 2>/dev/null || true
  fi

  # Restaurar resolv.conf padrão
  if [ ! -L /etc/resolv.conf ] && [ -f /etc/resolv.conf ]; then
    echo "   Restaurando configuração DNS padrão..."
    cat > /tmp/resolv.conf.new << EOF
# DNS temporário após purga BoxServer
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    sudo mv /tmp/resolv.conf.new /etc/resolv.conf 2>/dev/null || true
  fi

  # === FASE 11: LIMPEZA DE CRON E LOGS ===
  echo "⏰ FASE 11: Limpando cron jobs e logs..."

  # Remover cron jobs relacionados
  sudo crontab -u root -l 2>/dev/null | grep -v -E "(pihole|unbound|wireguard|cloudflared)" | sudo crontab -u root - 2>/dev/null || true

  # Limpar logs específicos
  sudo find /var/log -name "*pihole*" -delete 2>/dev/null || true
  sudo find /var/log -name "*unbound*" -delete 2>/dev/null || true
  sudo find /var/log -name "*wireguard*" -delete 2>/dev/null || true
  sudo find /var/log -name "*boxserver*" -delete 2>/dev/null || true

  # === FASE 12: VERIFICAÇÃO FINAL ===
  echo "🔍 FASE 12: Verificação final..."

  # Verificar se algum serviço ainda está rodando
  local remaining_services=()
  for service in "${all_services[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
      remaining_services+=("$service")
    fi
  done

  if [ ${#remaining_services[@]} -gt 0 ]; then
    echo "   ⚠️ Serviços ainda ativos: ${remaining_services[*]}"
    echo "   Tentando parar forçadamente..."
    for service in "${remaining_services[@]}"; do
      sudo systemctl kill "$service" 2>/dev/null || true
    done
  fi

  # Verificar processos remanescentes
  local remaining_processes
  remaining_processes=$(pgrep -f "(pihole|unbound|wireguard|cloudflared|filebrowser)" 2>/dev/null || true)
  if [ -n "$remaining_processes" ]; then
    echo "   ⚠️ Processos remanescentes detectados, terminando..."
    echo "$remaining_processes" | xargs sudo kill -TERM 2>/dev/null || true
    sleep 2
    echo "$remaining_processes" | xargs sudo kill -KILL 2>/dev/null || true
  fi

  echo "=========================================="
  echo "✅ PURGA COMPLETA FINALIZADA - $(date)"
  echo "=========================================="
  echo "📊 Resumo:"
  echo "   • Serviços parados e desabilitados"
  echo "   • Pacotes completamente purgados"
  echo "   • Usuários e grupos removidos"
  echo "   • Binários manuais removidos"
  echo "   • Configurações e dados apagados"
  echo "   • Configurações de rede limpas"
  echo "   • DNS restaurado ao padrão"
  echo "   • Logs e cron jobs limpos"
  echo ""
  echo "🚀 Sistema completamente limpo e pronto para nova instalação!"

  whiptail_msg "✅ Purga completa finalizada com sucesso!

O sistema foi completamente limpo:
• Todos os serviços BoxServer removidos
• Pacotes purgados com configurações
• Dados e logs apagados
• Configurações de rede restauradas
• DNS restaurado ao padrão

O sistema está pronto para uma instalação limpa."

  # Executar verificação pós-purga
  verify_purge_completion
}

# =========================
# Verificação pós-purga
# =========================
verify_purge_completion() {
  echo "🔍 Executando verificação pós-purga..."
  local issues_found=false

  # Verificar serviços ativos
  local active_services=()
  for service in "pihole-ftl" "unbound" "wg-quick@wg0" "lighttpd" "cloudflared" "minidlna" "filebrowser"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
      active_services+=("$service")
    fi
  done

  if [ ${#active_services[@]} -gt 0 ]; then
    echo "   ⚠️ Serviços ainda ativos: ${active_services[*]}"
    issues_found=true
  else
    echo "   ✅ Nenhum serviço BoxServer ativo"
  fi

  # Verificar pacotes instalados
  local remaining_packages=()
  for pkg in "pihole-ftl" "unbound" "wireguard" "minidlna"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      remaining_packages+=("$pkg")
    fi
  done

  if [ ${#remaining_packages[@]} -gt 0 ]; then
    echo "   ⚠️ Pacotes ainda instalados: ${remaining_packages[*]}"
    issues_found=true
  else
    echo "   ✅ Pacotes BoxServer removidos"
  fi

  # Verificar diretórios de configuração
  local remaining_dirs=()
  for dir in "/etc/pihole" "/etc/unbound" "/etc/wireguard" "/srv/boxserver-dashboard"; do
    if [ -d "$dir" ]; then
      remaining_dirs+=("$dir")
    fi
  done

  if [ ${#remaining_dirs[@]} -gt 0 ]; then
    echo "   ⚠️ Diretórios ainda existem: ${remaining_dirs[*]}"
    issues_found=true
  else
    echo "   ✅ Diretórios de configuração removidos"
  fi

  # Verificar interfaces virtuais
  local remaining_interfaces=()
  for iface in "wg0" "wg1"; do
    if ip link show "$iface" >/dev/null 2>&1; then
      remaining_interfaces+=("$iface")
    fi
  done

  if [ ${#remaining_interfaces[@]} -gt 0 ]; then
    echo "   ⚠️ Interfaces virtuais ainda existem: ${remaining_interfaces[*]}"
    issues_found=true
  else
    echo "   ✅ Interfaces virtuais removidas"
  fi

  # Verificar processos
  local remaining_processes
  remaining_processes=$(pgrep -f "(pihole|unbound|wireguard|cloudflared)" 2>/dev/null | wc -l || echo "0")

  if [ "$remaining_processes" -gt 0 ]; then
    echo "   ⚠️ $remaining_processes processos BoxServer ainda rodando"
    pgrep -f "(pihole|unbound|wireguard|cloudflared)" 2>/dev/null | head -5 | sed 's/^/      PID: /'
    issues_found=true
  else
    echo "   ✅ Nenhum processo BoxServer rodando"
  fi

  # Resultado final
  if [ "$issues_found" = false ]; then
    echo "✅ Verificação pós-purga: SISTEMA COMPLETAMENTE LIMPO"
  else
    echo "⚠️ Verificação pós-purga: Alguns itens podem precisar de limpeza manual"
    echo "   Execute novamente com --clean ou remova manualmente os itens listados"
  fi
}


# =========================
# Configuração IP fixo
# =========================
ask_static_ip() {
  NET_IF=$(detect_interface)
  local current_ip
  current_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [ -z "$current_ip" ] && current_ip="$DEFAULT_IP"

  if [ "$SILENT_MODE" = false ]; then
    STATIC_IP=$(whiptail --inputbox "Informe o IP fixo para este servidor:" 10 68 "$current_ip" 3>&1 1>&2 2>&3)
  else
    STATIC_IP="$current_ip"
  fi

  [ -z "$STATIC_IP" ] && STATIC_IP="$DEFAULT_IP"

  GATEWAY=$(ip route | awk '/^default/ {print $3; exit}' || true)
  [ -z "$GATEWAY" ] && GATEWAY="192.168.0.1"

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
    sudo netplan apply || echo "⚠️ Falha ao aplicar netplan, configure manualmente."
    SUMMARY_ENTRIES+=("IP Fixo: $STATIC_IP (interface $NET_IF)")
  else
    SUMMARY_ENTRIES+=("IP Fixo solicitado: $STATIC_IP (configure manualmente)")
  fi
}

# =========================
# Seleção de serviços
# =========================
choose_services() {
  if [ "$SILENT_MODE" = false ]; then
    CHOICES=$(whiptail --title "Seleção de Componentes" --checklist \
    "Selecione os serviços a instalar:" 20 80 12 \
    "UNBOUND" "Unbound DNS recursivo" ON \
    "PIHOLE" "Pi-hole (8081/8443)" ON \
    "WIREGUARD" "VPN WireGuard" ON \
    "CLOUDFLARE" "Cloudflared tunnel" ON \
    "RNG" "rng-tools" ON \
    "SAMBA" "Samba share" ON \
    "MINIDLNA" "MiniDLNA media" ON \
    "FILEBROWSER" "Filebrowser" ON \
    "DASHBOARD" "Dashboard web (nginx)" ON \
    3>&1 1>&2 2>&3)
    CHOICES="${CHOICES//\"/}"
  else
    # Modo silencioso - instala todos os serviços
    CHOICES="UNBOUND PIHOLE WIREGUARD CLOUDFLARE RNG SAMBA MINIDLNA FILEBROWSER DASHBOARD"
  fi
}

# =========================
# Funções de atualização
# =========================
update_services() {
  echo "Atualizando serviços..."

  # Atualizar Pi-hole
  if command -v pihole &> /dev/null; then
    echo "Atualizando Pi-hole..."
    sudo pihole -up
  fi

  # Atualizar Unbound
  if dpkg -l | grep -q "^ii.*unbound"; then
    echo "Atualizando Unbound..."
    sudo apt-get update
    sudo apt-get install --only-upgrade -y unbound
  fi

  # Atualizar Filebrowser
  if command -v filebrowser &> /dev/null; then
    echo "Atualizando Filebrowser..."
    FB_VERSION=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | grep tag_name | cut -d '"' -f4)
    ARCH=$(detect_arch)
    case "$ARCH" in
      amd64) FB_ARCH="linux-amd64";;
      arm64) FB_ARCH="linux-arm64";;
      arm) FB_ARCH="linux-armv7";;
      *) echo "Arquitetura não suportada pelo Filebrowser"; return;;
    esac

    if wget -O filebrowser.tar.gz https://github.com/filebrowser/filebrowser/releases/download/${FB_VERSION}/${FB_ARCH}-filebrowser.tar.gz; then
      tar -xzf filebrowser.tar.gz
      sudo mv filebrowser /usr/local/bin/
      rm -f filebrowser.tar.gz
      sudo systemctl restart filebrowser
    fi
  fi

  # Atualizar Cloudflared
  if command -v cloudflared &> /dev/null; then
    echo "Atualizando Cloudflared..."
    ARCH=$(detect_arch)
    URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
    if sudo wget -O /usr/local/bin/cloudflared "$URL"; then
      sudo chmod +x /usr/local/bin/cloudflared
      sudo systemctl restart cloudflared
    fi
  fi

  echo "Atualização concluída."
}

# =========================
# Função de diagnóstico WireGuard
# =========================
diagnose_wireguard() {
  echo_msg "🔍 Executando diagnóstico completo do WireGuard..."

  # 1. Verificar se o serviço existe
  if ! systemctl list-units --type=service --all | grep -q "wg-quick@wg0"; then
    echo_msg "❌ Serviço wg-quick@wg0 não encontrado"
    return 1
  fi

  # 2. Status detalhado do serviço
  echo_msg "📊 Status do serviço:"
  sudo systemctl status wg-quick@wg0 --no-pager | sed 's/^/   /'

  # 3. Logs recentes
  echo_msg "📝 Logs recentes (últimas 10 linhas):"
  sudo journalctl -u wg-quick@wg0 --no-pager -n 10 | sed 's/^/   /'

  # 4. Verificar configuração
  echo_msg "⚙️ Verificando configuração:"
  if [ -f /etc/wireguard/wg0.conf ]; then
    echo_msg "   Arquivo de configuração existe"
    if sudo wg-quick strip wg0 >/dev/null 2>&1; then
      echo_msg "   ✅ Configuração válida"
    else
      echo_msg "   ❌ Configuração inválida"
      echo_msg "   Conteúdo:"
      sudo cat /etc/wireguard/wg0.conf | sed 's/^/      /'
    fi
  else
    echo_msg "   ❌ Arquivo /etc/wireguard/wg0.conf não encontrado"
  fi

  # 5. Verificar módulo do kernel
  echo_msg "🔧 Módulo do kernel:"
  if lsmod | grep -q wireguard; then
    echo_msg "   ✅ Módulo wireguard carregado"
  else
    echo_msg "   ❌ Módulo wireguard não carregado"
    echo_msg "   Tentando carregar..."
    if sudo modprobe wireguard 2>/dev/null; then
      echo_msg "   ✅ Módulo carregado com sucesso"
    else
      echo_msg "   ❌ Falha ao carregar módulo"
    fi
  fi

  # 6. Verificar interface
  echo_msg "🌐 Interface de rede:"
  if ip link show wg0 >/dev/null 2>&1; then
    echo_msg "   ✅ Interface wg0 existe"
    ip addr show wg0 | sed 's/^/      /'
  else
    echo_msg "   ❌ Interface wg0 não existe"
  fi

  # 7. Verificar portas
  echo_msg "🔌 Portas de rede:"
  if sudo netstat -ulpn | grep -q wireguard; then
    echo_msg "   Portas WireGuard em uso:"
    sudo netstat -ulpn | grep wireguard | sed 's/^/      /'
  else
    echo_msg "   ❌ Nenhuma porta WireGuard detectada"
  fi

  # 8. IP Forwarding
  echo_msg "🔄 IP Forwarding:"
  if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
    echo_msg "   ✅ IP forwarding habilitado"
  else
    echo_msg "   ❌ IP forwarding desabilitado"
  fi

  # 9. Teste manual
  echo_msg "🧪 Teste de inicialização manual:"
  echo_msg "   Executando 'wg-quick up wg0'..."
  sudo wg-quick up wg0 2>&1 | sed 's/^/      /' || true
}

# =========================
# Funções de instalação
# =========================
install_unbound() {
  echo_msg "Instalando/reconfigurando Unbound otimizado para RK322x..."
  SUMMARY_ENTRIES+=("Unbound DNS: Porta $UNBOUND_PORT")

  if ! dpkg -s "unbound" >/dev/null 2>&1; then
    echo_msg "Instalando Unbound..."
    sudo apt install -y unbound
  fi

  sudo mkdir -p /etc/unbound/unbound.conf.d /var/lib/unbound

  backup_file /etc/unbound/unbound.conf.d/pi-hole.conf

  # Configuração otimizada para kernel 4.4.194-rk322x e dispositivos ARM de baixa potência
  local cache_size="64m"
  local msg_cache="32m"
  local threads=1

  # Ajustar para dispositivos com pouca memória
  if [ "${LOW_MEMORY:-false}" = "true" ]; then
    cache_size="32m"
    msg_cache="16m"
    echo_msg "   Ajustando configurações para baixa memória"
  fi

  cat <<EOF | sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    # Configurações básicas otimizadas para RK322x
    verbosity: 1
    interface: 127.0.0.1
    port: $UNBOUND_PORT
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no

    # Otimizações para Pi-hole
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    harden-algo-downgrade: no
    use-caps-for-id: no

    # Performance otimizada para ARM RK322x
    edns-buffer-size: 1232
    prefetch: yes
    prefetch-key: yes
    rrset-roundrobin: yes
    minimal-responses: yes

    # Threading otimizado para RK322x (single core focus)
    num-threads: $threads
    msg-cache-slabs: 4
    rrset-cache-slabs: 4
    infra-cache-slabs: 4
    key-cache-slabs: 4
    rrset-cache-size: $cache_size
    msg-cache-size: $msg_cache
    so-rcvbuf: 256k
    so-sndbuf: 256k

    # Timeouts ajustados para conexões ARM mais lentas
    infra-host-ttl: 900
    infra-cache-numhosts: 1000

    # Redes privadas
    private-address: 192.168.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10

    # DNSSEC otimizado para kernel 4.4
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no
    val-log-level: 1

    # Root hints
    root-hints: "/var/lib/unbound/root.hints"

    # Logging otimizado
    log-queries: no
    log-replies: no
    logfile: ""
    use-syslog: yes

    # Access control (apenas localhost)
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse

    # Security
    hide-identity: yes
    hide-version: yes

    # Reduce SERVFAIL responses
    serve-expired: yes
    serve-expired-ttl: 3600

    # Otimizações específicas para RK322x
    outgoing-range: 256
    num-queries-per-thread: 512
    jostle-timeout: 200
EOF

  # Baixar root hints se não existir ou estiver desatualizado (mais de 30 dias)
  if [ ! -f /var/lib/unbound/root.hints ] || [ $(find /var/lib/unbound/root.hints -mtime +30 2>/dev/null | wc -l) -gt 0 ]; then
    echo_msg "Baixando/atualizando root hints do DNS..."
    sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root || {
      echo_msg "⚠️ Falha ao baixar root hints, usando cache antigo se disponível"
    }
  fi

  # Configurar DNSSEC root key de forma robusta
  if [ ! -f /var/lib/unbound/root.key ]; then
    echo_msg "Configurando DNSSEC root key..."
    sudo unbound-anchor -a /var/lib/unbound/root.key || {
      echo_msg "⚠️ unbound-anchor falhou, criando root key alternativo..."
      # Criar um root key básico se unbound-anchor falhar
      sudo tee /var/lib/unbound/root.key > /dev/null << 'EOF'
; DNSSEC root key
. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
EOF
    }
  fi

  # Verificar se o root key está válido
  if ! sudo unbound-anchor -l | grep -q "root key"; then
    echo_msg "⚠️ Root key pode estar inválido, mas continuando..."
  fi

  # Garante permissões corretas e estrutura de diretórios
  sudo chown -R unbound:unbound /var/lib/unbound
  sudo chmod 644 /var/lib/unbound/root.* 2>/dev/null || true
  sudo chmod 755 /var/lib/unbound

  # Criar diretórios de cache se necessário
  sudo mkdir -p /var/lib/unbound/cache
  sudo chown unbound:unbound /var/lib/unbound/cache

  # Verifica a configuração antes de reiniciar
  if sudo unbound-checkconf; then
    echo "Configuração do Unbound verificada com sucesso."
    sudo systemctl enable unbound
    sudo systemctl restart unbound
    sleep 2 # Aguarda um momento para estabilização
  else
    echo_msg "❌ Erro na configuração do Unbound. O serviço não será iniciado."
    return 1
  fi

  # Verificação final e teste de integração
  if sudo systemctl is-active --quiet unbound; then
    echo_msg "✅ Unbound em execução, testando resolução DNS..."

    # Teste básico de resolução DNS
    if nslookup google.com 127.0.0.1#$UNBOUND_PORT >/dev/null 2>&1; then
      echo_msg "✅ Unbound instalado/reconfigurado e funcionando perfeitamente"
      echo_msg "   Pronto para integração com Pi-hole em 127.0.0.1:$UNBOUND_PORT"
    else
      echo_msg "⚠️ Unbound está rodando mas não responde a consultas DNS"
      echo_msg "   Verifique a configuração: sudo unbound-checkconf"
    fi
  else
    echo_msg "⚠️ Unbound instalado/reconfigurado mas não está em execução"
    echo_msg "   Logs: sudo journalctl -u unbound --no-pager -n 10"

    # Tentar mostrar o erro específico
    if sudo journalctl -u unbound --no-pager -n 5 | grep -i error; then
      echo_msg "   Erros detectados nos logs acima ↑"
    fi
  fi
}

install_pihole() {
  echo_msg "Instalando/reconfigurando Pi-hole otimizado para RK322x..."
  SUMMARY_ENTRIES+=("Pi-hole: Portas $PIHOLE_HTTP_PORT/$PIHOLE_HTTPS_PORT (RK322x)")

  # Verificar se as portas do Pi-hole estão livres antes de instalar
  echo_msg "Verificando disponibilidade das portas do Pi-hole..."
  if sudo netstat -tln | grep -q ":$PIHOLE_HTTP_PORT "; then
    echo_msg "❌ Porta $PIHOLE_HTTP_PORT já está em uso. Pi-hole não pode ser instalado."
    echo_msg "   Processo usando a porta:"
    sudo netstat -tlnp | grep ":$PIHOLE_HTTP_PORT " | sed 's/^/   /'
    return 1
  fi

  if sudo netstat -tln | grep -q ":53 "; then
    echo_msg "❌ Porta 53 (DNS) já está em uso. Pi-hole não pode ser instalado."
    echo_msg "   Processo usando a porta:"
    sudo netstat -tlnp | grep ":53 " | sed 's/^/   /'

    # Verificar se é systemd-resolved
    if systemctl is-active --quiet systemd-resolved; then
      echo_msg "⚠️  systemd-resolved detectado. Tentando desabilitá-lo..."
      sudo systemctl disable --now systemd-resolved

      # Remover link simbólico do resolv.conf se existir
      if [ -L /etc/resolv.conf ]; then
        sudo rm /etc/resolv.conf
      fi

      # Criar um resolv.conf temporário
      echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
      echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf

      # Verificar novamente se a porta está livre
      sleep 2
      if sudo netstat -tln | grep -q ":53 "; then
        echo_msg "❌ Porta 53 ainda está em uso mesmo após desabilitar systemd-resolved."
        return 1
      else
        echo_msg "✅ systemd-resolved desabilitado, porta 53 agora está livre."
      fi
    else
      return 1
    fi
  fi

  # Verificar se Unbound está rodando antes de instalar Pi-hole
  echo_msg "Verificando se Unbound está disponível para integração..."
  if ! sudo systemctl is-active --quiet unbound; then
    echo_msg "❌ Unbound não está rodando. Pi-hole precisa do Unbound como DNS upstream."
    echo_msg "   Tentando iniciar Unbound..."
    sudo systemctl start unbound || {
      echo_msg "❌ Falha ao iniciar Unbound. Instale Unbound primeiro."
      return 1
    }
    sleep 3
  fi

  # Testar se Unbound está respondendo
  if ! nslookup google.com 127.0.0.1#$UNBOUND_PORT >/dev/null 2>&1; then
    echo_msg "❌ Unbound não está respondendo em 127.0.0.1:$UNBOUND_PORT"
    echo_msg "   Pi-hole não pode ser configurado sem um DNS upstream funcional."
    return 1
  fi
  echo_msg "✅ Unbound está funcionando. Prosseguindo com instalação do Pi-hole..."

  # Se o Pi-hole não estiver instalado, prepara e executa a instalação não interativa
  if ! command -v pihole &> /dev/null; then
    echo_msg "Preparando para instalação não interativa do Pi-hole v6 otimizada para RK322x..."

    sudo mkdir -p /etc/pihole
    # Configuração otimizada para kernel 4.4.194-rk322x
    cat <<EOF | sudo tee /etc/pihole/setupVars.conf
PIHOLE_INTERFACE=$NET_IF
IPV4_ADDRESS=$STATIC_IP
PIHOLE_DNS_1=127.0.0.1#$UNBOUND_PORT
PIHOLE_DNS_2=
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
WEB_PORT=$PIHOLE_HTTP_PORT
WEBPASSWORD=
DNSSEC=false
# Otimizações RK322x
BLOCKING_ENABLED=true
REV_SERVER=false
# Cache reduzido para ARM
CACHE_SIZE=1000
# Log reduzido para economizar I/O
MAXDBDAYS=2
EOF

    echo_msg "Executando instalador do Pi-hole otimizado para ARM..."
    # O instalador irá ler o setupVars.conf
    if ! curl -sSL --max-time 120 https://install.pi-hole.net | sudo bash /dev/stdin --unattended; then
      echo_msg "❌ Falha na instalação do Pi-hole."
      return 1
    fi

    # Aguardar inicialização completa (mais tempo para ARM)
    echo_msg "Aguardando inicialização completa dos serviços do Pi-hole em RK322x..."
    sleep 15

    # Verificar se a instalação foi bem-sucedida
    if ! command -v pihole &> /dev/null; then
      echo_msg "❌ Pi-hole não foi instalado corretamente."
      return 1
    fi
  else
    echo_msg "Pi-hole já está instalado. Reconfigurando para otimização RK322x..."
    # Para instalações existentes, configura para usar apenas o Unbound local
    sudo pihole -a -i local -dns 127.0.0.1#$UNBOUND_PORT,

    # Aguardar um momento para aplicar as configurações
    sleep 5
  fi

  # --- Reconfiguração otimizada para RK322x ---

  # Garante que o DNS do Pi-hole aponte para o Unbound local
  sudo mkdir -p /etc/pihole
  if grep -q '^PIHOLE_DNS_1=' /etc/pihole/setupVars.conf; then
    sudo sed -i "s/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#$UNBOUND_PORT/" /etc/pihole/setupVars.conf
  else
    echo "PIHOLE_DNS_1=127.0.0.1#$UNBOUND_PORT" | sudo tee -a /etc/pihole/setupVars.conf
  fi

  # Garantir que não há DNS secundário configurado
  if grep -q '^PIHOLE_DNS_2=' /etc/pihole/setupVars.conf; then
    sudo sed -i "s/^PIHOLE_DNS_2=.*/PIHOLE_DNS_2=/" /etc/pihole/setupVars.conf
  else
    echo "PIHOLE_DNS_2=" | sudo tee -a /etc/pihole/setupVars.conf
  fi

  # Otimizações específicas para RK322x
  sudo sed -i 's/^CACHE_SIZE=.*/CACHE_SIZE=1000/' /etc/pihole/setupVars.conf 2>/dev/null || echo "CACHE_SIZE=1000" | sudo tee -a /etc/pihole/setupVars.conf
  sudo sed -i 's/^MAXDBDAYS=.*/MAXDBDAYS=2/' /etc/pihole/setupVars.conf 2>/dev/null || echo "MAXDBDAYS=2" | sudo tee -a /etc/pihole/setupVars.conf

  # Configurar lighttpd com otimizações ARM
  if [ -f /etc/lighttpd/lighttpd.conf ]; then
    backup_file /etc/lighttpd/lighttpd.conf
    sudo sed -i "s/server.port\s*=\s*80/server.port = $PIHOLE_HTTP_PORT/" /etc/lighttpd/lighttpd.conf

    # Adicionar otimizações RK322x ao lighttpd
    if ! grep -q "# RK322x optimizations" /etc/lighttpd/lighttpd.conf; then
      cat <<EOF | sudo tee -a /etc/lighttpd/lighttpd.conf
# RK322x optimizations
server.max-connections = 128
server.max-fds = 256
server.max-worker = 1
server.stat-cache-engine = "simple"
server.network-backend = "linux-sendfile"
EOF
    fi
  fi

  # Configuração SSL otimizada
  sudo mkdir -p /etc/lighttpd
  backup_file /etc/lighttpd/external.conf
  cat <<EOF | sudo tee /etc/lighttpd/external.conf
# Configuração SSL otimizada para RK322x
\$SERVER["socket"] == ":$PIHOLE_HTTPS_PORT" {
    ssl.engine = "enable"
    ssl.cipher-list = "ECDHE+AESGCM:ECDHE+AES256:ECDHE+AES128:!aNULL:!MD5:!DSS"
    ssl.honor-cipher-order = "enable"
    ssl.disable-client-renegotiation = "enable"
}
EOF

  # Reiniciar DNS do Pi-hole
  echo_msg "Reiniciando DNS do Pi-hole para aplicar configurações RK322x..."
  sudo pihole restartdns

  # Verificação final detalhada
  echo_msg "Verificando status dos serviços do Pi-hole em RK322x..."

  # Verificar pihole-ftl
  if sudo systemctl is-active --quiet pihole-ftl; then
    echo_msg "✅ pihole-ftl está rodando"
    pihole_ftl_ok=true
  else
    echo_msg "❌ pihole-ftl não está rodando"
    echo_msg "   Status: $(sudo systemctl is-active pihole-ftl)"
    echo_msg "   Logs recentes:"
    sudo journalctl -u pihole-ftl --no-pager -n 5 | sed 's/^/   /'
    pihole_ftl_ok=false
  fi

  # Verificar lighttpd
  if systemctl list-units --type=service | grep -q lighttpd; then
    if sudo systemctl is-active --quiet lighttpd; then
      echo_msg "✅ lighttpd está rodando"
      lighttpd_ok=true
    else
      echo_msg "❌ lighttpd não está rodando"
      lighttpd_ok=false
    fi
  else
    echo_msg "ℹ️  lighttpd não encontrado"
    lighttpd_ok=true
  fi

  # Teste DNS via Pi-hole
  if nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
    echo_msg "✅ Pi-hole DNS está respondendo"
    dns_ok=true
  else
    echo_msg "❌ Pi-hole DNS não está respondendo"
    dns_ok=false
  fi

  # Teste DNS via Unbound
  if nslookup google.com 127.0.0.1#$UNBOUND_PORT >/dev/null 2>&1; then
    echo_msg "✅ Unbound DNS está respondendo"
    unbound_ok=true
  else
    echo_msg "❌ Unbound DNS não está respondendo"
    unbound_ok=false
  fi

  # Resultado final
  if [ "$pihole_ftl_ok" = true ] && [ "$lighttpd_ok" = true ] && [ "$dns_ok" = true ] && [ "$unbound_ok" = true ]; then
    echo_msg "✅ Pi-hole + Unbound otimizados para RK322x funcionando completamente."
    echo_msg "   Interface web: http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin"
    echo_msg "   DNS Pipeline: Clientes → Pi-hole (porta 53) → Unbound (porta $UNBOUND_PORT) → Internet"
    echo_msg "   Otimizações: Cache reduzido, logs limitados, lighttpd otimizado"
  elif [ "$pihole_ftl_ok" = true ] && [ "$dns_ok" = true ] && [ "$unbound_ok" = true ]; then
    echo_msg "✅ Pi-hole + Unbound DNS funcionando, interface web pode ter problemas."
  else
    echo_msg "❌ Pi-hole com problemas. Execute diagnósticos específicos para RK322x."
  fi
}

install_wireguard() {
  echo_msg "Verificando compatibilidade WireGuard com kernel RK322x..."

  # Verificar se VPN foi desabilitada por incompatibilidade
  if [ "${DISABLE_VPN:-false}" = "true" ]; then
    echo_msg "⚠️ VPN desabilitada devido a incompatibilidade do kernel RK322x"
    echo_msg "   Instalando WireGuard em modo userspace como alternativa..."
    install_wireguard_userspace
    return $?
  fi

  echo_msg "Instalando/reconfigurando WireGuard para kernel 4.4.194-rk322x..."
  SUMMARY_ENTRIES+=("WireGuard: Porta UDP $WG_PORT")

  # === PRÉ-VERIFICAÇÕES CRÍTICAS PARA RK322x ===

  # 1. Verificar compatibilidade do kernel 4.4 com WireGuard
  local kernel_version=$(uname -r)
  echo_msg "Verificando compatibilidade kernel $kernel_version com WireGuard..."

  # Kernel 4.4 requer WireGuard DKMS ou backport
  if [[ "$kernel_version" == *"4.4"* ]]; then
    echo_msg "   Kernel 4.4 detectado - tentando instalação via DKMS..."
    sudo apt update
    sudo apt install -y dkms build-essential linux-headers-$(uname -r) || {
      echo_msg "❌ Falha ao instalar dependências DKMS. Tentando alternativa userspace..."
      install_wireguard_userspace
      return $?
    }
  fi

  # 2. Tentar carregar módulo WireGuard
  if ! sudo modprobe wireguard 2>/dev/null; then
    echo_msg "⚠️ Módulo WireGuard nativo não disponível"
    echo_msg "   Tentando instalação do wireguard-dkms..."

    if ! sudo apt install -y wireguard-dkms 2>/dev/null; then
      echo_msg "⚠️ DKMS falhou. Usando implementação userspace..."
      install_wireguard_userspace
      return $?
    fi

    # Tentar carregar novamente após DKMS
    if ! sudo modprobe wireguard 2>/dev/null; then
      echo_msg "⚠️ Módulo DKMS falhou. Usando userspace..."
      install_wireguard_userspace
      return $?
    fi
  fi

  echo_msg "✅ Módulo WireGuard carregado com sucesso"

  # 2. Verificar conflito de porta
  echo_msg "Verificando conflito de porta UDP $WG_PORT..."
  if sudo netstat -ulpn | grep -q ":$WG_PORT "; then
    echo_msg "❌ Porta UDP $WG_PORT já está em uso:"
    sudo netstat -ulpn | grep ":$WG_PORT " | sed 's/^/   /'
    echo_msg "   Escolhendo próxima porta disponível..."

    local original_port=$WG_PORT
    while sudo netstat -ulpn | grep -q ":$WG_PORT "; do
      WG_PORT=$((WG_PORT + 1))
    done
    echo_msg "   Nova porta WireGuard: $WG_PORT (era $original_port)"
  fi

  # 3. Verificar interface de rede
  echo_msg "Verificando interface de rede $NET_IF..."
  if ! ip link show "$NET_IF" >/dev/null 2>&1; then
    echo_msg "❌ Interface $NET_IF não encontrada"
    echo_msg "   Interfaces disponíveis:"
    ip link show | grep -E '^[0-9]+:' | sed 's/^/   /'

    # Tentar detectar interface padrão
    NEW_NET_IF=$(ip route | awk '/^default/ {print $5; exit}')
    if [ -n "$NEW_NET_IF" ]; then
      echo_msg "   Usando interface padrão: $NEW_NET_IF"
      NET_IF="$NEW_NET_IF"
    else
      echo_msg "❌ Não foi possível detectar interface de rede válida"
      return 1
    fi
  else
    echo_msg "✅ Interface $NET_IF está disponível"
  fi

  # 4. Verificar dependências
  echo_msg "Verificando/instalando dependências do WireGuard..."
  local missing_deps=()

  for pkg in iptables iproute2 wireguard-tools; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing_deps+=("$pkg")
    fi
  done

  if [ ${#missing_deps[@]} -gt 0 ]; then
    echo_msg "Instalando dependências: ${missing_deps[*]}"
    sudo apt update
    sudo apt install -y "${missing_deps[@]}" || {
      echo_msg "❌ Falha ao instalar dependências"
      return 1
    }
  fi

  # Verificar se WireGuard já está instalado
  if dpkg -l | grep -q "^ii.*wireguard"; then
    echo_msg "WireGuard já está instalado. Reconfigurando..."

    # Parar serviço existente para reconfiguração limpa
    if sudo systemctl is-active --quiet wg-quick@wg0; then
      echo_msg "Parando WireGuard existente..."
      sudo systemctl stop wg-quick@wg0
    fi
  else
    echo_msg "Instalando WireGuard..."
    sudo apt install -y wireguard wireguard-tools || {
      echo_msg "❌ Falha ao instalar pacotes do WireGuard"
      return 1
    }
  fi

  # === CONFIGURAÇÃO DE CHAVES ===

  sudo mkdir -p /etc/wireguard/keys
  sudo chmod 700 /etc/wireguard/keys
  umask 077

  # Verificar se as chaves já existem e são válidas
  if [ -f /etc/wireguard/keys/privatekey ] && [ -f /etc/wireguard/keys/publickey ]; then
    echo_msg "Chaves WireGuard existentes encontradas. Verificando validade..."

    # Verificar se a chave privada é válida
    if ! wg pubkey < /etc/wireguard/keys/privatekey >/dev/null 2>&1; then
      echo_msg "⚠️ Chave privada inválida. Gerando novas chaves..."
      rm -f /etc/wireguard/keys/privatekey /etc/wireguard/keys/publickey
    else
      echo_msg "✅ Chaves existentes são válidas"
    fi
  fi

  # Gerar chaves se não existirem ou forem inválidas
  if [ ! -f /etc/wireguard/keys/privatekey ] || [ ! -f /etc/wireguard/keys/publickey ]; then
    echo_msg "Gerando novas chaves WireGuard..."
    wg genkey | sudo tee /etc/wireguard/keys/privatekey | wg pubkey | sudo tee /etc/wireguard/keys/publickey

    # Verificar se as chaves foram geradas corretamente
    if [ ! -s /etc/wireguard/keys/privatekey ] || [ ! -s /etc/wireguard/keys/publickey ]; then
      echo_msg "❌ Falha ao gerar chaves WireGuard"
      return 1
    fi
  fi

  WG_PRIVATE=$(sudo cat /etc/wireguard/keys/privatekey)
  WG_PUBLIC=$(sudo cat /etc/wireguard/keys/publickey)

  # === CONFIGURAÇÃO DA INTERFACE ===

  backup_file /etc/wireguard/wg0.conf
  echo_msg "Criando configuração WireGuard..."

  # Verificar se já existe interface wg0 ativa
  if ip link show wg0 >/dev/null 2>&1; then
    echo_msg "Interface wg0 já existe. Removendo..."
    sudo ip link delete wg0 2>/dev/null || true
  fi

  cat <<EOF | sudo tee /etc/wireguard/wg0.conf
[Interface]
PrivateKey = $WG_PRIVATE
Address = 10.200.200.1/24
ListenPort = $WG_PORT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_IF -j MASQUERADE
EOF

  sudo chmod 600 /etc/wireguard/wg0.conf

  # === CONFIGURAÇÃO DO SISTEMA ===

  # Habilitar IP forwarding
  echo_msg "Configurando IP forwarding..."
  if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
  else
    sudo sed -i 's/^#*net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  fi
  sudo sysctl -p >/dev/null

  # Verificar configuração antes de iniciar
  echo_msg "Validando configuração WireGuard..."
  if ! sudo wg-quick strip wg0 >/dev/null 2>&1; then
    echo_msg "❌ Configuração WireGuard inválida"
    echo_msg "   Conteúdo de /etc/wireguard/wg0.conf:"
    sudo cat /etc/wireguard/wg0.conf | sed 's/^/   /'
    return 1
  fi

  # === INICIALIZAÇÃO DO SERVIÇO ===

  echo_msg "Habilitando e iniciando WireGuard..."

  # Habilitar serviço
  sudo systemctl enable wg-quick@wg0 || {
    echo_msg "❌ Falha ao habilitar serviço wg-quick@wg0"
    return 1
  }

  # Iniciar serviço
  echo_msg "Iniciando WireGuard..."
  if ! sudo systemctl start wg-quick@wg0; then
    echo_msg "❌ Falha ao iniciar WireGuard. Analisando logs..."

    # Diagnóstico detalhado
    echo_msg "   Status do serviço:"
    sudo systemctl status wg-quick@wg0 --no-pager | sed 's/^/   /'

    echo_msg "   Logs recentes:"
    sudo journalctl -u wg-quick@wg0 --no-pager -n 10 | sed 's/^/   /'

    echo_msg "   Tentando inicialização manual para diagnóstico:"
    sudo wg-quick up wg0 2>&1 | sed 's/^/   /' || true

    return 1
  fi

  # === VERIFICAÇÕES FINAIS ===

  # Aguardar estabilização
  sleep 3

  # Verificar se o serviço está realmente ativo
  if sudo systemctl is-active --quiet wg-quick@wg0; then
    echo_msg "✅ Serviço WireGuard ativo"
    service_ok=true
  else
    echo_msg "❌ Serviço WireGuard inativo"
    service_ok=false
  fi

  # Verificar se a interface foi criada
  if ip link show wg0 >/dev/null 2>&1; then
    echo_msg "✅ Interface wg0 criada"
    interface_ok=true
  else
    echo_msg "❌ Interface wg0 não foi criada"
    interface_ok=false
  fi

  # Verificar se a porta está listening
  if sudo netstat -ulpn | grep -q ":$WG_PORT "; then
    echo_msg "✅ WireGuard escutando na porta UDP $WG_PORT"
    port_ok=true
  else
    echo_msg "❌ WireGuard não está escutando na porta UDP $WG_PORT"
    port_ok=false
  fi

  # Verificar status com wg
  if sudo wg show >/dev/null 2>&1; then
    echo_msg "✅ Comando 'wg show' funcional"
    wg_cmd_ok=true

    # Mostrar informações da interface
    echo_msg "   Informações da interface wg0:"
    sudo wg show wg0 | sed 's/^/   /'
  else
    echo_msg "❌ Comando 'wg show' falhou"
    wg_cmd_ok=false
  fi

  # Resultado final
  if [ "$service_ok" = true ] && [ "$interface_ok" = true ] && [ "$port_ok" = true ] && [ "$wg_cmd_ok" = true ]; then
    echo_msg "✅ WireGuard instalado/reconfigurado e funcionando completamente"
    echo_msg "   Porta UDP: $WG_PORT"
    echo_msg "   Rede VPN: 10.200.200.1/24"
    echo_msg "   Chave pública: $WG_PUBLIC"
    echo_msg "   Configuração: /etc/wireguard/wg0.conf"
  else
    echo_msg "❌ WireGuard instalado mas com problemas. Diagnósticos:"
    echo_msg ""
    echo_msg "   1. Verificar status detalhado:"
    echo_msg "      sudo systemctl status wg-quick@wg0"
    echo_msg "      sudo journalctl -u wg-quick@wg0 -f"
    echo_msg ""
    echo_msg "   2. Testar configuração manualmente:"
    echo_msg "      sudo wg-quick down wg0"
    echo_msg "      sudo wg-quick up wg0"
    echo_msg ""
    echo_msg "   3. Verificar interface e routing:"
    echo_msg "      ip addr show wg0"
    echo_msg "      ip route show"
    echo_msg "      sudo wg show"
    echo_msg ""
    echo_msg "   4. Verificar iptables e forwarding:"
    echo_msg "      sudo iptables -L -n"
    echo_msg "      cat /proc/sys/net/ipv4/ip_forward"
    echo_msg ""
    echo_msg "   5. Verificar módulo do kernel:"
    echo_msg "      lsmod | grep wireguard"
    echo_msg "      sudo modprobe wireguard"
  fi
}

# Implementação alternativa WireGuard userspace para RK322x
install_wireguard_userspace() {
  echo_msg "Instalando WireGuard userspace para compatibilidade RK322x..."

  # Instalar wireguard-tools apenas (userspace)
  sudo apt install -y wireguard-tools

  # Configurar da mesma forma, mas aviso sobre performance
  sudo mkdir -p /etc/wireguard/keys
  sudo chmod 700 /etc/wireguard/keys
  umask 077

  if [ ! -f /etc/wireguard/keys/privatekey ] || [ ! -f /etc/wireguard/keys/publickey ]; then
    echo_msg "Gerando chaves WireGuard..."
    wg genkey | sudo tee /etc/wireguard/keys/privatekey | wg pubkey | sudo tee /etc/wireguard/keys/publickey
  fi

  WG_PRIVATE=$(sudo cat /etc/wireguard/keys/privatekey)
  WG_PUBLIC=$(sudo cat /etc/wireguard/keys/publickey)

  backup_file /etc/wireguard/wg0.conf
  cat <<EOF | sudo tee /etc/wireguard/wg0.conf
[Interface]
PrivateKey = $WG_PRIVATE
Address = 10.200.200.1/24
ListenPort = $WG_PORT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_IF -j MASQUERADE

# AVISO: Rodando em modo userspace - performance reduzida em RK322x
EOF

  sudo chmod 600 /etc/wireguard/wg0.conf

  # Habilitar IP forwarding
  if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
  fi
  sudo sysctl -p >/dev/null

  echo_msg "⚠️ WireGuard configurado em modo userspace"
  echo_msg "   Performance pode ser reduzida comparado ao modo kernel"

  SUMMARY_ENTRIES+=("WireGuard (userspace): Porta UDP $WG_PORT")
  return 0
}

install_cloudflared() {
  echo_msg "Instalando/reconfigurando Cloudflare Tunnel para RK322x..."
  SUMMARY_ENTRIES+=("Cloudflared: Domínio $DOMAIN (requer autenticação manual)")
  # Verificar arquitetura específica do RK322x
  local arch_rk322x=""
  case "$(uname -m)" in
    armv7l) arch_rk322x="arm" ;;
    aarch64) arch_rk322x="arm64" ;;
    *)
      echo_msg "❌ Arquitetura $(uname -m) não suportada pelo Cloudflared em RK322x"
      return 1
      ;;
  esac

  echo_msg "   Baixando Cloudflared para arquitetura $arch_rk322x..."
  URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch_rk322x}"

  # Baixar e instalar cloudflared com verificação específica para ARM
  if sudo wget --timeout=60 -O /usr/local/bin/cloudflared "$URL"; then
    sudo chmod +x /usr/local/bin/cloudflared
    sudo mkdir -p /etc/cloudflared

    backup_file /etc/cloudflared/config.yml
    cat <<EOF | sudo tee /etc/cloudflared/config.yml
tunnel: boxserver
credentials-file: /etc/cloudflared/boxserver.json
ingress:
  - hostname: $DOMAIN
    service: http://localhost:$PIHOLE_HTTP_PORT
  - service: http_status:404
EOF

    # Criar serviço systemd para cloudflared
    backup_file /etc/systemd/system/cloudflared.service
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
    sudo systemctl enable cloudflared

    # Verificar se já existe autenticação
    if [ -f "/etc/cloudflared/boxserver.json" ]; then
      sudo systemctl start cloudflared
      if sudo systemctl is-active --quiet cloudflared; then
        echo_msg "✅ Cloudflare Tunnel instalado/reconfigurado e em execução"
      else
        echo_msg "⚠️  Cloudflare Tunnel configurado mas falhou ao iniciar. Verifique as credenciais."
      fi
    else
      # Modo interativo: guiar usuário através da autenticação
      if [ "$SILENT_MODE" = false ]; then
        whiptail_msg "🔐 Cloudflare Tunnel requer autenticação manual:\n\n1. Execute: sudo cloudflared tunnel login\n2. Siga as instruções no navegador\n3. Execute: sudo cloudflared tunnel create boxserver\n4. Execute: sudo systemctl start cloudflared"
      else
        echo_msg "⚠️  Cloudflare Tunnel instalado mas requer autenticação manual:"
        echo_msg "  1. Execute: sudo cloudflared tunnel login"
        echo_msg "  2. Siga as instruções no navegador"
        echo_msg "  3. Execute: sudo cloudflared tunnel create boxserver"
        echo_msg "  4. Execute: sudo systemctl start cloudflared"
      fi
    fi
  else
    echo_msg "❌ Falha ao baixar Cloudflare Tunnel"
  fi
}

install_rng() {
  echo_msg "Instalando/reconfigurando RNG-tools otimizado para RK322x..."
  SUMMARY_ENTRIES+=("RNG-tools: Configurado para RK322x")

  # Verificar se RNG-tools já está instalado
  if dpkg -l | grep -q "^ii.*rng-tools"; then
    echo_msg "RNG-tools já está instalado. Reconfigurando..."
  else
    echo_msg "Instalando RNG-tools..."
    sudo apt install -y rng-tools
  fi

  sudo mkdir -p /etc/default

  # Verificar fontes de entropia específicas do RK322x
  local rng_device="/dev/urandom"

  if [ -e /dev/hwrng ]; then
    rng_device="/dev/hwrng"
    echo_msg "   Hardware RNG detectado: /dev/hwrng"
  elif [ -e /dev/random ]; then
    echo_msg "   Usando /dev/random como fonte de entropia"
    rng_device="/dev/random"
  else
    echo_msg "   Usando /dev/urandom (padrão para RK322x)"
  fi

  backup_file /etc/default/rng-tools

  # Configuração otimizada para dispositivos ARM de baixa potência
  cat <<EOF | sudo tee /etc/default/rng-tools
# Configuração otimizada para RK322x (kernel 4.4.194)
RNGDEVICE="$rng_device"
# Parâmetros conservadores para ARM de baixa potência
RNGDOPTIONS="--fill-watermark=1024 --feed-interval=120 --timeout=30 --no-drng=1"
EOF
  sudo systemctl enable --now rng-tools

  # Verificar se o serviço está rodando
  if sudo systemctl is-active --quiet rng-tools; then
    echo_msg "✅ RNG-tools instalado/reconfigurado e em execução"
  else
    echo_msg "⚠️  RNG-tools instalado/reconfigurado, mas pode não estar em execução"
  fi
}

install_samba() {
  echo_msg "Instalando/reconfigurando Samba..."
  SUMMARY_ENTRIES+=("Samba: Compartilhamento BoxShare em /srv/samba/share")

  # Verificar se Samba já está instalado
  if dpkg -l | grep -q "^ii.*samba"; then
    echo_msg "Samba já está instalado. Reconfigurando..."
  else
    echo_msg "Instalando Samba..."
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
    backup_file /etc/samba/smb.conf
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
    echo_msg "✅ Samba instalado/reconfigurado e em execução"
  else
    echo_msg "⚠️  Samba instalado/reconfigurado, mas pode não estar em execução"
  fi
}

install_minidlna() {
  echo_msg "Instalando/reconfigurando MiniDLNA otimizado para RK322x..."
  SUMMARY_ENTRIES+=("MiniDLNA: Porta $MINIDLNA_PORT, Pastas em /srv/media")

  # Verificar se MiniDLNA já está instalado
  if dpkg -l | grep -q "^ii.*minidlna"; then
    echo_msg "MiniDLNA já está instalado. Reconfigurando..."
  else
    echo_msg "Instalando MiniDLNA..."
    sudo apt install -y minidlna
  fi

  sudo mkdir -p /srv/media/{video,audio,photos}

  # Verificar se o arquivo minidlna.conf existe
  if [ ! -f /etc/minidlna.conf ]; then
    sudo touch /etc/minidlna.conf
  fi

  # Configuração otimizada para dispositivos RK322x com recursos limitados
  backup_file /etc/minidlna.conf
  cat <<EOF | sudo tee /etc/minidlna.conf
# Configuração MiniDLNA otimizada para RK322x
media_dir=V,/srv/media/video
media_dir=A,/srv/media/audio
media_dir=P,/srv/media/photos
friendly_name=BoxServer DLNA (RK322x)
inotify=yes
port=$MINIDLNA_PORT

# Otimizações para ARM RK322x
album_art_names=Cover.jpg/cover.jpg/Folder.jpg/folder.jpg
max_connections=10
# Reduzir uso de CPU em ARM
notify_interval=60
serial=12345678
model_number=1
# Otimizar para dispositivos com pouca RAM
presentation_url=http://$(hostname -I | awk '{print $1}'):$MINIDLNA_PORT/

# Configurações de rede otimizadas para RK322x
network_interface=$NET_IF
EOF

  sudo systemctl enable --now minidlna

  # Verificar se o serviço está rodando
  if sudo systemctl is-active --quiet minidlna; then
    echo_msg "✅ MiniDLNA instalado/reconfigurado e em execução"
  else
    echo_msg "⚠️  MiniDLNA instalado/reconfigurado, mas pode não estar em execução"
  fi
}

install_filebrowser() {
  echo_msg "Instalando/reconfigurando Filebrowser otimizado para RK322x..."
  SUMMARY_ENTRIES+=("Filebrowser: Porta $FILEBROWSER_PORT, Pasta /srv/filebrowser")

  # Verificar arquitetura específica do RK322x
  local fb_arch_rk322x=""
  case "$(uname -m)" in
    armv7l) fb_arch_rk322x="linux-armv7";;
    aarch64) fb_arch_rk322x="linux-arm64";;
    *)
      echo_msg "❌ Arquitetura $(uname -m) não suportada pelo Filebrowser em RK322x"
      return 1
      ;;
  esac

  echo_msg "   Detectada arquitetura: $fb_arch_rk322x"

  # Obter versão com timeout para conexões lentas
  FB_VERSION=$(curl -s --max-time 30 https://api.github.com/repos/filebrowser/filebrowser/releases/latest | grep tag_name | cut -d '"' -f4 2>/dev/null)

  if [ -z "$FB_VERSION" ]; then
    echo_msg "⚠️ Falha ao obter versão mais recente, usando versão fixa"
    FB_VERSION="v2.23.0"
  fi

  echo_msg "   Instalando Filebrowser $FB_VERSION..."

  # Baixar e instalar Filebrowser com retry para conexões instáveis
  local download_url="https://github.com/filebrowser/filebrowser/releases/download/${FB_VERSION}/${fb_arch_rk322x}-filebrowser.tar.gz"

  local retry_count=0
  local max_retries=3

  while [ $retry_count -lt $max_retries ]; do
    echo_msg "   Tentativa $((retry_count + 1))/$max_retries de download..."
    if wget --timeout=120 -O filebrowser.tar.gz "$download_url"; then
      break
    fi
    retry_count=$((retry_count + 1))
    if [ $retry_count -lt $max_retries ]; then
      echo_msg "   Falha no download, tentando novamente em 5s..."
      sleep 5
    fi
  done

  if [ $retry_count -eq $max_retries ]; then
    echo_msg "❌ Falha no download do Filebrowser após $max_retries tentativas"
    return 1
  fi

  if tar -xzf filebrowser.tar.gz; then
    sudo mv filebrowser /usr/local/bin/
    rm -f filebrowser.tar.gz
    sudo mkdir -p /srv/filebrowser
    sudo useradd -r -s /bin/false filebrowser || true

    # Configurar banco de dados e configurações do Filebrowser
    sudo mkdir -p /etc/filebrowser

    # Configuração otimizada para RK322x com recursos limitados
    cat <<EOF | sudo tee /etc/filebrowser/config.json
{
  "port": $FILEBROWSER_PORT,
  "baseURL": "",
  "address": "0.0.0.0",
  "log": "stdout",
  "database": "/etc/filebrowser/filebrowser.db",
  "root": "/srv/filebrowser",
  "cache": {
    "enabled": true,
    "expiration": "1h"
  },
  "auth": {
    "method": "proxy",
    "header": "X-User"
  },
  "signup": false,
  "createUserDir": false,
  "defaults": {
    "scope": ".",
    "locale": "pt-BR",
    "viewMode": "list",
    "sorting": {
      "by": "name",
      "asc": true
    },
    "perm": {
      "admin": false,
      "execute": true,
      "create": true,
      "rename": true,
      "modify": true,
      "delete": true,
      "share": true,
      "download": true
    }
  }
}
EOF

    sudo chown -R filebrowser:filebrowser /etc/filebrowser /srv/filebrowser

    backup_file /etc/systemd/system/filebrowser.service
    cat <<EOF | sudo tee /etc/systemd/system/filebrowser.service
[Unit]
Description=Filebrowser (RK322x optimized)
After=network.target
Documentation=https://filebrowser.org

[Service]
User=filebrowser
Group=filebrowser
ExecStart=/usr/local/bin/filebrowser --config /etc/filebrowser/config.json
Restart=on-failure
RestartSec=10
# Otimizações para ARM RK322x
LimitNOFILE=4096
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/srv/filebrowser /etc/filebrowser
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable filebrowser

    # Inicializar banco de dados se necessário
    if [ ! -f /etc/filebrowser/filebrowser.db ]; then
      echo_msg "   Inicializando banco de dados do Filebrowser..."
      sudo -u filebrowser /usr/local/bin/filebrowser --config /etc/filebrowser/config.json config init
      sudo -u filebrowser /usr/local/bin/filebrowser --config /etc/filebrowser/config.json users add admin admin --perm.admin 2>/dev/null || true
    fi

    sudo systemctl start filebrowser

    # Verificar se o serviço está rodando
    if sudo systemctl is-active --quiet filebrowser; then
      echo_msg "✅ Filebrowser instalado/reconfigurado e em execução"
      echo_msg "   Usuário padrão: admin / Senha: admin"
    else
      echo_msg "⚠️  Filebrowser instalado/reconfigurado, mas pode não estar em execução"
      echo_msg "   Logs: sudo journalctl -u filebrowser -n 10"
    fi
  else
    echo_msg "❌ Falha ao extrair Filebrowser"
    rm -f filebrowser.tar.gz
    return 1
  fi
}

# =========================
# DASHBOARD WEB OTIMIZADO PARA RK322x
# =========================
install_dashboard() {
  echo_msg "Instalando/reconfigurando Dashboard Web otimizado para RK322x..."
  SUMMARY_ENTRIES+=("Dashboard: http://$STATIC_IP/ (RK322x otimizado)")
  sudo mkdir -p "$DASHBOARD_DIR"

  backup_file "$DASHBOARD_DIR/index.html"
  cat <<EOF | sudo tee "$DASHBOARD_DIR/index.html"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BoxServer Dashboard - RK322x</title>
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
        <h1>🚀 BoxServer Dashboard (RK322x)</h1>
        <div class="info-box">
            <p><strong>📋 Sistema:</strong> Kernel $(uname -r) - Arquitetura $(uname -m)</p>
            <p><strong>💾 Memória:</strong> $(free -h | awk '/^Mem:/ {print $3 "/" $2}') utilizada</p>
            <p><strong>💽 Armazenamento:</strong> $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 " usado)"}') no sistema raiz</p>
            <p><strong>🌡️ Otimizado para:</strong> Dispositivos ARM RK322x de baixo consumo</p>
        </div>

        <div class="service-grid">
            <div class="service-card">
                <h3>🛡️ Pi-hole</h3>
                <a href="http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin" class="btn" target="_blank">Painel Admin</a>
                <a href="https://$STATIC_IP:$PIHOLE_HTTPS_PORT/admin" class="btn" target="_blank">Painel SSL</a>
            </div>

            <div class="service-card">
                <h3>🗂️ Filebrowser</h3>
                <a href="http://$STATIC_IP:$FILEBROWSER_PORT" class="btn" target="_blank">Acessar</a>
                <p>Usuário: admin<br>Senha: admin</p>
            </div>

            <div class="service-card">
                <h3>📺 MiniDLNA</h3>
                <a href="http://$STATIC_IP:$MINIDLNA_PORT" class="btn" target="_blank">Status</a>
                <p>Porta: $MINIDLNA_PORT</p>
            </div>

            <div class="service-card">
                <h3>📂 Samba</h3>
                <p>Compartilhamento: <code>smb://$STATIC_IP/BoxShare</code></p>
                <p>Pasta: <code>/srv/samba/share</code></p>
            </div>
        </div>

        <div class="info-box">
            <h3>🔑 WireGuard (RK322x)</h3>
            <p>Configuração: <code>/etc/wireguard/wg0.conf</code></p>
            <p>Porta UDP: $WG_PORT</p>
            <p>Chave Pública: <code>$WG_PUBLIC</code></p>
            <p><strong>⚠️ Nota:</strong> Executando em modo otimizado para kernel 4.4.194-rk322x</p>
            <p><strong>Comandos úteis:</strong></p>
            <p><code>sudo wg show</code> - Mostrar status</p>
            <p><code>sudo systemctl status wg-quick@wg0</code> - Status do serviço</p>
        </div>

        <div class="info-box">
            <h3>☁️ Cloudflare Tunnel</h3>
            <p>Configuração: <code>/etc/cloudflared/config.yml</code></p>
            <p>Domínio: <code>$DOMAIN</code></p>
            <p><strong>⚠️ Requer autenticação manual:</strong></p>
            <p>1. <code>sudo cloudflared tunnel login</code></p>
            <p>2. <code>sudo cloudflared tunnel create boxserver</code></p>
            <p>3. <code>sudo systemctl start cloudflared</code></p>
        </div>

        <div class="info-box">
            <h3>🌐 DNS Recursivo (RK322x Otimizado)</h3>
            <p>Unbound rodando em: <code>127.0.0.1:$UNBOUND_PORT</code></p>
            <p><strong>Configuração:</strong> Otimizada para ARM com cache reduzido</p>
            <p><strong>Cache:</strong> $(if [ "${LOW_MEMORY:-false}" = "true" ]; then echo "32MB (modo baixa memória)"; else echo "64MB (padrão)"; fi)</p>
            <p><strong>Threads:</strong> 1 (otimizado para single-core ARM)</p>
            <p><strong>Teste:</strong> <code>nslookup google.com 127.0.0.1#$UNBOUND_PORT</code></p>
        </div>

        <div class="info-box">
            <h3>⚙️ Otimizações RK322x</h3>
            <p><strong>Kernel:</strong> $(uname -r)</p>
            <p><strong>Arquitetura:</strong> $(uname -m)</p>
            <p><strong>CPU:</strong> $(cat /proc/cpuinfo | grep -i "model name" | head -1 | cut -d: -f2 | xargs || echo "ARM Cortex")</p>
            <p><strong>Configurações aplicadas:</strong></p>
            <ul style="text-align: left; margin: 10px 0;">
                <li>Cache DNS reduzido para economia de RAM</li>
                <li>Threading otimizado para single-core</li>
                <li>Timeouts ajustados para ARM</li>
                <li>Buffers de rede conservadores</li>
                $(if [ "${LOW_MEMORY:-false}" = "true" ]; then echo "<li>Modo baixa memória ativado</li>"; fi)
                $(if [ "${DISABLE_VPN:-false}" = "true" ]; then echo "<li>VPN em modo userspace</li>"; fi)
            </ul>
        </div>
    </div>
</body>
</html>
EOF

  # Parar serviços que possam estar usando a porta 80
  sudo systemctl stop apache2 || true  # Apache se estiver instalado

  # Configurar nginx otimizado para RK322x
  backup_file /etc/nginx/sites-available/boxserver-dashboard
  cat <<EOF | sudo tee /etc/nginx/sites-available/boxserver-dashboard
server {
    listen 80;
    server_name $STATIC_IP localhost;
    root $DASHBOARD_DIR;
    index index.html;

    # Otimizações para dispositivos ARM RK322x
    access_log off;  # Reduzir I/O
    error_log /var/log/nginx/boxserver-error.log error;

    # Cache estático agressivo para reduzir carga do ARM
    location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files \$uri =404;
    }

    # Compressão otimizada para ARM
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_comp_level 4;  # Balanceio CPU/bandwidth para ARM
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    location / {
        try_files \$uri \$uri/ =404;
        # Headers de segurança leves
        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-Content-Type-Options "nosniff";
    }

    # Limite de conexões para proteger ARM de sobrecarga
    limit_conn_zone \$binary_remote_addr zone=conn_limit_per_ip:10m;
    limit_conn conn_limit_per_ip 10;
}
EOF

  # Configurar nginx principal otimizado para RK322x
  backup_file /etc/nginx/nginx.conf
  cat <<EOF | sudo tee /etc/nginx/nginx.conf
user www-data;
# Otimizado para ARM single-core
worker_processes 1;
worker_rlimit_nofile 1024;
pid /run/nginx.pid;

events {
    # Otimizado para ARM com recursos limitados
    worker_connections 512;
    use epoll;
    multi_accept on;
}

http {
    # Configurações básicas
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 30;  # Reduzido para ARM
    types_hash_max_size 2048;
    server_tokens off;

    # MIME types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging otimizado para ARM (reduzir I/O)
    access_log off;
    error_log /var/log/nginx/error.log error;

    # Buffer sizes otimizados para ARM
    client_body_buffer_size 16k;
    client_header_buffer_size 1k;
    client_max_body_size 8m;
    large_client_header_buffers 2 1k;

    # Timeouts conservadores para ARM
    client_body_timeout 12;
    client_header_timeout 12;
    send_timeout 10;

    # Compressão balanceada CPU/largura de banda
    gzip on;
    gzip_vary on;
    gzip_min_length 1000;
    gzip_comp_level 4;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    # Configurações de sites
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

  sudo ln -sf /etc/nginx/sites-available/boxserver-dashboard /etc/nginx/sites-enabled/
  sudo rm -f /etc/nginx/sites-enabled/default

  # Verificar configuração antes de reiniciar
  if sudo nginx -t; then
    sudo systemctl restart nginx
  else
    echo_msg "❌ Erro na configuração do Nginx"
    return 1
  fi

  # Verificar se o serviço está rodando
  if sudo systemctl is-active --quiet nginx; then
    echo_msg "✅ Dashboard RK322x instalado/reconfigurado e acessível em http://$STATIC_IP/"
    echo_msg "   Configuração otimizada para dispositivos ARM de baixa potência"
  else
    echo_msg "⚠️  Dashboard instalado/reconfigurado, mas o Nginx pode não estar em execução"
    echo_msg "   Logs: sudo journalctl -u nginx -n 10"
  fi
}

# =========================
# Resumo final otimizado RK322x
# =========================
show_summary() {
  {
    echo "=== BoxServer Installation Summary (RK322x Optimized) ==="
    echo "Data: ${TIMESTAMP}"
    echo "Sistema:"
    echo "  Kernel: $(uname -r)"
    echo "  Arquitetura: $(uname -m)"
    echo "  Memória: $(free -h | awk '/^Mem:/ {print $2}')"
    echo "  Armazenamento usado: $(df -h / | awk 'NR==2 {print $5}')"
    echo "Rede:"
    echo "  IP: $STATIC_IP"
    echo "  Interface: $NET_IF"
    echo "  Gateway: $GATEWAY"
    echo "Otimizações RK322x aplicadas:"
    if [ "${LOW_MEMORY:-false}" = "true" ]; then
      echo "  - Modo baixa memória ativado"
    fi
    if [ "${DISABLE_VPN:-false}" = "true" ]; then
      echo "  - WireGuard em modo userspace"
    fi
    echo "  - Cache DNS reduzido para ARM"
    echo "  - Threading otimizado para single-core"
    echo "  - Buffers de rede conservadores"
    echo "Serviços instalados:"
    for s in "${SUMMARY_ENTRIES[@]}"; do
      echo "  - $s"
    done
    if [ -n "${WG_PRIVATE:-}" ] && [ -n "${WG_PUBLIC:-}" ]; then
      echo "WireGuard keys:"
      echo "  Private: $WG_PRIVATE"
      echo "  Public: $WG_PUBLIC"
    fi
  } | sudo tee "$SUMMARY_FILE" >/dev/null

  # Adicionar instruções específicas do Cloudflare Tunnel se estiver instalado
  if [[ "$CHOICES" == *CLOUDFLARE* ]]; then
    {
      echo ""
      echo "=== INSTRUÇÕES CLOUDFLARED (RK322x) ==="
      echo "Para completar a configuração do Cloudflare Tunnel:"
      echo "1. Execute: sudo cloudflared tunnel login"
      echo "2. Siga as instruções no navegador para autenticar"
      echo "3. Execute: sudo cloudflared tunnel create boxserver"
      echo "4. Execute: sudo systemctl start cloudflared"
      echo "5. Configure o DNS no painel Cloudflare para apontar para o tunnel"
      echo ""
      echo "Arquivo de configuração: /etc/cloudflared/config.yml"
      echo "Credenciais: /etc/cloudflared/boxserver.json (será criado após autenticação)"
      echo "Nota RK322x: Configurado para arquitetura ARM otimizada"
    } | sudo tee -a "$SUMMARY_FILE" >/dev/null
  fi

  # Adicionar dicas específicas para RK322x
  {
    echo ""
    echo "=== DICAS DE OTIMIZAÇÃO RK322x ==="
    echo "Comandos úteis para monitoramento:"
    echo "  - htop: Monitor de recursos em tempo real"
    echo "  - iostat 1: Monitor de I/O do sistema"
    echo "  - free -h: Verificar uso de memória"
    echo "  - df -h: Verificar espaço em disco"
    echo ""
    echo "Otimizações recomendadas:"
    echo "  - sudo apt autoremove: Remover pacotes desnecessários"
    echo "  - sudo apt autoclean: Limpar cache de pacotes"
    echo "  - sudo journalctl --vacuum-time=7d: Limpar logs antigos"
    echo ""
    echo "Troubleshooting específico RK322x:"
    echo "  - Se WireGuard falhar: Verifique 'lsmod | grep wireguard'"
    echo "  - Se DNS lento: Ajuste cache em /etc/unbound/unbound.conf.d/pi-hole.conf"
    echo "  - Se pouca RAM: Monitore com 'free -h' e ajuste serviços"
  } | sudo tee -a "$SUMMARY_FILE" >/dev/null

  sudo chmod 600 "$SUMMARY_FILE"
  if [ "$SILENT_MODE" = false ]; then
    whiptail --title "Resumo da instalação" --textbox "$SUMMARY_FILE" 30 80
  else
    echo "Resumo da instalação salvo em: $SUMMARY_FILE"
  fi
}

# =========================
# Função de uso
# =========================
usage() {
  echo "Uso: $0 [OPÇÕES]"
  echo "Opções:"
  echo "  --clean         Remove completamente todas as instalações e dados do BoxServer antes de instalar."
  echo "  --verify-clean  Verifica se o sistema está limpo sem executar purga"
  echo "  -s, --silent    Modo silencioso (sem interface whiptail)"
  echo "  -u, --update    Atualizar serviços já instalados"
  echo "  -r, --rollback  Reverter alterações"
  echo "  --diagnose-wg   Executar diagnóstico completo do WireGuard"
  echo "  -h, --help      Mostrar esta ajuda"
  exit 1
}

# =========================
# Processamento de argumentos
# =========================
CLEAN_INSTALL=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --clean)
      CLEAN_INSTALL=true
      shift
      ;;
    -s|--silent)
      SILENT_MODE=true
      shift
      ;;
    -u|--update)
      check_system
      check_connectivity
      update_services
      exit 0
      ;;
    -r|--rollback)
      rollback_changes
      exit 0
      ;;
    --diagnose-wg)
      check_system
      diagnose_wireguard
      exit 0
      ;;
    --verify-clean)
      echo "🔍 Verificando status de limpeza do sistema..."
      verify_purge_completion
      exit 0
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Opção desconhecida: $1"
      usage
      ;;
  esac
done

# =========================
# Fluxo principal
# =========================
main() {
  if [ "$CLEAN_INSTALL" = true ]; then
    if [ "$SILENT_MODE" = false ]; then
      local purge_details="🧹 PURGA COMPLETA DO BOXSERVER - ATENÇÃO!

A opção --clean irá executar uma PURGA TOTAL do sistema, removendo:

🚫 SERVIÇOS (parados e desabilitados):
- Pi-hole, Unbound, WireGuard, Cloudflared, Samba, MiniDLNA
- Nginx, Apache2, Lighttpd, DNS auxiliares
- RNG-tools e outros serviços relacionados

📦 PACOTES (purgados completamente):
- Todos os pacotes relacionados aos serviços acima
- Incluindo dependências e configurações
- Limpeza automática de pacotes órfãos

👥 USUÁRIOS E GRUPOS:
- Usuários: pihole, unbound, filebrowser, minidlna, etc.
- Grupos correspondentes

🗂️ BINÁRIOS E EXECUTÁVEIS:
- /usr/local/bin/cloudflared, filebrowser, pihole
- /opt/pihole e outros diretórios de instalação

📁 CONFIGURAÇÕES E DADOS:
- /etc/pihole, /etc/unbound, /etc/wireguard
- /etc/samba, /etc/minidlna, /etc/cloudflared
- /srv/boxserver-dashboard, /srv/filebrowser
- /srv/samba, /srv/media
- TODOS os logs relacionados

🌐 CONFIGURAÇÕES DE REDE:
- Configurações netplan do BoxServer
- Regras iptables do WireGuard
- Interfaces virtuais (wg0, etc.)
- Restauração do DNS padrão

⚠️  ESTA AÇÃO É COMPLETAMENTE IRREVERSÍVEL!
⚠️  TODOS OS DADOS E CONFIGURAÇÕES SERÃO PERDIDOS!
⚠️  O SISTEMA SERÁ RESTAURADO AO ESTADO ORIGINAL!
"
      whiptail --title "⚠️  CONFIRMAÇÃO DE PURGA TOTAL" --msgbox "$purge_details" 30 85
      if ! whiptail --yesno "🚨 VOCÊ TEM ABSOLUTA CERTEZA? 🚨

Esta ação irá DESTRUIR COMPLETAMENTE todas as instalações
e configurações do BoxServer.

TODOS OS DADOS SERÃO PERDIDOS PARA SEMPRE!

Deseja realmente continuar com a purga total?" 15 70; then
        exit 0
      fi
    fi
    purge_existing_installations
  fi

  check_system
  check_disk_space
  check_connectivity
  if [ "$SILENT_MODE" = false ]; then
    whiptail_msg "Bem-vindo ao instalador BoxServer (Armbian 21.08.8 Debian 11 Bullseye)."
  else
    echo "Bem-vindo ao instalador BoxServer (Armbian 21.08.8 Debian 11 Bullseye)."
  fi
  ensure_deps
  ask_static_ip
  check_and_set_ports
  if [ "$SILENT_MODE" = false ]; then
    DOMAIN=$(whiptail --inputbox "Informe o domínio para o Pi-hole:" 10 68 "$DOMAIN_DEFAULT" 3>&1 1>&2 2>&3)
  else
    DOMAIN="$DOMAIN_DEFAULT"
  fi
  [ -z "$DOMAIN" ] && DOMAIN="$DOMAIN_DEFAULT"
  choose_services

  # Instalar Unbound primeiro, pois Pi-hole depende dele
  if [[ "$CHOICES" == *UNBOUND* ]]; then
    install_unbound
  fi

  # Instalar Pi-hole somente se Unbound foi instalado ou já existe
  if [[ "$CHOICES" == *PIHOLE* ]]; then
    if [[ "$CHOICES" == *UNBOUND* ]] || sudo systemctl is-active --quiet unbound; then
      echo_msg "🕳️ Instalando Pi-hole otimizado para RK322x..."
      install_pihole
    else
      echo_msg "❌ Pi-hole não pode ser instalado sem Unbound. Selecione Unbound também."
    fi
  fi

  # Instalar WireGuard com verificação de compatibilidade RK322x
  if [[ "$CHOICES" == *WIREGUARD* ]]; then
    echo_msg "🔒 Instalando WireGuard com otimizações RK322x..."
    install_wireguard
  fi
  [[ "$CHOICES" == *CLOUDFLARE* ]] && install_cloudflared
  [[ "$CHOICES" == *RNG* ]] && install_rng
  [[ "$CHOICES" == *SAMBA* ]] && install_samba
  [[ "$CHOICES" == *MINIDLNA* ]] && install_minidlna
  [[ "$CHOICES" == *FILEBROWSER* ]] && install_filebrowser
  [[ "$CHOICES" == *DASHBOARD* ]] && install_dashboard

  # Verificação final do sistema após instalação
  echo_msg "🔍 Executando verificação final do sistema RK322x..."

  # Verificar uso de recursos após instalação
  local final_memory=$(free | awk '/^Mem:/ {print int($3*100/$2)}')
  local final_disk=$(df / | awk 'NR==2 {print int($3*100/$2)}')

  echo_msg "   Uso de memória: ${final_memory}%"
  echo_msg "   Uso de disco: ${final_disk}%"

  if [ "$final_memory" -gt 80 ]; then
    echo_msg "⚠️ Uso de memória alto (${final_memory}%) - considere otimizações adicionais"
  fi

  if [ "$final_disk" -gt 85 ]; then
    echo_msg "⚠️ Uso de disco alto (${final_disk}%) - considere limpeza"
  fi

  # Otimização final dos serviços para RK322x
  echo_msg "🎯 Aplicando otimizações finais de performance..."

  # Reduzir logs para economizar I/O em ARM
  sudo journalctl --vacuum-size=50M >/dev/null 2>&1

  # Configurar logrotate para dispositivos ARM
  cat <<EOF | sudo tee /etc/logrotate.d/boxserver-rk322x >/dev/null
/var/log/pihole*.log {
    daily
    missingok
    rotate 7
    compress
    notifempty
    create 644 pihole pihole
}

/var/log/unbound*.log {
    daily
    missingok
    rotate 7
    compress
    notifempty
}
EOF

  show_summary

  echo_msg "🎉 Instalação BoxServer otimizada para RK322x concluída!"
  echo_msg "   Dashboard: http://$STATIC_IP/"
  echo_msg "   Sistema otimizado para kernel 4.4.194-rk322x"
}

main "$@"
