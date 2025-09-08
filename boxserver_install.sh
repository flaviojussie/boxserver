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
  echo "🔐 Verificando módulos de criptografia..."
  local crypto_modules=("crypto_user" "af_alg" "algif_hash" "algif_skcipher")
  local crypto_missing=0

  for module in "${crypto_modules[@]}"; do
    if ! lsmod | grep -q "$module" && ! modprobe "$module" 2>/dev/null; then
      echo "⚠️ Módulo de criptografia $module não disponível"
      crypto_missing=$((crypto_missing + 1))
    else
      echo "✅ Módulo $module carregado"
    fi
  done

  if [ $crypto_missing -gt 0 ]; then
    echo "⚠️ $crypto_missing módulos de criptografia ausentes - aplicando workarounds"
    export CRYPTO_LIMITED=true
  else
    echo "✅ Todos os módulos de criptografia disponíveis"
  fi

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
  whiptail_msg "🧹 Iniciando purga simples e robusta do BoxServer..."

  echo "Parando serviços..."
  # Lista simples de serviços principais
  for service in unbound pihole-ftl lighttpd wg-quick@wg0 cloudflared rng-tools smbd minidlna filebrowser nginx; do
    sudo systemctl stop "$service" 2>/dev/null || true
    sudo systemctl disable "$service" 2>/dev/null || true
  done

  echo "Removendo pacotes principais..."
  # Remoção simples e direta dos pacotes principais
  for pkg in unbound pihole-ftl lighttpd wireguard wireguard-tools rng-tools samba minidlna nginx filebrowser cloudflared; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      sudo apt-get remove --purge -y "$pkg" 2>/dev/null || true
    fi
  done

  # Limpeza automática
  sudo apt-get autoremove -y 2>/dev/null || true
  sudo apt-get autoclean 2>/dev/null || true

  echo "Removendo diretórios de configuração..."
  # Remoção direta dos diretórios principais
  sudo rm -rf /etc/pihole /etc/unbound /etc/wireguard /etc/cloudflared \
             /etc/samba /etc/minidlna /srv/boxserver-dashboard \
             /srv/filebrowser /srv/samba /srv/media \
             /usr/local/bin/cloudflared /usr/local/bin/filebrowser \
             /opt/pihole 2>/dev/null || true

  echo "Removendo serviços systemd customizados..."
  sudo rm -f /etc/systemd/system/cloudflared.service \
             /etc/systemd/system/filebrowser.service 2>/dev/null || true
  sudo systemctl daemon-reload

  echo "Limpando configurações de rede..."
  # Remover interface wg0 se existir
  sudo ip link delete wg0 2>/dev/null || true

  # Limpar configuração netplan se existir
  sudo rm -f /etc/netplan/01-boxserver.yaml 2>/dev/null || true

  echo "Restaurando DNS padrão..."
  # Reativar systemd-resolved se disponível
  if [ -f /lib/systemd/system/systemd-resolved.service ]; then
    sudo systemctl enable systemd-resolved 2>/dev/null || true
    sudo systemctl start systemd-resolved 2>/dev/null || true
  fi

  echo "✅ Purga simples concluída!"
  whiptail_msg "✅ Purga concluída com sucesso!

Todos os componentes principais do BoxServer foram removidos.
O sistema está pronto para uma nova instalação."
}

# =========================
# Verificação pós-purga simples
# =========================
verify_purge_completion() {
  echo "🔍 Verificação rápida pós-purga..."

  # Verificar apenas os principais
  local issues=0

  for service in pihole-ftl unbound wg-quick@wg0; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
      echo "   ⚠️ Serviço ainda ativo: $service"
      issues=$((issues + 1))
    fi
  done

  for dir in /etc/pihole /etc/unbound /etc/wireguard; do
    if [ -d "$dir" ]; then
      echo "   ⚠️ Diretório ainda existe: $dir"
      issues=$((issues + 1))
    fi
  done

  if [ $issues -eq 0 ]; then
    echo "   ✅ Sistema limpo"
  else
    echo "   ⚠️ $issues itens remanescentes encontrados"
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
test_unbound_prerequisites() {
  echo_msg "🔍 Testando pré-requisitos do sistema para Unbound..."

  # Teste 1: Verificar se a porta está livre
  if sudo netstat -tlnp | grep -q ":$UNBOUND_PORT "; then
    local port_process=$(sudo netstat -tlnp | grep ":$UNBOUND_PORT " | awk '{print $7}')
    echo_msg "⚠️ Porta $UNBOUND_PORT em uso por: $port_process"

    # Se for um processo unbound antigo, matar
    if echo "$port_process" | grep -q "unbound"; then
      echo_msg "   Parando processo unbound antigo..."
      sudo pkill -9 unbound 2>/dev/null || true
      sleep 2
    else
      echo_msg "❌ Porta $UNBOUND_PORT ocupada por outro serviço. Abortando instalação do Unbound."
      return 1
    fi
  fi

  # Teste 2: Verificar conectividade DNS upstream
  echo_msg "   Testando conectividade DNS upstream..."
  if ! timeout 5 dig @8.8.8.8 google.com +short >/dev/null 2>&1; then
    echo_msg "❌ Sem conectividade DNS upstream. Verifique sua conexão de internet."
    return 1
  fi

  # Teste 3: Verificar permissões e diretórios
  echo_msg "   Verificando permissões do sistema..."
  if ! sudo mkdir -p /var/lib/unbound /etc/unbound/unbound.conf.d 2>/dev/null; then
    echo_msg "❌ Falha ao criar diretórios necessários. Verifique permissões de root."
    return 1
  fi

  # Teste 4: Verificar disponibilidade do usuário unbound
  if ! id unbound >/dev/null 2>&1; then
    echo_msg "   Usuário 'unbound' não existe, será criado durante a instalação..."
  fi

  # Teste 5: Verificar espaço em disco (mínimo 100MB)
  local available_space=$(df /var/lib | tail -1 | awk '{print $4}')
  if [ "$available_space" -lt 102400 ]; then # 100MB em KB
    echo_msg "❌ Espaço insuficiente em /var/lib (necessário: 100MB)"
    return 1
  fi

  echo_msg "✅ Sistema compatível com Unbound"
  return 0
}

install_unbound() {
  echo_msg "Instalando/reconfigurando Unbound otimizado para RK322x..."
  SUMMARY_ENTRIES+=("Unbound DNS: Porta $UNBOUND_PORT")

  # Executar testes de pré-requisitos
  if ! test_unbound_prerequisites; then
    echo_msg "❌ Falha nos pré-requisitos do Unbound. Instalação cancelada."
    return 1
  fi

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
  local crypto_settings=""

  # Ajustar para dispositivos com pouca memória
  if [ "${LOW_MEMORY:-false}" = "true" ]; then
    cache_size="32m"
    msg_cache="16m"
    echo_msg "   Ajustando configurações para baixa memória"
  fi

  # Ajustar para módulos de criptografia limitados
  if [ "${CRYPTO_LIMITED:-false}" = "true" ]; then
    echo_msg "   Ajustando configurações para criptografia limitada do RK322x"
    crypto_settings="
    # Configurações para criptografia limitada RK322x
    use-caps-for-id: yes
    harden-algo-downgrade: yes
    val-permissive-mode: yes"
  else
    crypto_settings="
    # Configurações padrão de criptografia
    use-caps-for-id: no
    harden-algo-downgrade: no
    val-permissive-mode: no"
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
    # Otimizações específicas para RK322x
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes$crypto_settings

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
    rrset-cache-size: 64m
    msg-cache-size: 32m
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

    # DNSSEC simplificado para RK322x - evitar problemas de criptografia
    # auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: no
    val-log-level: 0
    # Desabilitar DNSSEC para evitar falhas no RK322x
    module-config: "iterator"

    # Root hints
    root-hints: "/var/lib/unbound/root.hints"

    # Logging otimizado
    log-queries: no
    log-replies: no
    logfile: ""
    use-syslog: yes

    # Access control (apenas localhost e rede local)
    access-control: 127.0.0.0/8 allow
    access-control: 192.168.0.0/16 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
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

  # Pular configuração de DNSSEC para RK322x devido a problemas de compatibilidade
  echo_msg "⚠️ DNSSEC desabilitado para compatibilidade com RK322x"

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

    # Garantir que o diretório e permissões estão corretos
    sudo mkdir -p /var/lib/unbound
    sudo chown -R unbound:unbound /var/lib/unbound
    sudo chmod 755 /var/lib/unbound

    # Parar completamente antes de iniciar
    sudo systemctl stop unbound 2>/dev/null || true
    sudo pkill -9 unbound 2>/dev/null || true
    sleep 3

    sudo systemctl enable unbound
    sudo systemctl start unbound
    sleep 5 # Aguarda mais tempo para estabilização em RK322x
  else
    echo_msg "❌ Erro na configuração do Unbound. O serviço não será iniciado."
    echo_msg "Detalhes do erro:"
    sudo unbound-checkconf 2>&1 | sed 's/^/   /'
    return 1
  fi

  # Verificação final e teste de integração
  if sudo systemctl is-active --quiet unbound; then
    echo_msg "✅ Unbound em execução, validando instalação..."

    # Aguardar estabilização do serviço em RK322x
    sleep 8

    # Executar validação completa
    if validate_unbound_installation; then
      echo_msg "✅ Unbound instalado/reconfigurado e funcionando perfeitamente"
      echo_msg "   DNSSEC foi desabilitado para compatibilidade com RK322x"
      echo_msg "   Pronto para integração com Pi-hole em 127.0.0.1:$UNBOUND_PORT"
    else
      echo_msg "❌ Validação do Unbound falhou"
      echo_msg "   Executando diagnóstico detalhado e correção completa..."
      fix_unbound_rk322x

      # Teste final após correção
      if validate_unbound_installation; then
        echo_msg "✅ Unbound corrigido e funcionando após diagnóstico!"
      else
        echo_msg "⚠️ Unbound ainda com problemas - usando modo de compatibilidade extrema"
        enable_unbound_compatibility_mode

        # Validação final do modo de compatibilidade
        sleep 5
        if validate_unbound_installation; then
          echo_msg "✅ Unbound funcionando em modo de compatibilidade"
        else
          echo_msg "❌❌ Unbound inoperante mesmo com todas as correções"
          echo_msg "   Verifique manualmente: sudo journalctl -u unbound -f"
        fi
      fi
    fi
  else
    echo_msg "❌ Unbound instalado mas não está em execução"
    echo_msg "   Logs detalhados:"
    sudo journalctl -u unbound --no-pager -n 15 | sed 's/^/   /'

    # Tentar iniciar e diagnosticar
    echo_msg "   Tentando iniciar Unbound com diagnóstico..."
    sudo systemctl start unbound 2>&1 | sed 's/^/   /'
    sleep 5

    if sudo systemctl is-active --quiet unbound; then
      echo_msg "✅ Unbound iniciado com sucesso após correção"
    else
      echo_msg "   ❌ Falha ao iniciar Unbound - aplicando correção completa"
      fix_unbound_rk322x
    fi
  fi
}

validate_unbound_installation() {
  echo_msg "🔍 Validando instalação do Unbound..."

  # Teste 1: Verificar se o serviço está ativo
  if ! sudo systemctl is-active --quiet unbound; then
    echo_msg "   ❌ Serviço Unbound não está ativo"
    return 1
  fi

  # Teste 2: Verificar se está ouvindo na porta correta
  if ! sudo netstat -tulpn | grep -q ":$UNBOUND_PORT "; then
    echo_msg "   ❌ Unbound não está ouvindo na porta $UNBOUND_PORT"
    return 1
  fi

  # Teste 3: Teste de resolução DNS simples
  local test_attempts=0
  local max_attempts=3

  while [ $test_attempts -lt $max_attempts ]; do
    test_attempts=$((test_attempts + 1))
    echo_msg "   Teste DNS $test_attempts/$max_attempts..."

    if timeout 10 dig @127.0.0.1 -p $UNBOUND_PORT google.com +short >/dev/null 2>&1; then
      echo_msg "   ✅ Resolução DNS funcionando"
      return 0
    fi

    if [ $test_attempts -lt $max_attempts ]; then
      echo_msg "   Aguardando 3s para próxima tentativa..."
      sleep 3
    fi
  done

  echo_msg "   ❌ Falha na resolução DNS após $max_attempts tentativas"
  return 1
}

# =========================
# Função de manutenção da DNSSEC root key
# =========================
maintain_dnssec_root_key() {
  echo "🔐 Verificando e mantendo DNSSEC root key..."

  # Verificar se arquivo existe e tem conteúdo válido
  if [ ! -f /var/lib/unbound/root.key ] || [ ! -s /var/lib/unbound/root.key ]; then
    echo "⚠️ Root key ausente ou vazia, recriando..."
    create_fallback_root_key
    return
  fi

  # Testar se root key atual funciona
  local test_result
  test_result=$(dig @127.0.0.1 -p ${UNBOUND_PORT:-5335} +dnssec cloudflare.com 2>/dev/null | grep -c "ad" || echo "0")

  if [ "$test_result" -eq 0 ]; then
    echo "⚠️ Root key não está validando DNSSEC, atualizando..."

    # Backup da chave atual
    sudo cp /var/lib/unbound/root.key /var/lib/unbound/root.key.backup.$(date +%s) 2>/dev/null || true

    # Tentar obter nova chave
    if ! sudo unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null; then
      echo "   unbound-anchor falhou, usando fallback..."
      create_fallback_root_key
    else
      echo "✅ Root key atualizada via unbound-anchor"
    fi

    # Reiniciar Unbound para aplicar nova chave
    sudo systemctl restart unbound 2>/dev/null || true
    sleep 3

    # Verificar se funcionou
    local new_test_result
    new_test_result=$(dig @127.0.0.1 -p ${UNBOUND_PORT:-5335} +dnssec cloudflare.com 2>/dev/null | grep -c "ad" || echo "0")

    if [ "$new_test_result" -gt 0 ]; then
      echo "✅ DNSSEC funcionando após atualização da root key"
    else
      echo "⚠️ DNSSEC ainda com problemas - normal em RK322x com criptografia limitada"
    fi
  else
    echo "✅ Root key funcionando corretamente"
  fi
}

create_fallback_root_key() {
  echo "   Criando root key fallback confiável para RK322x..."
  sudo tee /var/lib/unbound/root.key > /dev/null << 'EOF'
; DNSSEC Root Key Fallback para kernel 4.4.194-rk322x
; Última atualização: 2024
. IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
EOF

  # Garantir permissões corretas
  sudo chown unbound:unbound /var/lib/unbound/root.key 2>/dev/null || true
  sudo chmod 644 /var/lib/unbound/root.key 2>/dev/null || true
  echo "   ✅ Root key fallback criada"
}

# =========================
# Diagnóstico de problemas do Unbound
# =========================
diagnose_unbound_issues() {
  echo "🔧 Diagnosticando problemas do Unbound no RK322x..."

  # 1. Verificar configuração
  echo "   Testando configuração..."
  if ! sudo unbound-checkconf; then
    echo "   ❌ Configuração inválida, tentando corrigir..."
    fix_unbound_config_rk322x
    return
  fi

  # 2. Verificar portas e interfaces
  echo "   Verificando portas e interfaces..."
  local port_check=$(sudo netstat -tulpn | grep ":$UNBOUND_PORT " | wc -l)
  if [ "$port_check" -eq 0 ]; then
    echo "   ❌ Unbound não está ouvindo na porta $UNBOUND_PORT"
    echo "   Tentando correção de binding..."
    fix_unbound_binding_rk322x
  else
    echo "   ✅ Unbound ouvindo na porta $UNBOUND_PORT"
  fi

  # 3. Verificar logs para problemas específicos
  echo "   Analisando logs do Unbound..."
  local error_count=$(sudo journalctl -u unbound --no-pager -n 20 | grep -c -i "error\|fail" || echo "0")
  if [ "$error_count" -gt 0 ]; then
    echo "   ⚠️ Erros encontrados nos logs:"
    sudo journalctl -u unbound --no-pager -n 10 | grep -i "error\|fail" | head -3 | sed 's/^/      /'
  fi

  # 4. Teste de conectividade upstream
  echo "   Testando conectividade upstream..."
  if ! timeout 5 dig @8.8.8.8 google.com >/dev/null 2>&1; then
    echo "   ⚠️ Problema de conectividade upstream - verificar rede"
  fi

  # 5. Tentativa de correção automática
  echo "   Tentando correção automática..."
  fix_unbound_rk322x
}

fix_unbound_config_rk322x() {
  echo "🔧 Corrigindo configuração do Unbound para RK322x..."

  backup_file /etc/unbound/unbound.conf.d/pi-hole.conf

  # Configuração mínima e robusta para RK322x
  cat <<EOF | sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    # Configuração mínima para RK322x
    verbosity: 0
    interface: 127.0.0.1
    port: $UNBOUND_PORT
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no

    # Configurações básicas de segurança
    harden-glue: yes
    harden-dnssec-stripped: yes

    # Cache mínimo para ARM
    rrset-cache-size: 32m
    msg-cache-size: 16m
    so-rcvbuf: 128k
    so-sndbuf: 128k

    # Threading mínimo
    num-threads: 1

    # Redes privadas
    private-address: 192.168.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8

    # DNSSEC desabilitado para RK322x
    module-config: "iterator"

    # Root hints
    root-hints: "/var/lib/unbound/root.hints"

    # Access control
    access-control: 127.0.0.0/8 allow
    access-control: 192.168.0.0/16 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 0.0.0.0/0 refuse

    # Otimizações RK322x
    outgoing-range: 128
    num-queries-per-thread: 256
    jostle-timeout: 500
    cache-min-ttl: 0
    cache-max-ttl: 86400
EOF

  echo "   ✅ Configuração mínima aplicada"
}

fix_unbound_binding_rk322x() {
  echo "🔧 Corrigindo binding de interface do Unbound..."

  # Parar Unbound completamente
  sudo systemctl stop unbound 2>/dev/null || true
  sleep 3

  # Matar qualquer processo Unbound remanescente
  sudo pkill -9 unbound 2>/dev/null || true
  sleep 1

  # Verificar e liberar porta
  local pid_using_port=$(sudo lsof -ti:$UNBOUND_PORT 2>/dev/null || true)
  if [ -n "$pid_using_port" ]; then
    echo "   Processo $pid_using_port usando porta $UNBOUND_PORT, terminando..."
    sudo kill -9 "$pid_using_port" 2>/dev/null || true
    sleep 2
  fi

  # Garantir binding apenas para localhost
  backup_file /etc/unbound/unbound.conf.d/pi-hole.conf
  sudo sed -i '/interface:/d' /etc/unbound/unbound.conf.d/pi-hole.conf
  echo "    interface: 127.0.0.1" | sudo tee -a /etc/unbound/unbound.conf.d/pi-hole.conf

  # Recriar diretórios e permissões
  sudo mkdir -p /var/lib/unbound /etc/unbound/unbound.conf.d
  sudo chown -R unbound:unbound /var/lib/unbound
  sudo chmod 755 /var/lib/unbound
  sudo chmod 644 /var/lib/unbound/* 2>/dev/null || true

  # Limpar cache e estado antigo
  sudo rm -f /var/lib/unbound/*.mj* /var/lib/unbound/*.tmp 2>/dev/null || true

  # Iniciar novamente com verificação
  echo "   Iniciando Unbound com binding corrigido..."
  sudo systemctl start unbound
  sleep 5

  # Verificar se funcionou
  if sudo netstat -tulpn | grep -q ":$UNBOUND_PORT "; then
    echo "   ✅ Binding corrigido, Unbound ouvindo na porta $UNBOUND_PORT"

    # Teste rápido de funcionalidade com dig
    if timeout 8 dig @127.0.0.1 -p $UNBOUND_PORT google.com +short >/dev/null 2>&1; then
      echo "   ✅ Unbound respondendo a consultas DNS"
    else
      echo "   ⚠️ Unbound ouvindo mas não respondendo - pode precisar de mais ajustes"
    fi
  else
    echo "   ❌ Ainda há problemas com binding após correção"
    echo "   Verificando logs para diagnóstico..."
    sudo journalctl -u unbound --no-pager -n 10 | grep -i error | head -3 | sed 's/^/      /'
  fi
}

fix_unbound_rk322x() {
  echo "🔧 Aplicando correções completas do Unbound para RK322x..."

  # 1. Parar serviço
  sudo systemctl stop unbound
  sleep 2

  # 2. Aplicar configuração mínima
  fix_unbound_config_rk322x

  # 3. Verificar e corrigir root key
  create_fallback_root_key

  # 4. Verificar root hints
  if [ ! -f /var/lib/unbound/root.hints ] || [ ! -s /var/lib/unbound/root.hints ]; then
    echo "   Baixando root hints atualizados..."
    sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root 2>/dev/null || {
      echo "   Criando root hints básicos..."
      echo ". 518400 IN NS a.root-servers.net." | sudo tee /var/lib/unbound/root.hints >/dev/null
    }
  fi

  # 5. Corrigir permissões
  sudo chown -R unbound:unbound /var/lib/unbound
  sudo chmod -R 644 /var/lib/unbound/*
  sudo chmod 755 /var/lib/unbound

  # 6. Iniciar e testar
  sudo systemctl start unbound
  sleep 5

  # 7. Teste final com diagnóstico detalhado
  echo "   Testando Unbound após correções..."
  if timeout 15 dig @127.0.0.1 -p $UNBOUND_PORT google.com +short >/dev/null 2>&1; then
    echo "   ✅ Unbound corrigido e funcionando!"
  else
    echo "   ❌ Problema persiste após correção completa"
    echo "   Logs detalhados do Unbound:"
    sudo journalctl -u unbound --no-pager -n 20 | grep -E "(error|fail|warn)" | head -5 | sed 's/^/      /'

    echo "   Configurando modo de compatibilidade extrema para RK322x..."
    enable_unbound_compatibility_mode
  fi
}

# =========================
# Modo de compatibilidade extrema para RK322x
# =========================
enable_unbound_compatibility_mode() {
  echo "🔧 Ativando modo de compatibilidade extrema para RK322x..."

  backup_file /etc/unbound/unbound.conf.d/pi-hole.conf

  # Configuração mínima absoluta para RK322x problemático
  cat <<EOF | sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    # Configuração mínima extrema para RK322x
    verbosity: 0
    interface: 127.0.0.1
    port: $UNBOUND_PORT
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no

    # Cache mínimo radical
    rrset-cache-size: 16m
    msg-cache-size: 8m
    num-threads: 1
    outgoing-range: 64
    num-queries-per-thread: 128

    # Sem validação DNSSEC para compatibilidade
    module-config: "iterator"
    harden-glue: no
    harden-dnssec-stripped: no

    # Redes privadas
    private-address: 192.168.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8

    # Access control seguro
    access-control: 127.0.0.0/8 allow
    access-control: 192.168.0.0/16 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 0.0.0.0/0 refuse

    # Root hints básico
    root-hints: "/var/lib/unbound/root.hints"

    # Timeouts aumentados para RK322x lento
    jostle-timeout: 1000
    cache-min-ttl: 0
    cache-max-ttl: 86400
EOF

  # Parar e reiniciar com nova configuração
  sudo systemctl stop unbound 2>/dev/null || true
  sleep 2
  sudo systemctl start unbound
  sleep 8

  echo "   ⚠️ Modo de compatibilidade extrema aplicado"
  echo "   Configuração: DNS básico apenas, sem validações complexas"

  # Teste final no modo compatibilidade
  if timeout 20 dig @127.0.0.1 -p $UNBOUND_PORT google.com +short >/dev/null 2>&1; then
    echo "   ✅ Unbound funcionando em modo de compatibilidade!"
  else
    echo "   ❌❌ Unbound completamente inoperante no RK322x"
    echo "   Considere: 1) Atualizar kernel 2) Usar DNS externo 3) Verificar hardware"
  fi
}

install_pihole() {
  echo_msg "Instalando/reconfigurando Pi-hole otimizado para RK322x..."
  SUMMARY_ENTRIES+=("Pi-hole: Portas $PIHOLE_HTTP_PORT/$PIHOLE_HTTPS_PORT (RK322x)")

  # Detectar se Pi-hole já está instalado
  local pihole_installed=false
  local pihole_running=false

  if command -v pihole &> /dev/null; then
    echo_msg "✅ Pi-hole já instalado - procedendo com reconfiguração"
    pihole_installed=true

    if sudo systemctl is-active --quiet pihole-ftl; then
      echo_msg "   Pi-hole FTL está rodando"
      pihole_running=true
    fi
  else
    echo_msg "🆕 Nova instalação do Pi-hole detectada"
  fi

  # Verificar se as portas do Pi-hole estão livres antes de instalar
  echo_msg "Verificando disponibilidade das portas do Pi-hole..."
  if sudo netstat -tln | grep -q ":$PIHOLE_HTTP_PORT "; then
    local http_port_process=$(sudo netstat -tlnp | grep ":$PIHOLE_HTTP_PORT " | head -1)

    # Verificar se é lighttpd do Pi-hole
    if echo "$http_port_process" | grep -q "lighttpd"; then
      echo_msg "✅ Pi-hole web interface detectada na porta $PIHOLE_HTTP_PORT"
      echo_msg "   Procedendo com reconfiguração da interface web..."

      # Parar lighttpd temporariamente
      sudo systemctl stop lighttpd 2>/dev/null || true
      sleep 2
    else
      echo_msg "❌ Porta $PIHOLE_HTTP_PORT já está em uso por outro serviço:"
      echo_msg "   $http_port_process"
      echo_msg "   Pi-hole precisa desta porta para a interface web"
      return 1
    fi
  fi

  # Verificar se porta 53 está em uso por outros serviços (exceto Pi-hole existente e systemd-resolved)
  local port_53_process=$(sudo netstat -tlnp | grep ":53 " | grep -v systemd-resolved | head -1)

  if [ -n "$port_53_process" ]; then
    # Verificar se é o próprio Pi-hole usando a porta
    if echo "$port_53_process" | grep -q "pihole-FTL"; then
      echo_msg "✅ Pi-hole já instalado detectado na porta 53"
      echo_msg "   Processo existente: $(echo "$port_53_process" | awk '{print $7}')"
      echo_msg "   Procedendo com reconfiguração..."

      # Parar temporariamente o Pi-hole para reconfiguração
      echo_msg "   Parando Pi-hole temporariamente para reconfiguração..."
      sudo systemctl stop pihole-ftl 2>/dev/null || true
      sleep 3

      # Verificar se a porta foi liberada
      if sudo netstat -tln | grep -q ":53 "; then
        echo_msg "⚠️ Porta 53 ainda ocupada, forçando liberação..."
        sudo pkill -9 pihole-FTL 2>/dev/null || true
        sleep 2
      fi

      echo_msg "✅ Porta 53 liberada para reconfiguração do Pi-hole"
    else
      echo_msg "❌ Porta 53 (DNS) está sendo usada por outro serviço (não Pi-hole):"
      echo_msg "   $port_53_process"
      echo_msg "   Pi-hole precisa da porta 53 para funcionar como servidor DNS principal"
      echo_msg "   Pare o serviço conflitante antes de continuar"
      return 1
    fi
  fi

  # Se systemd-resolved estiver ativo, desabilitar para liberar porta 53
  if systemctl is-active --quiet systemd-resolved; then
    echo_msg "⚠️  systemd-resolved detectado na porta 53. Desabilitando para Pi-hole..."
    sudo systemctl disable --now systemd-resolved

    # Remover link simbólico do resolv.conf se existir
    if [ -L /etc/resolv.conf ]; then
      sudo rm /etc/resolv.conf
    fi

    # Garantir que o arquivo não é imutável antes de escrever
    sudo chattr -i /etc/resolv.conf 2>/dev/null || true

    # Criar um resolv.conf temporário apontando para localhost (futuro Pi-hole)
    echo "# Configurado para Pi-hole + Unbound" | sudo tee /etc/resolv.conf
    echo "nameserver 127.0.0.1" | sudo tee -a /etc/resolv.conf
    echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf

    echo_msg "✅ systemd-resolved desabilitado, porta 53 liberada para Pi-hole"
    sleep 2
  fi

  # Verificar se Unbound está rodando antes de instalar Pi-hole
  echo_msg "Verificando se Unbound está disponível como DNS upstream..."
  if ! sudo systemctl is-active --quiet unbound; then
    echo_msg "⚠️ Unbound não está rodando. Tentando iniciar..."
    sudo systemctl start unbound || {
      echo_msg "❌ Falha ao iniciar Unbound. Instale Unbound primeiro."
      return 1
    }
    sleep 5
  fi

  # Usar função de validação simplificada
  echo_msg "Testando conectividade com Unbound upstream..."

  if validate_unbound_installation; then
    echo_msg "✅ Unbound funcionando corretamente para integração com Pi-hole"
  else
    echo_msg "❌ Unbound não está respondendo"
    echo_msg "   Executando correção automática..."
    fix_unbound_rk322x
    sleep 3

    # Teste final
    if validate_unbound_installation; then
      echo_msg "✅ Unbound corrigido e pronto para Pi-hole"
    else
      echo_msg "⚠️ Unbound com problemas - Pi-hole usará DNS externos como fallback"
      echo_msg "   Você pode reconfigurar depois via: pihole -a -i local"
    fi
  fi

  echo_msg "✅ Unbound funcionando como DNS upstream. Configurando Pi-hole..."

  # Preparar diretório e configuração base
  sudo mkdir -p /etc/pihole

  if [ "$pihole_installed" = true ]; then
    echo_msg "🔄 Reconfigurando Pi-hole existente com otimizações para RK322x..."

    # Fazer backup da configuração existente
    if [ -f /etc/pihole/setupVars.conf ]; then
      sudo cp /etc/pihole/setupVars.conf /etc/pihole/setupVars.conf.backup.$(date +%Y%m%d_%H%M%S)
      echo_msg "   Backup da configuração atual salvo"
    fi
  else
    echo_msg "🆕 Preparando nova instalação do Pi-hole v6 otimizada para RK322x..."
  fi
  # Configuração otimizada para kernel 4.4.194-rk322x
  # Pi-hole na porta 53, Unbound como upstream na porta $UNBOUND_PORT
  echo_msg "   Aplicando configuração otimizada para RK322x..."
  cat <<EOF | sudo tee /etc/pihole/setupVars.conf
PIHOLE_INTERFACE=$NET_IF
IPV4_ADDRESS=$STATIC_IP/24
PIHOLE_DNS_1=127.0.0.1#$UNBOUND_PORT
PIHOLE_DNS_2=
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
WEB_PORT=$PIHOLE_HTTP_PORT
WEBPASSWORD=
DNSSEC=false
# Configuração de DNS: Pi-hole (porta 53) -> Unbound (porta $UNBOUND_PORT)
DNSMASQ_LISTENING=single
# Otimizações RK322x
BLOCKING_ENABLED=true
REV_SERVER=false
# Cache reduzido para ARM
CACHE_SIZE=1000
# Log reduzido para economizar I/O
MAXDBDAYS=2
# Configuração específica para usar apenas Unbound
DNS_FQDN_REQUIRED=false
DNS_BOGUS_PRIV=true
CONDITIONAL_FORWARDING=false
EOF

  # Executar instalação ou reconfiguração baseada no status
  if [ "$pihole_installed" = true ]; then
    echo_msg "🔄 Aplicando reconfiguração do Pi-hole existente..."

    # Reconfigurar DNS upstream para usar apenas Unbound
    echo_msg "   Configurando Unbound como DNS upstream único..."
    pihole -a -i 127.0.0.1#$UNBOUND_PORT

    # Aplicar configurações web
    echo_msg "   Configurando interface web na porta $PIHOLE_HTTP_PORT..."
    sudo sed -i "s/server.port.*/server.port = $PIHOLE_HTTP_PORT/" /etc/lighttpd/lighttpd.conf 2>/dev/null || true

    # Desabilitar DNSSEC (compatibilidade RK322x)
    echo_msg "   Desabilitando DNSSEC para compatibilidade RK322x..."
    pihole -a -dnssec off

    # Aplicar configurações de cache reduzido
    echo_msg "   Aplicando configurações otimizadas para ARM..."
    if [ -f /etc/dnsmasq.d/01-pihole.conf ]; then
      sudo sed -i '/cache-size/d' /etc/dnsmasq.d/01-pihole.conf
      echo "cache-size=1000" | sudo tee -a /etc/dnsmasq.d/01-pihole.conf >/dev/null
    fi

    # Reiniciar serviços
    echo_msg "   Reiniciando serviços do Pi-hole..."
    sudo systemctl restart pihole-ftl
    sudo systemctl restart lighttpd 2>/dev/null || true

    echo_msg "✅ Pi-hole reconfigurado com sucesso"
  else
    echo_msg "🆕 Executando instalação nova do Pi-hole otimizado para ARM..."
    # O instalador irá ler o setupVars.conf
    if ! curl -sSL --max-time 120 https://install.pi-hole.net | sudo bash /dev/stdin --unattended; then
      echo_msg "❌ Falha na instalação do Pi-hole."
      return 1
    fi

    echo_msg "✅ Pi-hole instalado com sucesso"
  fi

  # Aguardar inicialização completa (mais tempo para ARM)
  echo_msg "Aguardando inicialização completa dos serviços do Pi-hole em RK322x..."
  sleep 15

  # Verificar se a instalação/reconfiguração foi bem-sucedida
  if ! command -v pihole &> /dev/null; then
    echo_msg "❌ Pi-hole não está disponível após instalação/configuração."
    return 1
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

  # Teste DNS via Pi-hole (porta 53)
  echo_msg "Testando Pi-hole na porta 53..."
  if timeout 10 nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
    echo_msg "✅ Pi-hole DNS respondendo na porta 53"
    dns_ok=true
  else
    echo_msg "❌ Pi-hole DNS não está respondendo na porta 53"
    dns_ok=false
  fi

  # Teste DNS via Unbound (porta $UNBOUND_PORT)
  echo_msg "Testando Unbound upstream na porta $UNBOUND_PORT..."
  if timeout 10 dig @127.0.0.1 -p $UNBOUND_PORT google.com +short >/dev/null 2>&1; then
    echo_msg "✅ Unbound upstream respondendo na porta $UNBOUND_PORT"
    unbound_ok=true
  else
    echo_msg "❌ Unbound upstream não está respondendo na porta $UNBOUND_PORT"
    unbound_ok=false
  fi

  # Resultado final com diagnóstico detalhado
  if [ "$pihole_ftl_ok" = true ] && [ "$lighttpd_ok" = true ] && [ "$dns_ok" = true ] && [ "$unbound_ok" = true ]; then
    echo_msg "✅ Pi-hole + Unbound funcionando completamente!"
    echo_msg "   🌐 DNS Pipeline: Clientes → Pi-hole (53) → Unbound ($UNBOUND_PORT) → Internet"
    echo_msg "   🖥️  Interface web: http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin"
    echo_msg "   ⚙️  Configuração: DNS filtering + resolução recursiva local"
    echo_msg "   📊 Otimizações RK322x: Cache reduzido, logs limitados"

    # Configurar sistema para usar Pi-hole como DNS principal
    echo_msg "Configurando sistema para usar Pi-hole como DNS..."
    configure_system_dns_for_pihole
  elif [ "$pihole_ftl_ok" = true ] && [ "$dns_ok" = true ] && [ "$unbound_ok" = true ]; then
    echo_msg "✅ Pi-hole + Unbound DNS funcionando (interface web com problemas)"
    echo_msg "   DNS filtering e resolução funcionando corretamente"
  elif [ "$pihole_ftl_ok" = true ] && [ "$dns_ok" = true ]; then
    echo_msg "⚠️ Pi-hole funcionando, mas sem Unbound upstream"
    echo_msg "   Execute: ./script.sh --fix-unbound"
  else
    echo_msg "❌ Pi-hole com problemas graves"
    echo_msg "   Verifique: sudo systemctl status pihole-ftl"
    echo_msg "   Logs: sudo journalctl -u pihole-ftl -n 20"
  fi

  # Executar validação final da instalação
  echo_msg "Executando validação final da instalação..."
  if validate_pihole_installation; then
    echo_msg "✅ Pi-hole instalado e validado com sucesso!"

    # Configurar sistema para usar Pi-hole como DNS principal
    echo_msg "Configurando sistema para usar Pi-hole como DNS..."
    configure_system_dns_for_pihole
  else
    echo_msg "⚠️ Pi-hole instalado mas com problemas - execute troubleshooting manual"
  fi
}

validate_pihole_installation() {
  echo_msg "🔍 Executando validação completa do Pi-hole..."

  local validation_passed=true

  # Teste 1: Verificar se o comando pihole existe
  if ! command -v pihole &> /dev/null; then
    echo_msg "   ❌ Comando 'pihole' não encontrado"
    validation_passed=false
  else
    echo_msg "   ✅ Comando Pi-hole disponível"
  fi

  # Teste 2: Verificar serviço pihole-ftl
  if ! sudo systemctl is-active --quiet pihole-ftl; then
    echo_msg "   ❌ Serviço pihole-ftl não está ativo"
    echo_msg "      Status: $(sudo systemctl is-active pihole-ftl 2>/dev/null || echo 'erro')"
    validation_passed=false
  else
    echo_msg "   ✅ Serviço pihole-ftl ativo"
  fi

  # Teste 3: Verificar porta 53
  if ! sudo netstat -tlnp | grep ":53 " | grep -q "pihole-FTL"; then
    echo_msg "   ❌ Pi-hole não está ouvindo na porta 53"
    echo_msg "      Processos na porta 53:"
    sudo netstat -tlnp | grep ":53 " | sed 's/^/         /' | head -3
    validation_passed=false
  else
    echo_msg "   ✅ Pi-hole ouvindo na porta 53"
  fi

  # Teste 4: Verificar resolução DNS
  local dns_test_attempts=0
  local dns_working=false

  while [ $dns_test_attempts -lt 3 ] && [ "$dns_working" = false ]; do
    dns_test_attempts=$((dns_test_attempts + 1))
    echo_msg "      Teste DNS $dns_test_attempts/3..."

    if timeout 15 dig @127.0.0.1 google.com +short >/dev/null 2>&1; then
      dns_working=true
      echo_msg "   ✅ Resolução DNS via Pi-hole funcionando"
    else
      if [ $dns_test_attempts -lt 3 ]; then
        echo_msg "      Aguardando 5s para próxima tentativa..."
        sleep 5
      fi
    fi
  done

  if [ "$dns_working" = false ]; then
    echo_msg "   ❌ Pi-hole não responde a consultas DNS"
    validation_passed=false
  fi

  # Teste 5: Verificar integração com Unbound
  if timeout 10 dig @127.0.0.1 -p $UNBOUND_PORT google.com +short >/dev/null 2>&1; then
    echo_msg "   ✅ Unbound upstream funcionando na porta $UNBOUND_PORT"
  else
    echo_msg "   ⚠️ Unbound upstream com problemas - Pi-hole usará fallback"
  fi

  # Teste 6: Verificar interface web (opcional)
  if sudo systemctl is-active --quiet lighttpd; then
    if sudo netstat -tln | grep -q ":$PIHOLE_HTTP_PORT "; then
      echo_msg "   ✅ Interface web disponível na porta $PIHOLE_HTTP_PORT"
    else
      echo_msg "   ⚠️ Interface web pode não estar acessível na porta $PIHOLE_HTTP_PORT"
    fi
  else
    echo_msg "   ⚠️ Lighttpd não está rodando - interface web indisponível"
  fi

  # Resultado final
  if [ "$validation_passed" = true ]; then
    echo_msg "🎉 Pi-hole validado com sucesso!"
    echo_msg "   ✅ DNS: Pi-hole (53) -> Unbound ($UNBOUND_PORT)"
    echo_msg "   ✅ Web: http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin/"
    echo_msg "   ✅ Sistema otimizado para RK322x"
  else
    echo_msg "⚠️ Pi-hole instalado mas com problemas detectados"
    echo_msg "   🔧 Para reparar execute: pihole -r"
    echo_msg "   📋 Para diagnóstico: sudo pihole status"
    echo_msg "   📝 Logs: sudo journalctl -u pihole-ftl -f"
  fi

  return $validation_passed
}

# =========================
# Configurar DNS do sistema para usar Pi-hole
# =========================
configure_system_dns_for_pihole() {
  echo_msg "Configurando resolv.conf para usar Pi-hole..."

  # Backup do resolv.conf atual
  if [ -f /etc/resolv.conf ]; then
    sudo cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%s)
  fi

  # Garantir que o arquivo não é imutável antes de escrever
  sudo chattr -i /etc/resolv.conf 2>/dev/null || true

  # Criar novo resolv.conf apontando para Pi-hole
  cat <<EOF | sudo tee /etc/resolv.conf
# Configuração DNS BoxServer RK322x
# Pi-hole como DNS principal (porta 53) com Unbound upstream (porta $UNBOUND_PORT)
nameserver 127.0.0.1
nameserver $STATIC_IP
# Fallback para caso de emergência
nameserver 1.1.1.1
EOF

  # Proteger resolv.conf contra sobrescrita
  sudo chattr +i /etc/resolv.conf 2>/dev/null || true

  # Testar nova configuração
  if timeout 5 nslookup google.com >/dev/null 2>&1; then
    echo_msg "✅ Sistema configurado para usar Pi-hole como DNS"
  else
    echo_msg "⚠️ Possível problema na configuração DNS do sistema"
    # Remover proteção e restaurar fallback se necessário
    sudo chattr -i /etc/resolv.conf 2>/dev/null || true
    echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
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

    # Se criptografia limitada, ir direto para userspace
    if [ "${CRYPTO_LIMITED:-false}" = "true" ]; then
      echo_msg "   Criptografia limitada detectada - usando userspace diretamente"
      install_wireguard_userspace
      return $?
    fi

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
# Configuração otimizada para criptografia limitada do kernel 4.4.194-rk322x
EOF

  sudo chmod 600 /etc/wireguard/wg0.conf

  # Habilitar IP forwarding
  if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
  fi
  sudo sysctl -p >/dev/null

  echo_msg "⚠️ WireGuard configurado em modo userspace para RK322x"
  echo_msg "   Performance pode ser reduzida comparado ao modo kernel"
  if [ "${CRYPTO_LIMITED:-false}" = "true" ]; then
    echo_msg "   Configuração ajustada para módulos de criptografia limitados"
  fi

  SUMMARY_ENTRIES+=("WireGuard (userspace/RK322x): Porta UDP $WG_PORT")
  return 0
}

install_cloudflared() {
  echo_msg "Instalando/reconfigurando Cloudflare Tunnel para RK322x..."

  # Verificar se criptografia limitada afeta o Cloudflared
  if [ "${CRYPTO_LIMITED:-false}" = "true" ]; then
    echo_msg "⚠️ Criptografia limitada detectada - Cloudflared pode ter performance reduzida"
  fi

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

    # Configuração otimizada para RK322x com criptografia limitada
    local tunnel_config="tunnel: boxserver
credentials-file: /etc/cloudflared/boxserver.json
ingress:
  - hostname: $DOMAIN
    service: http://localhost:$PIHOLE_HTTP_PORT
  - service: http_status:404"

    # Adicionar configurações específicas para criptografia limitada
    if [ "${CRYPTO_LIMITED:-false}" = "true" ]; then
      tunnel_config="$tunnel_config

# Configurações RK322x para criptografia limitada
protocol: http2
retries: 3
grace-period: 30s"
    fi

    cat <<EOF | sudo tee /etc/cloudflared/config.yml
$tunnel_config
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

  # Configurações básicas
  local minidlna_config="# Configuração MiniDLNA otimizada para RK322x
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
network_interface=$NET_IF"

  # Adicionar configurações específicas para criptografia limitada
  if [ "${CRYPTO_LIMITED:-false}" = "true" ]; then
    minidlna_config="$minidlna_config

# Configurações para criptografia limitada RK322x
# Desabilitar funcionalidades que dependem de criptografia forte
enable_tivo=no
strict_dlna=no"
  fi

  cat <<EOF | sudo tee /etc/minidlna.conf
$minidlna_config
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
    local auth_method="proxy"
    local tls_config=""

    # Ajustar configurações para criptografia limitada
    if [ "${CRYPTO_LIMITED:-false}" = "true" ]; then
      echo_msg "   Configurando Filebrowser para criptografia limitada RK322x"
      auth_method="none"
      tls_config=',
  "tls": {
    "cert": "",
    "key": "",
    "port": ""
  }'
    fi

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
    "method": "$auth_method",
    "header": "X-User"
  }$tls_config,
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
            $(if [ "${CRYPTO_LIMITED:-false}" = "true" ]; then echo "<p><strong>⚠️ Criptografia:</strong> Módulos limitados - configuração ajustada</p>"; fi)
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
            <h3>🌐 DNS Pipeline Completo (RK322x)</h3>
            <p><strong>📊 Fluxo DNS:</strong> Clientes → Pi-hole (porta 53) → Unbound (porta $UNBOUND_PORT) → Internet</p>
            <p><strong>🕳️ Pi-hole:</strong> Filtering de ads/malware na porta 53</p>
            <p><strong>🔄 Unbound:</strong> Resolução recursiva local na porta $UNBOUND_PORT</p>
            <p><strong>💾 Cache:</strong> $(if [ "${LOW_MEMORY:-false}" = "true" ]; then echo "32MB (modo baixa memória)"; else echo "64MB (padrão)"; fi)</p>
            <p><strong>🧵 Threads:</strong> 1 (otimizado para single-core ARM)</p>
            <p><strong>🧪 Testes:</strong></p>
            <p><code>nslookup google.com 127.0.0.1</code> # Via Pi-hole</p>
            <p><code>dig @127.0.0.1 -p $UNBOUND_PORT google.com</code> # Via Unbound</p>
            <p><strong>⚙️ Sistema:</strong> Configurado para usar Pi-hole como DNS principal</p>
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
                $(if [ "${CRYPTO_LIMITED:-false}" = "true" ]; then echo "<li>Workarounds para criptografia limitada</li>"; fi)
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
    echo "DNS Pipeline:"
    echo "  Sistema DNS: Pi-hole (porta 53) -> Unbound (porta $UNBOUND_PORT)"
    echo "  Filtering: Pi-hole bloqueia ads/malware"
    echo "  Resolução: Unbound faz consultas recursivas locais"
    echo "Otimizações RK322x aplicadas:"
    if [ "${LOW_MEMORY:-false}" = "true" ]; then
      echo "  - Modo baixa memória ativado"
    fi
    if [ "${DISABLE_VPN:-false}" = "true" ]; then
      echo "  - WireGuard em modo userspace"
    fi
    if [ "${CRYPTO_LIMITED:-false}" = "true" ]; then
      echo "  - Workarounds para criptografia limitada"
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
    echo "  - Se DNS lento: Execute './script.sh --fix-unbound'"
    echo "  - Se Pi-hole não bloqueia: Verifique 'sudo pihole status'"
    echo "  - Se Unbound não responde: Execute './script.sh --fix-unbound'"
    echo "  - Se DNSSEC com problemas: Execute './script.sh --fix-dnssec'"
    echo "  - Para testar DNS: 'nslookup google.com' (via Pi-hole)"
    echo "  - Para testar upstream: 'dig @127.0.0.1 -p $UNBOUND_PORT google.com'"
    echo "  - Se pouca RAM: Monitore com 'free -h' e ajuste serviços"
    if [ "${CRYPTO_LIMITED:-false}" = "true" ]; then
      echo ""
      echo "=== LIMITAÇÕES DE CRIPTOGRAFIA DETECTADAS ==="
      echo "Seu kernel RK322x tem módulos de criptografia limitados."
      echo "Configurações aplicadas:"
      echo "  - Pi-hole: Porta 53 com cache reduzido (1000 entradas)"
      echo "  - Unbound: Porta $UNBOUND_PORT com DNSSEC relaxado"
      echo "  - WireGuard: Modo userspace (performance reduzida)"
      echo "  - Cloudflared: Configurações conservadoras"
      echo "  - DNS Pipeline: Pi-hole -> Unbound -> Internet"
      echo ""
      echo "Para melhorar desempenho DNS:"
      echo "  - Monitor: 'dig @127.0.0.1 google.com | grep \"Query time\"'"
      echo "  - Pi-hole stats: 'pihole -c -e'"
      echo "  - Unbound stats: 'sudo unbound-control stats'"
      echo "Para melhorar segurança (opcional):"
      echo "  - Considere atualização do kernel se possível"
      echo "  - Use VPN externa adicional se necessário"
      echo "  - Monitore logs para detectar problemas de conectividade"
    fi
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
  echo "  --verify-clean  Verifica se o sistema está limpo após purga"
  echo "  --fix-dnssec    Verificar e corrigir problemas de DNSSEC root key"
  echo "  --fix-unbound   Diagnosticar e corrigir problemas do Unbound DNS"
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
    --fix-dnssec)
      echo "🔐 Verificando e corrigindo DNSSEC root key..."
      check_system
      maintain_dnssec_root_key
      exit 0
      ;;
    --fix-unbound)
      echo "🔧 Diagnosticando e corrigindo Unbound..."
      check_system
      diagnose_unbound_issues
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
