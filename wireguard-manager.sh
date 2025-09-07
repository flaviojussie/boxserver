#!/bin/bash
set -euo pipefail

# =========================
# Configurações
# =========================
WG_DIR="/etc/wireguard"
KEYS_DIR="$WG_DIR/keys"
CONF_FILE="$WG_DIR/wg0.conf"
SERVER_IP="10.200.200.1"
NETWORK="10.200.200.0/24"

# =========================
# Funções auxiliares
# =========================
msg() {
  echo "🤖 $1"
}

error() {
  echo "❌ ERRO: $1" >&2
  exit 1
}

check_wg_installed() {
  if ! command -v wg &> /dev/null; then
    error "WireGuard não está instalado. Execute primeiro o install_boxserver.sh"
  fi
}

check_wg_running() {
  if ! systemctl is-active --quiet wg-quick@wg0; then
    error "WireGuard não está rodando. Execute: sudo systemctl start wg-quick@wg0"
  fi
}

# =========================
# Funções principais
# =========================
add_peer() {
  local peer_name="$1"
  local peer_ip="$2"

  msg "Adicionando peer: $peer_name com IP: $peer_ip"

  # Gerar chaves do peer
  umask 077
  mkdir -p "$KEYS_DIR"
  cd "$KEYS_DIR"

  wg genkey | tee "${peer_name}_privatekey" | wg pubkey > "${peer_name}_publickey"

  local peer_private=$(cat "${peer_name}_privatekey")
  local peer_public=$(cat "${peer_name}_publickey")
  local server_public=$(cat "${KEYS_DIR}/publickey")

  # Adicionar peer à configuração do servidor
  cat <<EOF | tee -a "$CONF_FILE"

# Peer: $peer_name
[Peer]
PublicKey = $peer_public
AllowedIPs = $peer_ip/32
EOF

  # Criar arquivo de configuração do peer
  cat <<EOF > "${peer_name}.conf"
[Interface]
PrivateKey = $peer_private
Address = $peer_ip/24
DNS = $SERVER_IP

[Peer]
PublicKey = $server_public
Endpoint = $(curl -s ifconfig.me):51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

  # Reiniciar WireGuard para aplicar mudanças
  sudo wg syncconf wg0 <(wg-quick strip wg0)

  msg "Peer $peer_name adicionado com sucesso!"
  echo "📋 Arquivo de configuração: ${KEYS_DIR}/${peer_name}.conf"
  echo "📱 Use este arquivo no cliente WireGuard"
}

remove_peer() {
  local peer_name="$1"

  msg "Removendo peer: $peer_name"

  # Remover da configuração
  sudo sed -i "/# Peer: $peer_name/,+3d" "$CONF_FILE"

  # Remover arquivos de chaves
  rm -f "${KEYS_DIR}/${peer_name}_privatekey" \
        "${KEYS_DIR}/${peer_name}_publickey" \
        "${KEYS_DIR}/${peer_name}.conf"

  # Reiniciar WireGuard
  sudo wg syncconf wg0 <(wg-quick strip wg0)

  msg "Peer $peer_name removido com sucesso!"
}

list_peers() {
  msg "Peers configurados:"
  echo ""

  if grep -q "\[Peer\]" "$CONF_FILE"; then
    grep -A 3 "# Peer:" "$CONF_FILE" | awk '
      /# Peer:/ {peer=$3; print "👤 " peer}
      /PublicKey:/ {print "   🔑 Chave: " $3}
      /AllowedIPs:/ {print "   📡 IP: " $3; print ""}
    '
  else
    echo "📭 Nenhum peer configurado"
  fi

  echo "📊 Total de peers: $(grep -c "\[Peer\]" "$CONF_FILE")"
}

generate_qr() {
  local peer_name="$1"
  local config_file="${KEYS_DIR}/${peer_name}.conf"

  if [ ! -f "$config_file" ]; then
    error "Arquivo de configuração não encontrado para $peer_name"
  fi

  if ! command -v qrencode &> /dev/null; then
    sudo apt install -y qrencode
  fi

  msg "Gerando QR Code para: $peer_name"
  qrencode -t UTF8 < "$config_file"
  echo ""
  echo "📱 Escaneie este QR code com o app WireGuard"
}

show_server_status() {
  msg "Status do Servidor WireGuard:"
  echo ""

  if systemctl is-active --quiet wg-quick@wg0; then
    echo "✅ WireGuard rodando"
    echo "📡 Interface: $(ip -o -4 addr show wg0 | awk '{print $4}')"
    echo "👥 Peers conectados: $(sudo wg show wg0 peers | wc -l)"
    echo ""
    sudo wg show
  else
    echo "❌ WireGuard não está rodando"
    echo "💡 Execute: sudo systemctl start wg-quick@wg0"
  fi
}

# =========================
# Menu interativo
# =========================
show_menu() {
  while true; do
    echo ""
    echo "🔧 GERENCIADOR WIREGUARD - BOXSERVER"
    echo "===================================="
    echo "1️⃣  Adicionar novo peer"
    echo "2️⃣  Remover peer"
    echo "3️⃣  Listar peers"
    echo "4️⃣  Gerar QR Code"
    echo "5️⃣  Status do servidor"
    echo "6️⃣  Testar conectividade"
    echo "0️⃣  Sair"
    echo ""

    read -p "Escolha uma opção: " choice

    case $choice in
      1)
        read -p "Nome do peer (ex: celular-flavio): " peer_name
        read -p "IP do peer (ex: 10.200.200.2): " peer_ip
        add_peer "$peer_name" "$peer_ip"
        ;;
      2)
        read -p "Nome do peer para remover: " peer_name
        remove_peer "$peer_name"
        ;;
      3)
        list_peers
        ;;
      4)
        read -p "Nome do peer para QR Code: " peer_name
        generate_qr "$peer_name"
        ;;
      5)
        show_server_status
        ;;
      6)
        msg "Testando conectividade..."
        ping -c 4 $SERVER_IP && echo "✅ Conexão OK" || echo "❌ Sem conexão"
        ;;
      0)
        echo "👋 Até logo!"
        exit 0
        ;;
      *)
        echo "❌ Opção inválida"
        ;;
    esac
  done
}

# =========================
# Modo de uso direto
# =========================
usage() {
  echo "Uso: $0 [comando]"
  echo ""
  echo "Comandos:"
  echo "  add <nome> <ip>     - Adicionar novo peer"
  echo "  remove <nome>       - Remover peer"
  echo "  list                - Listar peers"
  echo "  qr <nome>           - Gerar QR code"
  echo "  status              - Mostrar status"
  echo "  menu                - Menu interativo (padrão)"
  echo ""
  echo "Exemplos:"
  echo "  $0 add notebook 10.200.200.2"
  echo "  $0 remove celular"
  echo "  $0 qr tablet"
}

# =========================
# Fluxo principal
# =========================
main() {
  check_wg_installed

  case "${1:-menu}" in
    add)
      if [ $# -ne 3 ]; then
        error "Uso: $0 add <nome> <ip>"
      fi
      add_peer "$2" "$3"
      ;;
    remove)
      if [ $# -ne 2 ]; then
        error "Uso: $0 remove <nome>"
      fi
      remove_peer "$2"
      ;;
    list)
      list_peers
      ;;
    qr)
      if [ $# -ne 2 ]; then
        error "Uso: $0 qr <nome>"
      fi
      generate_qr "$2"
      ;;
    status)
      show_server_status
      ;;
    menu)
      show_menu
      ;;
    help|--help|-h)
      usage
      ;;
    *)
      error "Comando inválido: $1"
      ;;
  esac
}

# Executar apenas se chamado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
