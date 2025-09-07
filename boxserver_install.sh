#!/bin/bash
set -euo pipefail

# ==============================================
# BoxServer - Instalador Simplificado
# Versão: 1.0
# ==============================================

# Diretório base do projeto
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="$SCRIPT_DIR/boxserver.conf"
readonly BACKUP_DIR="/opt/boxserver/backups"
readonly LOGFILE="/var/log/boxserver_install.log"

# Cores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# ==============================================
# Funções de Logging
# ==============================================
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOGFILE"
}

log_error() {
    echo -e "${RED}[ERRO] $(date '+%Y-%m-%d %H:%M:%S')${NC} $1" | tee -a "$LOGFILE" >&2
}

log_warn() {
    echo -e "${YELLOW}[AVISO] $(date '+%Y-%m-%d %H:%M:%S')${NC} $1" | tee -a "$LOGFILE"
}

log_info() {
    echo -e "${BLUE}[INFO] $(date '+%Y-%m-%d %H:%M:%S')${NC} $1" | tee -a "$LOGFILE"
}

# ==============================================
# Funções de Verificação
# ==============================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script deve ser executado como root."
        exit 1
    fi
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

# ==============================================
# Gestão de Configurações
# ==============================================
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Carregando configuração de $CONFIG_FILE"
        
        # Limpar variáveis antes de carregar
        unset NET_IF DOMAIN ARCH CHOICES INSTALL_MODE FORCE_INSTALL SKIP_BACKUP \
              VERBOSE_MODE DRY_RUN NO_COLOR QUIET_MODE SKIP_PORT_CHECK 2>/dev/null || true

        # Parse seguro do arquivo de configuração
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Remover espaços em branco no início e fim da linha
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"

            # Ignorar comentários e linhas vazias
            [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

            # Verificar se a linha contém um '='
            if [[ "$line" =~ ^[[:space:]]*([^=[:space:]]+)[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
                local key="${BASH_REMATCH[1]}"
                local value="${BASH_REMATCH[2]}"

                # Validar nome da variável (deve conter apenas letras, números e underscore)
                if [[ ! "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
                    log_warn "Nome de variável inválido ignorado: '$key'"
                    continue
                fi

                # Remover aspas duplas e simples do valor
                if [[ "$value" =~ ^\"(.*)\"$ ]]; then
                    value="${BASH_REMATCH[1]}"
                elif [[ "$value" =~ ^\'(.*)\'$ ]]; then
                    value="${BASH_REMATCH[1]}"
                fi

                # Exportar a variável de forma segura
                if [[ -n "$key" ]]; then
                    export "$key"="$value"
                    log_info "Variável carregada: $key='$value'"
                fi
            else
                # Apenas registrar advertência para linhas que não estão completamente vazias
                if [[ -n "$line" ]]; then
                    log_warn "Linha mal formada ignorada: '$line'"
                fi
            fi
        done < "$CONFIG_FILE"

        log_info "Configuração carregada com sucesso"
    else
        log_error "Arquivo de configuração não encontrado: $CONFIG_FILE"
        exit 1
    fi
}

# ==============================================
# Funções de Instalação
# ==============================================
install_unbound() {
    log_info "Instalando Unbound..."
    
    # Instalar pacotes
    apt update
    apt install -y unbound unbound-anchor

    # Criar configuração
    mkdir -p /etc/unbound/unbound.conf.d
    cat << EOF > /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
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

    # Configurar arquivos necessários
    mkdir -p /var/lib/unbound
    wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root
    unbound-anchor -a /var/lib/unbound/root.key || {
        wget -O /tmp/root.key https://data.iana.org/root-anchors/icannbundle.pem
        mv /tmp/root.key /var/lib/unbound/root.key
    }

    chown -R unbound:unbound /var/lib/unbound
    chmod 644 /var/lib/unbound/root.*

    # Verificar configuração e iniciar serviço
    if unbound-checkconf; then
        systemctl restart unbound
        systemctl enable unbound
        log_info "Unbound instalado com sucesso"
    else
        log_error "Falha na configuração do Unbound"
        return 1
    fi
}

install_pihole() {
    log_info "Instalando Pi-hole..."
    
    # Instalar dependências
    apt install -y curl wget gnupg dnsutils

    # Instalar Pi-hole
    curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
    
    log_info "Pi-hole instalado"

    log_info "Configurando Pi-hole para usar Unbound..."
    sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
    pihole restartdns

    log_info "Alterando portas do Pi-hole para 8081/8443..."
    sed -i 's/server.port\s*=\s*80/server.port = 8081/' /etc/lighttpd/lighttpd.conf
    echo '$SERVER["socket"] == ":8443" { ssl.engine = "enable" }' > /etc/lighttpd/external.conf
    systemctl restart lighttpd
    log_info "Pi-hole configurado com sucesso"
}

install_rng() {
    log_info "Instalando RNG-tools..."
    
    # Instalar pacotes
    apt install -y rng-tools

    # Configurar
    local RNGDEVICE="/dev/urandom"
    [[ -e /dev/hwrng ]] && RNGDEVICE="/dev/hwrng"

    cat << EOF > /etc/default/rng-tools
RNGDEVICE="$RNGDEVICE"
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10"
EOF

    # Iniciar e habilitar serviço
    systemctl enable rng-tools
    systemctl restart rng-tools
    log_info "RNG-tools instalado com sucesso"
}

# ==============================================
# Funções de Operação
# ==============================================
install_services() {
    local services=("$@")
    log_info "Iniciando instalação dos serviços: ${services[*]}"

    for service in "${services[@]}"; do
        case "$service" in
            "UNBOUND") install_unbound ;;
            "PIHOLE") install_pihole ;;
            "RNG") install_rng ;;
            *) log_warn "Serviço desconhecido ou não suportado: $service" ;;
        esac
    done
    
    log_info "Instalação dos serviços concluída"
}

# ==============================================
# Função Principal
# ==============================================
main() {
    log_info "Iniciando BoxServer Installer Simplificado"
    
    # Verificar root
    check_root
    
    # Carregar configuração
    load_config
    
    # Verificar variáveis obrigatórias
    if [[ -z "${CHOICES:-}" ]]; then
        log_error "Nenhum serviço especificado para instalação"
        exit 1
    fi
    
    # Converter CHOICES em array
    read -ra SERVICES <<< "$CHOICES"
    
    # Instalar serviços
    install_services "${SERVICES[@]}"
    
    log_info "Instalação concluída com sucesso!"
    log_info "Log detalhado disponível em: $LOGFILE"
}

# Executar função principal
main "$@"
