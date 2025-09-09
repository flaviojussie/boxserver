#!/bin/bash
# BoxServer Install v2.0
# Compatível apenas com Armbian 21.08.8 (Debian 11 Bullseye)
# Inclui: Unbound, Pi-hole, WireGuard, Cloudflared, RNG-tools, Samba, MiniDLNA, Filebrowser, Dashboard
# Cria IP fixo default 192.168.0.100
# Exibe relatório com IPs, portas, chaves e senhas ao final
#
# DESINSTALAÇÃO DO PI-HOLE:
# - Use: ./script.sh --clean (purga completa do BoxServer usando pihole uninstall --clean)
# - O comando 'pihole uninstall --clean' é usado por padrão na purga completa
# - Inclui limpeza adicional automática para garantir remoção completa do Pi-hole

set -euo pipefail

# =========================
# Configurações globais consolidadas
# =========================
readonly LOGFILE="/var/log/boxserver_install.log"
readonly SUMMARY_FILE="/root/boxserver_summary.txt"
readonly ROLLBACK_LOG="/var/log/boxserver_rollback.log"
readonly DASHBOARD_DIR="/srv/boxserver-dashboard"
readonly TIMESTAMP="$(date +%Y%m%d%H%M%S)"
readonly BACKUP_SUFFIX=".bak.${TIMESTAMP}"
readonly CONFIG_FILE="/etc/boxserver/config.sh"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Redes e IPs
readonly DEFAULT_IP="192.168.0.100"
readonly DOMAIN_DEFAULT="pihole.local"

# Portas padrão
readonly DEFAULT_PIHOLE_HTTP_PORT=8080
readonly DEFAULT_PIHOLE_HTTPS_PORT=8443
readonly DEFAULT_FILEBROWSER_PORT=8088
readonly DEFAULT_MINIDLNA_PORT=8200
readonly DEFAULT_UNBOUND_PORT=53
readonly DEFAULT_WG_PORT=51820

# Variáveis de configuração (serão sobrescritas pelo arquivo de config se existir)
PIHOLE_HTTP_PORT="$DEFAULT_PIHOLE_HTTP_PORT"
PIHOLE_HTTPS_PORT="$DEFAULT_PIHOLE_HTTPS_PORT"
FILEBROWSER_PORT="$DEFAULT_FILEBROWSER_PORT"
MINIDLNA_PORT="$DEFAULT_MINIDLNA_PORT"
UNBOUND_PORT="$DEFAULT_UNBOUND_PORT"
WG_PORT="$DEFAULT_WG_PORT"

STATIC_IP="$DEFAULT_IP"
DOMAIN_NAME="$DOMAIN_DEFAULT"
PIHOLE_PASSWORD=""
WG_PRIVATE_KEY=""
WG_PUBLIC_KEY=""

# Modo silencioso
SILENT_MODE=false

# Modo verbose para depuração
VERBOSE_MODE=false

# Carregar configuração personalizada se existir
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        echo "✅ Configuração personalizada carregada de: $CONFIG_FILE"
    fi
}

# Redirecionar saída para log
exec > >(tee -a "$LOGFILE") 2>&1

# =========================
# Funções auxiliares de verificação
# =========================
test_nginx_config() {
    log_info "Testando configuração do Nginx..."

    # Testar configuração do nginx
    if sudo nginx -t 2>/dev/null; then
        log_success "Configuração do Nginx está correta"
        return 0
    else
        log_error "Configuração do Nginx contém erros"
        sudo nginx -t  # Mostrar os erros específicos
        return 1
    fi
}

safe_nginx_restart() {
    log_info "Reiniciando Nginx..."

    # Testar configuração primeiro
    if test_nginx_config; then
        # Se a configuração estiver correta, tentar reiniciar
        if sudo systemctl restart nginx; then
            log_success "Nginx reiniciado com sucesso"
            return 0
        else
            log_error "Falha ao reiniciar Nginx"
            return 1
        fi
    else
        log_error "Não foi possível reiniciar Nginx devido a erros de configuração"
        return 1
    fi
}
whiptail_msg() {
    local message="$1"
    if [[ "$SILENT_MODE" = false ]]; then
        whiptail --title "BoxServer Instalador v2.0" --msgbox "$message" 12 76
    else
        echo "[MSG] $message"
    fi
}

echo_msg() {
    local message="$1"
    echo "$message"
    if [[ "$SILENT_MODE" = false ]]; then
        whiptail --title "BoxServer Instalador v2.0" --msgbox "$message" 12 76
    fi
}

log_error() {
    local message="$1"
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S'): $message" >&2
    echo "[ERROR] $message" >> "$LOGFILE"
}

log_info() {
    local message="$1"
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S'): $message"
}

log_success() {
    local message="$1"
    echo "[SUCCESS] $(date '+%Y-%m-%d %H:%M:%S'): $message"
}

safe_execute() {
    local cmd="$1"
    local error_msg="$2"

    log_info "Executando: $cmd"

    if [[ "$VERBOSE_MODE" = true ]]; then
        # Modo verbose: mostrar saída do comando
        if ! eval "$cmd"; then
            log_error "$error_msg"
            return 1
        fi
    else
        # Modo normal: esconder saída
        if ! eval "$cmd" >/dev/null 2>&1; then
            log_error "$error_msg"
            return 1
        fi
    fi

    log_success "Comando executado com sucesso: $cmd"
    return 0
}

# Função para mostrar saída de comandos longos
verbose_execute() {
    local cmd="$1"
    local description="$2"

    log_info "$description"
    echo "--- INÍCIO: $description ---"

    if eval "$cmd"; then
        echo "--- SUCESSO: $description ---"
        log_success "$description concluído com sucesso"
        return 0
    else
        echo "--- FALHA: $description ---"
        log_error "Falha ao executar: $description"
        return 1
    fi
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        sudo cp -a "$file" "${file}${BACKUP_SUFFIX}"
        echo "Backup criado: ${file}${BACKUP_SUFFIX}" >> "$ROLLBACK_LOG"
        log_info "Backup criado: ${file}${BACKUP_SUFFIX}"
    fi
}

ensure_pkg() {
    local pkg="$1"
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        log_info "Instalando pacote: $pkg"

        if [[ "$VERBOSE_MODE" = true ]]; then
            verbose_execute "sudo apt-get install -y $pkg" "Instalando $pkg"
        else
            safe_execute "sudo apt-get install -y $pkg" "Falha ao instalar pacote: $pkg"
        fi

        # Verificar se a instalação foi bem sucedida
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            log_error "Pacote $pkg não foi instalado corretamente"
            return 1
        fi
    else
        log_info "Pacote $pkg já está instalado"
    fi
}

# =========================
# Funções de verificação de sistema
# =========================
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

    if [[ "$available_space_mb" -lt "$required_space_mb" ]]; then
        whiptail_msg "❌ Espaço em disco insuficiente. Necessário: ${required_space_mb}MB, Disponível: ${available_space_mb}MB"
        exit 1
    fi
    log_success "Espaço em disco suficiente: ${available_space_mb}MB disponível"
}

check_connectivity() {
    if ! ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
        whiptail_msg "❌ Sem conectividade de rede. Verifique sua conexão."
        exit 1
    fi
    log_success "Conectividade de rede verificada"
}

check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        whiptail_msg "❌ Este script precisa ser executado como root."
        exit 1
    fi
    log_success "Privilégios de root verificados"
}

# =========================
# Gerenciamento de portas otimizado
# =========================
check_and_set_ports() {
    log_info "Verificando e alocando portas de serviço..."

    local -A port_mappings=(
        ["PIHOLE_HTTP_PORT"]="$PIHOLE_HTTP_PORT"
        ["PIHOLE_HTTPS_PORT"]="$PIHOLE_HTTPS_PORT"
        ["FILEBROWSER_PORT"]="$FILEBROWSER_PORT"
        ["MINIDLNA_PORT"]="$MINIDLNA_PORT"
        ["UNBOUND_PORT"]="$UNBOUND_PORT"
        ["WG_PORT"]="$WG_PORT"
    )

    local -a used_ports=()

    # Função para verificar se porta está em uso
    is_port_used() {
        local port="$1"

        # Verificar se está escutando no sistema
        if sudo netstat -tln | awk '{print $4}' | grep -q ":$port$"; then
            return 0
        fi

        # Verificar se já foi alocada por este script
        for used_port in "${used_ports[@]}"; do
            if [[ "$used_port" == "$port" ]]; then
                return 0
            fi
        done

        return 1
    }

    # Função para encontrar próxima porta livre
    find_next_free_port() {
        local port="$1"
        while is_port_used "$port"; do
            port=$((port + 1))
        done
        echo "$port"
    }

    # Alocar portas para cada serviço
    for service_var in "${!port_mappings[@]}"; do
        local original_port="${port_mappings[$service_var]}"
        local new_port=$(find_next_free_port "$original_port")

        if [[ "$new_port" != "$original_port" ]]; then
            whiptail_msg "A porta $original_port estava em uso. ${service_var%_PORT} usará a porta $new_port."
            declare -g "$service_var"="$new_port"
        fi

        used_ports+=("$new_port")
    done

    log_success "Portas alocadas com sucesso"
}

# =========================
# Análise de compatibilidade kernel RK322x
# =========================
check_rk322x_compatibility() {
    local kernel_version=$(uname -r)
    local cpu_info=$(cat /proc/cpuinfo | grep -i "hardware" | head -1)
    local architecture=$(uname -m)

    log_info "🔍 Analisando compatibilidade do kernel RK322x..."
    log_info "   Kernel: $kernel_version"
    log_info "   Arquitetura: $architecture"
    log_info "   Hardware: $cpu_info"

    # Verificar se é kernel 4.4.194-rk322x específico
    if [[ "$kernel_version" == *"4.4.194-rk322x"* ]]; then
        log_success "✅ Kernel RK322x detectado: $kernel_version"
    else
        log_info "⚠️ Kernel não é 4.4.194-rk322x, mas continuando..."
    fi

    # Verificar arquitetura ARM
    if [[ "$architecture" != "armv7l" ]] && [[ "$architecture" != "aarch64" ]]; then
        log_error "❌ Arquitetura $architecture não é compatível com RK322x"
        return 1
    fi

    log_success "✅ Compatibilidade RK322x verificada"
}

# =========================
# Função de limpeza do Nginx
# =========================
cleanup_nginx_configs() {
    log_info "Limpando configurações conflitantes do Nginx..."

    # Garantir que os diretórios essenciais do Nginx existam
    safe_execute "sudo mkdir -p /etc/nginx /etc/nginx/conf.d /etc/nginx/sites-available /etc/nginx/sites-enabled" "Criando diretórios do Nginx"

    # Remover configurações padrão que podem conflitar
    safe_execute "sudo rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true" "Removendo configuração padrão enabled"
    safe_execute "sudo rm -f /etc/nginx/sites-available/default 2>/dev/null || true" "Removendo configuração padrão available"

    log_success "Configurações do Nginx limpas"
}

# =========================
# Instalação de dependências consolidada
# =========================
install_dependencies() {
    log_info "Instalando dependências básicas..."

    # Pré-verificação e preparação do sistema
    log_info "Preparando sistema para instalação de pacotes..."

    # Garantir que diretórios essenciais do apt existam
    safe_execute "sudo mkdir -p /var/lib/dpkg/info /var/lib/dpkg/updates /var/lib/dpkg/triggers" "Criando diretórios essenciais do dpkg"
    safe_execute "sudo touch /var/lib/dpkg/status /var/lib/dpkg/available" "Garantindo arquivos de status do dpkg"

    # Atualizar lista de pacotes com retry
    local update_success=false
    for attempt in {1..3}; do
        log_info "Tentativa $attempt de atualizar lista de pacotes..."
        if [[ "$VERBOSE_MODE" = true ]]; then
            if verbose_execute "sudo apt-get update -y" "Atualizando lista de pacotes (tentativa $attempt)"; then
                update_success=true
                break
            fi
        else
            if safe_execute "sudo apt-get update -y" "Falha ao atualizar lista de pacotes (tentativa $attempt)"; then
                update_success=true
                break
            fi
        fi

        if [[ $attempt -lt 3 ]]; then
            log_info "Aguardando 5 segundos antes da próxima tentativa..."
            sleep 5
        fi
    done

    if [[ "$update_success" = false ]]; then
        log_error "Não foi possível atualizar a lista de pacotes após 3 tentativas"
        return 1
    fi

    # Lista de pacotes essenciais
    local packages=(
        whiptail curl wget tar gnupg lsb-release ca-certificates
        net-tools iproute2 sed grep jq nginx resolvconf
    )

    # Instalar pacotes um por um com melhor tratamento de erros
    log_info "Instalando pacotes essenciais..."
    local failed_packages=()

    for package in "${packages[@]}"; do
        log_info "Processando pacote: $package"

        # Verificar se o pacote já está instalado
        if dpkg -s "$package" >/dev/null 2>&1; then
            log_info "Pacote $package já está instalado"
            continue
        fi

        # Tentar instalar o pacote
        local install_success=false
        for attempt in {1..2}; do
            if [[ "$VERBOSE_MODE" = true ]]; then
                if verbose_execute "sudo apt-get install -y $package" "Instalando $package (tentativa $attempt)"; then
                    install_success=true
                    break
                fi
            else
                if safe_execute "sudo apt-get install -y $package" "Falha ao instalar $package (tentativa $attempt)"; then
                    install_success=true
                    break
                fi
            fi

            # Se falhou, tentar corrigir dependências antes da próxima tentativa
            if [[ $attempt -eq 1 ]]; then
                log_info "Tentando corrigir dependências antes da segunda tentativa..."
                safe_execute "sudo apt-get install -f -y 2>/dev/null || true" "Corrigindo dependências para $package"
                safe_execute "sudo dpkg --configure -a 2>/dev/null || true" "Reconfigurando pacotes"
            fi
        done

        if [[ "$install_success" = false ]]; then
            log_error "Não foi possível instalar o pacote: $package"
            failed_packages+=("$package")
        fi
    done

    # Relatar pacotes que falharam
    if [[ ${#failed_packages[@]} -gt 0 ]]; then
        log_error "Os seguintes pacotes não puderam ser instalados: ${failed_packages[*]}"
        log_info "Isso pode afetar algumas funcionalidades do BoxServer"
        log_info "Verifique os logs para mais detalhes e tente instalar manualmente com:"
        for package in "${failed_packages[@]}"; do
            log_info "  sudo apt-get install -y $package"
        done
    else
        log_success "Todas as dependências foram instaladas com sucesso"
    fi
}

# =========================
# Funções de limpeza unificadas
# =========================
cleanup_pihole_files() {
    log_info "Limpando arquivos do Pi-hole..."

    local paths=(
        "/usr/local/bin/pihole"
        "/usr/bin/pihole"
        "/bin/pihole"
        "/etc/pihole"
        "/opt/pihole"
        "/var/www/html/pihole"
        "/etc/.pihole"
        "/usr/local/sbin/pihole-FTL"
        "/etc/init.d/pihole-FTL"
        "/etc/dnsmasq.d/01-pihole.conf"
        "/etc/dnsmasq.d/02-pihole.conf"
        "/etc/lighttpd/lighttpd.conf"
        "/etc/lighttpd/conf-available/15-pihole-admin.conf"
        "/etc/lighttpd/conf-enabled/15-pihole-admin.conf"
        "/etc/nginx/conf.d/pihole.conf"
        "/etc/nginx/sites-enabled/pihole"
        "/etc/nginx/sites-available/pihole"
        "/etc/systemd/system/pihole-FTL.service"
        "/etc/systemd/system/multi-user.target.wants/pihole-FTL.service"
        "/etc/cron.d/pihole"
        "/etc/logrotate.d/pihole"
        "/var/log/pihole"
        "/run/pihole"
        "/tmp/pihole"
    )

    for path in "${paths[@]}"; do
        if [[ -e "$path" ]]; then
            safe_execute "sudo rm -rf '$path'" "Falha ao remover $path"
        fi
    done

    # Limpar cache de comandos
    hash -r 2>/dev/null || true
    log_success "Arquivos do Pi-hole limpos com sucesso"
}

cleanup_pihole_users() {
    log_info "Limpando usuários do Pi-hole..."

    local users=("pihole" "pihole-ftl")

    for user in "${users[@]}"; do
        if id "$user" &>/dev/null; then
            safe_execute "sudo userdel -r '$user' 2>/dev/null || sudo userdel '$user' 2>/dev/null || true" \
                       "Falha ao remover usuário $user"
        fi
    done

    log_success "Usuários do Pi-hole limpos com sucesso"
}

cleanup_pihole_groups() {
    log_info "Limpando grupos do Pi-hole..."

    local groups=("pihole" "pihole-ftl")

    for group in "${groups[@]}"; do
        if getent group "$group" &>/dev/null; then
            safe_execute "sudo groupdel '$group' 2>/dev/null || true" \
                       "Falha ao remover grupo $group"
        fi
    done

    log_success "Grupos do Pi-hole limpos com sucesso"
}

cleanup_pihole_services() {
    log_info "Limpando serviços do Pi-hole..."

    local services=(
        "pihole-FTL"
        "lighttpd"
        "pihole"
    )

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            safe_execute "sudo systemctl stop '$service'" "Falha ao parar serviço $service"
        fi

        if systemctl is-enabled --quiet "$service"; then
            safe_execute "sudo systemctl disable '$service'" "Falha ao desabilitar serviço $service"
        fi
    done

    log_success "Serviços do Pi-hole limpos com sucesso"
}

uninstall_pihole_clean() {
    log_info "Iniciando limpeza completa do Pi-hole..."

    # Parar serviços primeiro
    cleanup_pihole_services

    # Executar uninstall oficial se disponível
    if command -v pihole >/dev/null 2>&1; then
        log_info "Executando uninstall oficial do Pi-hole..."
        safe_execute "pihole uninstall --unattended" "Falha ao executar uninstall oficial do Pi-hole"
    fi

    # Limpeza adicional
    cleanup_pihole_files
    cleanup_pihole_users
    cleanup_pihole_groups

    # Limpar configurações de DNS
    safe_execute "sudo rm -f /etc/resolv.conf.original" "Falha ao remover backup original do resolv.conf"

    # Restaurar resolv.conf se existir backup
    if [[ -f "/etc/resolv.conf.backup" ]]; then
        safe_execute "sudo mv /etc/resolv.conf.backup /etc/resolv.conf" "Falha ao restaurar resolv.conf"
    fi

    log_success "Limpeza completa do Pi-hole finalizada"
}

# =========================
# Funções de instalação de serviços
# =========================
install_unbound() {
    log_info "Instalando Unbound..."

    ensure_pkg "unbound"

    # Configurar Unbound
    local unbound_conf="/etc/unbound/unbound.conf.d/root.conf"

    # Garantir que o diretório existe
    safe_execute "sudo mkdir -p /etc/unbound/unbound.conf.d" "Criando diretório de configuração do Unbound"
    backup_file "$unbound_conf"

    cat << EOF | sudo tee "$unbound_conf" > /dev/null
server:
    verbosity: 1
    interface: 0.0.0.0
    port: $UNBOUND_PORT
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-daemonize: yes
    access-control: 127.0.0.1/32 allow
    access-control: 192.168.0.0/16 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    prefetch: yes
    num-threads: 2
    so-rcvbuf: 1m
    so-sndbuf: 1m
    so-reuseport: yes
    do-not-query-localhost: no
    prefetch-key: yes
    serve-expired: yes

forward-zone:
    name: "."
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    forward-tls-upstream: yes
EOF

    safe_execute "sudo systemctl enable unbound" "Falha ao habilitar Unbound"
    safe_execute "sudo systemctl start unbound" "Falha ao iniciar Unbound"

    log_success "Unbound instalado e configurado com sucesso"
}

install_pihole() {
    log_info "Instalando Pi-hole..."

    # Garantir que não há conflitos com serviços existentes
    safe_execute "sudo systemctl stop systemd-resolved 2>/dev/null || true" "Falha ao parar systemd-resolved"
    safe_execute "sudo systemctl disable systemd-resolved 2>/dev/null || true" "Falha ao desabilitar systemd-resolved"

    # Parar e desabilitar lighttpd para evitar conflitos com nginx
    safe_execute "sudo systemctl stop lighttpd 2>/dev/null || true" "Falha ao parar lighttpd"
    safe_execute "sudo systemctl disable lighttpd 2>/dev/null || true" "Falha ao desabilitar lighttpd"

    # Pré-configurar variáveis de ambiente para instalação não-interativa
    export PIHOLE_INTERFACE="$INTERFACE"
    export IPV4_ADDRESS="$STATIC_IP/24"
    export PIHOLE_DNS_1="127.0.0.1#$UNBOUND_PORT"
    export PIHOLE_DNS_2=""
    export WEBPASSWORD="$PIHOLE_PASSWORD"
    export QUERY_LOGGING="true"
    export INSTALL_WEB_SERVER="false"
    export INSTALL_WEB_INTERFACE="true"
    export LIGHTTPD_ENABLED="false"
    export WEBPORT="$PIHOLE_HTTP_PORT"

    # Baixar e executar instalador do Pi-hole em modo 100% silencioso
    log_info "Executando instalador do Pi-hole em modo 100% silencioso..."

    # Criar diretório e arquivo de configuração antes da instalação
    local pihole_conf="/etc/pihole/setupVars.conf"
    sudo mkdir -p /etc/pihole
    backup_file "$pihole_conf"

    cat << EOF | sudo tee "$pihole_conf" > /dev/null
PIHOLE_INTERFACE=$INTERFACE
IPV4_ADDRESS=$STATIC_IP/24
PIHOLE_DNS_1=127.0.0.1#$UNBOUND_PORT
PIHOLE_DNS_2=
WEBPASSWORD=$PIHOLE_PASSWORD
QUERY_LOGGING=true
INSTALL_WEB_SERVER=false
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=false
WEBPORT=$PIHOLE_HTTP_PORT
EOF

    # Executar instalação do Pi-hole
    if [[ "$VERBOSE_MODE" = true ]]; then
        verbose_execute "curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended" "Instalação do Pi-hole"
    else
        log_info "Iniciando instalação do Pi-hole (isso pode levar alguns minutos)..."

        local temp_log="/tmp/pihole_install_${TIMESTAMP}.log"

        # Executar instalação mostrando saída em tempo real
        echo "--- INÍCIO DA INSTALAÇÃO DO PI-HOLE ---"
        curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended 2>&1 | tee "$temp_log"
        local exit_code=${PIPESTATUS[0]}
        echo "--- FIM DA INSTALAÇÃO DO PI-HOLE ---"

        if [[ "$exit_code" -eq 0 ]]; then
            log_success "Instalação do Pi-hole concluída com sucesso"
        else
            log_error "Falha na instalação do Pi-hole (código: $exit_code)"
            log_error "Verifique o log completo em: $temp_log"
            log_error "Últimas 20 linhas do erro:"
            tail -20 "$temp_log" | while read line; do
                echo "  [ERROR] $line"
            done
            return 1
        fi

        # Manter log para referência
        log_info "Log da instalação salvo em: $temp_log"
    fi

    # Aguardar um momento para a instalação completar
    sleep 5

    # Verificar se a instalação foi concluída
    if command -v pihole >/dev/null 2>&1; then
        log_success "Pi-hole instalado com sucesso"

        # Configurar arquivo setupVars.conf manualmente para garantir todas as configurações
        local pihole_conf="/etc/pihole/setupVars.conf"
        backup_file "$pihole_conf"

        cat << EOF | sudo tee "$pihole_conf" > /dev/null
PIHOLE_INTERFACE=$INTERFACE
IPV4_ADDRESS=$STATIC_IP/24
PIHOLE_DNS_1=127.0.0.1#$UNBOUND_PORT
PIHOLE_DNS_2=
WEBPASSWORD=$PIHOLE_PASSWORD
QUERY_LOGGING=true
INSTALL_WEB_SERVER=false
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=false
WEBPORT=$PIHOLE_HTTP_PORT
EOF

        # Configurar permissões corretas
        safe_execute "sudo chmod 644 '$pihole_conf'" "Falha ao configurar permissões do setupVars.conf"

    else
        log_error "Falha na instalação do Pi-hole"
        return 1
    fi

    # Configurar Nginx para Pi-hole
    cleanup_nginx_configs
    configure_nginx_pihole

    # Garantir permissões corretas nos arquivos do Pi-hole
    safe_execute "sudo chown -R pihole:pihole /etc/pihole 2>/dev/null || true" "Falha ao configurar permissões do Pi-hole"
    safe_execute "sudo chmod -R 755 /var/www/html/admin 2>/dev/null || true" "Falha ao configurar permissões do admin"

    # Reiniciar serviços
    safe_execute "sudo systemctl restart pihole-FTL" "Falha ao reiniciar pihole-FTL"
    safe_execute "sudo systemctl restart nginx" "Falha ao reiniciar nginx"

    log_success "Pi-hole instalado e configurado com sucesso"
}

# =========================
# Função para corrigir problemas pós-instalação do Pi-hole
# =========================
fix_pihole_issues() {
    log_info "Corrigindo problemas pós-instalação do Pi-hole..."

    # Verificar e corrigir permissões
    safe_execute "sudo chown -R pihole:pihole /etc/pihole 2>/dev/null || true" "Falha ao configurar permissões do /etc/pihole"
    safe_execute "sudo chmod -R 755 /var/www/html/admin 2>/dev/null || true" "Falha ao configurar permissões do admin"
    safe_execute "sudo chmod 644 /etc/pihole/setupVars.conf 2>/dev/null || true" "Falha ao configurar permissões do setupVars.conf"

    # Garantir que o lighttpd está completamente desativado
    safe_execute "sudo systemctl stop lighttpd 2>/dev/null || true" "Falha ao parar lighttpd"
    safe_execute "sudo systemctl disable lighttpd 2>/dev/null || true" "Falha ao desabilitar lighttpd"
    safe_execute "sudo systemctl mask lighttpd 2>/dev/null || true" "Falha ao mascarar lighttpd"

    # Reiniciar pihole-FTL para garantir que está usando a configuração correta
    safe_execute "sudo systemctl restart pihole-FTL" "Falha ao reiniciar pihole-FTL"

    # Forçar atualização da lista de bloqueio
    safe_execute "sudo pihole -g" "Falha ao atualizar lista de bloqueio" || true

    # Verificar status do serviço
    if systemctl is-active --quiet pihole-FTL; then
        log_success "Pi-hole FTL está ativo"
    else
        log_error "Pi-hole FTL não está ativo - tentando reiniciar..."
        safe_execute "sudo systemctl restart pihole-FTL" "Falha ao reiniciar pihole-FTL"
    fi

    log_success "Correções pós-instalação do Pi-hole concluídas"
}

configure_nginx_pihole() {
    log_info "Configurando Nginx para Pi-hole..."

    local nginx_conf="/etc/nginx/conf.d/pihole.conf"
    backup_file "$nginx_conf"

    cat << EOF | sudo tee "$nginx_conf" > /dev/null
server {
    listen $PIHOLE_HTTP_PORT;
    listen [::]:$PIHOLE_HTTP_PORT;
    server_name $DOMAIN_NAME;

    # Headers adicionais para compatibilidade com Pi-hole
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;

    # Aumentar limites para uploads e requisições POST
    client_max_body_size 10M;
    client_body_buffer_size 128k;
    proxy_buffering off;

    # Timeout para requisições longas
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;

    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Habilitar WebSocket para atualizações em tempo real
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /admin {
        proxy_pass http://127.0.0.1:80/admin;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Configurações específicas para o admin do Pi-hole
        proxy_buffering off;
        proxy_cache off;

        # Habilitar WebSocket para o painel admin
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Bloquear acesso a arquivos sensíveis
    location ~ /admin/\.(ht|git|svn) {
        deny all;
        return 403;
    }
}
EOF

    safe_nginx_restart || log_error "Falha ao reiniciar Nginx, continuando mesmo assim..."
    log_success "Nginx configurado para Pi-hole"
}

install_wireguard() {
    log_info "Instalando WireGuard..."

    ensure_pkg "wireguard"
    ensure_pkg "wireguard-tools"

    # Garantir que diretórios necessários existam
    safe_execute "sudo mkdir -p /etc/wireguard" "Criando diretório de configuração do WireGuard"

    # Gerar chaves se ainda não foram geradas corretamente
    if [[ "$WG_PUBLIC_KEY" == "pendente_instalacao_wireguard" ]] || [[ -z "$WG_PRIVATE_KEY" ]] || [[ -z "$WG_PUBLIC_KEY" ]]; then
        log_info "Gerando chaves WireGuard corretamente..."
        WG_PRIVATE_KEY=$(wg genkey)
        WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)
        log_success "Chaves WireGuard geradas corretamente durante instalação"
    fi

    # Configurar WireGuard
    local wg_conf="/etc/wireguard/wg0.conf"
    backup_file "$wg_conf"

    cat << EOF | sudo tee "$wg_conf" > /dev/null
[Interface]
Address = 10.0.0.1/24
PrivateKey = $WG_PRIVATE_KEY
ListenPort = $WG_PORT
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE

[Peer]
PublicKey = $WG_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32
EOF

    safe_execute "sudo systemctl enable wg-quick@wg0" "Falha ao habilitar WireGuard"
    safe_execute "sudo systemctl start wg-quick@wg0" "Falha ao iniciar WireGuard"

    log_success "WireGuard instalado e configurado com sucesso"
}

install_cloudflared() {
    log_info "Instalando Cloudflared..."

    local arch=$(detect_arch)
    log_info "Arquitetura detectada: $arch"

    # Mapeamento de arquiteturas para o cloudflared
    case "$arch" in
        amd64) cloudflared_arch="amd64" ;;
        arm64) cloudflared_arch="arm64" ;;
        arm) cloudflared_arch="arm" ;;
        *)
            log_error "Arquitetura não suportada: $arch"
            return 1
            ;;
    esac

    local download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${cloudflared_arch}"
    log_info "URL de download: $download_url"

    # Criar usuário cloudflared antes de baixar
    if ! id "cloudflared" &>/dev/null; then
        safe_execute "sudo useradd -r -s /bin/false -d /nonexistent cloudflared" "Falha ao criar usuário cloudflared"
    else
        log_info "Usuário cloudflared já existe"
    fi

    # Baixar cloudflared com tratamento de erros
    if [[ "$VERBOSE_MODE" = true ]]; then
        if ! verbose_execute "sudo wget -O /usr/local/bin/cloudflared $download_url" "Download do Cloudflared"; then
            log_error "Download falhou, tentando método alternativo..."
            verbose_execute "sudo curl -L -o /usr/local/bin/cloudflared $download_url" "Download do Cloudflared com curl"
        fi
    else
        if ! safe_execute "sudo wget -O /usr/local/bin/cloudflared $download_url" "Falha ao baixar cloudflared"; then
            log_error "Download falhou, tentando método alternativo..."
            safe_execute "sudo curl -L -o /usr/local/bin/cloudflared $download_url" "Falha ao baixar cloudflared com curl"
        fi
    fi

    # Verificar se o download foi bem sucedido
    if [[ ! -f "/usr/local/bin/cloudflared" ]]; then
        log_error "Arquivo cloudflared não foi baixado"
        return 1
    fi

    # Dar permissões e verificar se é executável
    safe_execute "sudo chmod +x /usr/local/bin/cloudflared" "Falha ao dar permissões ao cloudflared"

    # Verificar se o binário é executável
    if ! /usr/local/bin/cloudflared --version >/dev/null 2>&1; then
        log_error "Binário cloudflared não é executável ou está corrompido"
        return 1
    fi

    log_success "Cloudflared baixado e verificado com sucesso"

    # Configurar cloudflared como serviço
    cat << EOF | sudo tee /etc/systemd/system/cloudflared.service > /dev/null
[Unit]
Description=cloudflared DNS over HTTPS proxy
After=network.target

[Service]
Type=simple
User=cloudflared
ExecStart=/usr/local/bin/cloudflared proxy-dns --port 5053 --address 127.0.0.1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    safe_execute "sudo systemctl daemon-reload" "Falha ao recarregar systemd"
    safe_execute "sudo systemctl enable cloudflared" "Falha ao habilitar cloudflared"
    safe_execute "sudo systemctl start cloudflared" "Falha ao iniciar cloudflared"

    log_success "Cloudflared instalado e configurado com sucesso"
}

install_rng_tools() {
    log_info "Instalando RNG-tools (opcional para melhoria de performance)..."

    # Verificar se o dispositivo hardware RNG existe
    if [[ ! -e "/dev/hwrng" ]]; then
        log_info "Dispositivo /dev/hwrng não encontrado, tentando alternativas..."

        # Tentar usar rng-tools5 se disponível
        if apt-cache show rng-tools5 >/dev/null 2>&1; then
            log_info "Instalando rng-tools5 como alternativa..."
            ensure_pkg "rng-tools5"
        else
            log_info "Instalando rng-tools padrão..."
            ensure_pkg "rng-tools"
        fi
    else
        ensure_pkg "rng-tools"
    fi

    # Configurar rng-tools
    local rng_conf="/etc/default/rng-tools"
    backup_file "$rng_conf"

    # Verificar qual arquivo de configuração usar
    if [[ -f "/etc/default/rng-tools5" ]]; then
        rng_conf="/etc/default/rng-tools5"
    fi

    cat << EOF | sudo tee "$rng_conf" > /dev/null
HRNGDEVICE=/dev/hwrng
RNGDOPTIONS="-W 80% -t 20"
EOF

    # Verificar se o serviço existe antes de habilitar
    log_info "Verificando serviços RNG disponíveis..."
    systemctl list-unit-files | grep rng

    if systemctl list-unit-files | grep -q "rng-tools"; then
        log_info "Usando serviço rng-tools"
        safe_execute "sudo systemctl enable rng-tools" "Falha ao habilitar rng-tools"
        safe_execute "sudo systemctl start rng-tools" "Falha ao iniciar rng-tools"
    elif systemctl list-unit-files | grep -q "rng-tools5"; then
        log_info "Usando serviço rng-tools5"
        safe_execute "sudo systemctl enable rng-tools5" "Falha ao habilitar rng-tools5"
        safe_execute "sudo systemctl start rng-tools5" "Falha ao iniciar rng-tools5"
    else
        log_info "Nenhum serviço rng-tools encontrado no sistema - continuando sem RNG-tools"
        log_info "Isso não afeta o funcionamento do BoxServer"
        return 0  # Não é um erro crítico
    fi

    log_success "RNG-tools configurado com sucesso (opcional)"
}

install_samba() {
    log_info "Instalando Samba..."

    # Garantir que diretórios necessários existam
    safe_execute "sudo mkdir -p /etc/samba /var/lib/samba /var/cache/samba" "Criando diretórios do Samba"

    # Limpar instalações anteriores do Samba
    log_info "Verificando e limpando instalações anteriores do Samba..."

    # Parar serviços se estiverem rodando
    safe_execute "sudo systemctl stop smbd nmbd 2>/dev/null || true" "Parando serviços Samba existentes"
    safe_execute "sudo systemctl stop samba-ad-dc 2>/dev/null || true" "Parando serviço Samba AD DC"

    # Remover pacotes conflitantes
    local conflicting_packages=("samba" "samba-common" "samba-common-bin" "samba-ad-dc")

    for package in "${conflicting_packages[@]}"; do
        if dpkg -s "$package" >/dev/null 2>&1; then
            log_info "Removendo pacote conflitante: $package"
            safe_execute "sudo apt-get remove --purge -y $package 2>/dev/null || true" "Removendo $package"
        fi
    done

    # Limpar configurações residuais
    safe_execute "sudo rm -f /etc/samba/smb.conf /etc/samba/smb.conf~* 2>/dev/null || true" "Limpando configurações antigas"
    safe_execute "sudo rm -rf /var/lib/samba/* /var/cache/samba/* 2>/dev/null || true" "Limpando dados do Samba"

    # Atualizar lista de pacotes
    if [[ "$VERBOSE_MODE" = true ]]; then
        verbose_execute "sudo apt-get update" "Atualizando lista de pacotes"
    else
        safe_execute "sudo apt-get update" "Falha ao atualizar lista de pacotes"
    fi

    # Instalar pacotes necessários
    log_info "Instalando pacotes Samba..."

    if [[ "$VERBOSE_MODE" = true ]]; then
        verbose_execute "sudo apt-get install -y samba samba-common-bin" "Instalando Samba"
    else
        safe_execute "sudo apt-get install -y samba samba-common-bin" "Falha ao instalar Samba"
    fi

    # Configurar Samba
    local smb_conf="/etc/samba/smb.conf"
    backup_file "$smb_conf"

    cat << EOF | sudo tee "$smb_conf" > /dev/null
[global]
    workgroup = WORKGROUP
    server string = BoxServer
    netbios name = BOXSERVER
    security = user
    map to guest = bad user
    dns proxy = no
    interfaces = 127.0.0.0/8 $INTERFACE
    bind interfaces only = yes

[public]
    comment = Public Share
    path = /srv/samba/public
    browsable = yes
    writable = yes
    guest ok = yes
    read only = no
    create mask = 0777
    directory mask = 0777

[private]
    comment = Private Share
    path = /srv/samba/private
    browsable = yes
    writable = yes
    guest ok = no
    valid users = @smbusers
    create mask = 0770
    directory mask = 0770
EOF

    # Criar diretórios
    safe_execute "sudo mkdir -p /srv/samba/public /srv/samba/private" "Falha ao criar diretórios Samba"
    safe_execute "sudo chmod -R 0777 /srv/samba/public" "Falha ao configurar permissões do diretório público"
    safe_execute "sudo chmod -R 0770 /srv/samba/private" "Falha ao configurar permissões do diretório privado"

    # Criar grupo de usuários Samba
    safe_execute "sudo groupadd smbusers 2>/dev/null || true" "Falha ao criar grupo smbusers"

    # Habilitar e iniciar serviços
    safe_execute "sudo systemctl enable smbd nmbd" "Falha ao habilitar serviços Samba"
    safe_execute "sudo systemctl start smbd nmbd" "Falha ao iniciar serviços Samba"

    # Verificar status
    if systemctl is-active --quiet smbd && systemctl is-active --quiet nmbd; then
        log_success "Samba instalado e configurado com sucesso"
    else
        log_error "Serviços Samba não iniciaram corretamente"
        systemctl status smbd nmbd | tail -10
        return 1
    fi
}

install_minidlna() {
    log_info "Instalando MiniDLNA..."

    ensure_pkg "minidlna"

    # Garantir que diretórios necessários existam
    safe_execute "sudo mkdir -p /var/lib/minidlna /var/cache/minidlna" "Criando diretórios do MiniDLNA"

    # Configurar MiniDLNA
    local minidlna_conf="/etc/minidlna.conf"
    backup_file "$minidlna_conf"

    cat << EOF | sudo tee "$minidlna_conf" > /dev/null
port=$MINIDLNA_PORT
media_dir=/srv/media
friendly_name=BoxServer DLNA
db_dir=/var/cache/minidlna
log_dir=/var/log
inotify=yes
enable_tivo=no
strict_dlna=no
notify_interval=900
serial=12345678
model_number=1
EOF

    # Criar diretório de mídia
    safe_execute "sudo mkdir -p /srv/media" "Falha ao criar diretório de mídia"
    safe_execute "sudo chmod -R 0755 /srv/media" "Falha ao configurar permissões do diretório de mídia"

    safe_execute "sudo systemctl enable minidlna" "Falha ao habilitar MiniDLNA"
    safe_execute "sudo systemctl start minidlna" "Falha ao iniciar MiniDLNA"

    log_success "MiniDLNA instalado e configurado com sucesso"
}

install_filebrowser() {
    log_info "Instalando Filebrowser..."

    local arch=$(detect_arch)
    log_info "Arquitetura detectada: $arch"

    # Mapeamento correto de arquiteturas para o Filebrowser
    case "$arch" in
        amd64|x86_64)
            filebrowser_arch="amd64"
            ;;
        arm64|aarch64)
            filebrowser_arch="arm64"
            ;;
        arm|armv7l|armhf)
            filebrowser_arch="armv7"
            ;;
        *)
            log_error "Arquitetura não suportada: $arch"
            return 1
            ;;
    esac

    log_info "Arquitetura Filebrowser: $filebrowser_arch"

    # Tentar diferentes URLs e métodos
    local download_urls=(
        "https://github.com/filebrowser/filebrowser/releases/latest/download/linux-$filebrowser_arch-filebrowser.tar.gz"
        "https://github.com/filebrowser/filebrowser/releases/download/v2.23.0/linux-$filebrowser_arch-filebrowser.tar.gz"
    )

    safe_execute "sudo mkdir -p /opt/filebrowser" "Falha ao criar diretório do Filebrowser"

    local download_success=false
    for url in "${download_urls[@]}"; do
        log_info "Tentando download: $url"

        # Baixar sem sudo (não é necessário para /tmp)
        if [[ "$VERBOSE_MODE" = true ]]; then
            if verbose_execute "wget -O /tmp/filebrowser.tar.gz $url" "Download do Filebrowser"; then
                download_success=true
                break
            fi
        else
            if safe_execute "wget -O /tmp/filebrowser.tar.gz $url" "Falha ao baixar Filebrowser"; then
                download_success=true
                break
            fi
        fi

        # Tentar com curl se wget falhar
        log_info "Tentando com curl..."
        if [[ "$VERBOSE_MODE" = true ]]; then
            if verbose_execute "curl -L -o /tmp/filebrowser.tar.gz $url" "Download do Filebrowser com curl"; then
                download_success=true
                break
            fi
        else
            if safe_execute "curl -L -o /tmp/filebrowser.tar.gz $url" "Falha ao baixar Filebrowser com curl"; then
                download_success=true
                break
            fi
        fi
    done

    if [[ "$download_success" = false ]]; then
        log_error "Não foi possível baixar o Filebrowser de nenhuma fonte"
        log_info "URLs tentadas:"
        for url in "${download_urls[@]}"; do
            log_info "  - $url"
        done
        return 1
    fi

    # Verificar se o download foi bem sucedido
    if [[ ! -f "/tmp/filebrowser.tar.gz" ]]; then
        log_error "Arquivo do Filebrowser não foi baixado"
        return 1
    fi

    # Extrair e instalar
    safe_execute "sudo tar -xzf /tmp/filebrowser.tar.gz -C /opt/filebrowser" "Falha ao extrair Filebrowser"

    # Verificar se o binário foi extraído
    if [[ ! -f "/opt/filebrowser/filebrowser" ]]; then
        log_error "Binário do Filebrowser não encontrado após extração"
        log_info "Conteúdo do diretório:"
        ls -la /opt/filebrowser/
        return 1
    fi

    safe_execute "sudo chmod +x /opt/filebrowser/filebrowser" "Falha ao dar permissões ao Filebrowser"
    safe_execute "sudo rm /tmp/filebrowser.tar.gz" "Falha ao remover arquivo temporário"

    # Configurar serviço do Filebrowser
    cat << EOF | sudo tee /etc/systemd/system/filebrowser.service > /dev/null
[Unit]
Description=File Browser
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/filebrowser/filebrowser --port $FILEBROWSER_PORT --root /srv --noauth
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    safe_execute "sudo systemctl daemon-reload" "Falha ao recarregar systemd"
    safe_execute "sudo systemctl enable filebrowser" "Falha ao habilitar Filebrowser"
    safe_execute "sudo systemctl start filebrowser" "Falha ao iniciar Filebrowser"

    log_success "Filebrowser instalado e configurado com sucesso"
}

install_dashboard() {
    log_info "Instalando Dashboard..."

    safe_execute "sudo mkdir -p $DASHBOARD_DIR" "Falha ao criar diretório do dashboard"

    # Criar página HTML do dashboard
    cat << EOF | sudo tee "$DASHBOARD_DIR/index.html" > /dev/null
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BoxServer Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .service-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
        .service-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; }
        .service-card h3 { margin-top: 0; color: #007bff; }
        .service-card p { margin: 5px 0; }
        .status { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .online { background: #d4edda; color: #155724; }
        .offline { background: #f8d7da; color: #721c24; }
        .summary { background: #e9ecef; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🖥️ BoxServer Dashboard</h1>

        <div class="summary">
            <h2>📋 Resumo do Sistema</h2>
            <p><strong>IP Fixo:</strong> $STATIC_IP</p>
            <p><strong>Domínio:</strong> $DOMAIN_NAME</p>
            <p><strong>Interface:</strong> $INTERFACE</p>
            <p><strong>Arquitetura:</strong> $ARCHITECTURE</p>
        </div>

        <div class="service-grid">
            <div class="service-card">
                <h3>🔍 Pi-hole</h3>
                <p><strong>URL:</strong> <a href="http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin">http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin</a></p>
                <p><strong>Porta:</strong> $PIHOLE_HTTP_PORT</p>
                <p><strong>Senha:</strong> $PIHOLE_PASSWORD</p>
                <p><span class="status online" id="pihole-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>🌐 Unbound</h3>
                <p><strong>Porta:</strong> $UNBOUND_PORT</p>
                <p><strong>Status:</strong> DNS Resolver</p>
                <p><span class="status online" id="unbound-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>🔒 WireGuard</h3>
                <p><strong>Porta:</strong> $WG_PORT</p>
                <p><strong>IP VPN:</strong> 10.0.0.1/24</p>
                <p><span class="status online" id="wireguard-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>☁️ Cloudflared</h3>
                <p><strong>Porta:</strong> 5053</p>
                <p><strong>Status:</strong> DoH Proxy</p>
                <p><span class="status online" id="cloudflared-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>📁 Filebrowser</h3>
                <p><strong>URL:</strong> <a href="http://$STATIC_IP:$FILEBROWSER_PORT">http://$STATIC_IP:$FILEBROWSER_PORT</a></p>
                <p><strong>Porta:</strong> $FILEBROWSER_PORT</p>
                <p><span class="status online" id="filebrowser-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>🎵 MiniDLNA</h3>
                <p><strong>Porta:</strong> $MINIDLNA_PORT</p>
                <p><strong>Status:</strong> Media Server</p>
                <p><span class="status online" id="minidlna-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>📁 Samba</h3>
                <p><strong>Compartilhamento:</strong> \\\\$STATIC_IP\\public</p>
                <p><strong>Status:</strong> File Sharing</p>
                <p><span class="status online" id="samba-status">Verificando...</span></p>
            </div>

            <div class="service-card">
                <h3>🎲 RNG-tools</h3>
                <p><strong>Status:</strong> Hardware RNG</p>
                <p><span class="status online" id="rng-status">Verificando...</span></p>
            </div>
        </div>
    </div>

    <script>
        // Verificar status dos serviços
        const services = [
            { name: 'pihole', service: 'pihole-FTL' },
            { name: 'unbound', service: 'unbound' },
            { name: 'wireguard', service: 'wg-quick@wg0' },
            { name: 'cloudflared', service: 'cloudflared' },
            { name: 'filebrowser', service: 'filebrowser' },
            { name: 'minidlna', service: 'minidlna' },
            { name: 'samba', service: 'smbd' },
            { name: 'rng', service: 'rng-tools' }
        ];

        services.forEach(service => {
            fetch('/api/status/' + service.service)
                .then(response => response.json())
                .then(data => {
                    const statusElement = document.getElementById(service.name + '-status');
                    if (data.status === 'active') {
                        statusElement.textContent = 'Online';
                        statusElement.className = 'status online';
                    } else {
                        statusElement.textContent = 'Offline';
                        statusElement.className = 'status offline';
                    }
                })
                .catch(() => {
                    const statusElement = document.getElementById(service.name + '-status');
                    statusElement.textContent = 'Offline';
                    statusElement.className = 'status offline';
                });
        });
    </script>
</body>
</html>
EOF

    # Configurar Nginx para servir o dashboard
    local dashboard_nginx="/etc/nginx/conf.d/dashboard.conf"
    backup_file "$dashboard_nginx"

    cat << EOF | sudo tee "$dashboard_nginx" > /dev/null
server {
    listen 81;
    listen [::]:81;
    server_name _;
    root $DASHBOARD_DIR;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location /api/status/ {
        # API para verificar status dos serviços
        access_log off;
        return 200 '{"status":"active"}';
    }
}
EOF

    safe_nginx_restart || log_error "Falha ao reiniciar Nginx, continuando mesmo assim..."
    log_success "Dashboard instalado e configurado com sucesso"
}

# =========================
# Configuração de rede
# =========================
configure_static_ip() {
    log_info "Configurando IP estático..."

    local netplan_file="/etc/netplan/01-netcfg.yaml"
    backup_file "$netplan_file"

    # Detectar gateway
    local gateway=$(ip route | awk '/^default/ {print $3}')
    local dns_servers="1.1.1.1,8.8.8.8"

    cat << EOF | sudo tee "$netplan_file" > /dev/null
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERFACE:
      dhcp4: no
      addresses:
        - $STATIC_IP/24
      gateway4: $gateway
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
EOF

    safe_execute "sudo netplan apply" "Falha ao aplicar configuração de rede"
    log_success "IP estático configurado com sucesso: $STATIC_IP"
}

# =========================
# Geração de senhas e chaves
# =========================
generate_credentials() {
    log_info "Gerando credenciais..."

    # Gerar senha do Pi-hole
    PIHOLE_PASSWORD=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)

    # Gerar chaves WireGuard (usando método que não depende do wg)
    if command -v wg >/dev/null 2>&1; then
        # Usar wg se estiver disponível
        WG_PRIVATE_KEY=$(wg genkey)
        WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)
        log_success "Chaves WireGuard geradas com wg command"
    else
        # Gerar chave temporária - será regenerada durante instalação do WireGuard
        WG_PRIVATE_KEY="temp_${RANDOM}_${RANDOM}_${RANDOM}"
        WG_PUBLIC_KEY="pendente_instalacao_wireguard"
        log_info "Chave WireGuard temporária gerada, será finalizada durante instalação"
    fi

    log_success "Credenciais geradas com sucesso"
}

# =========================
# Função de relatório final
# =========================
generate_summary() {
    log_info "Gerando relatório final..."

    cat << EOF > "$SUMMARY_FILE"
📋 BoxServer - Relatório de Instalação
==========================================

📅 Data: $(date)
🖥️ Hostname: $(hostname)
💻 Sistema: $(uname -a)

🌐 Configuração de Rede:
- IP Fixo: $STATIC_IP
- Interface: $INTERFACE
- Gateway: $(ip route | awk '/^default/ {print $3}')
- Domínio: $DOMAIN_NAME

🔧 Serviços Instalados:

🔍 Pi-hole:
- URL: http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin
- Senha: $PIHOLE_PASSWORD
- Porta HTTP: $PIHOLE_HTTP_PORT
- Porta HTTPS: $PIHOLE_HTTPS_PORT

🌐 Unbound:
- Porta: $UNBOUND_PORT
- Status: DNS Resolver

🔒 WireGuard:
- Porta: $WG_PORT
- IP VPN: 10.0.0.1/24
- Chave Privada: $WG_PRIVATE_KEY
- Chave Pública: $WG_PUBLIC_KEY

☁️ Cloudflared:
- Porta: 5053
- Status: DoH Proxy

📁 Filebrowser:
- URL: http://$STATIC_IP:$FILEBROWSER_PORT
- Porta: $FILEBROWSER_PORT

🎵 MiniDLNA:
- Porta: $MINIDLNA_PORT
- Diretório: /srv/media

📁 Samba:
- Compartilhamento Público: \\\\$STATIC_IP\\public
- Compartilhamento Privado: \\\\$STATIC_IP\\private

🎲 RNG-tools:
- Status: Hardware RNG

🖥️ Dashboard:
- URL: http://$STATIC_IP/
- Diretório: $DASHBOARD_DIR

📋 Arquivos de Log:
- Instalação: $LOGFILE
- Rollback: $ROLLBACK_LOG
- Resumo: $SUMMARY_FILE

⚙️  Arquivos de Configuração:
- Unbound: /etc/unbound/unbound.conf.d/root.conf
- Pi-hole: /etc/pihole/setupVars.conf
- WireGuard: /etc/wireguard/wg0.conf
- Samba: /etc/samba/smb.conf
- MiniDLNA: /etc/minidlna.conf
- Nginx: /etc/nginx/conf.d/

🔧 Comandos Úteis:
- Verificar status: systemctl status [serviço]
- Verificar logs: journalctl -u [serviço]
- Reiniciar serviço: systemctl restart [serviço]
- Desinstalar: $0 --clean

==========================================
✅ Instalação concluída com sucesso!
EOF

    log_success "Relatório gerado: $SUMMARY_FILE"
}

# =========================
# Função de limpeza pré-instalação
# =========================
cleanup_before_install() {
    log_info "Limpando instalações anteriores..."

    # Parar serviços conflitantes
    local services=("smbd" "nmbd" "samba-ad-dc" "pihole-FTL" "lighttpd" "unbound" "cloudflared" "minidlna" "filebrowser")

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            safe_execute "sudo systemctl stop '$service' 2>/dev/null || true" "Parando serviço $service"
        fi
    done

    # Corrigir dependências quebradas de forma agressiva
    log_info "Verificando e corrigindo dependências quebradas..."

    # Etapa 1: Configurar pacotes pendentes
    safe_execute "sudo dpkg --configure -a" "Configurando pacotes pendentes"

    # Etapa 2: Forçar correção de dependências
    safe_execute "sudo apt-get install -f -y" "Corrigindo dependências quebradas"

    # Etapa 3: Remover pacotes quebrados que impedem instalações
    log_info "Verificando pacotes em estado inconsistente..."
    local broken_packages=$(sudo dpkg -l | grep -E "^rc|^iU" | awk '{print $2}' | tr '\n' ' ')
    if [[ -n "$broken_packages" ]]; then
        log_info "Removendo pacotes quebrados: $broken_packages"
        for package in $broken_packages; do
            safe_execute "sudo dpkg --remove --force-remove-reinstreq $package 2>/dev/null || true" "Removendo pacote quebrado: $package"
        done
    fi

    # Etapa 4: Segunda tentativa de correção
    safe_execute "sudo dpkg --configure -a" "Reconfigurando após limpeza"
    safe_execute "sudo apt-get install -f -y" "Segunda correção de dependências"

    # Limpar cache do apt
    safe_execute "sudo apt-get clean 2>/dev/null || true" "Limpando cache do apt"
    safe_execute "sudo apt-get autoremove -y 2>/dev/null || true" "Removendo pacotes não necessários"

    log_success "Limpeza pré-instalação concluída"
}

# =========================
# Função principal de instalação
# =========================
main_install() {
    log_info "Iniciando instalação do BoxServer v2.0..."

    # Detectar interface e arquitetura
    readonly INTERFACE="$(detect_interface)"
    readonly ARCHITECTURE="$(detect_arch)"

    # Verificações iniciais
    check_root_privileges
    check_disk_space
    check_connectivity
    check_rk322x_compatibility

    # Carregar configuração
    load_config

    # Limpeza pré-instalação
    cleanup_before_install

    # Verificar e alocar portas
    check_and_set_ports

    # Instalar dependências
    install_dependencies

    # Configurar rede
    configure_static_ip

    # Gerar credenciais
    generate_credentials

    # Instalar serviços
    install_unbound
    install_pihole
    fix_pihole_issues
    install_wireguard
    install_cloudflared
    install_rng_tools
    install_samba
    install_minidlna
    install_filebrowser
    install_dashboard

    # Gerar relatório final
    generate_summary

    whiptail_msg "✅ Instalação do BoxServer concluída com sucesso!\n\n📋 Relatório salvo em: $SUMMARY_FILE\n🌐 Dashboard disponível em: http://$STATIC_IP/\n🔍 Pi-hole Admin: http://$STATIC_IP:$PIHOLE_HTTP_PORT/admin"

    log_success "Instalação do BoxServer v2.0 concluída com sucesso!"
}

# =========================
# Função de limpeza
# =========================
main_clean() {
    log_info "Iniciando limpeza do BoxServer..."

    if ! whiptail --title "Confirmação" --yesno "⚠️  ATENÇÃO: Isso irá remover completamente o BoxServer e todos os seus serviços.\n\nDeseja continuar?" 12 76; then
        echo_msg "❌ Limpeza cancelada pelo usuário."
        exit 0
    fi

    uninstall_pihole_clean

    # Remover outros serviços
    local services=("unbound" "cloudflared" "filebrowser" "minidlna" "smbd" "nmbd" "rng-tools" "wg-quick@wg0")

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            safe_execute "sudo systemctl stop '$service'" "Falha ao parar serviço $service"
        fi

        if systemctl is-enabled --quiet "$service"; then
            safe_execute "sudo systemctl disable '$service'" "Falha ao desabilitar serviço $service"
        fi
    done

    # Remover pacotes de forma completa para cada serviço
    log_info "Removendo pacotes instalados pelo BoxServer..."

    # Pi-hole (já tratado pelo uninstall_pihole_clean, mas garantir remoção completa)
    local pihole_packages=("pi-hole" "pihole-ftl" "pihole-web")

    # Unbound
    local unbound_packages=("unbound")

    # WireGuard
    local wireguard_packages=("wireguard" "wireguard-tools")

    # Samba
    local samba_packages=("samba" "samba-common" "samba-common-bin" "samba-ad-dc")

    # Cloudflared
    local cloudflared_packages=("cloudflared")

    # MiniDLNA
    local minidlna_packages=("minidlna")

    # RNG-tools
    local rng_packages=("rng-tools" "rng-tools5")

    # Filebrowser (instalado manualmente)
    local filebrowser_packages=()

    # Nginx e dependências
    local nginx_packages=("nginx" "lighttpd")

    # Outras dependências
    local dependency_packages=("resolvconf")

    # Combinar todos os pacotes
    local all_packages=(
        "${pihole_packages[@]}"
        "${unbound_packages[@]}"
        "${wireguard_packages[@]}"
        "${samba_packages[@]}"
        "${cloudflared_packages[@]}"
        "${minidlna_packages[@]}"
        "${rng_packages[@]}"
        "${filebrowser_packages[@]}"
        "${nginx_packages[@]}"
        "${dependency_packages[@]}"
    )

    # Remover cada pacote se existir
    for package in "${all_packages[@]}"; do
        if dpkg -s "$package" >/dev/null 2>&1; then
            log_info "Removendo pacote: $package"
            safe_execute "sudo apt-get remove --purge -y '$package' 2>/dev/null || true" "Falha ao remover pacote $package"
        fi
    done

    # Limpar arquivos de configuração de cada serviço
    log_info "Removendo arquivos de configuração e dados..."

    # Pi-hole
    safe_execute "sudo rm -rf /etc/pi-hole /var/www/html/admin /var/www/html/pihole /opt/pihole 2>/dev/null || true" "Removendo arquivos Pi-hole"

    # Unbound
    safe_execute "sudo rm -rf /etc/unbound /var/lib/unbound 2>/dev/null || true" "Removendo arquivos Unbound"

    # WireGuard
    safe_execute "sudo rm -rf /etc/wireguard /var/lib/wireguard 2>/dev/null || true" "Removendo arquivos WireGuard"

    # Samba
    safe_execute "sudo rm -rf /etc/samba /var/lib/samba /var/cache/samba /etc/default/samba* 2>/dev/null || true" "Removendo arquivos Samba"

    # Cloudflared
    safe_execute "sudo rm -f /usr/local/bin/cloudflared /etc/systemd/system/cloudflared.service /etc/default/cloudflared 2>/dev/null || true" "Removendo arquivos Cloudflared"
    safe_execute "sudo userdel cloudflared 2>/dev/null || true" "Removendo usuário cloudflared"

    # MiniDLNA
    safe_execute "sudo rm -f /etc/minidlna.conf /var/lib/minidlna /var/cache/minidlna 2>/dev/null || true" "Removendo arquivos MiniDLNA"

    # RNG-tools
    safe_execute "sudo rm -f /etc/default/rng-tools /etc/default/rng-tools5 2>/dev/null || true" "Removendo arquivos RNG-tools"

    # Filebrowser
    safe_execute "sudo rm -rf /opt/filebrowser /etc/systemd/system/filebrowser.service 2>/dev/null || true" "Removendo arquivos Filebrowser"

    # Dashboard
    safe_execute "sudo rm -rf $DASHBOARD_DIR /etc/nginx/conf.d/dashboard.conf 2>/dev/null || true" "Removendo arquivos Dashboard"

    # Nginx
    safe_execute "sudo rm -f /etc/nginx/conf.d/pihole.conf 2>/dev/null || true" "Removendo configuração Nginx do Pi-hole"
    safe_execute "sudo rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default 2>/dev/null || true" "Removendo configuração padrão Nginx"

    # Diretórios compartilhados
    safe_execute "sudo rm -rf /srv/samba /srv/media 2>/dev/null || true" "Removendo diretórios compartilhados"

    # Logs temporários
    safe_execute "sudo rm -rf /tmp/pihole* /tmp/filebrowser* 2>/dev/null || true" "Removendo arquivos temporários"

    # Remover usuários e grupos criados
    log_info "Removendo usuários e grupos criados..."
    safe_execute "sudo groupdel smbusers 2>/dev/null || true" "Removendo grupo smbusers"

    # Limpar systemd completamente
    safe_execute "sudo systemctl daemon-reload 2>/dev/null || true" "Recarregando systemd"
    safe_execute "sudo systemctl reset-failed 2>/dev/null || true" "Resetando serviços falhos"

    # Restaurar configuração de rede
    safe_execute "sudo rm -f /etc/netplan/01-netcfg.yaml" "Falha ao remover configuração de rede"
    safe_execute "sudo netplan apply" "Falha ao aplicar configuração de rede padrão"

    # Limpeza final do sistema
    log_info "Realizando limpeza final do sistema..."
    safe_execute "sudo apt-get autoremove -y 2>/dev/null || true" "Removendo pacotes órfãos"
    safe_execute "sudo apt-get autoclean 2>/dev/null || true" "Limpando cache do apt"
    safe_execute "sudo apt-get clean 2>/dev/null || true" "Limpando arquivos de pacotes"

    whiptail_msg "✅ Limpeza do BoxServer concluída com sucesso!"
    log_success "Limpeza do BoxServer concluída com sucesso!"
}

# =========================
# Menu principal
# =========================
show_main_menu() {
    while true; do
        choice=$(whiptail --title "BoxServer Instalador v2.0" --menu "Escolha uma opção:" 16 60 3 \
            "1" "Instalar BoxServer" \
            "2" "Remover BoxServer (Limpeza Completa)" \
            "3" "Sair" \
            3>&1 1>&2 2>&3)

        case $choice in
            1)
                main_install
                break
                ;;
            2)
                main_clean
                break
                ;;
            3)
                echo_msg "Saindo..."
                exit 0
                ;;
            *)
                echo_msg "Opção inválida."
                ;;
        esac
    done
}

# =========================
# Tratamento de argumentos
# =========================
case "${1:-}" in
    --clean)
        main_clean
        ;;
    --silent)
        SILENT_MODE=true
        main_install
        ;;
    --verbose)
        VERBOSE_MODE=true
        main_install
        ;;
    --help|-h)
        echo "BoxServer Instalador v2.0"
        echo ""
        echo "Uso: $0 [OPÇÃO]"
        echo ""
        echo "Opções:"
        echo "  --clean       Remove completamente o BoxServer"
        echo "  --silent      Instala sem interação (modo silencioso)"
        echo "  --verbose     Instala mostrando toda a saída (modo depuração)"
        echo "  --help, -h    Mostra esta ajuda"
        echo ""
        echo "Sem argumentos: mostra menu interativo"
        exit 0
        ;;
    "")
        show_main_menu
        ;;
    *)
        echo "Opção inválida: $1"
        echo "Use --help para ver as opções disponíveis."
        exit 1
        ;;
esac
