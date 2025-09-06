#!/bin/bash

###############################################################################
# BOXSERVER AUTO-INSTALLER v2.0
# Script Automatizado com TUI para Configuração Completa
#
# Componentes: Pi-hole + Unbound + Cloudflared + WireGuard + RNG-tools + Otimizações
# Otimizado para: ARM RK322x, Debian/Ubuntu, Armbian
# Hardware Mínimo: 1GB RAM, 8GB Storage
#
# Autor: BOXSERVER Project
# Data: $(date +%Y-%m-%d)
###############################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

readonly SCRIPT_VERSION="2.0"
readonly SCRIPT_NAME="BOXSERVER Auto-Installer"
readonly LOG_FILE="/var/log/boxserver-installer.log"
readonly CONFIG_DIR="/etc/boxserver"
readonly BACKUP_DIR="/tmp/boxserver-backup"

# Cores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Variáveis globais dinâmicas
NETWORK_INTERFACE=""
SYSTEM_IP=""
GATEWAY_IP=""
DNS_SERVERS=""
TOTAL_RAM=""
AVAILABLE_STORAGE=""
CPU_ARCHITECTURE=""
INSTALL_MODE=""

# ============================================================================
# FUNÇÕES DE UTILIDADE E LOGGING
# ============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_success() { log "SUCCESS" "$@"; }

show_message() {
    local type="$1"
    local title="$2"
    local message="$3"

    case "$type" in
        "info")
            dialog --title "$title" --msgbox "$message" 10 60
            ;;
        "error")
            dialog --title "❌ $title" --msgbox "$message" 10 60
            log_error "$title: $message"
            ;;
        "success")
            dialog --title "✅ $title" --msgbox "$message" 10 60
            log_success "$title: $message"
            ;;
        "warning")
            dialog --title "⚠️ $title" --msgbox "$message" 10 60
            log_warn "$title: $message"
            ;;
    esac
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

run_with_progress() {
    local title="$1"
    local cmd="$2"
    local timeout_minutes="${3:-10}"  # Default 10 minutes

    # Criar arquivo temporário para o resultado
    local temp_result="/tmp/boxserver-progress-$$"
    local temp_log="/tmp/boxserver-cmd-$$"

    # Executar comando em background
    (
        echo "10"
        sleep 1
        echo "25"
        timeout "${timeout_minutes}m" bash -c "$cmd" &>"$temp_log"
        local exit_code=$?
        echo "$exit_code" > "$temp_result"

        if [ $exit_code -eq 0 ]; then
            echo "100"
        else
            echo "ERROR"
        fi
    ) | dialog --title "$title" --gauge "Executando... (timeout: ${timeout_minutes}min)" 8 70 0

    # Verificar resultado
    local result_code=1
    if [[ -f "$temp_result" ]]; then
        result_code=$(cat "$temp_result")
        rm -f "$temp_result"
    fi

    # Mostrar logs em caso de erro
    if [[ $result_code -ne 0 ]]; then
        if [[ -f "$temp_log" ]]; then
            local error_msg="Falha na execução:\n\n$(tail -10 "$temp_log" 2>/dev/null || echo "Sem logs disponíveis")"
            show_message "error" "$title - Erro" "$error_msg"
        fi
        log_error "$title falhou (código: $result_code)"
        rm -f "$temp_log"
        return 1
    else
        log_success "$title concluído"
        rm -f "$temp_log"
        return 0
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        show_message "error" "Privilégios Insuficientes" "Este script deve ser executado como root.\nUse: sudo $0"
        exit 1
    fi
}

check_dependencies() {
    local deps=("curl" "wget" "dig" "iptables" "systemctl")
    local missing_deps=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_warn "Instalando dependências faltantes: ${missing_deps[*]}"
        apt update &>/dev/null
        apt install -y "${missing_deps[@]}" dialog &>/dev/null || {
            show_message "error" "Erro de Dependências" "Falha ao instalar: ${missing_deps[*]}"
            exit 1
        }
    fi
}

# ============================================================================
# FUNÇÕES DE DETECÇÃO DE SISTEMA
# ============================================================================

detect_system_info() {
    log_info "Detectando informações do sistema..."

    # Detectar interface de rede principal
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$NETWORK_INTERFACE" ]]; then
        NETWORK_INTERFACE=$(ip link show | grep -E "^[0-9].*state UP" | head -1 | awk -F': ' '{print $2}')
    fi

    # IP do sistema
    SYSTEM_IP=$(ip route get 8.8.8.8 | grep -oP 'src \K\S+' | head -1)

    # Gateway
    GATEWAY_IP=$(ip route | grep default | awk '{print $3}' | head -1)

    # RAM total
    TOTAL_RAM=$(free -m | awk 'NR==2{print $2}')

    # Armazenamento disponível
    AVAILABLE_STORAGE=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')

    # Arquitetura
    CPU_ARCHITECTURE=$(uname -m)

    # DNS atual
    DNS_SERVERS=$(grep -E "^nameserver" /etc/resolv.conf | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')

    log_info "Sistema detectado:"
    log_info "  Interface: $NETWORK_INTERFACE"
    log_info "  IP: $SYSTEM_IP"
    log_info "  Gateway: $GATEWAY_IP"
    log_info "  RAM: ${TOTAL_RAM}MB"
    log_info "  Storage: ${AVAILABLE_STORAGE}GB"
    log_info "  Arquitetura: $CPU_ARCHITECTURE"
}

validate_system_requirements() {
    local errors=()

    # Verificar RAM mínima
    if [[ $TOTAL_RAM -lt 512 ]]; then
        errors+=("RAM insuficiente: ${TOTAL_RAM}MB (mínimo 512MB)")
    fi

    # Verificar storage
    if [[ $AVAILABLE_STORAGE -lt 4 ]]; then
        errors+=("Storage insuficiente: ${AVAILABLE_STORAGE}GB (mínimo 4GB)")
    fi

    # Verificar interface de rede
    if [[ -z "$NETWORK_INTERFACE" ]]; then
        errors+=("Interface de rede não detectada")
    fi

    # Verificar conectividade
    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        errors+=("Sem conectividade com a internet")
    fi

    if [[ ${#errors[@]} -gt 0 ]]; then
        local error_msg=""
        for error in "${errors[@]}"; do
            error_msg+="• $error\n"
        done
        show_message "error" "Requisitos Não Atendidos" "$error_msg"
        exit 1
    fi

    log_success "Requisitos do sistema validados"
}

# ============================================================================
# FUNÇÕES DE BACKUP E ROLLBACK
# ============================================================================

create_backup() {
    log_info "Criando backup das configurações atuais..."

    mkdir -p "$BACKUP_DIR"

    # Backup de arquivos de configuração importantes
    local config_files=(
        "/etc/resolv.conf"
        "/etc/systemd/resolved.conf"
        "/etc/pihole"
        "/etc/unbound"
        "/etc/wireguard"
        "/etc/default/rng-tools"
        "/etc/sysctl.conf"
    )

    for config in "${config_files[@]}"; do
        if [[ -e "$config" ]]; then
            cp -r "$config" "$BACKUP_DIR/" 2>/dev/null || true
        fi
    done

    # Salvar lista de pacotes instalados
    dpkg --get-selections > "$BACKUP_DIR/installed-packages.txt"

    log_success "Backup criado em $BACKUP_DIR"
}

rollback_changes() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        show_message "warning" "Rollback" "Backup não encontrado. Rollback não disponível."
        return 1
    fi

    if dialog --title "⚠️ Confirmar Rollback" --yesno "Deseja realmente desfazer todas as alterações?\nIsso irá restaurar as configurações originais." 8 60; then
        log_info "Iniciando rollback..."

        # Parar serviços
        systemctl stop pihole-FTL unbound wg-quick@wg0 rng-tools 2>/dev/null || true

        # Restaurar configurações
        cp -r "$BACKUP_DIR"/* / 2>/dev/null || true

        # Remover pacotes instalados (básico)
        apt remove -y pihole unbound wireguard rng-tools 2>/dev/null || true
        apt autoremove -y 2>/dev/null || true

        show_message "success" "Rollback Concluído" "Configurações originais restauradas.\nReinicie o sistema para aplicar completamente."

        log_success "Rollback concluído"
    fi
}

# ============================================================================
# FUNÇÕES DE VERIFICAÇÃO DE SERVIÇOS
# ============================================================================

check_service_installed() {
    local service_name="$1"
    local package_name="${2:-$service_name}"

    # Verificar se o pacote está instalado
    if dpkg -l | grep -q "^ii.*$package_name"; then
        log_info "$service_name já está instalado"
        return 0
    fi

    # Verificar se o serviço existe
    if systemctl list-unit-files | grep -q "$service_name"; then
        log_info "Serviço $service_name já existe"
        return 0
    fi

    return 1
}

check_dependencies_status() {
    log_info "Verificando status de dependências entre componentes..."

    local dependency_issues=()
    local recommendations=()

    # Verificar RNG-tools (base de entropia)
    local rng_status="❌"
    local rng_entropy="0"
    if systemctl is-active --quiet rng-tools; then
        rng_status="✅"
        rng_entropy=$(cat /proc/sys/kernel/random/entropy_avail)
        if [[ $rng_entropy -lt 1000 ]]; then
            dependency_issues+=("⚠️ RNG-tools ativo mas entropia baixa ($rng_entropy)")
            recommendations+=("• Reiniciar rng-tools ou instalar haveged")
        fi
    else
        dependency_issues+=("❌ RNG-tools inativo - chaves fracas para WireGuard")
        recommendations+=("• Instalar e ativar RNG-tools")
    fi

    # Verificar Unbound (DNS recursivo)
    local unbound_status="❌"
    local unbound_responding="❌"
    if systemctl is-active --quiet unbound; then
        unbound_status="✅"
        if timeout 5 dig @127.0.0.1 -p 5335 google.com +short &>/dev/null; then
            unbound_responding="✅"
        else
            dependency_issues+=("⚠️ Unbound ativo mas não responde na porta 5335")
            recommendations+=("• Verificar configuração do Unbound")
        fi
    else
        dependency_issues+=("❌ Unbound inativo - Pi-hole usará DNS público ou Cloudflared")
        recommendations+=("• Instalar Unbound ou Cloudflared para melhor performance")
    fi

    # Verificar Cloudflared (DNS DoH)
    local cloudflared_status="❌"
    local cloudflared_responding="❌"
    if systemctl is-active --quiet cloudflared-dns; then
        cloudflared_status="✅"
        if timeout 5 dig @127.0.0.1 -p 5053 google.com +short &>/dev/null; then
            cloudflared_responding="✅"
        else
            dependency_issues+=("⚠️ Cloudflared ativo mas não responde na porta 5053")
            recommendations+=("• Verificar configuração do Cloudflared")
        fi
    else
        dependency_issues+=("ℹ️ Cloudflared não configurado (opcional)")
    fi

    # Verificar Pi-hole (DNS + bloqueio)
    local pihole_status="❌"
    local pihole_dns_config="unknown"
    if systemctl is-active --quiet pihole-FTL; then
        pihole_status="✅"

        # Verificar configuração DNS do Pi-hole
        if [[ -f /etc/pihole/setupVars.conf ]]; then
            local pihole_dns=$(grep "PIHOLE_DNS_1=" /etc/pihole/setupVars.conf | cut -d'=' -f2)
            case "$pihole_dns" in
                "127.0.0.1#5335")
                    pihole_dns_config="Unbound"
                    if [[ "$unbound_responding" != "✅" ]]; then
                        dependency_issues+=("❌ Pi-hole configurado para Unbound mas Unbound não responde")
                        recommendations+=("• Ativar Unbound ou reconfigurar Pi-hole")
                    fi
                    ;;
                "127.0.0.1#5053")
                    pihole_dns_config="Cloudflared DoH"
                    if [[ "$cloudflared_responding" != "✅" ]]; then
                        dependency_issues+=("❌ Pi-hole configurado para Cloudflared mas Cloudflared não responde")
                        recommendations+=("• Ativar Cloudflared ou reconfigurar Pi-hole")
                    fi
                    ;;
                *)
                    pihole_dns_config="Público ($pihole_dns)"
                    if [[ "$unbound_status" == "✅" ]] || [[ "$cloudflared_status" == "✅" ]]; then
                        dependency_issues+=("⚠️ DNS local disponível mas Pi-hole usa DNS público")
                        recommendations+=("• Reconfigurar Pi-hole para usar DNS local")
                    fi
                    ;;
            esac
        fi
    else
        dependency_issues+=("❌ Pi-hole inativo - WireGuard não terá DNS otimizado")
        recommendations+=("• Instalar Pi-hole para DNS + bloqueio de anúncios")
    fi

    # Verificar WireGuard (VPN)
    local wireguard_status="❌"
    local wireguard_dns="unknown"
    if systemctl is-active --quiet wg-quick@wg0; then
        wireguard_status="✅"

        # Verificar configuração DNS do WireGuard
        if [[ -f /etc/wireguard/wg0.conf ]]; then
            local wg_dns=$(grep "DNS =" /etc/wireguard/wg0.conf | cut -d'=' -f2 | tr -d ' ')
            if [[ "$wg_dns" == "$SYSTEM_IP" ]]; then
                wireguard_dns="Pi-hole ($SYSTEM_IP)"
                if [[ "$pihole_status" != "✅" ]]; then
                    dependency_issues+=("❌ WireGuard configurado para Pi-hole mas Pi-hole inativo")
                    recommendations+=("• Ativar Pi-hole ou reconfigurar WireGuard")
                fi
            else
                wireguard_dns="Outro ($wg_dns)"
            fi
        fi
    else
        dependency_issues+=("ℹ️ WireGuard não configurado")
    fi

    # Montar relatório
    local report="🔗 STATUS DE DEPENDÊNCIAS:

📊 COMPONENTES:
• RNG-tools: $rng_status (Entropia: $rng_entropy)
• Unbound: $unbound_status (Responde: $unbound_responding)
• Cloudflared: $cloudflare

    if [[ ${#dependency_issues[@]} -gt 0 ]]; then
        report+="\n\n⚠️ PROBLEMAS ENCONTRADOS:"
        for issue in "${dependency_issues[@]}"; do
            report+="\n$issue"
        done

        report+="\n\n🔧 RECOMENDAÇÕES:"
        for rec in "${recommendations[@]}"; do
            report+="\n$rec"
        done
    else
        report+="\n\n✅ Todas as dependências estão corretas!"
    fi

    dialog --title "🔗 Relatório de Dependências" --msgbox "$report" 25 80

    return ${#dependency_issues[@]}
}

fix_dependencies_automatically() {
    log_info "Iniciando correção automática de dependências..."

    if ! dialog --title "🔧 Correção Automática" --yesno "Deseja corrigir automaticamente as dependências?\n\nIsso irá:\n• Verificar e corrigir configurações\n• Reiniciar serviços se necessário\n• Instalar componentes faltantes\n\nContinuar?" 12 60; then
        return 1
    fi

    local fixes_applied=()
    local fixes_failed=()

    # 1. Verificar e corrigir RNG-tools
    if ! systemctl is-active --quiet rng-tools; then
        log_info "Instalando/ativando RNG-tools..."
        if install_rng_tools; then
            fixes_applied+=("✅ RNG-tools ativado")
        else
            fixes_failed+=("❌ Falha ao ativar RNG-tools")
        fi
    else
        local entropy=$(cat /proc/sys/kernel/random/entropy_avail)
        if [[ $entropy -lt 1000 ]]; then
            log_info "Melhorando entropia..."
            if setup_entropy_alternatives; then
                fixes_applied+=("✅ Entropia melhorada")
            else
                fixes_failed+=("❌ Falha ao melhorar entropia")
            fi
        fi
    fi

    # 2. Verificar e corrigir Unbound
    if ! systemctl is-active --quiet unbound || ! timeout 5 dig @127.0.0.1 -p 5335 google.com +short &>/dev/null; then
        log_info "Instalando/corrigindo Unbound..."
        if install_unbound && test_unbound_dns; then
            fixes_applied+=("✅ Unbound funcionando")
        else
            fixes_failed+=("❌ Falha ao corrigir Unbound")
        fi
    fi

    # 3. Verificar e corrigir Pi-hole
    if systemctl is-active --quiet pihole-FTL; then
        # Pi-hole ativo, verificar se está usando Unbound
        local pihole_dns=$(grep "PIHOLE_DNS_1=" /etc/pihole/setupVars.conf 2>/dev/null | cut -d'=' -f2)
        if [[ "$pihole_dns" != "127.0.0.1#5335" ]] && systemctl is-active --quiet unbound; then
            log_info "Reconfigurando Pi-hole para usar Unbound..."
            if configure_pihole_unbound_integration; then
                fixes_applied+=("✅ Pi-hole integrado com Unbound")
            else
                fixes_failed+=("❌ Falha na integração Pi-hole → Unbound")
            fi
        fi
    else
        log_info "Instalando Pi-hole..."
        if install_pihole && configure_pihole_optimizations; then
            if systemctl is-active --quiet unbound; then
                configure_pihole_unbound_integration
            fi
            fixes_applied+=("✅ Pi-hole instalado e configurado")
        else
            fixes_failed+=("❌ Falha ao instalar Pi-hole")
        fi
    fi

    # 4. Verificar WireGuard (opcional)
    if systemctl is-active --quiet wg-quick@wg0; then
        local wg_dns=$(grep "DNS =" /etc/wireguard/wg0.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        if [[ "$wg_dns" != "$SYSTEM_IP" ]] && systemctl is-active --quiet pihole-FTL; then
            log_info "WireGuard detectado mas não otimizado para Pi-hole"
            fixes_applied+=("ℹ️ WireGuard funcional (não otimizado)")
        fi
    fi

    # Mostrar resultado
    local result_msg="🔧 CORREÇÕES APLICADAS:\n\n"

    if [[ ${#fixes_applied[@]} -gt 0 ]]; then
        for fix in "${fixes_applied[@]}"; do
            result_msg+="$fix\n"
        done
    fi

    if [[ ${#fixes_failed[@]} -gt 0 ]]; then
        result_msg+="\n❌ FALHAS:\n"
        for fail in "${fixes_failed[@]}"; do
            result_msg+="$fail\n"
        done
    fi

    if [[ ${#fixes_failed[@]} -eq 0 ]]; then
        result_msg+="\n🎉 Todas as correções foram aplicadas com sucesso!"
        show_message "success" "Correção Concluída" "$result_msg"
    else
        show_message "warning" "Correção Parcial" "$result_msg"
    fi

    log_success "Correção automática de dependências concluída"
    return 0
}

# ============================================================================
# FUNÇÕES DE INSTALAÇÃO - CLOUDFLARED
# ============================================================================

install_cloudflared() {
    log_info "Verificando instalação do Cloudflared..."

    # Verificar se Cloudflared já está instalado
    if command -v cloudflared &>/dev/null; then
        log_info "Cloudflared detectado, verificando configuração..."
        show_message "info" "Cloudflared já instalado" "Cloudflared já está instalado.\nVerificando configuração..."

        # Verificar se serviço DoH está ativo
        if systemctl is-active --quiet cloudflared-dns; then
            log_success "Cloudflared DNS já configurado e funcionando"
            return 0
        else
            log_info "Cloudflared instalado mas não configurado, configurando..."
        fi
    fi

    log_info "Iniciando instalação do Cloudflared..."

    # Detectar arquitetura para download
    local arch=""
    case "$CPU_ARCHITECTURE" in
        "x86_64") arch="amd64" ;;
        "aarch64"|"arm64") arch="arm64" ;;
        "armv7l"|"armhf") arch="arm" ;;
        *)
            log_error "Arquitetura não suportada: $CPU_ARCHITECTURE"
            show_message "error" "Arquitetura não suportada" "Cloudflared não suporta a arquitetura $CPU_ARCHITECTURE"
            return 1
            ;;
    esac

    # Instalar Cloudflared
    local install_cmd="wget -O /tmp/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch} && chmod +x /tmp/cloudflared && mv /tmp/cloudflared /usr/local/bin/cloudflared"

    if ! run_with_progress "Instalação Cloudflared" "$install_cmd" "5"; then
        show_message "error" "Erro Cloudflared" "Falha na instalação do Cloudflared"
        return 1
    fi

    # Configurar serviços DNS e Túnel
    setup_cloudflared_services

    log_success "Cloudflared instalado e configurado"
    return 0
}

setup_cloudflared_services() {
    log_info "Configurando serviços do Cloudflared..."

    # Perguntar que serviços configurar
    local services_choice
    services_choice=$(dialog --title "🌐 Configuração Cloudflared" --checklist \
        "Escolha os serviços do Cloudflared:" 15 60 4 \
        "dns" "DNS over HTTPS (DoH) - Substitui Unbound" ON \
        "tunnel" "Túnel para acesso remoto - Pi-hole web" OFF \
        "proxy" "Proxy para WireGuard (experimental)" OFF \
        "warp" "WARP para conectividade (experimental)" OFF \
        3>&1 1>&2 2>&3) || services_choice="dns"

    # Configurar DNS over HTTPS se selecionado
    if echo "$services_choice" | grep -q "dns"; then
        setup_cloudflared_dns
    fi

    # Configurar túnel se selecionado
    if echo "$services_choice" | grep -q "tunnel"; then
        setup_cloudflared_tunnel
    fi

    # Configurar proxy se selecionado
    if echo "$services_choice" | grep -q "proxy"; then
        setup_cloudflared_proxy
    fi

    # Configurar WARP se selecionado
    if echo "$services_choice" | grep -q "warp"; then
        setup_cloudflared_warp
    fi
}

setup_cloudflared_dns() {
    log_info "Configurando Cloudflared DNS over HTTPS..."

    # Criar configuração DNS DoH
    mkdir -p /etc/cloudflared
    cat > /etc/cloudflared/dns-config.yml <<EOF
# Configuração DNS over HTTPS para ARM RK322x
# Otimizada para ${TOTAL_RAM}MB RAM

# Servidores upstream Cloudflare
upstream:
  - https://1.1.1.1/dns-query
  - https://1.0.0.1/dns-query

# Configurações locais
proxy-dns: true
proxy-dns-port: 5053
proxy-dns-address: 127.0.0.1

# Configurações de performance para ARM
proxy-dns-upstream:
  - https://1.1.1.1/dns-query
  - https://1.0.0.1/dns-query

# Otimizações para recursos limitados
max-upstream-conns: 10
proxy-dns-workers: 2

# Logging otimizado
loglevel: warn
transport-loglevel: warn
EOF

    # Criar serviço systemd para DNS
    cat > /etc/systemd/system/cloudflared-dns.service <<EOF
[Unit]
Description=Cloudflared DNS over HTTPS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cloudflared
Group=cloudflared
ExecStart=/usr/local/bin/cloudflared --config /etc/cloudflared/dns-config.yml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Otimizações para ARM
Nice=10
IOSchedulingClass=2
IOSchedulingPriority=7

[Install]
WantedBy=multi-user.target
EOF

    # Criar usuário cloudflared
    if ! id cloudflared &>/dev/null; then
        useradd -r -s /bin/false cloudflared
    fi
    chown -R cloudflared:cloudflared /etc/cloudflared

    # Habilitar e iniciar serviço DNS
    systemctl daemon-reload
    systemctl enable cloudflared-dns &>/dev/null
    systemctl start cloudflared-dns &>/dev/null

    # Testar DNS DoH
    sleep 3
    if timeout 10 dig @127.0.0.1 -p 5053 google.com +short &>/dev/null; then
        log_success "Cloudflared DNS DoH funcionando na porta 5053"

        # Perguntar se deve integrar com Pi-hole
        if systemctl is-active --quiet pihole-FTL; then
            if dialog --title "Integração Pi-hole" --yesno "Pi-hole detectado!\n\nDeseja configurar Pi-hole para usar Cloudflared DoH\nem vez do Unbound?\n\nCloudflared DoH vs Unbound:\n• DoH: Mais privado, passa por HTTPS\n• Unbound: Mais rápido, consulta direta\n\nConfigurar Pi-hole → Cloudflared?" 14 60; then
                configure_pihole_cloudflared_integration
            fi
        fi
    else
        log_error "Cloudflared DNS não está respondendo"
        return 1
    fi
}

configure_pihole_cloudflared_integration() {
    log_info "Configurando integração Pi-hole → Cloudflared..."

    # Verificar se Cloudflared DoH está funcionando
    if ! timeout 5 dig @127.0.0.1 -p 5053 google.com +short &>/dev/null; then
        log_error "Cloudflared DNS não está respondendo na porta 5053"
        return 1
    fi

    log_info "Cloudflared DoH verificado, configurando Pi-hole..."

    # Atualizar configuração do Pi-hole para usar Cloudflared
    sed -i 's/PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5053/' /etc/pihole/setupVars.conf
    sed -i 's/PIHOLE_DNS_2=.*/PIHOLE_DNS_2=/' /etc/pihole/setupVars.conf

    # Reconfigurar Pi-hole
    pihole reconfigure --unattended &>/dev/null

    # Reiniciar Pi-hole para aplicar mudanças
    systemctl restart pihole-FTL &>/dev/null

    # Aguardar reinicialização
    sleep 5

    # Testar integração
    if timeout 10 dig @127.0.0.1 google.com +short &>/dev/null; then
        log_success "Integração Pi-hole → Cloudflared DoH configurada com sucesso"
        show_message "success" "Integração Configurada" "Pi-hole agora usa Cloudflared DoH!\n\n✅ DNS seguro via HTTPS\n✅ Maior privacidade\n✅ Bloqueio de anúncios mantido"
        return 0
    else
        log_error "Falha na integração Pi-hole → Cloudflared"
        return 1
    fi
}

setup_cloudflared_tunnel() {
    log_info "Configurando Cloudflared Tunnel para acesso remoto..."

    # Verificar se usuário tem conta Cloudflare
    if ! dialog --title "Cloudflare Account" --yesno "Para configurar o túnel, você precisa:\n\n1. Conta gratuita no Cloudflare\n2. Domínio configurado no Cloudflare (opcional)\n\nVocê tem uma conta Cloudflare?" 10 60; then
        show_message "info" "Conta Necessária" "Você pode criar uma conta gratuita em:\nhttps://dash.cloudflare.com/sign-up\n\nO túnel pode funcionar sem domínio próprio\nusando subdomínio *.trycloudflare.com"

        if ! dialog --title "Continuar" --yesno "Deseja continuar com túnel temporário\n(sem domínio próprio)?" 8 50; then
            return 1
        fi
    fi

    # Escolher tipo de túnel
    local tunnel_type
    tunnel_type=$(dialog --title "Tipo de Túnel" --menu \
        "Escolha o tipo de túnel:" 12 60 3 \
        "quick" "Túnel rápido (temporário, sem login)" \
        "named" "Túnel nomeado (permanente, requer login)" \
        "local" "Túnel local (desenvolvimento)" \
        3>&1 1>&2 2>&3) || tunnel_type="quick"

    case "$tunnel_type" in
        "quick")
            setup_cloudflared_quick_tunnel
            ;;
        "named")
            setup_cloudflared_named_tunnel
            ;;
        "local")
            setup_cloudflared_local_tunnel
            ;;
    esac
}

setup_cloudflared_quick_tunnel() {
    log_info "Configurando túnel rápido do Cloudflared..."

    # Detectar serviços para expor
    local services=()
    local service_ports=()

    if systemctl is-active --quiet pihole-FTL && systemctl is-active --quiet lighttpd; then
        services+=("Pi-hole Web Interface")
        service_ports+=("80")
    fi

    if systemctl is-active --quiet ssh; then
        services+=("SSH")
        service_ports+=("22")
    fi

    if [[ ${#services[@]} -eq 0 ]]; then
        show_message "warning" "Nenhum Serviço" "Nenhum serviço web detectado para expor.\nInstale Pi-hole primeiro."
        return 1
    fi

    # Escolher serviço para expor
    local choices=""
    for i in "${!services[@]}"; do
        choices+="$i \"${services[i]} (porta ${service_ports[i]})\" "
    done

    local selected
    selected=$(eval "dialog --title \"Expor Serviço\" --menu \"Escolha o serviço para expor:\" 12 60 ${#services[@]} $choices" 3>&1 1>&2 2>&3) || return 1

    local target_port="${service_ports[$selected]}"
    local service_name="${services[$selected]}"

    # Criar script de túnel rápido
    cat > /usr/local/bin/cloudflared-quick-tunnel <<EOF
#!/bin/bash
# Túnel rápido Cloudflared para $service_name

echo "🌐 Iniciando túnel Cloudflared para $service_name..."
echo "⏳ Aguarde a URL do túnel..."
echo ""

# Executar túnel rápido
cloudflared tunnel --url http://127.0.0.1:$target_port
EOF

    chmod +x /usr/local/bin/cloudflared-quick-tunnel

    # Mostrar instruções
    show_message "success" "Túnel Configurado" "Túnel rápido configurado!\n\n🚀 Para iniciar o túnel:\nsudo cloudflared-quick-tunnel\n\n📝 O túnel criará uma URL temporária\ncomo: https://xyz.trycloudflare.com\n\n⚠️ URL muda a cada reinicialização"

    log_success "Túnel rápido configurado para $service_name na porta $target_port"
}

setup_cloudflared_named_tunnel() {
    log_info "Configurando túnel nomeado do Cloudflared..."

    show_message "info" "Login Necessário" "Para túnel nomeado, você precisa:\n\n1. Fazer login no Cloudflare\n2. Criar um túnel\n3. Configurar DNS\n\nO processo será interativo."

    # Fazer login
    if dialog --title "Cloudflare Login" --yesno "Executar login no Cloudflare?\n\nIsso abrirá uma página web para autorização." 8 50; then
        cloudflared tunnel login
    else
        return 1
    fi

    # Criar túnel
    local tunnel_name
    tunnel_name=$(dialog --title "Nome do Túnel" --inputbox "Digite um nome para o túnel:" 8 40 "boxserver-$(hostname)" 3>&1 1>&2 2>&3) || return 1

    if cloudflared tunnel create "$tunnel_name"; then
        # Configurar túnel para Pi-hole
        local tunnel_id=$(cloudflared tunnel list | grep "$tunnel_name" | awk '{print $1}')

        cat > /etc/cloudflared/tunnel-config.yml <<EOF
tunnel: $tunnel_id
credentials-file: /home/cloudflared/.cloudflared/$tunnel_id.json

ingress:
  - hostname: $tunnel_name.example.com
    service: http://127.0.0.1:80
  - service: http_status:404
EOF

        show_message "success" "Túnel Criado" "Túnel '$tunnel_name' criado!\n\n📝 Configure DNS no Cloudflare:\n$tunnel_name.seu-dominio.com → $tunnel_id\n\n🚀 Inicie com:\ncloudflared tunnel run $tunnel_name"
    else
        show_message "error" "Erro no Túnel" "Falha ao criar túnel nomeado"
        return 1
    fi
}

setup_cloudflared_local_tunnel() {
    log_info "Configurando túnel local do Cloudflared..."

    # Túnel local para desenvolvimento/teste
    cat > /usr/local/bin/cloudflared-local-tunnel <<EOF
#!/bin/bash
# Túnel local Cloudflared para desenvolvimento

echo "🛠️ Iniciando túnel local para desenvolvimento..."
echo "📡 Expondo serviços locais:"
echo "   • Pi-hole: http://127.0.0.1:80"
echo "   • SSH: tcp://127.0.0.1:22"
echo ""

cloudflared tunnel --config /dev/stdin <<CONFIG
tunnel: local-dev
ingress:
  - hostname: pihole.localhost
    service: http://127.0.0.1:80
  - hostname: ssh.localhost
    service: tcp://127.0.0.1:22
  - service: http_status:404
CONFIG
EOF

    chmod +x /usr/local/bin/cloudflared-local-tunnel

    show_message "success" "Túnel Local" "Túnel local configurado!\n\n🛠️ Para desenvolvimento:\nsudo cloudflared-local-tunnel\n\n🌐 Acesso local:\n• Pi-hole: pihole.localhost\n• SSH: ssh.localhost"
}

setup_cloudflared_proxy() {
    log_info "Configurando Cloudflared Proxy (experimental)..."

    show_message "info" "Recurso Experimental" "Proxy Cloudflared para WireGuard\né um recurso experimental.\n\nPermite roteamento de tráfego VPN\natravés da rede Cloudflare."

    # Configuração básica de proxy
    cat > /etc/cloudflared/proxy-config.yml <<EOF
# Configuração experimental de proxy
# Roteamento via rede Cloudflare

proxy:
  enabled: true
  bind-address: 127.0.0.1:7000

upstream:
  - 127.0.0.1:51820  # WireGuard

# Experimental - use com cuidado
experimental: true
EOF

    log_info "Proxy configurado (experimental) na porta 7000"
}

setup_cloudflared_warp() {
    log_info "Configurando Cloudflared WARP (experimental)..."

    show_message "info" "WARP Experimental" "WARP do Cloudflare pode melhorar\nconectividade e performance.\n\n⚠️ Recurso experimental\nPode conflitar com WireGuard"

    # Configuração WARP básica
    cloudflared warp-service install 2>/dev/null || {
        log_warn "WARP service não disponível nesta arquitetura"
        return 1
    }

    log_info "WARP configurado (se disponível para $CPU_ARCHITECTURE)"
}

test_cloudflared_services() {
    log_info "Testando serviços Cloudflared..."

    local test_results=()
    local total_tests=0
    local passed_tests=0

    # Teste DNS DoH
    ((total_tests++))
    if timeout 5 dig @127.0.0.1 -p 5053 google.com +short &>/dev/null; then
        test_results+=("✅ Cloudflared DNS DoH: FUNCIONANDO")
        ((passed_tests++))
    else
        test_results+=("❌ Cloudflared DNS DoH: FALHOU")
    fi

    # Teste serviço systemd
    ((total_tests++))
    if systemctl is-active --quiet cloudflared-dns; then
        test_results+=("✅ Serviço cloudflared-dns: ATIVO")
        ((passed_tests++))
    else
        test_results+=("❌ Serviço cloudflared-dns: INATIVO")
    fi

    # Teste de conectividade
    ((total_tests++))
    if timeout 10 curl -s https://1.1.1.1/cdn-cgi/trace | grep -q "fl="; then
        test_results+=("✅ Conectividade Cloudflare: OK")
        ((passed_tests++))
    else
        test_results+=("❌ Conectividade Cloudflare: FALHOU")
    fi

    # Mostrar resultados
    local result_text=""
    for result in "${test_results[@]}"; do
        result_text+="$result\n"
    done
    result_text+="\nResultado: $passed_tests/$total_tests testes aprovados"

    if [[ $passed_tests -eq $total_tests ]]; then
        show_message "success" "Testes Cloudflared" "$result_text"
        log_success "Todos os testes Cloudflared passaram ($passed_tests/$total_tests)"
        return 0
    else
        show_message "warning" "Testes Cloudflared" "$result_text"
        log_warn "Alguns testes Cloudflared falharam ($passed_tests/$total_tests)"
        return 1
    fi
}

# ============================================================================
# FUNÇÕES DE DIAGNÓSTICO - PI-HOLE
# ============================================================================

diagnose_pihole_status() {
    log_info "Executando diagnóstico detalhado do Pi-hole..."

    local issues=()
    local status_msg=""

    # 1. Verificar se Pi-hole está instalado
    if command -v pihole &>/dev/null; then
        status_msg+="✅ Comando pihole disponível\n"
    else
        issues+=("❌ Comando pihole não encontrado")
        status_msg+="❌ Comando pihole não encontrado\n"
    fi

    # 2. Verificar serviço pihole-FTL
    if systemctl list-unit-files | grep -q "pihole-FTL"; then
        if systemctl is-active --quiet pihole-FTL; then
            status_msg+="✅ Serviço pihole-FTL ativo\n"
        else
            issues+=("⚠️ Serviço pihole-FTL inativo")
            status_msg+="⚠️ Serviço pihole-FTL inativo\n"
        fi
    else
        issues+=("❌ Serviço pihole-FTL não existe")
        status_msg+="❌ Serviço pihole-FTL não existe\n"
    fi

    # 3. Verificar arquivos de configuração
    if [[ -f /etc/pihole/setupVars.conf ]]; then
        status_msg+="✅ Arquivo setupVars.conf existe\n"
        local interface=$(grep "PIHOLE_INTERFACE" /etc/pihole/setupVars.conf | cut -d'=' -f2)
        if [[ -n "$interface" ]]; then
            status_msg+="   Interface configurada: $interface\n"
        fi
    else
        issues+=("❌ Arquivo setupVars.conf não existe")
        status_msg+="❌ Arquivo setupVars.conf não existe\n"
    fi

    # 4. Verificar porta 53
    if netstat -tulpn 2>/dev/null | grep -q ":53 "; then
        local service_on_53=$(netstat -tulpn 2>/dev/null | grep ":53 " | awk '{print $7}' | head -1)
        status_msg+="ℹ️ Porta 53 ocupada por: $service_on_53\n"
    else
        status_msg+="⚠️ Porta 53 livre\n"
    fi

    # 5. Verificar DNS atual do sistema
    if [[ -f /etc/resolv.conf ]]; then
        local current_dns=$(grep "nameserver" /etc/resolv.conf | head -1 | awk '{print $2}')
        status_msg+="ℹ️ DNS atual do sistema: $current_dns\n"
    fi

    # 6. Verificar logs recentes
    if [[ -f /var/log/pihole.log ]]; then
        status_msg+="✅ Log do Pi-hole existe\n"
        local log_size=$(du -h /var/log/pihole.log | cut -f1)
        status_msg+="   Tamanho do log: $log_size\n"
    else
        issues+=("⚠️ Log do Pi-hole não existe")
        status_msg+="⚠️ Log do Pi-hole não existe\n"
    fi

    # 7. Verificar diretório web
    if [[ -d /var/www/html/admin ]]; then
        status_msg+="✅ Interface web existe\n"
    else
        issues+=("⚠️ Interface web não existe")
        status_msg+="⚠️ Interface web não existe\n"
    fi

    # 8. Teste de conectividade
    if timeout 5 dig @127.0.0.1 google.com &>/dev/null; then
        status_msg+="✅ DNS local funcionando\n"
    else
        issues+=("⚠️ DNS local não responde")
        status_msg+="⚠️ DNS local não responde\n"
    fi

    # Mostrar resultado do diagnóstico
    local title="Diagnóstico Pi-hole"
    if [[ ${#issues[@]} -eq 0 ]]; then
        status_msg+="\n🎉 Nenhum problema crítico detectado!"
        show_message "success" "$title" "$status_msg"
    else
        status_msg+="\n⚠️ Problemas encontrados:\n"
        for issue in "${issues[@]}"; do
            status_msg+="$issue\n"
        done
        show_message "warning" "$title" "$status_msg"
    fi

    return ${#issues[@]}
}

fix_pihole_common_issues() {
    log_info "Tentando corrigir problemas comuns do Pi-hole..."

    # 1. Parar serviços conflitantes
    local conflicting_services=("systemd-resolved" "dnsmasq" "bind9")
    for service in "${conflicting_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_info "Parando serviço conflitante: $service"
            systemctl stop "$service" &>/dev/null || true
            systemctl disable "$service" &>/dev/null || true
        fi
    done

    # 2. Liberar porta 53 se ocupada por outro processo
    local pid_on_53=$(netstat -tulpn 2>/dev/null | grep ":53 " | awk '{print $7}' | cut -d'/' -f1 | head -1)
    if [[ -n "$pid_on_53" && "$pid_on_53" != "-" ]]; then
        local process_name=$(ps -p "$pid_on_53" -o comm= 2>/dev/null || echo "unknown")
        if [[ "$process_name" != "pihole-FTL" ]]; then
            log_info "Finalizando processo que ocupa porta 53: $process_name (PID: $pid_on_53)"
            kill -TERM "$pid_on_53" 2>/dev/null || true
            sleep 2
            kill -KILL "$pid_on_53" 2>/dev/null || true
        fi
    fi

    # 3. Recriar configurações básicas se necessário
    if [[ ! -f /etc/pihole/setupVars.conf ]] && [[ -n "$NETWORK_INTERFACE" ]] && [[ -n "$SYSTEM_IP" ]]; then
        log_info "Recriando configuração básica do Pi-hole..."
        mkdir -p /etc/pihole
        cat > /etc/pihole/setupVars.conf <<EOF
PIHOLE_INTERFACE=$NETWORK_INTERFACE
IPV4_ADDRESS=$SYSTEM_IP/24
IPV6_ADDRESS=
PIHOLE_DNS_1=8.8.8.8
PIHOLE_DNS_2=8.8.4.4
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSSEC=false
TEMPERATUREUNIT=C
WEBUIBOXEDLAYOUT=boxed
API_EXCLUDE_DOMAINS=
API_EXCLUDE_CLIENTS=
API_QUERY_LOG_SHOW=permittedonly
API_PRIVACY_MODE=false
EOF
    fi

    # 4. Tentar reiniciar o serviço
    if systemctl list-unit-files | grep -q "pihole-FTL"; then
        log_info "Reiniciando serviço pihole-FTL..."
        systemctl enable pihole-FTL &>/dev/null || true
        systemctl restart pihole-FTL &>/dev/null || true
        sleep 3

        if systemctl is-active --quiet pihole-FTL; then
            log_success "Serviço pihole-FTL reiniciado com sucesso"
            return 0
        else
            log_error "Falha ao reiniciar pihole-FTL"
        fi
    fi

    return 1
}

# ============================================================================
# FUNÇÕES DE INSTALAÇÃO - PI-HOLE
# ============================================================================

install_pihole() {
    log_info "Verificando instalação do Pi-hole..."

    # Verificar se Pi-hole já está instalado
    if check_service_installed "pihole-FTL" "pihole"; then
        log_info "Pi-hole detectado, executando diagnóstico..."

        # Executar diagnóstico detalhado
        if diagnose_pihole_status; then
            show_message "info" "Pi-hole já instalado" "Pi-hole já está instalado e funcionando adequadamente.\nAplicando otimizações..."
            configure_pihole_optimizations
            return 0
        else
            log_info "Problemas detectados no Pi-hole, tentando correções..."
            if fix_pihole_common_issues; then
                log_success "Problemas do Pi-hole corrigidos"
                configure_pihole_optimizations
                return 0
            else
                if dialog --title "Problema Pi-hole" --yesno "Pi-hole está instalado mas com problemas.\n\nDeseja tentar reinstalação completa?" 8 50; then
                    log_info "Removendo instalação problemática do Pi-hole..."
                    systemctl stop pihole-FTL &>/dev/null || true
                    systemctl disable pihole-FTL &>/dev/null || true
                    # Continuar com nova instalação
                else
                    return 1
                fi
            fi
        fi
    fi

    log_info "Iniciando instalação do Pi-hole..."

    # Pré-configurar variáveis do Pi-hole
    cat > /tmp/pihole-setupvars.conf <<EOF
WEBPASSWORD=
PIHOLE_INTERFACE=$NETWORK_INTERFACE
IPV4_ADDRESS=$SYSTEM_IP/24
IPV6_ADDRESS=
PIHOLE_DNS_1=8.8.8.8
PIHOLE_DNS_2=8.8.4.4
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSSEC=true
TEMPERATUREUNIT=C
WEBUIBOXEDLAYOUT=boxed
API_EXCLUDE_DOMAINS=
API_EXCLUDE_CLIENTS=
API_QUERY_LOG_SHOW=permittedonly
API_PRIVACY_MODE=false
EOF

    # Corrigir problemas comuns antes da instalação
    fix_pihole_common_issues

    # Mostrar progresso mais detalhado
    show_message "info" "Instalando Pi-hole" "Iniciando instalação do Pi-hole...\nEsta operação pode levar 5-15 minutos.\nPor favor, aguarde sem interromper o processo."

    # Instalar Pi-hole com timeout maior e melhor feedback
    local pihole_install_cmd="curl -sSL https://install.pi-hole.net | timeout 25m bash /dev/stdin --unattended"

    if ! run_with_progress "Instalação Pi-hole" "$pihole_install_cmd" "25"; then
        log_error "Tentativa de instalação automática do Pi-hole falhou"

        # Executar diagnóstico para identificar problema
        diagnose_pihole_status

        # Tentar método alternativo
        if dialog --title "Erro na Instalação" --yesno "Instalação automática falhou.\n\nTentar instalação manual do Pi-hole?\n(Método alternativo - pode levar 10-20 minutos)" 12 65; then

            show_message "info" "Instalação Manual" "Tentando instalação manual...\nEsta operação pode levar mais tempo.\nNão interrompa o processo."

            # Instalação manual como fallback
            (
                echo "10"
                apt update &>/dev/null
                echo "25"
                apt install -y curl wget git dialog &>/dev/null
                echo "40"
                # Limpar instalação anterior se existir
                rm -rf /tmp/pi-hole 2>/dev/null || true
                echo "50"
                git clone --depth 1 https://github.com/pi-hole/pi-hole.git /tmp/pi-hole &>/dev/null || true
                echo "70"
                if [[ -d /tmp/pi-hole ]]; then
                    cd "/tmp/pi-hole/automated install/" && timeout 15m bash basic-install.sh --unattended &>/dev/null
                fi
                echo "90"
                # Aplicar configurações personalizadas
                if [[ -f /tmp/pihole-setupvars.conf ]] && [[ -f /etc/pihole/setupVars.conf ]]; then
                    cp /tmp/pihole-setupvars.conf /etc/pihole/setupVars.conf
                    pihole reconfigure --unattended &>/dev/null || true
                fi
                echo "100"
            ) | dialog --title "Instalação Manual Pi-hole" --gauge "Instalando via método alternativo..." 8 70 0

            # Verificar se funcionou
            sleep 5
            if ! systemctl is-active --quiet pihole-FTL; then
                # Último diagnóstico
                diagnose_pihole_status
                show_message "error" "Erro Pi-hole" "Falha na instalação manual do Pi-hole.\n\nConsulte os logs em /var/log/boxserver-installer.log\ne tente a instalação manual posteriormente."
                return 1
            else
                log_success "Instalação manual do Pi-hole bem-sucedida"
            fi
        else
            return 1
        fi
    fi

    # Aplicar configurações personalizadas
    if [[ -f /etc/pihole/setupVars.conf ]]; then
        cp /tmp/pihole-setupvars.conf /etc/pihole/setupVars.conf
        pihole reconfigure --unattended &>/dev/null
    fi

    # Configurar password do admin
    local admin_password
    admin_password=$(dialog --title "Configuração Pi-hole" --passwordbox "Digite a senha do administrador Pi-hole:" 8 50 3>&1 1>&2 2>&3) || admin_password="admin123"

    if [[ -n "$admin_password" ]]; then
        pihole -a -p "$admin_password" &>/dev/null
    fi

    # Habilitar e iniciar serviço
    systemctl enable pihole-FTL &>/dev/null
    systemctl start pihole-FTL &>/dev/null

    log_success "Pi-hole instalado e configurado"
    return 0
}

configure_pihole_optimizations() {
    log_info "Aplicando otimizações do Pi-hole para ARM..."

    # Configurações otimizadas para ARM com pouca RAM
    cat >> /etc/pihole/pihole-FTL.conf <<EOF
# Otimizações para ARM RK322x
MAXDBDAYS=30
DBINTERVAL=60.0
MAXLOGAGE=7
PRIVACYLEVEL=0
IGNORE_LOCALHOST=no
AAAA_QUERY_ANALYSIS=yes
ANALYZE_ONLY_A_AND_AAAA=false
DBFILE=/etc/pihole/pihole-FTL.db
LOGFILE=/var/log/pihole-FTL.log
PIDFILE=/var/run/pihole-FTL.pid
SOCKETFILE=/var/run/pihole/FTL.sock
MACVENDORDB=/etc/pihole/macvendor.db
GRAVITYDB=/etc/pihole/gravity.db

# Configurações de memória para sistemas limitados
FTLCHUNKSIZE=4096
MAXNETAGE=365
MAXDBDAYS=30

# Configurações de rede otimizadas
SOCKET_LISTENING=localonly
FTLPORT=4711
RESOLVE_IPV6=no
RESOLVE_IPV4=yes
EOF

    # Reiniciar serviço para aplicar configurações
    systemctl restart pihole-FTL &>/dev/null

    log_success "Otimizações do Pi-hole aplicadas"
}

configure_pihole_unbound_integration() {
    log_info "Configurando integração Pi-hole → Unbound..."

    # Verificar se Unbound está funcionando
    if ! systemctl is-active --quiet unbound; then
        log_error "Unbound não está ativo. Não é possível configurar integração."
        return 1
    fi

    # Testar se Unbound responde
    # Verificar se Unbound está funcionando
    if ! timeout 5 dig @127.0.0.1 -p 5335 google.com +short &>/dev/null; then
        log_error "Unbound não está respondendo na porta 5335"
        return 1
    fi

    log_info "Unbound verificado e funcionando, configurando Pi-hole para usar Unbound..."

    # Verificar se existe Cloudflared DoH ativo
    if systemctl is-active --quiet cloudflared-dns && timeout 5 dig @127.0.0.1 -p 5053 google.com +short &>/dev/null; then
        # Oferecer escolha entre Unbound e Cloudflared
        local dns_choice
        dns_choice=$(dialog --title "Escolha DNS Upstream" --menu \
            "Ambos DNS estão funcionando. Escolha:" 10 60 2 \
            "unbound" "Unbound (local, mais rápido)" \
            "cloudflared" "Cloudflared DoH (HTTPS, mais privado)" \
            3>&1 1>&2 2>&3) || dns_choice="unbound"

        if [[ "$dns_choice" == "cloudflared" ]]; then
            # Usar Cloudflared DoH
            sed -i 's/PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5053/' /etc/pihole/setupVars.conf
            sed -i 's/PIHOLE_DNS_2=.*/PIHOLE_DNS_2=/' /etc/pihole/setupVars.conf
            log_info "Pi-hole configurado para usar Cloudflared DoH"
        else
            # Usar Unbound (padrão)
            sed -i 's/PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
            sed -i 's/PIHOLE_DNS_2=.*/PIHOLE_DNS_2=/' /etc/pihole/setupVars.conf
            log_info "Pi-hole configurado para usar Unbound"
        fi
    else
        # Usar apenas Unbound
        sed -i 's/PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
        sed -i 's/PIHOLE_DNS_2=.*/PIHOLE_DNS_2=/' /etc/pihole/setupVars.conf
    fi

    # Reconfigurar Pi-hole
    pihole reconfigure --unattended &>/dev/null

    # Reiniciar Pi-hole para aplicar mudanças
    systemctl restart pihole-FTL &>/dev/null

    # Aguardar reinicialização
    sleep 5

    # Testar integração
    if timeout 10 dig @127.0.0.1 google.com +short &>/dev/null; then
        log_success "Integração Pi-hole → Unbound configurada com sucesso"
        return 0
    else
        log_error "Falha na integração Pi-hole → Unbound"
        return 1
    fi
}

# ============================================================================
# FUNÇÕES DE INSTALAÇÃO - UNBOUND
# ============================================================================

install_unbound() {
    log_info "Verificando instalação do Unbound..."

    # Verificar se Unbound já está instalado
    if check_service_installed "unbound" "unbound"; then
        log_info "Unbound detectado, verificando configuração..."

        if systemctl is-active --quiet unbound; then
            show_message "info" "Unbound já instalado" "Unbound já está instalado e funcionando.\nVerificando configuração..."
            # Verificar se configuração do Pi-hole existe
            if [[ -f /etc/unbound/unbound.conf.d/pi-hole.conf ]]; then
                log_success "Configuração do Unbound já está otimizada"
                return 0
            else
                log_info "Aplicando configuração otimizada..."
            fi
        fi
    fi

    log_info "Iniciando instalação do Unbound..."

    # Instalar Unbound
    if ! run_with_progress "Instalação Unbound" "apt update && apt install -y unbound" "5"; then
        show_message "error" "Erro Unbound" "Falha na instalação do Unbound"
        return 1
    fi

    # Criar configuração otimizada para ARM
    cat > /etc/unbound/unbound.conf.d/pi-hole.conf <<EOF
server:
    # Configurações básicas
    verbosity: 1
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    prefer-ip6: no

    # Configurações de rede
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    edns-buffer-size: 1232
    prefetch: yes
    prefetch-key: yes

    # Otimizações para ARM/baixa RAM (${TOTAL_RAM}MB)
    num-threads: 1
    msg-cache-slabs: 1
    rrset-cache-slabs: 1
    infra-cache-slabs: 1
    key-cache-slabs: 1

    # Configurações de cache otimizadas
    rrset-cache-size: 32m
    msg-cache-size: 16m
    so-rcvbuf: 512k
    so-sndbuf: 512k

    # Configurações de privacidade
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
    hide-identity: yes
    hide-version: yes

    # Configurações de segurança
    harden-short-bufsize: yes
    harden-large-queries: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes

    # Trust anchor e root hints
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    root-hints: "/var/lib/unbound/root.hints"

    # Configurações de tempo
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    serve-expired: yes
    serve-expired-ttl: 3600
EOF

    # Configurar trust anchor e root hints
    setup_unbound_security

    # Habilitar e iniciar serviço
    systemctl enable unbound &>/dev/null

    # Testar configuração antes de iniciar
    if unbound-checkconf &>/dev/null; then
        systemctl start unbound &>/dev/null
        log_success "Unbound instalado e configurado"
        return 0
    else
        show_message "error" "Erro Unbound" "Configuração inválida do Unbound"
        return 1
    fi
}

setup_unbound_security() {
    log_info "Configurando segurança do Unbound..."

    # Criar diretório se necessário
    mkdir -p /var/lib/unbound

    # Baixar root hints
    if ! wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root &>/dev/null; then
        log_warn "Falha ao baixar root.hints online, usando configuração local"
        # Fallback para configuração básica
        echo ". 518400 IN NS a.root-servers.net." > /var/lib/unbound/root.hints
    fi

    # Configurar trust anchor automático
    if ! unbound-anchor -a /var/lib/unbound/root.key &>/dev/null; then
        log_warn "Falha no trust anchor automático, configurando manualmente"
        # Trust anchor manual (última versão conhecida)
        cat > /var/lib/unbound/root.key <<EOF
. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
EOF
    fi

    # Configurar permissões
    chown unbound:unbound /var/lib/unbound/root.key /var/lib/unbound/root.hints 2>/dev/null || true
    chmod 644 /var/lib/unbound/root.key /var/lib/unbound/root.hints

    log_success "Segurança do Unbound configurada"
}

test_unbound_dns() {
    log_info "Testando resolução DNS do Unbound..."

    # Aguardar serviço inicializar
    sleep 3

    # Teste básico
    if dig @127.0.0.1 -p 5335 google.com +short &>/dev/null; then
        log_success "Unbound DNS funcionando"
        return 0
    else
        log_error "Unbound DNS não está funcionando"
        return 1
    fi
}

# ============================================================================
# FUNÇÕES DE INSTALAÇÃO - WIREGUARD
# ============================================================================

install_wireguard() {
    log_info "Verificando instalação do WireGuard..."

    # Verificar se WireGuard já está instalado
    if check_service_installed "wg-quick@wg0" "wireguard"; then
        if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
            show_message "info" "WireGuard já instalado" "WireGuard já está instalado e ativo.\nVerificando configuração..."
            log_success "WireGuard já configurado e funcionando"
            return 0
        else
            log_info "WireGuard instalado mas não configurado, reconfigurando..."
        fi
    fi

    log_info "Iniciando instalação do WireGuard..."

    # Instalar WireGuard
    if ! run_with_progress "Instalação WireGuard" "apt update && apt install -y wireguard wireguard-tools" "5"; then
        show_message "error" "Erro WireGuard" "Falha na instalação do WireGuard"
        return 1
    fi

    # Configurar geração de chaves e configuração
    setup_wireguard_config

    # Configurar firewall e forwarding
    setup_wireguard_network

    log_success "WireGuard instalado e configurado"
    return 0
}

setup_wireguard_config() {
    log_info "Configurando WireGuard..."

    # Criar diretório de chaves
    mkdir -p /etc/wireguard/keys
    cd /etc/wireguard/keys

    # Gerar chaves com permissões corretas
    umask 077
    wg genkey | tee privatekey | wg pubkey > publickey

    # Obter chaves
    local private_key=$(cat privatekey)
    local public_key=$(cat publickey)

    # Configurar VPN subnet
    local vpn_subnet="10.200.200.0/24"
    local vpn_server_ip="10.200.200.1"

    # Criar configuração do servidor
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
# Configuração do Servidor WireGuard
PrivateKey = $private_key
Address = $vpn_server_ip/24
ListenPort = 51820

# Configurações de NAT e forwarding
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE

# Configurações DNS para clientes
DNS = $SYSTEM_IP

# Exemplo de peer - Configure clientes aqui
# [Peer]
# PublicKey = <CHAVE_PUBLICA_DO_CLIENTE>
# AllowedIPs = 10.200.200.2/32

EOF

    # Salvar informações para configuração de clientes
    cat > /etc/wireguard/client-template.conf <<EOF
# Configuração do Cliente WireGuard
# Substitua <PRIVATE_KEY_CLIENT> pela chave privada do cliente
# Configure no servidor a chave pública correspondente

[Interface]
PrivateKey = <PRIVATE_KEY_CLIENT>
Address = 10.200.200.X/24  # X = 2,3,4... para cada cliente
DNS = $SYSTEM_IP

[Peer]
PublicKey = $public_key
Endpoint = $SYSTEM_IP:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # Mostrar informações para configuração manual
    dialog --title "🔐 Configuração WireGuard" --msgbox "Chave Pública do Servidor:\n$public_key\n\nTemplate de cliente salvo em:\n/etc/wireguard/client-template.conf\n\nConfigure os clientes manualmente editando:\n/etc/wireguard/wg0.conf" 15 70

    log_info "Chave pública do servidor: $public_key"
}

setup_wireguard_network() {
    log_info "Configurando rede para WireGuard..."

    # Habilitar IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=1 &>/dev/null

    # Configurar UFW se estiver instalado
    if command -v ufw &>/dev/null; then
        # Configurar UFW para WireGuard
        ufw allow 51820/udp comment "WireGuard" &>/dev/null || true
        ufw allow 22/tcp comment "SSH" &>/dev/null || true
        ufw --force enable &>/dev/null || true
    else
        # Configurar iptables básico
        iptables -A INPUT -p udp --dport 51820 -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT

        # Salvar regras do iptables
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    fi

    # Habilitar e testar WireGuard
    systemctl enable wg-quick@wg0 &>/dev/null

    if systemctl start wg-quick@wg0 &>/dev/null; then
        log_success "WireGuard network configurado e ativo"
        return 0
    else
        log_error "Falha ao iniciar WireGuard"
        return 1
    fi
}

# ============================================================================
# FUNÇÕES DE INSTALAÇÃO - RNG-TOOLS
# ============================================================================

install_rng_tools() {
    log_info "Verificando instalação do RNG-tools..."

    # Verificar se RNG-tools já está instalado
    if check_service_installed "rng-tools" "rng-tools"; then
        if systemctl is-active --quiet rng-tools; then
            local entropy=$(cat /proc/sys/kernel/random/entropy_avail)
            show_message "info" "RNG-tools já instalado" "RNG-tools já está ativo.\nEntropia atual: $entropy\nVerificando otimizações..."

            if [[ $entropy -gt 1000 ]]; then
                log_success "RNG-tools já configurado e funcionando adequadamente"
                return 0
            else
                log_info "RNG-tools ativo mas entropia baixa, reotimizando..."
            fi
        fi
    fi

    log_info "Iniciando instalação do RNG-tools..."

    # Instalar rng-tools
    if ! run_with_progress "Instalação RNG-tools" "apt update && apt install -y rng-tools" "3"; then
        show_message "error" "Erro RNG-tools" "Falha na instalação do RNG-tools"
        return 1
    fi

    # Configurar para hardware específico
    setup_rng_optimization

    # Verificar alternativas se necessário
    setup_entropy_alternatives

    log_success "RNG-tools instalado e configurado"
    return 0
}

setup_rng_optimization() {
    log_info "Configurando RNG para hardware ARM..."

    # Detectar dispositivos de entropia disponíveis
    local rng_device="/dev/urandom"  # Fallback seguro

    if [[ -e "/dev/hwrng" ]]; then
        rng_device="/dev/hwrng"
        log_info "Hardware RNG detectado: /dev/hwrng"
    elif [[ -e "/dev/random" ]]; then
        rng_device="/dev/random"
        log_info "Usando /dev/random como fonte de entropia"
    fi

    # Configurar rng-tools
    cat > /etc/default/rng-tools <<EOF
# Configuração RNG-tools otimizada para ARM RK322x

# Dispositivo de entropia
HRNGDEVICE="$rng_device"

# Opções otimizadas para ARM com pouca RAM
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10 --random-step=64"

# Configurações específicas para RK322x
RNGD_OPTS="-f -r $rng_device -W 2048"

# Enable para inicialização automática
RNGD_ENABLED=1
EOF

    # Habilitar e iniciar serviço
    systemctl enable rng-tools &>/dev/null
    systemctl start rng-tools &>/dev/null

    # Verificar nível de entropia
    sleep 2
    local entropy_level=$(cat /proc/sys/kernel/random/entropy_avail)
    log_info "Nível de entropia atual: $entropy_level"

    if [[ $entropy_level -lt 1000 ]]; then
        log_warn "Entropia baixa ($entropy_level), configurando alternativas..."
        return 1
    fi

    return 0
}

setup_entropy_alternatives() {
    local current_entropy=$(cat /proc/sys/kernel/random/entropy_avail)

    if [[ $current_entropy -lt 1000 ]]; then
        log_info "Configurando haveged como alternativa..."

        if apt install -y haveged &>/dev/null; then
            systemctl enable haveged &>/dev/null
            systemctl start haveged &>/dev/null

            # Aguardar e verificar novamente
            sleep 3
            local new_entropy=$(cat /proc/sys/kernel/random/entropy_avail)

            if [[ $new_entropy -gt $current_entropy ]]; then
                log_success "Haveged instalado, entropia melhorada: $new_entropy"
            fi
        fi
    fi
}

# ============================================================================
# FUNÇÕES DE OTIMIZAÇÃO DO SISTEMA
# ============================================================================

apply_system_optimizations() {
    log_info "Aplicando otimizações do sistema para ARM..."

    # Otimizações de memória para ARM
    cat >> /etc/sysctl.conf <<EOF

# Otimizações BOXSERVER para ARM RK322x
# Configurações de memória
vm.swappiness=10
vm.vfs_cache_pressure=50
vm.dirty_background_ratio=5
vm.dirty_ratio=10

# Configurações de rede
net.core.rmem_default=262144
net.core.wmem_default=262144
net.core.rmem_max=16777216
net.core.wmem_max=16777216

# Otimizações DNS
net.core.netdev_max_backlog=5000
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3

# Segurança de rede
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1
EOF

    # Aplicar configurações
    sysctl -p &>/dev/null

    # Configurar chrony para sincronização de tempo
    setup_time_sync

    # Configurar logrotate
    setup_log_rotation

    # Configurar limpeza automática
    setup_automated_cleanup

    log_success "Otimizações do sistema aplicadas"
}

setup_time_sync() {
    log_info "Configurando sincronização de tempo..."

    if apt install -y chrony &>/dev/null; then
        # Configurar servidores NTP brasileiros
        cat >> /etc/chrony/chrony.conf <<EOF

# Servidores NTP brasileiros - BOXSERVER
server a.st1.ntp.br iburst
server b.st1.ntp.br iburst
server c.st1.ntp.br iburst
server d.st1.ntp.br iburst
EOF

        systemctl enable chrony &>/dev/null
        systemctl start chrony &>/dev/null

        log_success "Sincronização de tempo configurada"
    else
        log_warn "Falha ao instalar chrony"
    fi
}

setup_log_rotation() {
    log_info "Configurando rotação de logs..."

    # Configuração para Pi-hole
    cat > /etc/logrotate.d/boxserver <<EOF
/var/log/pihole.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 pihole pihole
    postrotate
        systemctl reload pihole-FTL > /dev/null 2>&1 || true
    endscript
}

/var/log/boxserver-installer.log {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
    create 644 root root
}

/var/log/unbound.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 unbound unbound
    postrotate
        systemctl reload unbound > /dev/null 2>&1 || true
    endscript
}
EOF

    log_success "Rotação de logs configurada"
}

setup_automated_cleanup() {
    log_info "Configurando limpeza automática..."

    # Script de limpeza semanal
    cat > /etc/cron.weekly/boxserver-cleanup <<'EOF'
#!/bin/bash
# Script de limpeza automática do BOXSERVER

LOG_FILE="/var/log/boxserver-cleanup.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

log "Iniciando limpeza automática..."

# Limpeza de pacotes
apt autoremove --purge -y >> "$LOG_FILE" 2>&1
apt autoclean >> "$LOG_FILE" 2>&1

# Limpeza de logs (manter últimos 7 dias)
journalctl --vacuum-time=7d >> "$LOG_FILE" 2>&1

# Limpeza de logs do Pi-hole (manter últimos 30 dias)
find /var/log -name "pihole*.log*" -mtime +30 -delete 2>/dev/null

# Limpeza de cache DNS
if systemctl is-active --quiet unbound; then
    unbound-control flush_zone . >> "$LOG_FILE" 2>&1 || true
fi

# Verificar espaço em disco
DISK_USAGE=$(df / | awk 'NR==2{print $5}' | sed 's/%//')
log "Uso do disco: ${DISK_USAGE}%"

if [ "$DISK_USAGE" -gt 90 ]; then
    log "ALERTA: Uso de disco alto (${DISK_USAGE}%)"
fi

# Verificar entropia
ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail)
log "Entropia atual: $ENTROPY"

if [ "$ENTROPY" -lt 1000 ]; then
    log "ALERTA: Entropia baixa ($ENTROPY)"
    systemctl restart rng-tools >> "$LOG_FILE" 2>&1 || true
fi

log "Limpeza automática concluída"
EOF

    chmod +x /etc/cron.weekly/boxserver-cleanup

    log_success "Limpeza automática configurada"
}

# ============================================================================
# FUNÇÕES DE TESTE E VALIDAÇÃO
# ============================================================================

run_system_tests() {
    log_info "Executando testes do sistema..."

    local test_results=()
    local total_tests=0
    local passed_tests=0

    # Teste 1: Serviços ativos
    log_info "Testando serviços..."
    local services=("pihole-FTL" "unbound" "wg-quick@wg0" "rng-tools" "chrony")

    for service in "${services[@]}"; do
        ((total_tests++))
        if systemctl is-active --quiet "$service"; then
            test_results+=("✅ Serviço $service: ATIVO")
            ((passed_tests++))
        else
            test_results+=("❌ Serviço $service: INATIVO")
        fi
    done

    # Teste 2: DNS Pi-hole
    ((total_tests++))
    if timeout 5 dig @127.0.0.1 google.com +short &>/dev/null; then
        test_results+=("✅ DNS Pi-hole: FUNCIONANDO")
        ((passed_tests++))
    else
        test_results+=("❌ DNS Pi-hole: FALHOU")
    fi

    # Teste 3: DNS Unbound
    ((total_tests++))
    if timeout 5 dig @127.0.0.1 -p 5335 google.com +short &>/dev/null; then
        test_results+=("✅ DNS Unbound: FUNCIONANDO")
        ((passed_tests++))
    else
        test_results+=("❌ DNS Unbound: FALHOU")
    fi

    # Teste 4: Conectividade externa
    ((total_tests++))
    if timeout 5 ping -c 1 8.8.8.8 &>/dev/null; then
        test_results+=("✅ Conectividade externa: OK")
        ((passed_tests++))
    else
        test_results+=("❌ Conectividade externa: FALHOU")
    fi

    # Teste 5: WireGuard interface
    ((total_tests++))
    if ip link show wg0 &>/dev/null; then
        test_results+=("✅ Interface WireGuard: ATIVA")
        ((passed_tests++))
    else
        test_results+=("❌ Interface WireGuard: INATIVA")
    fi

    # Teste 6: Entropia
    ((total_tests++))
    local entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    if [[ $entropy -gt 1000 ]]; then
        test_results+=("✅ Entropia: ADEQUADA ($entropy)")
        ((passed_tests++))
    else
        test_results+=("⚠️  Entropia: BAIXA ($entropy)")
    fi

    # Mostrar resultados
    local result_text=""
    for result in "${test_results[@]}"; do
        result_text+="$result\n"
    done
    result_text+="\nResultado: $passed_tests/$total_tests testes aprovados"

    if [[ $passed_tests -eq $total_tests ]]; then
        show_message "success" "Testes Concluídos" "$result_text"
        log_success "Todos os testes passaram ($passed_tests/$total_tests)"
        return 0
    else
        show_message "warning" "Testes com Problemas" "$result_text"
        log_warn "Alguns testes falharam ($passed_tests/$total_tests)"
        return 1
    fi
}

show_system_status() {
    log_info "Coletando status do sistema..."

    # Informações do sistema
    local uptime_info=$(uptime -p)
    local memory_info=$(free -h | awk 'NR==2{printf "%.1f%% (%s/%s)", $3*100/$2, $3, $2}')
    local disk_info=$(df -h / | awk 'NR==2{printf "%s usado de %s (%s)", $3, $2, $5}')
    local entropy_info=$(cat /proc/sys/kernel/random/entropy_avail)

    # Temperatura (se disponível)
    local temp_info="N/A"
    if [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
        temp_info="$(($(cat /sys/class/thermal/thermal_zone0/temp)/1000))°C"
    fi

    # Status dos serviços
    local service_status=""
    local services=("pihole-FTL" "unbound" "wg-quick@wg0" "rng-tools" "chrony")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            service_status+="✅ $service: ATIVO\n"
        else
            service_status+="❌ $service: INATIVO\n"
        fi
    done

    # Informações de rede
    local vpn_clients="0"
    if systemctl is-active --quiet wg-quick@wg0; then
        vpn_clients=$(wg show wg0 peers 2>/dev/null | wc -l)
    fi

    # Testes rápidos de DNS
    local pihole_dns="❌"
    local unbound_dns="❌"

    if timeout 3 dig @127.0.0.1 google.com +short &>/dev/null; then
        pihole_dns="✅"
    fi

    if timeout 3 dig @127.0.0.1 -p 5335 google.com +short &>/dev/null; then
        unbound_dns="✅"
    fi

    # Montar mensagem de status
    local status_msg="=== INFORMAÇÕES DO SISTEMA ===
Uptime: $uptime_info
Memória: $memory_info
Disco: $disk_info
Temperatura: $temp_info
Entropia: $entropy_info

=== STATUS DOS SERVIÇOS ===
$service_status
=== CONECTIVIDADE ===
$pihole_dns Pi-hole DNS
$unbound_dns Unbound DNS
VPN Clientes conectados: $vpn_clients

=== CONFIGURAÇÃO DE REDE ===
Interface: $NETWORK_INTERFACE
IP do sistema: $SYSTEM_IP
Gateway: $GATEWAY_IP"

    dialog --title "📊 Status do BOXSERVER" --msgbox "$status_msg" 25 80
}

# ============================================================================
# INTERFACE TUI - MENUS
# ============================================================================

show_main_menu() {
    while true; do
        local choice
        choice=$(dialog --clear --title "🚀 BOXSERVER Auto-Installer v$SCRIPT_VERSION" \
            --menu "Escolha uma opção:" 22 70 14 \
            "1" "🔧 Instalação Completa Automática" \
            "2" "📦 Instalação Individual por Componente" \
            "3" "🔍 Verificar Requisitos do Sistema" \
            "4" "🧪 Executar Testes do Sistema" \
            "5" "📊 Mostrar Status Atual" \
            "6" "🔗 Verificar Dependências dos Componentes" \
            "7" "🔧 Corrigir Dependências Automaticamente" \
            "8" "⚡ Otimizações do Sistema" \
            "9" "📋 Configurar Cliente WireGuard" \
            "10" "🗂️  Criar Backup das Configurações" \
            "11" "↩️  Rollback (Desfazer Alterações)" \
            "12" "📖 Mostrar Logs do Sistema" \
            "13" "ℹ️  Sobre" \
            "0" "🚪 Sair" \
            3>&1 1>&2 2>&3) || exit 0

        case $choice in
            1) full_installation ;;
            2) component_installation_menu ;;
            3) system_requirements_check ;;
            4) run_system_tests ;;
            5) show_system_status ;;
            6) check_dependencies_status ;;
            7) fix_dependencies_automatically ;;
            8) apply_system_optimizations ;;
            9) configure_wireguard_client ;;
            10) create_backup ;;
            11) rollback_changes ;;
            12) show_logs_menu ;;
            13) show_about ;;
            0) exit 0 ;;
            *) show_message "error" "Opção Inválida" "Por favor, selecione uma opção válida." ;;
        esac
    done
}

component_installation_menu() {
    while true; do
        local choice
        choice=$(dialog --clear --title "📦 Instalação Individual" \
            --menu "⚠️ ORDEM RECOMENDADA (baseada em dependências):" 20 75 12 \
            "1" "🎲 RNG-tools (Entropia) - INSTALE PRIMEIRO" \
            "2" "🔒 Unbound (DNS Recursivo) - DEPOIS RNG" \
            "3" "🛡️  Pi-hole (DNS + Ad-block) - DEPOIS UNBOUND" \
            "4" "🌐 WireGuard (VPN) - DEPOIS PI-HOLE" \
            "5" "⚡ Otimizações do Sistema - POR ÚLTIMO" \
            "" "" \
            "6" "🧪 Testar Componentes" \
            "7" "ℹ️  Ver Dependências Detalhadas" \
            "8" "🔗 Verificar Status de Dependências" \
            "9" "🔧 Corrigir Dependências Automaticamente" \
            "0" "↩️  Voltar ao Menu Principal" \
            3>&1 1>&2 2>&3) || break

        case $choice in
            1)
                if install_rng_tools; then
                    show_message "success" "RNG-tools" "RNG-tools instalado com sucesso!\n\n✅ Próximo recomendado: Unbound (opção 2)"
                fi
                ;;
            2)
                # Verificar se RNG-tools está ativo
                if ! systemctl is-active --quiet rng-tools; then
                    show_message "warning" "Dependência" "⚠️ RNG-tools não está ativo!\n\nRecomenda-se instalar RNG-tools primeiro (opção 1)\npara garantir boa entropia.\n\nContinuar mesmo assim?"
                    if ! dialog --title "Confirmar" --yesno "Instalar Unbound sem RNG-tools?" 8 50; then
                        continue
                    fi
                fi

                if install_unbound && test_unbound_dns; then
                    show_message "success" "Unbound" "Unbound instalado com sucesso!\n\n✅ Próximo recomendado: Pi-hole (opção 3)"
                fi
                ;;
            3)
                # Verificar se Unbound está funcionando
                if ! systemctl is-active --quiet unbound; then
                    show_message "warning" "Dependência" "⚠️ Unbound não está ativo!\n\nPi-hole funcionará melhor com Unbound como DNS upstream.\n\nRecomenda-se instalar Unbound primeiro (opção 2).\n\nContinuar com Pi-hole usando DNS público?"
                    if ! dialog --title "Confirmar" --yesno "Instalar Pi-hole sem Unbound?" 9 50; then
                        continue
                    fi
                fi

                if install_pihole && configure_pihole_optimizations; then
                    # Se Unbound estiver ativo, configurar integração
                    if systemctl is-active --quiet unbound; then
                        configure_pihole_unbound_integration
                        show_message "success" "Pi-hole" "Pi-hole instalado e integrado com Unbound!\n\n✅ Próximo recomendado: WireGuard (opção 4)"
                    else
                        show_message "success" "Pi-hole" "Pi-hole instalado com DNS público!\n\n⚠️ Para melhor performance, instale Unbound depois.\n\n✅ Próximo recomendado: WireGuard (opção 4)"
                    fi
                fi
                ;;
            4)
                # Verificar se Pi-hole está funcionando
                if ! systemctl is-active --quiet pihole-FTL; then
                    show_message "warning" "Dependência" "⚠️ Pi-hole não está ativo!\n\nWireGuard usará Pi-hole como servidor DNS para clientes.\n\nRecomenda-se instalar Pi-hole primeiro (opção 3).\n\nContinuar mesmo assim?"
                    if ! dialog --title "Confirmar" --yesno "Instalar WireGuard sem Pi-hole?" 9 50; then
                        continue
                    fi
                fi

                if install_wireguard; then
                    show_message "success" "WireGuard" "WireGuard instalado com sucesso!\n\n✅ Próximo recomendado: Otimizações (opção 5)"
                fi
                ;;
            5)
                if apply_system_optimizations; then
                    show_message "success" "Otimizações" "Otimizações aplicadas com sucesso!\n\n🎉 Sistema otimizado!"
                fi
                ;;
            6) run_system_tests ;;
            7) show_dependency_details ;;
            8) check_dependencies_status ;;
            9) fix_dependencies_automatically ;;
            0) break ;;
        esac
    done
}

full_installation() {
    log_info "=== INSTALAÇÃO COMPLETA COM SEQUÊNCIA OTIMIZADA ==="
    log_info "Sequência baseada em dependências:"
    log_info "1. RNG-tools → Entropia para chaves seguras"
    log_info "2. Unbound → DNS recursivo independente"
    log_info "3. Pi-hole → DNS + bloqueio (integrado com Unbound)"
    log_info "4. WireGuard → VPN (usando Pi-hole como DNS)"
    log_info "5. Otimizações → Ajustes finais do sistema"

    if dialog --title "⚠️ Confirmação" --yesno "Deseja executar a instalação completa?\n\nOrdem de instalação otimizada:\n• RNG-tools (entropia)\n• Unbound (DNS recursivo)\n• Pi-hole (DNS + bloqueio)\n• WireGuard (VPN)\n• Otimizações do sistema\n\nContinuar?" 14 65; then

        log_info "Iniciando instalação completa..."

        # Criar backup
        create_backup

        # Executar instalações sequencialmente (ORDEM CORRIGIDA BASEADA EM DEPENDÊNCIAS)
        local components=("RNG-tools" "Unbound" "Pi-hole" "WireGuard" "Otimizações")
        local functions=("install_rng_tools"
                        "install_unbound && test_unbound_dns"
                        "install_pihole && configure_pihole_optimizations && configure_pihole_unbound_integration"
                        "install_wireguard"
                        "apply_system_optimizations")

        local failed_components=()
        local total_components=${#components[@]}

        for i in "${!components[@]}"; do
            local component="${components[i]}"
            local func="${functions[i]}"
            local progress=$(( (i + 1) * 100 / total_components ))

            log_info "Instalando: $component ($((i+1))/$total_components)"

            # Mostrar progresso geral
            echo "$progress" | dialog --title "Instalação Completa" --gauge "Instalando $component ($((i+1))/$total_components)" 8 60 0 &
            local gauge_pid=$!

            # Executar função
            if eval "$func"; then
                log_success "Instalação concluída: $component"
                kill $gauge_pid 2>/dev/null
            else
                failed_components+=("$component")
                log_error "Falha na instalação: $component"
                kill $gauge_pid 2>/dev/null

                # Perguntar se deve continuar
                if ! dialog --title "Erro na Instalação" --yesno "Falha ao instalar $component.\n\nDeseja continuar com os outros componentes?" 8 50; then
                    break
                fi
            fi
        done

        # Mostrar resultado final
        if [ ${#failed_components[@]} -eq 0 ]; then
            show_message "success" "Instalação Completa" "Todos os componentes foram instalados com sucesso!\n\nExecute os testes do sistema para verificar o funcionamento."

            # Executar testes automáticos
            if dialog --title "Testes Automáticos" --yesno "Deseja executar os testes do sistema agora?" 8 50; then
                run_system_tests
            fi
        else
            local failed_list=""
            for comp in "${failed_components[@]}"; do
                failed_list+="• $comp\n"
            done
            show_message "warning" "Instalação Parcial" "Alguns componentes falharam:\n$failed_list\nConsulte os logs para mais detalhes."
        fi
    fi
}

configure_wireguard_client() {
    if ! systemctl is-active --quiet wg-quick@wg0; then
        show_message "error" "WireGuard Inativo" "WireGuard não está instalado ou ativo.\nInstale o WireGuard primeiro."
        return 1
    fi

    # Obter próximo IP disponível
    local next_ip=2
    while grep -q "10.200.200.$next_ip" /etc/wireguard/wg0.conf; do
        ((next_ip++))
        if [[ $next_ip -gt 254 ]]; then
            show_message "error" "Limite Atingido" "Máximo de clientes VPN atingido (254)."
            return 1
        fi
    done

    # Solicitar nome do cliente
    local client_name
    client_name=$(dialog --title "Configuração Cliente VPN" --inputbox "Digite o nome do cliente:" 8 40 "cliente$next_ip" 3>&1 1>&2 2>&3) || return

    if [[ -z "$client_name" ]]; then
        show_message "error" "Nome Inválido" "Nome do cliente não pode estar vazio."
        return 1
    fi

    # Gerar chaves do cliente
    local client_dir="/etc/wireguard/clients/$client_name"
    mkdir -p "$client_dir"
    cd "$client_dir"

    wg genkey | tee private.key | wg pubkey > public.key
    local client_private_key=$(cat private.key)
    local client_public_key=$(cat public.key)
    local server_public_key=$(cat /etc/wireguard/keys/publickey)

    # Adicionar peer ao servidor
    cat >> /etc/wireguard/wg0.conf <<EOF

# Cliente: $client_name
[Peer]
PublicKey = $client_public_key
AllowedIPs = 10.200.200.$next_ip/32
EOF

    # Criar configuração do cliente
    cat > "$client_dir/$client_name.conf" <<EOF
[Interface]
PrivateKey = $client_private_key
Address = 10.200.200.$next_ip/24
DNS = $SYSTEM_IP

[Peer]
PublicKey = $server_public_key
Endpoint = $SYSTEM_IP:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # Gerar QR Code se possível
    if command -v qrencode &>/dev/null; then
        qrencode -t ansiutf8 < "$client_dir/$client_name.conf" > "$client_dir/$client_name.qr"
    fi

    # Reiniciar WireGuard
    systemctl restart wg-quick@wg0

    # Mostrar informações
    local config_content=$(cat "$client_dir/$client_name.conf")
    dialog --title "✅ Cliente VPN Configurado" --msgbox "Cliente '$client_name' configurado com sucesso!\n\nIP: 10.200.200.$next_ip\n\nArquivo de configuração salvo em:\n$client_dir/$client_name.conf\n\nImporte esta configuração no aplicativo WireGuard do cliente." 15 70

    log_success "Cliente VPN '$client_name' configurado com IP 10.200.200.$next_ip"
}

show_dependency_details() {
    dialog --title "ℹ️ Dependências Detalhadas" --msgbox "
🔗 DEPENDÊNCIAS ENTRE COMPONENTES:

📋 ORDEM RECOMENDADA:
1️⃣ RNG-tools
   └─ Fornece entropia para chaves seguras

2️⃣ Unbound
   └─ DNS recursivo independente
   └─ Requer: Boa entropia para DNSSEC

3️⃣ Pi-hole
   └─ DNS + bloqueio de anúncios
   └─ Requer: Unbound como upstream DNS
   └─ Configurado para: 127.0.0.1#5335

4️⃣ WireGuard
   └─ Servidor VPN
   └─ Requer: Pi-hole como DNS para clientes
   └─ Requer: Boa entropia para chaves

5️⃣ Otimizações
   └─ Ajustes finais do sistema
   └─ Aplica configurações para todos os serviços

⚠️  PROBLEMAS SE ORDEM ERRADA:
• Pi-hole antes Unbound → DNS instável
• WireGuard antes RNG → Chaves fracas
• WireGuard antes Pi-hole → DNS não otimizado
" 25 70
}

system_requirements_check() {
    log_info "Verificando requisitos do sistema..."

    detect_system_info

    local req_msg="=== REQUISITOS DO SISTEMA ===

Hardware Detectado:
• Arquitetura: $CPU_ARCHITECTURE
• RAM Total: ${TOTAL_RAM}MB
• Storage Disponível: ${AVAILABLE_STORAGE}GB
• Interface de Rede: $NETWORK_INTERFACE

Configurações de Rede:
• IP do Sistema: $SYSTEM_IP
• Gateway: $GATEWAY_IP
• DNS Atual: $DNS_SERVERS

Requisitos Mínimos:
✓ RAM: 512MB (Recomendado: 1GB)
✓ Storage: 4GB (Recomendado: 8GB)
✓ Conectividade com Internet
✓ Interface de Rede Ativa"

    # Validar requisitos
    local warnings=""

    if [[ $TOTAL_RAM -lt 1024 ]]; then
        warnings+="⚠️  RAM abaixo do recomendado (${TOTAL_RAM}MB < 1GB)\n"
    fi

    if [[ $AVAILABLE_STORAGE -lt 8 ]]; then
        warnings+="⚠️  Storage abaixo do recomendado (${AVAILABLE_STORAGE}GB < 8GB)\n"
    fi

    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        warnings+="❌ Sem conectividade com a internet\n"
    fi

    if [[ -n "$warnings" ]]; then
        req_msg+="\n\n=== AVISOS ===\n$warnings"
    fi

    dialog --title "🔍 Verificação de Requisitos" --msgbox "$req_msg" 25 80

    # Validação automática
    validate_system_requirements
}

show_logs_menu() {
    while true; do
        local choice
        choice=$(dialog --clear --title "📖 Logs do Sistema" \
            --menu "Escolha o log:" 15 60 8 \
            "1" "📋 Log do Installer" \
            "2" "🛡️  Log do Pi-hole" \
            "3" "🔒 Log do Unbound" \
            "4" "🌐 Log do WireGuard" \
            "5" "🎲 Log do RNG-tools" \
            "6" "⚙️  Log do Sistema (journalctl)" \
            "7" "🧹 Log de Limpeza" \
            "0" "↩️  Voltar" \
            3>&1 1>&2 2>&3) || break

        case $choice in
            1) show_log_file "$LOG_FILE" ;;
            2) show_log_file "/var/log/pihole.log" ;;
            3) show_journal_log "unbound" ;;
            4) show_journal_log "wg-quick@wg0" ;;
            5) show_journal_log "rng-tools" ;;
            6) show_journal_log "" ;;
            7) show_log_file "/var/log/boxserver-cleanup.log" ;;
            0) break ;;
        esac
    done
}

show_log_file() {
    local log_file="$1"
    if [[ -f "$log_file" ]]; then
        dialog --title "📖 $log_file" --textbox "$log_file" 20 80
    else
        show_message "error" "Log não encontrado" "Arquivo de log não existe: $log_file"
    fi
}

show_journal_log() {
    local service="$1"
    local temp_log="/tmp/boxserver-journal.log"

    if [[ -n "$service" ]]; then
        journalctl -u "$service" -n 50 --no-pager > "$temp_log"
    else
        journalctl -n 50 --no-pager > "$temp_log"
    fi

    dialog --title "📖 Journal Log${service:+ - $service}" --textbox "$temp_log" 20 80
    rm -f "$temp_log"
}

show_about() {
    dialog --title "ℹ️ Sobre o BOXSERVER" --msgbox "
🚀 BOXSERVER Auto-Installer v$SCRIPT_VERSION

Instalador automatizado para configuração completa de:
• Pi-hole (DNS + Bloqueio de anúncios)
• Unbound (DNS recursivo local)
• WireGuard (VPN segura)
• RNG-tools (Gerador de entropia)
• Otimizações para ARM RK322x

📋 Características:
✓ Interface TUI amigável
✓ Detecção automática de hardware
✓ Configurações otimizadas para ARM
✓ Sistema de backup e rollback
✓ Testes automáticos de validação
✓ Monitoramento integrado

🎯 Otimizado para:
• Sistemas ARM RK322x
• Debian/Ubuntu/Armbian
• Hardware com recursos limitados

📧 Projeto: BOXSERVER
📅 Data: $(date +%Y-%m-%d)
" 25 70
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

main() {
    # Configurar logging
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$CONFIG_DIR"

    # Verificações iniciais
    check_root
    check_dependencies

    # Detectar informações do sistema
    detect_system_info

    log_info "=== BOXSERVER Auto-Installer v$SCRIPT_VERSION iniciado ==="
    log_info "Sistema: $CPU_ARCHITECTURE, RAM: ${TOTAL_RAM}MB, Interface: $NETWORK_INTERFACE"

    # Mostrar tela de boas-vindas
    dialog --title "🚀 Bem-vindo ao BOXSERVER" --msgbox "
BOXSERVER Auto-Installer v$SCRIPT_VERSION

Este script irá configurar automaticamente:
• Pi-hole (DNS + Ad-block)
• Unbound (DNS recursivo)
• WireGuard (VPN)
• RNG-tools (Entropia)
• Otimizações do sistema

Sistema detectado:
• Arquitetura: $CPU_ARCHITECTURE
• RAM: ${TOTAL_RAM}MB
• Interface: $NETWORK_INTERFACE
• IP: $SYSTEM_IP

Pressione OK para continuar...
" 20 60

    # Iniciar menu principal
    show_main_menu

    log_info "=== BOXSERVER Auto-Installer finalizado ==="
}

# ============================================================================
# TRATAMENTO DE SINAIS E LIMPEZA
# ============================================================================

cleanup() {
    log_info "Limpeza em andamento..."
    clear
    echo "👋 Obrigado por usar o BOXSERVER Auto-Installer!"
    echo "📋 Logs salvos em: $LOG_FILE"
    echo "🔧 Configurações em: $CONFIG_DIR"
    exit 0
}

trap cleanup EXIT INT TERM

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

# Verificar se foi executado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
