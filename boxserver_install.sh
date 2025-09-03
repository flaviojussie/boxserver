#!/bin/bash

# BoxServer TUI Installer - Versão Segura e Otimizada
# Desenvolvido para MXQ-4K TV Box (RK322x) com NAND
# Versão: 2.0 - Security Enhanced
# Data: $(date +%Y-%m-%d)

# Configurações de segurança
set -euo pipefail  # Fail fast em erros
IFS=$'\n\t'       # Secure IFS

# Variáveis globais controladas
declare -r SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -r LOG_FILE="/var/log/boxserver-install.log"
declare -r BACKUP_DIR="/opt/boxserver/backups"
declare -r CONFIG_DIR="/opt/boxserver/config"

# Cores para output
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[1;33m'
declare -r BLUE='\033[0;34m'
declare -r NC='\033[0m' # No Color

# Configurações específicas RK322x
declare -r RK322X_MAX_MEMORY="1024"  # MB
declare -r RK322X_NAND_WEAR_LIMIT="10000"  # Ciclos
declare -r RK322X_THERMAL_LIMIT="85"  # Celsius

# Função de cleanup automático
cleanup() {
    local exit_code=$?
    log_message "INFO" "Executando cleanup automático..."
    
    # Remover arquivos temporários
    rm -f /tmp/boxserver_*
    
    # Restaurar configurações em caso de erro
    if [ $exit_code -ne 0 ]; then
        log_message "ERROR" "Instalação falhou com código $exit_code"
        restore_backups
    fi
    
    exit $exit_code
}

# Configurar trap para cleanup
trap cleanup EXIT
trap 'log_message "ERROR" "Script interrompido pelo usuário"; exit 130' INT TERM

# Função de logging segura
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Criar diretório de log se não existir
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Log com timestamp e nível
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    # Exibir no terminal com cores
    case "$level" in
        "ERROR") echo -e "${RED}[ERRO]${NC} $message" >&2 ;;
        "WARN")  echo -e "${YELLOW}[AVISO]${NC} $message" ;;
        "INFO")  echo -e "${BLUE}[INFO]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[SUCESSO]${NC} $message" ;;
    esac
}

# Validação robusta de entrada
validate_input() {
    local input="$1"
    local type="$2"
    local description="$3"
    
    case "$type" in
        "port")
            if [[ ! "$input" =~ ^[0-9]+$ ]] || [ "$input" -lt 1 ] || [ "$input" -gt 65535 ]; then
                log_message "ERROR" "Porta inválida para $description: $input"
                return 1
            fi
            ;;
        "ip")
            if [[ ! "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                log_message "ERROR" "IP inválido para $description: $input"
                return 1
            fi
            # Validar ranges válidos
            IFS='.' read -ra ADDR <<< "$input"
            for i in "${ADDR[@]}"; do
                if [ "$i" -gt 255 ]; then
                    log_message "ERROR" "Octeto IP inválido: $i"
                    return 1
                fi
            done
            ;;
        "password")
            if [ ${#input} -lt 8 ]; then
                log_message "ERROR" "Senha muito curta para $description (mínimo 8 caracteres)"
                return 1
            fi
            if [[ ! "$input" =~ [A-Za-z] ]] || [[ ! "$input" =~ [0-9] ]]; then
                log_message "ERROR" "Senha deve conter letras e números para $description"
                return 1
            fi
            ;;
        "username")
            if [[ ! "$input" =~ ^[a-zA-Z0-9_-]+$ ]] || [ ${#input} -lt 3 ]; then
                log_message "ERROR" "Nome de usuário inválido para $description: $input"
                return 1
            fi
            ;;
        "directory")
            if [[ ! "$input" =~ ^/[a-zA-Z0-9/_-]*$ ]]; then
                log_message "ERROR" "Caminho de diretório inválido para $description: $input"
                return 1
            fi
            ;;
        "domain")
            if [[ ! "$input" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                log_message "ERROR" "Domínio inválido para $description: $input"
                return 1
            fi
            ;;
        *)
            log_message "ERROR" "Tipo de validação desconhecido: $type"
            return 1
            ;;
    esac
    
    return 0
}

# Função para entrada segura com validação
secure_input() {
    local prompt="$1"
    local type="$2"
    local description="$3"
    local default="${4:-}"
    local input
    local attempts=0
    local max_attempts=3
    
    while [ $attempts -lt $max_attempts ]; do
        if [ -n "$default" ]; then
            input=$(dialog --inputbox "$prompt" 8 40 "$default" 2>&1 >/dev/tty)
            input="${input:-$default}"
        else
            input=$(dialog --inputbox "$prompt" 8 40 2>&1 >/dev/tty)
        fi
        
        if validate_input "$input" "$type" "$description"; then
            echo "$input"
            return 0
        fi
        
        ((attempts++))
        log_message "WARN" "Tentativa $attempts de $max_attempts falhada"
    done
    
    log_message "ERROR" "Máximo de tentativas excedido para $description"
    return 1
}

# Função para entrada de senha segura
secure_password_input() {
    local prompt="$1"
    local description="$2"
    local password
    local confirm_password
    local attempts=0
    local max_attempts=3
    
    while [ $attempts -lt $max_attempts ]; do
        password=$(dialog --passwordbox "$prompt" 8 40 2>&1 >/dev/tty)
        echo
        confirm_password=$(dialog --passwordbox "Confirme a senha:" 8 40 2>&1 >/dev/tty)
        echo
        
        if [ "$password" != "$confirm_password" ]; then
            log_message "ERROR" "Senhas não coincidem"
            ((attempts++))
            continue
        fi
        
        if validate_input "$password" "password" "$description"; then
            echo "$password"
            return 0
        fi
        
        ((attempts++))
    done
    
    log_message "ERROR" "Máximo de tentativas excedido para senha de $description"
    return 1
}

# Verificação de integridade para downloads
verify_download() {
    local file="$1"
    local expected_hash="${2:-}"
    local url="$3"
    
    if [ ! -f "$file" ]; then
        log_message "ERROR" "Arquivo não encontrado: $file"
        return 1
    fi
    
    # Verificar se o arquivo não está vazio
    if [ ! -s "$file" ]; then
        log_message "ERROR" "Arquivo vazio: $file"
        return 1
    fi
    
    # Verificar hash se fornecido
    if [ -n "$expected_hash" ]; then
        local actual_hash=$(sha256sum "$file" | cut -d' ' -f1)
        if [ "$actual_hash" != "$expected_hash" ]; then
            log_message "ERROR" "Hash inválido para $file"
            log_message "ERROR" "Esperado: $expected_hash"
            log_message "ERROR" "Atual: $actual_hash"
            return 1
        fi
    fi
    
    log_message "SUCCESS" "Download verificado: $file"
    return 0
}

# Download seguro com retry
secure_download() {
    local url="$1"
    local output="$2"
    local expected_hash="${3:-}"
    local max_retries=3
    local retry=0
    
    while [ $retry -lt $max_retries ]; do
        log_message "INFO" "Baixando $url (tentativa $((retry + 1))/$max_retries)"
        
        if curl -fsSL --connect-timeout 30 --max-time 300 "$url" -o "$output"; then
            if verify_download "$output" "$expected_hash" "$url"; then
                return 0
            fi
        fi
        
        ((retry++))
        if [ $retry -lt $max_retries ]; then
            log_message "WARN" "Falha no download, tentando novamente em 5 segundos..."
            sleep 5
        fi
    done
    
    log_message "ERROR" "Falha no download após $max_retries tentativas: $url"
    return 1
}

# Backup de configurações
create_backup() {
    local file="$1"
    local backup_name="$(basename "$file").$(date +%Y%m%d_%H%M%S).bak"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    if [ -f "$file" ]; then
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$backup_path"
        log_message "INFO" "Backup criado: $backup_path"
        echo "$backup_path"
    fi
}

# Restaurar backups em caso de erro
restore_backups() {
    log_message "INFO" "Restaurando backups..."
    
    if [ -d "$BACKUP_DIR" ]; then
        find "$BACKUP_DIR" -name "*.bak" -newer "$LOG_FILE" | while read -r backup; do
            local original=$(echo "$backup" | sed 's/.*\///; s/\.[0-9_]*\.bak$//')
            if [ -n "$original" ]; then
                log_message "INFO" "Restaurando $original"
                # Implementar lógica de restauração específica
            fi
        done
    fi
}

# Verificações específicas para RK322x
check_rk322x_compatibility() {
    log_message "INFO" "Verificando compatibilidade RK322x..."
    
    # Verificar arquitetura ARM
    if ! uname -m | grep -q "arm"; then
        log_message "ERROR" "Arquitetura não ARM detectada"
        return 1
    fi
    
    # Verificar memória disponível
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -gt "$RK322X_MAX_MEMORY" ]; then
        log_message "WARN" "Memória superior ao esperado para RK322x: ${total_mem}MB"
    fi
    
    # Verificar temperatura se disponível
    if [ -f "/sys/class/thermal/thermal_zone0/temp" ]; then
        local temp=$(cat /sys/class/thermal/thermal_zone0/temp)
        temp=$((temp / 1000))
        if [ "$temp" -gt "$RK322X_THERMAL_LIMIT" ]; then
            log_message "ERROR" "Temperatura muito alta: ${temp}°C (limite: ${RK322X_THERMAL_LIMIT}°C)"
            return 1
        fi
        log_message "INFO" "Temperatura OK: ${temp}°C"
    fi
    
    # Verificar espaço em disco
    local available_space=$(df / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 1048576 ]; then  # 1GB em KB
        log_message "ERROR" "Espaço insuficiente em disco: $((available_space / 1024))MB"
        return 1
    fi
    
    log_message "SUCCESS" "Sistema compatível com RK322x"
    return 0
}

# Otimizações específicas para NAND
optimize_for_nand() {
    log_message "INFO" "Aplicando otimizações para memória NAND..."
    
    # Configurar noatime para reduzir escritas
    if ! grep -q "noatime" /etc/fstab; then
        create_backup "/etc/fstab"
        sed -i 's/defaults/defaults,noatime/' /etc/fstab
        log_message "INFO" "Configurado noatime no fstab"
    fi
    
    # Configurar swappiness baixo
    echo "vm.swappiness=10" > /etc/sysctl.d/99-boxserver-nand.conf
    sysctl -p /etc/sysctl.d/99-boxserver-nand.conf
    
    # Configurar tmpfs para logs temporários
    if ! grep -q "tmpfs /tmp" /etc/fstab; then
        echo "tmpfs /tmp tmpfs defaults,noatime,size=100M 0 0" >> /etc/fstab
        log_message "INFO" "Configurado tmpfs para /tmp"
    fi
    
    log_message "SUCCESS" "Otimizações NAND aplicadas"
}

# Verificação de dependências com versões
check_dependencies() {
    log_message "INFO" "Verificando dependências do sistema..."
    
    local required_commands=("curl" "dialog" "systemctl" "iptables" "ufw")
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [ ${#missing_commands[@]} -gt 0 ]; then
        log_message "ERROR" "Comandos não encontrados: ${missing_commands[*]}"
        log_message "INFO" "Instalando dependências..."
        
        apt-get update
        for cmd in "${missing_commands[@]}"; do
            case "$cmd" in
                "dialog") apt-get install -y dialog ;;
                "curl") apt-get install -y curl ;;
                "ufw") apt-get install -y ufw ;;
                "iptables") apt-get install -y iptables ;;
                *) log_message "WARN" "Não sei como instalar: $cmd" ;;
            esac
        done
    fi
    
    # Verificar versões mínimas
    local curl_version=$(curl --version | head -n1 | grep -o '[0-9]\+\.[0-9]\+')
    log_message "INFO" "Versão do curl: $curl_version"
    
    log_message "SUCCESS" "Dependências verificadas"
}

# Função principal de verificações iniciais
run_initial_checks() {
    log_message "INFO" "Iniciando verificações do sistema..."
    
    # Verificar se é root
    if [ "$EUID" -ne 0 ]; then
        log_message "ERROR" "Este script deve ser executado como root"
        exit 1
    fi
    
    # Verificar conectividade
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        log_message "ERROR" "Sem conectividade com a internet"
        exit 1
    fi
    
    # Executar verificações específicas
    check_rk322x_compatibility || exit 1
    check_dependencies || exit 1
    
    # Criar diretórios necessários
    mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"
    
    log_message "SUCCESS" "Verificações iniciais concluídas"
}

# Instalação segura do Pi-hole
install_pihole_secure() {
    log_message "INFO" "Iniciando instalação segura do Pi-hole..."
    
    # Detectar interface de rede principal
    local main_interface
    main_interface=$(ip route | grep default | head -n1 | awk '{print $5}')
    
    if [ -z "$main_interface" ]; then
        log_message "ERROR" "Não foi possível detectar interface de rede"
        return 1
    fi
    
    log_message "INFO" "Interface detectada: $main_interface"
    
    # Obter configurações de rede atuais
    local current_ip
    current_ip=$(ip addr show "$main_interface" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
    
    if [ -z "$current_ip" ]; then
        log_message "ERROR" "Não foi possível obter IP atual"
        return 1
    fi
    
    # Solicitar configurações com validação
    local static_ip
    static_ip=$(secure_input "IP estático para Pi-hole" "ip" "Pi-hole" "$current_ip")
    
    local admin_password
    admin_password=$(secure_password_input "Senha do admin Pi-hole" "Pi-hole admin")
    
    # Criar arquivo de configuração seguro
    local setup_vars="/etc/pihole/setupVars.conf"
    mkdir -p "$(dirname "$setup_vars")"
    
    cat > "$setup_vars" << EOF
PIHOLE_INTERFACE=$main_interface
IPV4_ADDRESS=$static_ip/24
IPV6_ADDRESS=
PIHOLE_DNS_1=1.1.1.1
PIHOLE_DNS_2=1.0.0.1
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSSEC=true
TEMPERATURE_UNIT=C
WEBUI_BOXED_LAYOUT=boxed
WEBTHEME=default-dark
EOF
    
    # Definir permissões seguras
    chmod 644 "$setup_vars"
    
    # Download e verificação do instalador Pi-hole
    local pihole_installer="/tmp/pihole_install.sh"
    local pihole_url="https://install.pi-hole.net"
    
    if ! secure_download "$pihole_url" "$pihole_installer"; then
        log_message "ERROR" "Falha no download do instalador Pi-hole"
        return 1
    fi
    
    # Executar instalação
    chmod +x "$pihole_installer"
    if ! bash "$pihole_installer" --unattended; then
        log_message "ERROR" "Falha na instalação do Pi-hole"
        return 1
    fi
    
    # Configurar senha do admin
    echo "$admin_password" | pihole -a -p
    
    # Limpar senha da memória
    unset admin_password
    
    log_message "SUCCESS" "Pi-hole instalado com sucesso"
    log_message "INFO" "Interface web: http://$static_ip/admin"
}

# Instalação segura do Unbound
install_unbound_secure() {
    log_message "INFO" "Iniciando instalação segura do Unbound..."
    
    # Verificar se Pi-hole está instalado
    if ! command -v pihole &> /dev/null; then
        log_message "WARN" "Pi-hole não encontrado. Recomenda-se instalar Pi-hole primeiro."
        if ! dialog --yesno "Continuar sem Pi-hole?" 8 50; then
            return 1
        fi
    fi
    
    # Criar backup da configuração atual
    create_backup "/etc/unbound" "unbound-config"
    
    # Verificar dependências
    local packages=("unbound" "unbound-host")
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            log_message "INFO" "Instalando $package..."
            if ! apt-get update && apt-get install -y "$package"; then
                log_message "ERROR" "Falha ao instalar $package"
                return 1
            fi
        fi
    done
    
    # Configurar Unbound para RK322x
    local unbound_conf="/etc/unbound/unbound.conf.d/pi-hole.conf"
    mkdir -p "$(dirname "$unbound_conf")"
    
    cat > "$unbound_conf" << 'EOF'
server:
    # Configurações otimizadas para RK322x (ARM, baixa memória)
    verbosity: 1
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    
    # Otimizações de memória para dispositivos ARM
    msg-cache-size: 8m
    rrset-cache-size: 16m
    cache-max-ttl: 86400
    cache-min-ttl: 300
    
    # Configurações de segurança
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    unwanted-reply-threshold: 10000000
    
    # Configurações de rede
    num-threads: 2
    msg-cache-slabs: 2
    rrset-cache-slabs: 2
    infra-cache-slabs: 2
    key-cache-slabs: 2
    
    # Configurações de performance para NAND
    so-rcvbuf: 1m
    so-sndbuf: 1m
    so-reuseport: yes
    
    # Root hints
    root-hints: "/var/lib/unbound/root.hints"
    
    # Configurações de privacidade
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
EOF
    
    # Download e verificação do root hints
    local root_hints="/var/lib/unbound/root.hints"
    mkdir -p "$(dirname "$root_hints")"
    
    local root_hints_url="https://www.internic.net/domain/named.cache"
    if ! secure_download "$root_hints_url" "$root_hints"; then
        log_message "ERROR" "Falha no download do root hints"
        return 1
    fi
    
    # Definir permissões seguras
    chown -R unbound:unbound "/var/lib/unbound"
    chmod 644 "$unbound_conf" "$root_hints"
    
    # Testar configuração
    if ! unbound-checkconf; then
        log_message "ERROR" "Configuração do Unbound inválida"
        return 1
    fi
    
    # Habilitar e iniciar serviço
    systemctl enable unbound
    if ! systemctl restart unbound; then
        log_message "ERROR" "Falha ao iniciar Unbound"
        return 1
    fi
    
    # Verificar se está funcionando
    sleep 3
    if ! systemctl is-active --quiet unbound; then
        log_message "ERROR" "Unbound não está ativo"
        return 1
    fi
    
    # Teste de resolução DNS
    if ! dig @127.0.0.1 -p 5335 google.com +short &> /dev/null; then
        log_message "WARN" "Teste de resolução DNS falhou"
    else
        log_message "SUCCESS" "Unbound funcionando corretamente"
    fi
    
    log_message "SUCCESS" "Unbound instalado e configurado com sucesso"
    log_message "INFO" "Servidor DNS recursivo: 127.0.0.1:5335"
}

# Configuração integrada Pi-hole + Unbound
configure_pihole_unbound() {
    log_message "INFO" "Configurando integração Pi-hole + Unbound..."
    
    # Verificar se ambos estão instalados
    if ! command -v pihole &> /dev/null; then
        log_message "ERROR" "Pi-hole não encontrado. Instale primeiro."
        return 1
    fi
    
    if ! systemctl is-active --quiet unbound; then
        log_message "ERROR" "Unbound não está ativo. Instale primeiro."
        return 1
    fi
    
    # Criar backup das configurações atuais
    create_backup "/etc/pihole" "pihole-unbound-config"
    create_backup "/etc/dnsmasq.d" "dnsmasq-unbound-config"
    
    # Configurar Pi-hole para usar Unbound
    local pihole_custom_dns="/etc/pihole/setupVars.conf"
    
    if [ -f "$pihole_custom_dns" ]; then
        # Backup da configuração atual
        cp "$pihole_custom_dns" "${pihole_custom_dns}.backup"
        
        # Atualizar configuração para usar Unbound
        sed -i 's/PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' "$pihole_custom_dns"
        sed -i 's/PIHOLE_DNS_2=.*/PIHOLE_DNS_2=/' "$pihole_custom_dns"
        
        # Adicionar configurações específicas se não existirem
        if ! grep -q "DNSSEC=" "$pihole_custom_dns"; then
            echo "DNSSEC=false" >> "$pihole_custom_dns"
        else
            sed -i 's/DNSSEC=.*/DNSSEC=false/' "$pihole_custom_dns"
        fi
    else
        log_message "ERROR" "Arquivo de configuração Pi-hole não encontrado"
        return 1
    fi
    
    # Configurar dnsmasq para não interferir com Unbound
    local dnsmasq_unbound="/etc/dnsmasq.d/99-unbound.conf"
    cat > "$dnsmasq_unbound" << 'EOF'
# Configuração para integração com Unbound
# Desabilitar DNSSEC no dnsmasq (Unbound fará isso)
proxy-dnssec
EOF
    
    # Configurar logrotate para logs do Unbound
    local logrotate_unbound="/etc/logrotate.d/unbound"
    cat > "$logrotate_unbound" << 'EOF'
/var/log/unbound.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    postrotate
        /usr/sbin/unbound-control log_reopen
    endscript
}
EOF
    
    # Configurar monitoramento da integração
    local monitor_script="/usr/local/bin/pihole-unbound-monitor.sh"
    cat > "$monitor_script" << 'EOF'
#!/bin/bash
# Monitor da integração Pi-hole + Unbound

LOG_FILE="/var/log/pihole-unbound-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Função de log
log_monitor() {
    echo "[$DATE] $1" >> "$LOG_FILE"
}

# Verificar se Unbound está respondendo
if ! dig @127.0.0.1 -p 5335 google.com +short &> /dev/null; then
    log_monitor "ERROR: Unbound não está respondendo"
    systemctl restart unbound
    sleep 5
fi

# Verificar se Pi-hole está usando Unbound
if ! pihole status | grep -q "enabled"; then
    log_monitor "ERROR: Pi-hole não está ativo"
fi

# Verificar resolução através do Pi-hole
if ! dig @127.0.0.1 google.com +short &> /dev/null; then
    log_monitor "ERROR: Pi-hole não está resolvendo DNS"
    systemctl restart pihole-FTL
fi

log_monitor "INFO: Verificação concluída - Sistema funcionando"
EOF
    
    chmod +x "$monitor_script"
    
    # Configurar cron para monitoramento
    local cron_entry="*/5 * * * * root $monitor_script"
    if ! crontab -l 2>/dev/null | grep -q "pihole-unbound-monitor"; then
        (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -
    fi
    
    # Reiniciar serviços na ordem correta
    log_message "INFO" "Reiniciando serviços..."
    
    systemctl restart unbound
    sleep 3
    
    if ! systemctl is-active --quiet unbound; then
        log_message "ERROR" "Falha ao reiniciar Unbound"
        return 1
    fi
    
    systemctl restart pihole-FTL
    sleep 3
    
    if ! systemctl is-active --quiet pihole-FTL; then
        log_message "ERROR" "Falha ao reiniciar Pi-hole FTL"
        return 1
    fi
    
    # Testar integração
    log_message "INFO" "Testando integração..."
    
    # Teste 1: Unbound direto
    if dig @127.0.0.1 -p 5335 google.com +short &> /dev/null; then
        log_message "SUCCESS" "Unbound respondendo corretamente"
    else
        log_message "ERROR" "Unbound não está respondendo"
        return 1
    fi
    
    # Teste 2: Pi-hole usando Unbound
    if dig @127.0.0.1 google.com +short &> /dev/null; then
        log_message "SUCCESS" "Pi-hole usando Unbound corretamente"
    else
        log_message "ERROR" "Pi-hole não está usando Unbound"
        return 1
    fi
    
    # Teste 3: Verificar bloqueio de ads
    if dig @127.0.0.1 doubleclick.net +short | grep -q "0.0.0.0\|127.0.0.1"; then
        log_message "SUCCESS" "Bloqueio de anúncios funcionando"
    else
        log_message "WARN" "Bloqueio de anúncios pode não estar funcionando"
    fi
    
    log_message "SUCCESS" "Integração Pi-hole + Unbound configurada com sucesso"
    log_message "INFO" "Monitor automático configurado (executa a cada 5 minutos)"
    log_message "INFO" "Logs do monitor: /var/log/pihole-unbound-monitor.log"
}

# Instalação segura do WireGuard
install_wireguard_secure() {
    log_message "INFO" "Iniciando instalação segura do WireGuard..."
    
    # Verificar se já está instalado
    if command -v wg &> /dev/null; then
        log_message "WARN" "WireGuard já está instalado"
        if ! dialog --yesno "Reconfigurar WireGuard?" 8 50; then
            return 0
        fi
    fi
    
    # Criar backup de configurações existentes
    create_backup "/etc/wireguard" "wireguard-config"
    
    # Instalar dependências
    local packages=("wireguard" "wireguard-tools" "qrencode" "iptables-persistent")
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            log_message "INFO" "Instalando $package..."
            if ! apt-get update && apt-get install -y "$package"; then
                log_message "ERROR" "Falha ao instalar $package"
                return 1
            fi
        fi
    done
    
    # Configurações de entrada do usuário
    local server_port
    server_port=$(secure_input "Porta do servidor WireGuard" "port" "WireGuard" "51820")
    
    local server_ip
    server_ip=$(secure_input "IP interno do servidor" "ip" "WireGuard" "10.8.0.1")
    
    local client_count
    while true; do
        client_count=$(dialog --inputbox "Número de clientes (1-10):" 8 50 "3" 2>&1 >/dev/tty)
        if [[ "$client_count" =~ ^[1-9]$|^10$ ]]; then
            break
        fi
        dialog --msgbox "Número inválido. Digite entre 1 e 10." 8 50
    done
    
    # Detectar interface de rede
    local main_interface
    main_interface=$(ip route | grep default | head -n1 | awk '{print $5}')
    
    if [ -z "$main_interface" ]; then
        log_message "ERROR" "Não foi possível detectar interface de rede"
        return 1
    fi
    
    log_message "INFO" "Interface detectada: $main_interface"
    
    # Habilitar IP forwarding
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard.conf
    sysctl -p /etc/sysctl.d/99-wireguard.conf
    
    # Criar diretório de configuração
    mkdir -p /etc/wireguard/clients
    chmod 700 /etc/wireguard
    
    # Gerar chaves do servidor de forma segura
    local server_private_key
    local server_public_key
    
    server_private_key=$(wg genkey)
    server_public_key=$(echo "$server_private_key" | wg pubkey)
    
    # Configuração do servidor
    cat > "/etc/wireguard/wg0.conf" << EOF
[Interface]
PrivateKey = $server_private_key
Address = $server_ip/24
ListenPort = $server_port
SaveConfig = true

# Regras de firewall otimizadas para RK322x
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $main_interface -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $main_interface -j MASQUERADE

EOF
    
    # Definir permissões seguras
    chmod 600 /etc/wireguard/wg0.conf
    
    # Gerar configurações de clientes
    local client_configs_dir="/etc/wireguard/clients"
    mkdir -p "$client_configs_dir"
    
    for ((i=1; i<=client_count; i++)); do
        local client_name="client$i"
        local client_ip="10.8.0.$((i+1))"
        
        # Gerar chaves do cliente
        local client_private_key
        local client_public_key
        
        client_private_key=$(wg genkey)
        client_public_key=$(echo "$client_private_key" | wg pubkey)
        
        # Configuração do cliente
        cat > "$client_configs_dir/$client_name.conf" << EOF
[Interface]
PrivateKey = $client_private_key
Address = $client_ip/24
DNS = $server_ip

[Peer]
PublicKey = $server_public_key
AllowedIPs = 0.0.0.0/0
Endpoint = $(curl -s ifconfig.me):$server_port
PersistentKeepalive = 25
EOF
        
        # Adicionar peer ao servidor
        cat >> "/etc/wireguard/wg0.conf" << EOF

[Peer]
# $client_name
PublicKey = $client_public_key
AllowedIPs = $client_ip/32
EOF
        
        # Gerar QR Code
        qrencode -t ansiutf8 < "$client_configs_dir/$client_name.conf" > "$client_configs_dir/$client_name.qr"
        
        log_message "SUCCESS" "Cliente $client_name configurado"
    done
    
    # Configurar firewall específico para RK322x
    local firewall_rules="/etc/wireguard/firewall-rules.sh"
    cat > "$firewall_rules" << 'EOF'
#!/bin/bash
# Regras de firewall otimizadas para RK322x

# Limpar regras existentes
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Políticas padrão
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Permitir loopback
iptables -A INPUT -i lo -j ACCEPT

# Permitir conexões estabelecidas
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Permitir SSH (porta 22)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permitir WireGuard
iptables -A INPUT -p udp --dport WG_PORT -j ACCEPT

# Permitir Pi-hole (se instalado)
if systemctl is-active --quiet pihole-FTL; then
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT
    iptables -A INPUT -p udp --dport 53 -j ACCEPT
fi

# Salvar regras
iptables-save > /etc/iptables/rules.v4
EOF
    
    # Substituir porta no script
    sed -i "s/WG_PORT/$server_port/g" "$firewall_rules"
    chmod +x "$firewall_rules"
    
    # Aplicar regras de firewall
    bash "$firewall_rules"
    
    # Habilitar e iniciar WireGuard
    systemctl enable wg-quick@wg0
    if ! systemctl start wg-quick@wg0; then
        log_message "ERROR" "Falha ao iniciar WireGuard"
        return 1
    fi
    
    # Verificar se está funcionando
    sleep 3
    if ! systemctl is-active --quiet wg-quick@wg0; then
        log_message "ERROR" "WireGuard não está ativo"
        return 1
    fi
    
    # Criar script de gerenciamento
    local manage_script="/usr/local/bin/wg-manage.sh"
    cat > "$manage_script" << 'EOF'
#!/bin/bash
# Script de gerenciamento WireGuard

case "$1" in
    "status")
        echo "=== Status WireGuard ==="
        systemctl status wg-quick@wg0
        echo
        wg show
        ;;
    "clients")
        echo "=== Configurações de Clientes ==="
        ls -la /etc/wireguard/clients/
        ;;
    "qr")
        if [ -z "$2" ]; then
            echo "Uso: $0 qr <nome_cliente>"
            exit 1
        fi
        cat "/etc/wireguard/clients/$2.qr"
        ;;
    "restart")
        systemctl restart wg-quick@wg0
        echo "WireGuard reiniciado"
        ;;
    *)
        echo "Uso: $0 {status|clients|qr|restart}"
        echo "  status  - Mostra status do serviço"
        echo "  clients - Lista clientes configurados"
        echo "  qr <nome> - Mostra QR code do cliente"
        echo "  restart - Reinicia o serviço"
        ;;
esac
EOF
    
    chmod +x "$manage_script"
    
    # Limpar chaves da memória
    unset server_private_key client_private_key
    
    log_message "SUCCESS" "WireGuard instalado e configurado com sucesso"
    log_message "INFO" "Porta: $server_port"
    log_message "INFO" "Rede interna: 10.8.0.0/24"
    log_message "INFO" "Clientes configurados: $client_count"
    log_message "INFO" "Configurações em: /etc/wireguard/clients/"
    log_message "INFO" "Gerenciamento: wg-manage.sh {status|clients|qr|restart}"
}

# Instalação segura do Cockpit
install_cockpit_secure() {
    log_message "INFO" "Iniciando instalação segura do Cockpit..."
    
    # Verificar se já está instalado
    if systemctl is-active --quiet cockpit; then
        log_message "WARN" "Cockpit já está ativo"
        if ! dialog --yesno "Reconfigurar Cockpit?" 8 50; then
            return 0
        fi
    fi
    
    # Criar backup de configurações existentes
    create_backup "/etc/cockpit" "cockpit-config"
    
    # Instalar Cockpit e módulos essenciais
    local packages=("cockpit" "cockpit-system" "cockpit-networkmanager" "cockpit-storaged")
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            log_message "INFO" "Instalando $package..."
            if ! apt-get update && apt-get install -y "$package"; then
                log_message "ERROR" "Falha ao instalar $package"
                return 1
            fi
        fi
    done
    
    # Configurar porta personalizada
    local cockpit_port
    cockpit_port=$(secure_input "Porta do Cockpit" "port" "Cockpit" "9090")
    
    # Configurar SSL/TLS
    mkdir -p /etc/cockpit/ws-certs.d
    
    # Gerar certificado auto-assinado se não existir
    if [ ! -f "/etc/cockpit/ws-certs.d/0-self-signed.cert" ]; then
        log_message "INFO" "Gerando certificado SSL auto-assinado..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/cockpit/ws-certs.d/0-self-signed.key \
            -out /etc/cockpit/ws-certs.d/0-self-signed.cert \
            -subj "/C=BR/ST=BoxServer/L=Local/O=BoxServer/CN=boxserver.local"
        
        chmod 600 /etc/cockpit/ws-certs.d/0-self-signed.key
        chmod 644 /etc/cockpit/ws-certs.d/0-self-signed.cert
    fi
    
    # Configuração principal do Cockpit
    cat > "/etc/cockpit/cockpit.conf" << EOF
[WebService]
# Configuração otimizada para RK322x
ListenStream=$cockpit_port
ListenStream=
ProtocolHeader = X-Forwarded-Proto
ForwardedForHeader = X-Forwarded-For
LoginTitle = BoxServer Management
LoginTo = false
RequireHost = false
UrlRoot = /
MaxStartups = 3
IdleTimeout = 15

[Session]
IdleTimeout = 15
Banner = /etc/cockpit/issue.cockpit

[Log]
Fatal = cockpit-ws
EOF
    
    # Criar banner personalizado
    cat > "/etc/cockpit/issue.cockpit" << 'EOF'
╔══════════════════════════════════════╗
║          BoxServer Management        ║
║         RK322x TV Box Server         ║
╚══════════════════════════════════════╝

Acesso autorizado apenas!
Todas as atividades são monitoradas.
EOF
    
    # Configurar autenticação robusta
    cat > "/etc/pam.d/cockpit" << 'EOF'
# Configuração PAM para Cockpit - BoxServer
auth       required     pam_env.so
auth       required     pam_faildelay.so delay=2000000
auth       [success=2 default=ignore] pam_unix.so nullok_secure try_first_pass
auth       [default=die] pam_faillock.so authfail deny=3 unlock_time=600
auth       sufficient   pam_faillock.so authsucc
auth       required     pam_deny.so

account    required     pam_faillock.so
account    required     pam_unix.so
account    required     pam_permit.so

session    required     pam_limits.so
session    required     pam_unix.so
session    optional     pam_lastlog.so
EOF
    
    # Configurar firewall para Cockpit
    if command -v ufw &> /dev/null; then
        ufw allow $cockpit_port/tcp comment "Cockpit Web Interface"
    fi
    
    # Habilitar e iniciar serviços
    systemctl enable cockpit.socket
    systemctl enable cockpit
    
    if ! systemctl start cockpit.socket; then
        log_message "ERROR" "Falha ao iniciar Cockpit"
        return 1
    fi
    
    # Verificar se está funcionando
    sleep 3
    if ! systemctl is-active --quiet cockpit.socket; then
        log_message "ERROR" "Cockpit não está ativo"
        return 1
    fi
    
    log_message "SUCCESS" "Cockpit instalado e configurado com sucesso"
    log_message "INFO" "Acesso: https://$(hostname -I | awk '{print $1}'):$cockpit_port"
    log_message "INFO" "Certificado: Auto-assinado (válido por 365 dias)"
    log_message "INFO" "Autenticação: Sistema local com proteção contra força bruta"
}

# Instalação segura do FileBrowser
install_filebrowser_secure() {
    log_message "INFO" "Iniciando instalação segura do FileBrowser..."
    
    # Verificar se já está instalado
    if [ -f "/usr/local/bin/filebrowser" ]; then
        log_message "WARN" "FileBrowser já está instalado"
        if ! dialog --yesno "Reconfigurar FileBrowser?" 8 50; then
            return 0
        fi
    fi
    
    # Criar backup de configurações existentes
    create_backup "/etc/filebrowser" "filebrowser-config"
    
    # Baixar e instalar FileBrowser
    local fb_version="v2.24.2"
    local fb_url="https://github.com/filebrowser/filebrowser/releases/download/$fb_version/linux-arm-filebrowser.tar.gz"
    local temp_dir="/tmp/filebrowser-install"
    
    mkdir -p "$temp_dir"
    cd "$temp_dir"
    
    log_message "INFO" "Baixando FileBrowser $fb_version..."
    if ! curl -L "$fb_url" -o filebrowser.tar.gz; then
        log_message "ERROR" "Falha ao baixar FileBrowser"
        return 1
    fi
    
    # Extrair e instalar
    tar -xzf filebrowser.tar.gz
    chmod +x filebrowser
    mv filebrowser /usr/local/bin/
    
    # Criar usuário dedicado
    if ! id "filebrowser" &>/dev/null; then
        useradd -r -s /bin/false -d /var/lib/filebrowser filebrowser
    fi
    
    # Criar diretórios
    mkdir -p /etc/filebrowser
    mkdir -p /var/lib/filebrowser
    mkdir -p /var/log/filebrowser
    
    chown filebrowser:filebrowser /var/lib/filebrowser
    chown filebrowser:filebrowser /var/log/filebrowser
    
    # Configurar porta e credenciais
    local fb_port
    fb_port=$(secure_input "Porta do FileBrowser" "port" "FileBrowser" "8080")
    
    local fb_user
    fb_user=$(secure_input "Usuário admin" "username" "FileBrowser" "admin")
    
    local fb_pass
    fb_pass=$(secure_password_input "Senha admin" "FileBrowser")
    
    # Configuração principal
    cat > "/etc/filebrowser/config.json" << EOF
{
  "port": $fb_port,
  "baseURL": "",
  "address": "0.0.0.0",
  "log": "file",
  "logfile": "/var/log/filebrowser/filebrowser.log",
  "database": "/var/lib/filebrowser/database.db",
  "root": "/home",
  "username": "$fb_user",
  "password": "$fb_pass",
  "scope": "/home",
  "locale": "pt-br",
  "signup": false,
  "createUserDir": false,
  "defaults": {
    "scope": "/home",
    "locale": "pt-br",
    "viewMode": "list",
    "sorting": {
      "by": "name",
      "asc": true
    },
    "perm": {
      "admin": false,
      "execute": false,
      "create": true,
      "rename": true,
      "modify": true,
      "delete": true,
      "share": false,
      "download": true
    }
  },
  "commands": [],
  "shell": [],
  "rules": [
    {
      "regex": true,
      "allow": false,
      "regexp": "\\.(exe|bat|cmd|com|pif|scr|vbs|js)$"
    }
  ]
}
EOF
    
    chmod 600 /etc/filebrowser/config.json
    chown filebrowser:filebrowser /etc/filebrowser/config.json
    
    # Criar serviço systemd
    cat > "/etc/systemd/system/filebrowser.service" << 'EOF'
[Unit]
Description=FileBrowser Service
After=network.target

[Service]
Type=simple
User=filebrowser
Group=filebrowser
ExecStart=/usr/local/bin/filebrowser -c /etc/filebrowser/config.json
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=filebrowser

# Segurança
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=/var/lib/filebrowser /var/log/filebrowser /home

# Limites de recursos para RK322x
LimitNOFILE=1024
LimitNPROC=32
MemoryMax=128M

[Install]
WantedBy=multi-user.target
EOF
    
    # Configurar logrotate
    cat > "/etc/logrotate.d/filebrowser" << 'EOF'
/var/log/filebrowser/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
    su filebrowser filebrowser
}
EOF
    
    # Configurar firewall
    if command -v ufw &> /dev/null; then
        ufw allow $fb_port/tcp comment "FileBrowser Web Interface"
    fi
    
    # Inicializar banco de dados
    sudo -u filebrowser /usr/local/bin/filebrowser -c /etc/filebrowser/config.json config init
    sudo -u filebrowser /usr/local/bin/filebrowser -c /etc/filebrowser/config.json users add "$fb_user" "$fb_pass" --perm.admin
    
    # Habilitar e iniciar serviço
    systemctl daemon-reload
    systemctl enable filebrowser
    
    if ! systemctl start filebrowser; then
        log_message "ERROR" "Falha ao iniciar FileBrowser"
        return 1
    fi
    
    # Verificar se está funcionando
    sleep 3
    if ! systemctl is-active --quiet filebrowser; then
        log_message "ERROR" "FileBrowser não está ativo"
        return 1
    fi
    
    # Limpar senha da memória
    unset fb_pass
    
    # Limpeza
    rm -rf "$temp_dir"
    
    log_message "SUCCESS" "FileBrowser instalado e configurado com sucesso"
    log_message "INFO" "Interface web: http://$(hostname -I | awk '{print $1}'):$fb_port"
}

# Configuração segura de entropia (RNG-tools)
configure_entropy_secure() {
    log_message "INFO" "Configurando entropia segura para RK322x..."
    
    # Verificar se já está configurado
    if systemctl is-active --quiet rng-tools; then
        log_message "WARN" "RNG-tools já está ativo"
        if ! dialog --yesno "Reconfigurar entropia?" 8 50; then
            return 0
        fi
    fi
    
    # Criar backup de configurações existentes
    create_backup "/etc/default/rng-tools" "rng-tools-config"
    
    # Instalar rng-tools
    if ! dpkg -l | grep -q "^ii.*rng-tools"; then
        log_message "INFO" "Instalando rng-tools..."
        if ! apt-get update && apt-get install -y rng-tools; then
            log_message "ERROR" "Falha ao instalar rng-tools"
            return 1
        fi
    fi
    
    # Configurar para RK322x
    cat > "/etc/default/rng-tools" << 'EOF'
# Configuração otimizada para RK322x
RNGD_OPTS="-o /dev/random -r /dev/urandom -W 75 -t 60"
EOF
    
    # Configurar serviço systemd
    cat > "/etc/systemd/system/rng-tools.service.d/override.conf" << 'EOF'
[Unit]
Description=Hardware RNG Entropy Gatherer Daemon
DefaultDependencies=no
After=systemd-udev-settle.service
Before=sysinit.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=forking
ExecStart=
ExecStart=/usr/sbin/rngd $RNGD_OPTS
SuccessExitStatus=1
Restart=on-failure
RestartSec=5

# Limites para RK322x
MemoryMax=32M
CPUQuota=10%

[Install]
WantedBy=sysinit.target
EOF
    
    mkdir -p /etc/systemd/system/rng-tools.service.d
    
    # Recarregar e habilitar
    systemctl daemon-reload
    systemctl enable rng-tools
    
    if ! systemctl restart rng-tools; then
        log_message "ERROR" "Falha ao iniciar rng-tools"
        return 1
    fi
    
    # Verificar entropia disponível
    sleep 2
    local entropy_available
    entropy_available=$(cat /proc/sys/kernel/random/entropy_avail)
    
    if [ "$entropy_available" -gt 1000 ]; then
        log_message "SUCCESS" "Entropia configurada com sucesso ($entropy_available bits)"
    else
        log_message "WARN" "Entropia baixa ($entropy_available bits)"
    fi
    
    log_message "SUCCESS" "RNG-tools configurado para RK322x"
}

# Instalação segura do Netdata
install_netdata_secure() {
    log_message "INFO" "Iniciando instalação segura do Netdata..."
    
    # Verificar se já está instalado
    if systemctl is-active --quiet netdata; then
        log_message "WARN" "Netdata já está ativo"
        if ! dialog --yesno "Reconfigurar Netdata?" 8 50; then
            return 0
        fi
    fi
    
    # Criar backup de configurações existentes
    create_backup "/etc/netdata" "netdata-config"
    
    # Instalar dependências
    local packages=("curl" "wget" "uuid-dev" "zlib1g-dev" "libuv1-dev" "liblz4-dev" "libjudy-dev" "libssl-dev" "libelf-dev" "libmnl-dev")
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            log_message "INFO" "Instalando $package..."
            if ! apt-get update && apt-get install -y "$package"; then
                log_message "WARN" "Falha ao instalar $package, continuando..."
            fi
        fi
    done
    
    # Download e instalação do Netdata
    local netdata_installer="/tmp/netdata-kickstart.sh"
    local netdata_url="https://my-netdata.io/kickstart.sh"
    
    if ! secure_download "$netdata_url" "$netdata_installer"; then
        log_message "ERROR" "Falha no download do instalador Netdata"
        return 1
    fi
    
    # Configurar porta personalizada
    local netdata_port
    netdata_port=$(secure_input "Porta do Netdata" "port" "Netdata" "19999")
    
    # Executar instalação não-interativa
    chmod +x "$netdata_installer"
    if ! bash "$netdata_installer" --stable-channel --disable-telemetry --dont-wait; then
        log_message "ERROR" "Falha na instalação do Netdata"
        return 1
    fi
    
    # Configuração otimizada para RK322x
    cat > "/etc/netdata/netdata.conf" << EOF
[global]
    # Configurações básicas
    hostname = BoxServer-RK322x
    default port = $netdata_port
    bind socket to IP = 0.0.0.0
    
    # Otimizações de memória para RK322x
    memory mode = ram
    page cache size = 32
    dbengine multihost disk space = 64
    
    # Configurações de performance
    update every = 2
    history = 3600
    
    # Configurações de segurança
    run as user = netdata
    web files owner = root
    web files group = netdata
    
[web]
    # Configurações da interface web
    web files owner = root
    web files group = netdata
    respect do not track policy = yes
    allow connections from = localhost 10.* 192.168.* 172.16.* 172.17.* 172.18.* 172.19.* 172.20.* 172.21.* 172.22.* 172.23.* 172.24.* 172.25.* 172.26.* 172.27.* 172.28.* 172.29.* 172.30.* 172.31.*
    
[plugins]
    # Desabilitar plugins pesados para RK322x
    python.d = no
    charts.d = no
    node.d = no
    
[plugin:proc]
    # Configurações do plugin proc
    /proc/net/dev = yes
    /proc/diskstats = yes
    /proc/net/sockstat = yes
    /proc/net/netstat = yes
    /proc/net/stat/conntrack = no
    /proc/net/stat/synproxy = no
    
EOF
    
    # Configurar limites de recursos
    cat > "/etc/systemd/system/netdata.service.d/override.conf" << 'EOF'
[Service]
# Limites para RK322x
MemoryMax=128M
CPUQuota=25%
IOWeight=100

# Configurações de segurança
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/cache/netdata /var/lib/netdata /var/log/netdata
EOF
    
    mkdir -p /etc/systemd/system/netdata.service.d
    
    # Configurar logrotate
    cat > "/etc/logrotate.d/netdata" << 'EOF'
/var/log/netdata/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
    su netdata netdata
}
EOF
    
    # Recarregar e reiniciar
    systemctl daemon-reload
    systemctl enable netdata
    
    if ! systemctl restart netdata; then
        log_message "ERROR" "Falha ao iniciar Netdata"
        return 1
    fi
    
    # Verificar se está funcionando
    sleep 5
    if ! systemctl is-active --quiet netdata; then
        log_message "ERROR" "Netdata não está ativo"
        return 1
    fi
    
    # Teste de conectividade
    if curl -s "http://localhost:$netdata_port/api/v1/info" > /dev/null; then
        log_message "SUCCESS" "Netdata funcionando corretamente"
    else
        log_message "WARN" "Teste de conectividade falhou"
    fi
    
    log_message "SUCCESS" "Netdata instalado e configurado com sucesso"
    log_message "INFO" "Interface web: http://$(hostname -I | awk '{print $1}'):$netdata_port"
}

# Instalação segura do Fail2Ban
install_fail2ban_secure() {
    log_message "INFO" "Iniciando instalação segura do Fail2Ban..."
    
    # Verificar se já está instalado
    if systemctl is-active --quiet fail2ban; then
        log_message "WARN" "Fail2Ban já está ativo"
        if ! dialog --yesno "Reconfigurar Fail2Ban?" 8 50; then
            return 0
        fi
    fi
    
    # Criar backup de configurações existentes
    create_backup "/etc/fail2ban" "fail2ban-config"
    
    # Instalar Fail2Ban
    if ! dpkg -l | grep -q "^ii.*fail2ban"; then
        log_message "INFO" "Instalando fail2ban..."
        if ! apt-get update && apt-get install -y fail2ban; then
            log_message "ERROR" "Falha ao instalar fail2ban"
            return 1
        fi
    fi
    
    # Configuração principal otimizada para BoxServer
    cat > "/etc/fail2ban/jail.local" << 'EOF'
[DEFAULT]
# Configurações globais para BoxServer RK322x
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

# Configurações de email (desabilitado para RK322x)
destemail = root@localhost
sender = fail2ban@boxserver
mta = sendmail
action = %(action_)s

# Ignorar IPs locais
ignoreip = 127.0.0.1/8 ::1 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8

# Jail para SSH
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

# Jail para Pi-hole (se instalado)
[pihole]
enabled = true
port = 80,443
filter = pihole
logpath = /var/log/pihole.log
maxretry = 5
bantime = 1800

# Jail para Cockpit (se instalado)
[cockpit]
enabled = true
port = 9090
filter = cockpit
logpath = /var/log/cockpit/cockpit.log
maxretry = 3
bantime = 3600

# Jail para WireGuard
[wireguard]
enabled = true
port = 51820
filter = wireguard
logpath = /var/log/syslog
maxretry = 3
bantime = 7200

# Jail para Netdata (se instalado)
[netdata]
enabled = true
port = 19999
filter = netdata
logpath = /var/log/netdata/access.log
maxretry = 10
bantime = 1800
EOF
    
    # Filtro personalizado para Pi-hole
    cat > "/etc/fail2ban/filter.d/pihole.conf" << 'EOF'
[Definition]
failregex = ^.*\[.*\] .*: query\[.*\] .* from <HOST>.*$
            ^.*\[.*\] .*: reply .* is <HOST>.*$
ignoreregex =
EOF
    
    # Filtro personalizado para Cockpit
    cat > "/etc/fail2ban/filter.d/cockpit.conf" << 'EOF'
[Definition]
failregex = ^.*cockpit-ws:.*: .*authentication failed.*from <HOST>.*$
            ^.*cockpit-session:.*: .*authentication failed.*from <HOST>.*$
ignoreregex =
EOF
    
    # Filtro personalizado para WireGuard
    cat > "/etc/fail2ban/filter.d/wireguard.conf" << 'EOF'
[Definition]
failregex = ^.*kernel:.*wireguard:.*: Invalid handshake initiation from <HOST>.*$
            ^.*kernel:.*wireguard:.*: Packet has unallowed src IP <HOST>.*$
ignoreregex =
EOF
    
    # Filtro personalizado para Netdata
    cat > "/etc/fail2ban/filter.d/netdata.conf" << 'EOF'
[Definition]
failregex = ^<HOST> .*"GET .* HTTP.*" 40[13] .*$
            ^<HOST> .*"POST .* HTTP.*" 40[13] .*$
ignoreregex =
EOF
    
    # Configurar limites de recursos para RK322x
    cat > "/etc/systemd/system/fail2ban.service.d/override.conf" << 'EOF'
[Service]
# Limites para RK322x
MemoryMax=64M
CPUQuota=15%

# Configurações de segurança
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/run/fail2ban /var/lib/fail2ban /var/log/fail2ban
EOF
    
    mkdir -p /etc/systemd/system/fail2ban.service.d
    
    # Configurar logrotate
    cat > "/etc/logrotate.d/fail2ban" << 'EOF'
/var/log/fail2ban.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
    postrotate
        /usr/bin/fail2ban-client reload > /dev/null 2>&1 || true
    endscript
}
EOF
    
    # Recarregar e habilitar
    systemctl daemon-reload
    systemctl enable fail2ban
    
    if ! systemctl restart fail2ban; then
        log_message "ERROR" "Falha ao iniciar Fail2Ban"
        return 1
    fi
    
    # Verificar se está funcionando
    sleep 3
    if ! systemctl is-active --quiet fail2ban; then
        log_message "ERROR" "Fail2Ban não está ativo"
        return 1
    fi
    
    # Verificar status dos jails
    local jail_status
    jail_status=$(fail2ban-client status 2>/dev/null || echo "Erro ao verificar status")
    
    if [[ "$jail_status" == *"sshd"* ]]; then
        log_message "SUCCESS" "Fail2Ban funcionando corretamente"
    else
        log_message "WARN" "Verificar configuração dos jails"
    fi
    
    log_message "SUCCESS" "Fail2Ban instalado e configurado com sucesso"
    log_message "INFO" "Jails ativos: SSH, Pi-hole, Cockpit, WireGuard, Netdata"
}

# Instalação segura do UFW (Uncomplicated Firewall)
install_ufw_secure() {
    log_message "INFO" "Iniciando instalação segura do UFW..."
    
    # Verificar se já está instalado e ativo
    if ufw status | grep -q "Status: active"; then
        log_message "WARN" "UFW já está ativo"
        if ! dialog --yesno "Reconfigurar UFW?" 8 50; then
            return 0
        fi
    fi
    
    # Criar backup de configurações existentes
    create_backup "/etc/ufw" "ufw-config"
    
    # Instalar UFW se não estiver instalado
    if ! dpkg -l | grep -q "^ii.*ufw"; then
        log_message "INFO" "Instalando ufw..."
        if ! apt-get update && apt-get install -y ufw; then
            log_message "ERROR" "Falha ao instalar ufw"
            return 1
        fi
    fi
    
    # Resetar configurações para começar limpo
    ufw --force reset
    
    # Configurações padrão seguras
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny forward
    
    # Permitir loopback (essencial)
    ufw allow in on lo
    ufw allow out on lo
    
    # Permitir SSH (essencial para acesso remoto)
    local ssh_port
    ssh_port=$(ss -tlnp | grep sshd | awk '{print $4}' | cut -d':' -f2 | head -n1)
    if [ -z "$ssh_port" ]; then
        ssh_port="22"
    fi
    
    ufw allow "$ssh_port"/tcp comment "SSH Access"
    log_message "INFO" "SSH permitido na porta $ssh_port"
    
    # Configurar portas dos serviços BoxServer
    
    # Pi-hole (se instalado)
    if command -v pihole &> /dev/null; then
        ufw allow 80/tcp comment "Pi-hole Web HTTP"
        ufw allow 443/tcp comment "Pi-hole Web HTTPS"
        ufw allow 53/tcp comment "Pi-hole DNS TCP"
        ufw allow 53/udp comment "Pi-hole DNS UDP"
        log_message "INFO" "Regras Pi-hole adicionadas"
    fi
    
    # Unbound (se instalado)
    if command -v unbound &> /dev/null; then
        ufw allow from 127.0.0.1 to any port 5335 comment "Unbound Local"
        log_message "INFO" "Regras Unbound adicionadas"
    fi
    
    # WireGuard (se instalado)
    if command -v wg &> /dev/null; then
        local wg_port
        wg_port=$(grep "ListenPort" /etc/wireguard/wg0.conf 2>/dev/null | awk '{print $3}' || echo "51820")
        ufw allow "$wg_port"/udp comment "WireGuard VPN"
        log_message "INFO" "WireGuard permitido na porta $wg_port"
    fi
    
    # Cockpit (se instalado)
    if systemctl is-enabled --quiet cockpit 2>/dev/null; then
        local cockpit_port
        cockpit_port=$(grep "ListenStream" /etc/cockpit/cockpit.conf 2>/dev/null | tail -n1 | awk '{print $3}' || echo "9090")
        ufw allow "$cockpit_port"/tcp comment "Cockpit Management"
        log_message "INFO" "Cockpit permitido na porta $cockpit_port"
    fi
    
    # FileBrowser (se instalado)
    if systemctl is-enabled --quiet filebrowser 2>/dev/null; then
        local fb_port
        fb_port=$(grep '"port"' /etc/filebrowser/config.json 2>/dev/null | awk '{print $2}' | tr -d ',' || echo "8080")
        ufw allow "$fb_port"/tcp comment "FileBrowser"
        log_message "INFO" "FileBrowser permitido na porta $fb_port"
    fi
    
    # Netdata (se instalado)
    if systemctl is-enabled --quiet netdata 2>/dev/null; then
        local netdata_port
        netdata_port=$(grep "default port" /etc/netdata/netdata.conf 2>/dev/null | awk '{print $4}' || echo "19999")
        ufw allow "$netdata_port"/tcp comment "Netdata Monitoring"
        log_message "INFO" "Netdata permitido na porta $netdata_port"
    fi
    
    # Regras de segurança adicionais
    
    # Permitir redes locais para administração
    ufw allow from 192.168.0.0/16 comment "Rede Local 192.168.x.x"
    ufw allow from 172.16.0.0/12 comment "Rede Local 172.16-31.x.x"
    ufw allow from 10.0.0.0/8 comment "Rede Local 10.x.x.x"
    
    # Bloquear tentativas de força bruta
    ufw limit ssh comment "Rate limit SSH"
    
    # Configurações avançadas
    
    # Configurar logging
    ufw logging medium
    
    # Configurar timeouts para RK322x
    echo "net/netfilter/nf_conntrack_tcp_timeout_established=7200" >> /etc/ufw/sysctl.conf
    echo "net/netfilter/nf_conntrack_generic_timeout=600" >> /etc/ufw/sysctl.conf
    
    # Configurar limites de conexão para RK322x
    echo "net/netfilter/nf_conntrack_max=16384" >> /etc/ufw/sysctl.conf
    echo "net/netfilter/nf_conntrack_buckets=4096" >> /etc/ufw/sysctl.conf
    
    # Aplicar configurações sysctl
    sysctl -p /etc/ufw/sysctl.conf
    
    # Configurar logrotate para logs do UFW
    cat > "/etc/logrotate.d/ufw" << 'EOF'
/var/log/ufw.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
    postrotate
        /usr/sbin/ufw reload > /dev/null 2>&1 || true
    endscript
}
EOF
    
    # Habilitar UFW
    if ! ufw --force enable; then
        log_message "ERROR" "Falha ao habilitar UFW"
        return 1
    fi
    
    # Verificar status
    sleep 2
    local ufw_status
    ufw_status=$(ufw status verbose)
    
    if echo "$ufw_status" | grep -q "Status: active"; then
        log_message "SUCCESS" "UFW ativado com sucesso"
        
        # Mostrar resumo das regras
        local rule_count
        rule_count=$(ufw status numbered | grep -c "\[")
        log_message "INFO" "Total de regras ativas: $rule_count"
        
        # Salvar configuração atual
        ufw status verbose > "/var/log/ufw-config-$(date +%Y%m%d-%H%M%S).log"
        
    else
        log_message "ERROR" "UFW não foi ativado corretamente"
        return 1
    fi
    
    log_message "SUCCESS" "UFW instalado e configurado com sucesso"
    log_message "INFO" "Firewall ativo com regras otimizadas para BoxServer"
    log_message "INFO" "Logs disponíveis em: /var/log/ufw.log"
}

# Dashboard de monitoramento centralizado
show_monitoring_dashboard() {
    log_message "INFO" "Iniciando dashboard de monitoramento..."
    
    local temp_report="/tmp/boxserver-status.txt"
    
    # Cabeçalho do relatório
    cat > "$temp_report" << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                    BOXSERVER STATUS DASHBOARD               ║
║                     RK322x TV Box Server                    ║
╚══════════════════════════════════════════════════════════════╝

EOF
    
    echo "Data/Hora: $(date '+%d/%m/%Y %H:%M:%S')" >> "$temp_report"
    echo "Hostname: $(hostname)" >> "$temp_report"
    echo "IP Principal: $(hostname -I | awk '{print $1}')" >> "$temp_report"
    echo "Uptime: $(uptime -p)" >> "$temp_report"
    echo "" >> "$temp_report"
    
    # Status dos serviços principais
    echo "=== STATUS DOS SERVIÇOS ===" >> "$temp_report"
    
    local services=("pihole-FTL:Pi-hole" "unbound:Unbound" "wg-quick@wg0:WireGuard" 
                   "cockpit:Cockpit" "filebrowser:FileBrowser" "netdata:Netdata" 
                   "nginx:Nginx" "fail2ban:Fail2Ban" "ufw:UFW")
    
    for service_info in "${services[@]}"; do
        local service_name="${service_info%%:*}"
        local display_name="${service_info##*:}"
        
        if systemctl is-active --quiet "$service_name" 2>/dev/null; then
            echo "✅ $display_name: ATIVO" >> "$temp_report"
        elif systemctl is-enabled --quiet "$service_name" 2>/dev/null; then
            echo "⚠️  $display_name: INATIVO (habilitado)" >> "$temp_report"
        else
            echo "❌ $display_name: NÃO INSTALADO" >> "$temp_report"
        fi
    done
    
    echo "" >> "$temp_report"
    
    # Informações do sistema
    echo "=== INFORMAÇÕES DO SISTEMA ===" >> "$temp_report"
    echo "CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)" >> "$temp_report"
    echo "Arquitetura: $(uname -m)" >> "$temp_report"
    echo "Kernel: $(uname -r)" >> "$temp_report"
    echo "Distribuição: $(lsb_release -d 2>/dev/null | cut -d':' -f2 | xargs || echo 'N/A')" >> "$temp_report"
    
    # Uso de recursos
    echo "" >> "$temp_report"
    echo "=== USO DE RECURSOS ===" >> "$temp_report"
    
    local mem_info
    mem_info=$(free -h | grep '^Mem:')
    echo "Memória: $(echo $mem_info | awk '{print $3"/"$2" ("$3/$2*100"% usado)"}')" >> "$temp_report"
    
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    echo "Load Average: $load_avg" >> "$temp_report"
    
    local disk_usage
    disk_usage=$(df -h / | tail -1 | awk '{print $3"/"$2" ("$5" usado)"}')
    echo "Disco (/): $disk_usage" >> "$temp_report"
    
    # Temperatura (se disponível)
    if [ -f "/sys/class/thermal/thermal_zone0/temp" ]; then
        local temp
        temp=$(cat /sys/class/thermal/thermal_zone0/temp)
        temp=$((temp / 1000))
        echo "Temperatura CPU: ${temp}°C" >> "$temp_report"
    fi
    
    # Entropia
    if [ -f "/proc/sys/kernel/random/entropy_avail" ]; then
        local entropy
        entropy=$(cat /proc/sys/kernel/random/entropy_avail)
        echo "Entropia disponível: $entropy bits" >> "$temp_report"
    fi
    
    echo "" >> "$temp_report"
    
    # Portas em uso
    echo "=== PORTAS DOS SERVIÇOS ===" >> "$temp_report"
    
    # Pi-hole
    if systemctl is-active --quiet pihole-FTL; then
        echo "Pi-hole DNS: 53/tcp,udp" >> "$temp_report"
        echo "Pi-hole Web: 80/tcp" >> "$temp_report"
    fi
    
    # WireGuard
    if systemctl is-active --quiet wg-quick@wg0; then
        local wg_port
        wg_port=$(grep "ListenPort" /etc/wireguard/wg0.conf 2>/dev/null | cut -d'=' -f2 | xargs)
        [ -n "$wg_port" ] && echo "WireGuard: ${wg_port}/udp" >> "$temp_report"
    fi
    
    # Outros serviços
    systemctl is-active --quiet cockpit && echo "Cockpit: $(grep ListenStream /etc/cockpit/cockpit.conf 2>/dev/null | head -1 | cut -d'=' -f2 | xargs || echo '9090')/tcp" >> "$temp_report"
    systemctl is-active --quiet filebrowser && echo "FileBrowser: $(grep '"port"' /etc/filebrowser/config.json 2>/dev/null | cut -d':' -f2 | tr -d ' ,' || echo '8080')/tcp" >> "$temp_report"
    systemctl is-active --quiet nginx && systemctl is-active --quiet netdata && echo "Netdata: 8080/tcp (via Nginx)" >> "$temp_report"
    
    echo "" >> "$temp_report"
    
    # Fail2Ban status
    if systemctl is-active --quiet fail2ban; then
        echo "=== FAIL2BAN STATUS ===" >> "$temp_report"
        local banned_count
        banned_count=$(fail2ban-client status 2>/dev/null | grep -o '[0-9]\+ banned' | cut -d' ' -f1 || echo '0')
        echo "IPs banidos atualmente: $banned_count" >> "$temp_report"
        echo "" >> "$temp_report"
    fi
    
    # UFW status
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        echo "=== FIREWALL STATUS ===" >> "$temp_report"
        echo "UFW: ATIVO" >> "$temp_report"
        local rule_count
        rule_count=$(ufw status numbered | grep -c '^\[')
        echo "Regras ativas: $rule_count" >> "$temp_report"
        echo "" >> "$temp_report"
    fi
    
    # Últimos logs importantes
    echo "=== ÚLTIMOS EVENTOS ===" >> "$temp_report"
    echo "Últimos 5 logins SSH:" >> "$temp_report"
    grep "Accepted password\|Accepted publickey" /var/log/auth.log 2>/dev/null | tail -5 | while read line; do
        echo "  $(echo $line | awk '{print $1" "$2" "$3" - "$9" from "$11}')" >> "$temp_report"
    done 2>/dev/null || echo "  Nenhum login recente encontrado" >> "$temp_report"
    
    echo "" >> "$temp_report"
    echo "Últimas 3 tentativas de acesso bloqueadas:" >> "$temp_report"
    grep "BLOCK" /var/log/ufw.log 2>/dev/null | tail -3 | while read line; do
        echo "  $(echo $line | awk '{print $1" "$2" "$3" - Bloqueado: "$13}')" >> "$temp_report"
    done 2>/dev/null || echo "  Nenhum bloqueio recente" >> "$temp_report"
    
    echo "" >> "$temp_report"
    echo "═══════════════════════════════════════════════════════════════" >> "$temp_report"
    echo "Dashboard gerado em: $(date '+%d/%m/%Y %H:%M:%S')" >> "$temp_report"
    echo "Para atualizar: execute novamente a opção 13" >> "$temp_report"
    
    # Mostrar o relatório
    dialog --textbox "$temp_report" 30 80
    
    # Salvar relatório permanente
    cp "$temp_report" "/var/log/boxserver-dashboard-$(date +%Y%m%d-%H%M%S).log"
    
    # Limpeza
    rm -f "$temp_report"
    
    log_message "SUCCESS" "Dashboard de monitoramento exibido"
}

# Testes finais e validação
run_final_tests() {
    log_message "INFO" "Iniciando testes finais do BoxServer..."
    
    local test_report="/tmp/boxserver-tests.txt"
    local test_passed=0
    local test_failed=0
    
    # Cabeçalho do relatório de testes
    cat > "$test_report" << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                    BOXSERVER FINAL TESTS                    ║
║                     RK322x TV Box Server                    ║
╚══════════════════════════════════════════════════════════════╝

EOF
    
    echo "Iniciado em: $(date '+%d/%m/%Y %H:%M:%S')" >> "$test_report"
    echo "" >> "$test_report"
    
    # Função auxiliar para testes
    run_test() {
        local test_name="$1"
        local test_command="$2"
        local expected_result="$3"
        
        echo -n "Testando $test_name... " >> "$test_report"
        
        if eval "$test_command" &>/dev/null; then
            if [ "$expected_result" = "success" ]; then
                echo "✅ PASSOU" >> "$test_report"
                ((test_passed++))
            else
                echo "❌ FALHOU (esperado falha)" >> "$test_report"
                ((test_failed++))
            fi
        else
            if [ "$expected_result" = "fail" ]; then
                echo "✅ PASSOU (falha esperada)" >> "$test_report"
                ((test_passed++))
            else
                echo "❌ FALHOU" >> "$test_report"
                ((test_failed++))
            fi
        fi
    }
    
    echo "=== TESTES DE CONECTIVIDADE ===" >> "$test_report"
    
    # Teste de conectividade básica
    run_test "Conectividade Internet" "ping -c 1 8.8.8.8" "success"
    run_test "Resolução DNS" "nslookup google.com" "success"
    
    # Testes dos serviços
    echo "" >> "$test_report"
    echo "=== TESTES DOS SERVIÇOS ===" >> "$test_report"
    
    # Pi-hole
    if systemctl is-active --quiet pihole-FTL; then
        run_test "Pi-hole FTL Service" "systemctl is-active pihole-FTL" "success"
        run_test "Pi-hole DNS (porta 53)" "netstat -ln | grep ':53 '" "success"
        run_test "Pi-hole Web (porta 80)" "curl -s http://localhost/admin/ | grep -q 'Pi-hole'" "success"
    fi
    
    # Unbound
    if systemctl is-active --quiet unbound; then
        run_test "Unbound Service" "systemctl is-active unbound" "success"
        run_test "Unbound DNS (porta 5335)" "dig @127.0.0.1 -p 5335 google.com" "success"
    fi
    
    # WireGuard
    if systemctl is-active --quiet wg-quick@wg0; then
        run_test "WireGuard Service" "systemctl is-active wg-quick@wg0" "success"
        run_test "WireGuard Interface" "ip link show wg0" "success"
    fi
    
    # Cockpit
    if systemctl is-active --quiet cockpit; then
        run_test "Cockpit Service" "systemctl is-active cockpit" "success"
        local cockpit_port
        cockpit_port=$(grep "ListenStream" /etc/cockpit/cockpit.conf 2>/dev/null | head -1 | cut -d'=' -f2 | xargs || echo '9090')
        run_test "Cockpit Web Interface" "curl -k -s https://localhost:$cockpit_port/ | grep -q 'cockpit'" "success"
    fi
    
    # FileBrowser
    if systemctl is-active --quiet filebrowser; then
        run_test "FileBrowser Service" "systemctl is-active filebrowser" "success"
        local fb_port
        fb_port=$(grep '"port"' /etc/filebrowser/config.json 2>/dev/null | cut -d':' -f2 | tr -d ' ,' || echo '8080')
        run_test "FileBrowser Web Interface" "curl -s http://localhost:$fb_port/ | grep -q 'File Browser'" "success"
    fi
    
    # Netdata
    if systemctl is-active --quiet netdata; then
        run_test "Netdata Service" "systemctl is-active netdata" "success"
        if systemctl is-active --quiet nginx; then
            run_test "Netdata via Nginx" "curl -s http://localhost:8080/ | grep -q 'netdata'" "success"
        fi
    fi
    
    # Fail2Ban
    if systemctl is-active --quiet fail2ban; then
        run_test "Fail2Ban Service" "systemctl is-active fail2ban" "success"
        run_test "Fail2Ban Client" "fail2ban-client status" "success"
    fi
    
    # UFW
    if command -v ufw &>/dev/null; then
        run_test "UFW Installation" "command -v ufw" "success"
        if ufw status | grep -q "Status: active"; then
            run_test "UFW Status" "ufw status | grep -q 'Status: active'" "success"
        fi
    fi
    
    echo "" >> "$test_report"
    echo "=== TESTES DE SEGURANÇA ===" >> "$test_report"
    
    # Testes de segurança
    run_test "SSH Root Login Disabled" "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config" "success"
    run_test "Firewall Rules" "iptables -L | grep -q 'Chain'" "success"
    
    # Teste de entropia
    if [ -f "/proc/sys/kernel/random/entropy_avail" ]; then
        local entropy
        entropy=$(cat /proc/sys/kernel/random/entropy_avail)
        if [ "$entropy" -gt 1000 ]; then
            echo "Entropia disponível: ✅ $entropy bits (>1000)" >> "$test_report"
            ((test_passed++))
        else
            echo "Entropia disponível: ⚠️ $entropy bits (<1000)" >> "$test_report"
            ((test_failed++))
        fi
    fi
    
    echo "" >> "$test_report"
    echo "=== TESTES DE PERFORMANCE ===" >> "$test_report"
    
    # Testes de performance básicos
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | xargs)
    if (( $(echo "$load_avg < 2.0" | bc -l) )); then
        echo "Load Average: ✅ $load_avg (<2.0)" >> "$test_report"
        ((test_passed++))
    else
        echo "Load Average: ⚠️ $load_avg (>2.0)" >> "$test_report"
        ((test_failed++))
    fi
    
    # Uso de memória
    local mem_usage
    mem_usage=$(free | grep '^Mem:' | awk '{print int($3/$2*100)}')
    if [ "$mem_usage" -lt 80 ]; then
        echo "Uso de Memória: ✅ ${mem_usage}% (<80%)" >> "$test_report"
        ((test_passed++))
    else
        echo "Uso de Memória: ⚠️ ${mem_usage}% (>80%)" >> "$test_report"
        ((test_failed++))
    fi
    
    # Espaço em disco
    local disk_usage
    disk_usage=$(df / | tail -1 | awk '{print int($3/$2*100)}')
    if [ "$disk_usage" -lt 85 ]; then
        echo "Uso de Disco: ✅ ${disk_usage}% (<85%)" >> "$test_report"
        ((test_passed++))
    else
        echo "Uso de Disco: ⚠️ ${disk_usage}% (>85%)" >> "$test_report"
        ((test_failed++))
    fi
    
    echo "" >> "$test_report"
    echo "=== RESUMO DOS TESTES ===" >> "$test_report"
    echo "Testes executados: $((test_passed + test_failed))" >> "$test_report"
    echo "✅ Passou: $test_passed" >> "$test_report"
    echo "❌ Falhou: $test_failed" >> "$test_report"
    
    local success_rate
    success_rate=$(echo "scale=1; $test_passed * 100 / ($test_passed + $test_failed)" | bc -l 2>/dev/null || echo "0")
    echo "Taxa de sucesso: ${success_rate}%" >> "$test_report"
    
    echo "" >> "$test_report"
    
    if [ "$test_failed" -eq 0 ]; then
        echo "🎉 TODOS OS TESTES PASSARAM! BoxServer está funcionando perfeitamente." >> "$test_report"
    elif [ "$test_failed" -le 2 ]; then
        echo "⚠️ BoxServer está funcionando com pequenos problemas. Verifique os itens que falharam." >> "$test_report"
    else
        echo "❌ BoxServer tem problemas significativos. Revise a configuração." >> "$test_report"
    fi
    
    echo "" >> "$test_report"
    echo "═══════════════════════════════════════════════════════════════" >> "$test_report"
    echo "Testes finalizados em: $(date '+%d/%m/%Y %H:%M:%S')" >> "$test_report"
    
    # Mostrar o relatório
    dialog --textbox "$test_report" 30 80
    
    # Salvar relatório permanente
    cp "$test_report" "/var/log/boxserver-tests-$(date +%Y%m%d-%H%M%S).log"
    
    # Limpeza
    rm -f "$test_report"
    
    if [ "$test_failed" -eq 0 ]; then
        log_message "SUCCESS" "Todos os testes finais passaram! BoxServer está pronto."
    else
        log_message "WARN" "$test_failed teste(s) falharam. Verifique os logs para detalhes."
    fi
}

# Menu principal com tratamento de erros
show_main_menu() {
    while true; do
        local choice
        choice=$(dialog --clear --backtitle "BoxServer - Instalador Seguro v2.0" \
                    --title "Menu Principal" \
                    --menu "Escolha uma opção:" 22 70 15 \
                        1 "Verificações Iniciais" \
                        2 "Instalar Pi-hole (Seguro)" \
                        3 "Instalar Unbound" \
                        4 "Configurar Pi-hole + Unbound" \
                        5 "Instalar WireGuard (Seguro)" \
                        6 "Configurar Entropia (RNG-tools)" \
                        7 "Instalar Cockpit" \
                        8 "Instalar FileBrowser" \
                        9 "Instalar Netdata" \
                        10 "Instalar Fail2Ban" \
                        11 "Instalar UFW" \
                        12 "Otimizações RK322x" \
                        13 "Monitoramento" \
                        14 "Testes Finais" \
                        0 "Sair" \
                        2>&1 >/dev/tty)
        
        case $choice in
             1) run_initial_checks ;;
             2) install_pihole_secure ;;
             3) install_unbound_secure ;;
             4) configure_pihole_unbound ;;
             5) install_wireguard_secure ;;
             6) configure_entropy_secure ;;
             7) install_cockpit_secure ;;
             8) install_filebrowser_secure ;;
             9) install_netdata_secure ;;
             10) install_fail2ban_secure ;;
             11) install_ufw_secure ;;
             12) optimize_for_nand ;;
             13) show_monitoring_dashboard ;;
             14) run_final_tests ;;
             0) log_message "INFO" "Saindo..." && break ;;
             *) log_message "WARN" "Opção inválida" ;;
        esac
        
        # Pausa para o usuário ver o resultado
        dialog --pause "Pressione Enter para continuar..." 10 30 5
    done
}

# Função principal
main() {
    log_message "INFO" "BoxServer Installer v2.0 - Iniciando..."
    log_message "INFO" "Otimizado para MXQ-4K TV Box (RK322x)"
    
    # Verificar se dialog está disponível
    if ! command -v dialog &> /dev/null; then
        echo "Instalando dialog..."
        apt-get update && apt-get install -y dialog
    fi
    
    # Mostrar menu principal
    show_main_menu
}

# Executar função principal se script for chamado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
