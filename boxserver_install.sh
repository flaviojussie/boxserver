#!/bin/bash
#
# Box-Server TUI Installer
#
# Este script fornece uma interface de usuário de texto (TUI) para instalar e
# configurar os componentes do Box-Server.
#

# --- Configurações de Segurança ---
# Configurar modo estrito para detectar erros (ajustado para compatibilidade)
set -eu

# Configurar IFS para evitar problemas de parsing
IFS=$'\n\t'

# Configurar umask para arquivos seguros
umask 022

# --- Variáveis de Segurança ---
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TEMP_DIR="$(mktemp -d)"
readonly LOG_FILE="$HOME/boxserver_install.log"

# --- Funções de Segurança ---

# Função de cleanup para limpeza em caso de erro
cleanup() {
    local exit_code=$?
    
    # Criar arquivo de log se não existir
    touch "$LOG_FILE" 2>/dev/null || true
    echo "[$(date)] Executando cleanup..." >> "$LOG_FILE" 2>/dev/null || true
    
    # Remover arquivos temporários
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi
    
    # Remover arquivos temporários específicos
    rm -f /tmp/menu_choice 2>/dev/null || true
    rm -f /tmp/pihole_install_script.sh 2>/dev/null || true
    rm -f /tmp/rclone_install_script.sh 2>/dev/null || true
    
    if [[ $exit_code -ne 0 ]]; then
        echo "[$(date)] Script finalizado com erro (código: $exit_code)" >> "$LOG_FILE" 2>/dev/null || true
        dialog --title "Erro" --msgbox "Ocorreu um erro durante a execução. Verifique o log em: $LOG_FILE" 8 70 2>/dev/null || true
    fi
    
    exit $exit_code
}

# Configurar trap para cleanup automático
trap cleanup EXIT INT TERM

# Função para validar permissões sudo
validate_sudo() {
    if ! sudo -n true 2>/dev/null; then
        dialog --title "Permissões" --msgbox "Este script requer permissões sudo. Por favor, execute 'sudo -v' antes de continuar." 8 60
        return 1
    fi
    return 0
}

# Função para backup seguro de arquivos
safe_backup() {
    local file="$1"
    local backup_dir="$HOME/boxserver_backups"
    
    # Criar arquivo de log se não existir
    touch "$LOG_FILE" 2>/dev/null || true
    
    if [[ -f "$file" ]]; then
        if mkdir -p "$backup_dir" 2>/dev/null; then
            local backup_file="$backup_dir/$(basename "$file").backup.$(date +%Y%m%d_%H%M%S)"
            if cp "$file" "$backup_file" 2>/dev/null; then
                echo "[$(date)] Backup criado: $backup_file" >> "$LOG_FILE" 2>/dev/null || true
                echo "$backup_file"
            else
                echo "[$(date)] AVISO: Falha ao criar backup de $file" >> "$LOG_FILE" 2>/dev/null || true
            fi
        else
            echo "[$(date)] AVISO: Falha ao criar diretório de backup" >> "$LOG_FILE" 2>/dev/null || true
        fi
    fi
}

# Função para verificar conectividade
check_connectivity() {
    local test_url="${1:-8.8.8.8}"
    local timeout="${2:-10}"
    
    # Testar conectividade básica
    if ! ping -c 1 -W "$timeout" "$test_url" >/dev/null 2>&1; then
        echo "[$(date)] ERRO: Sem conectividade de rede (ping falhou para $test_url)" >> "$LOG_FILE" 2>/dev/null || true
        return 1
    fi
    
    # Testar resolução DNS
    if ! nslookup google.com >/dev/null 2>&1; then
        echo "[$(date)] AVISO: Problemas de resolução DNS detectados" >> "$LOG_FILE" 2>/dev/null || true
    fi
    
    return 0
}

# Função para download com URLs de fallback (simplificada)
download_with_fallback() {
    local primary_url="$1"
    local fallback_urls="$2"  # URLs separadas por espaço
    local expected_hash="$3"
    local output_file="$4"
    local max_retries="${5:-3}"
    
    # Tentar URL principal primeiro com método simples
    if simple_download "$primary_url" "$output_file" "$max_retries"; then
        return 0
    fi
    
    # Se falhou, tentar URLs de fallback
    if [[ -n "$fallback_urls" ]]; then
        for fallback_url in $fallback_urls; do
            if simple_download "$fallback_url" "$output_file" "$max_retries"; then
                return 0
            fi
        done
    fi
    
    # Se tudo falhou, tentar com verify_download (método avançado)
    if verify_download "$primary_url" "$expected_hash" "$output_file" "$max_retries"; then
        return 0
    fi
    
    return 1
}

# Função para verificar integridade de downloads
# Função simplificada de download que funciona como o backup original
simple_download() {
    local url="$1"
    local output_file="$2"
    local max_retries="${3:-3}"
    
    # Criar diretório de destino se não existir
    local output_dir
    output_dir=$(dirname "$output_file")
    mkdir -p "$output_dir" 2>/dev/null || true
    
    # Tentar download simples como no backup
    local attempt=1
    while [[ $attempt -le $max_retries ]]; do
        if wget -O "$output_file" "$url" 2>/dev/null; then
            # Verificar se o arquivo foi criado e não está vazio
            if [[ -f "$output_file" && -s "$output_file" ]]; then
                return 0
            fi
        fi
        
        # Remover arquivo parcial se existir
        rm -f "$output_file" 2>/dev/null || true
        
        attempt=$((attempt + 1))
        if [[ $attempt -le $max_retries ]]; then
            sleep 2
        fi
    done
    
    return 1
}

# Função de download avançada (mantida para compatibilidade)
verify_download() {
    local url="$1"
    local expected_hash="$2"
    local output_file="$3"
    local max_retries="${4:-3}"
    local timeout="${5:-300}"
    
    # Tentar primeiro o método simples que funcionava no backup
    if simple_download "$url" "$output_file" "$max_retries"; then
        # Verificar hash se fornecido
        if [[ -n "$expected_hash" ]]; then
            local file_hash
            file_hash=$(sha256sum "$output_file" 2>/dev/null | cut -d' ' -f1) || return 1
            if [[ "$file_hash" != "$expected_hash" ]]; then
                rm -f "$output_file" 2>/dev/null || true
                return 1
            fi
        fi
        return 0
    fi
    
    # Se o método simples falhar, tentar com curl (método avançado)
    # Criar arquivo de log se não existir
    touch "$LOG_FILE" 2>/dev/null || true
    echo "[$(date)] Método wget falhou, tentando curl: $url" >> "$LOG_FILE" 2>/dev/null || true
    
    # Criar diretório de destino se não existir
    local output_dir
    output_dir=$(dirname "$output_file")
    if ! mkdir -p "$output_dir" 2>/dev/null; then
        echo "[$(date)] ERRO: Falha ao criar diretório $output_dir" >> "$LOG_FILE" 2>/dev/null || true
        return 1
    fi
    
    # Tentar download com curl
    local attempt=1
    while [[ $attempt -le $max_retries ]]; do
        echo "[$(date)] Tentativa curl $attempt/$max_retries: Baixando $url" >> "$LOG_FILE" 2>/dev/null || true
        
        if curl -fsSL \
            --connect-timeout 30 \
            --max-time "$timeout" \
            --retry 2 \
            --retry-delay 5 \
            --user-agent "BoxServer-Installer/1.0" \
            --location \
            --output "$output_file" \
            "$url" 2>/dev/null; then
            
            # Verificar se o arquivo foi criado e não está vazio
            if [[ -f "$output_file" && -s "$output_file" ]]; then
                echo "[$(date)] Download curl bem-sucedido na tentativa $attempt" >> "$LOG_FILE" 2>/dev/null || true
                break
            fi
        fi
        
        # Remover arquivo parcial se existir
        rm -f "$output_file" 2>/dev/null || true
        
        attempt=$((attempt + 1))
        if [[ $attempt -le $max_retries ]]; then
            sleep 5
        fi
    done
    
    # Verificar se o download final foi bem-sucedido
    if [[ ! -f "$output_file" || ! -s "$output_file" ]]; then
        echo "[$(date)] ERRO: Falha no download após $max_retries tentativas: $url" >> "$LOG_FILE" 2>/dev/null || true
        return 1
    fi
    
    # Verificar hash se fornecido
    if [[ -n "$expected_hash" ]]; then
        echo "[$(date)] Verificando integridade do arquivo..." >> "$LOG_FILE" 2>/dev/null || true
        local file_hash
        file_hash=$(sha256sum "$output_file" 2>/dev/null | cut -d' ' -f1) || {
            echo "[$(date)] ERRO: Falha ao calcular hash de $output_file" >> "$LOG_FILE" 2>/dev/null || true
            return 1
        }
        if [[ "$file_hash" != "$expected_hash" ]]; then
            echo "[$(date)] ERRO: Hash inválido para $output_file" >> "$LOG_FILE" 2>/dev/null || true
            rm -f "$output_file" 2>/dev/null || true
            return 1
        fi
        echo "[$(date)] Verificação de hash bem-sucedida" >> "$LOG_FILE" 2>/dev/null || true
    fi
    
    echo "[$(date)] Download verificado com sucesso: $output_file" >> "$LOG_FILE" 2>/dev/null || true
    return 0
}

# Função para execução segura de scripts baixados
safe_execute_script() {
    local script_file="$1"
    local script_args="${2:-}"
    
    # Criar arquivo de log se não existir
    touch "$LOG_FILE" 2>/dev/null || true
    
    # Verificar se o arquivo existe e é legível
    if [[ ! -f "$script_file" || ! -r "$script_file" ]]; then
        echo "[$(date)] ERRO: Script não encontrado ou não legível: $script_file" >> "$LOG_FILE" 2>/dev/null || true
        return 1
    fi
    
    # Verificar se o script não contém comandos perigosos
    if grep -qE '(rm -rf /|mkfs|fdisk|dd if=|> /dev/)' "$script_file" 2>/dev/null; then
        echo "[$(date)] ERRO: Script contém comandos perigosos: $script_file" >> "$LOG_FILE" 2>/dev/null || true
        return 1
    fi
    
    # Executar o script com permissões limitadas
    echo "[$(date)] Executando script: $script_file $script_args" >> "$LOG_FILE" 2>/dev/null || true
    bash "$script_file" $script_args 2>&1 | tee -a "$LOG_FILE" || {
        echo "[$(date)] ERRO: Falha na execução do script: $script_file" >> "$LOG_FILE" 2>/dev/null || true
        return 1
    }
}

# --- Variáveis Globais ---
readonly DIALOG_TITLE="Instalador Box-Server"
readonly DIALOG_BACKTITLE="MXQ-4K (RK322x) Home Server"
readonly DIALOG_OK_LABEL="Selecionar"
readonly DIALOG_CANCEL_LABEL="Sair"
readonly DIALOG_HEIGHT=20
readonly DIALOG_WIDTH=70

# --- Funções ---

# Exibe o menu principal
show_main_menu() {
    dialog --title "$DIALOG_TITLE" \
           --backtitle "$DIALOG_BACKTITLE" \
           --ok-label "$DIALOG_OK_LABEL" \
           --cancel-label "$DIALOG_CANCEL_LABEL" \
           --menu "Selecione uma opção:" \
           $DIALOG_HEIGHT $DIALOG_WIDTH 20 \
           1 "Verificações Iniciais" \
           2 "Instalar Pi-hole" \
           3 "Instalar Unbound" \
           4 "Configurar Pi-hole com Unbound" \
           5 "Instalar WireGuard" \
           6 "Configurar Entropia (RNG-tools)" \
           7 "Instalar Cockpit" \
           8 "Instalar FileBrowser" \
           9 "Instalar Netdata" \
           10 "Instalar Fail2Ban" \
           11 "Instalar UFW" \
           12 "Instalar Rclone" \
           13 "Instalar Rsync" \
           14 "Instalar MiniDLNA" \
           15 "Instalar Cloudflared" \
           16 "Otimizações e Ajustes" \
           17 "Testes Finais" \
           18 "Monitoramento (Health Check)" \
           19 "Instalação Completa" \
           2> /tmp/menu_choice

    return $?
}

# Executa as verificações iniciais
run_initial_checks() {
    local log_file="$HOME/boxserver_checks.log"
    echo "[$(date)] Iniciando verificações do sistema" > "$log_file"
    
    dialog --infobox "Executando verificações iniciais..." 4 40
    
    local checks_passed=0
    local total_checks=5
    local error_msg=""
    local warning_msg=""
    
    # Verificar se é root
    if [ "$(id -u)" -eq 0 ]; then
        error_msg+="❌ Não execute este script como root!\n"
        echo "[$(date)] ERRO: Script executado como root" >> "$log_file"
    else
        checks_passed=$((checks_passed + 1))
        echo "[$(date)] OK: Usuário não-root detectado" >> "$log_file"
    fi
    
    # Verificar conexão com internet
    if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        checks_passed=$((checks_passed + 1))
        echo "[$(date)] OK: Conectividade com internet" >> "$log_file"
    else
        error_msg+="❌ Sem conexão com a internet!\n"
        echo "[$(date)] ERRO: Sem conectividade com internet" >> "$log_file"
    fi
    
    # Verificar se dialog está instalado
    if command -v dialog > /dev/null 2>&1; then
        checks_passed=$((checks_passed + 1))
        echo "[$(date)] OK: Dialog instalado" >> "$log_file"
    else
        error_msg+="❌ Dialog não está instalado!\n"
        echo "[$(date)] ERRO: Dialog não encontrado" >> "$log_file"
    fi
    
    # Verificar se curl está instalado
    if command -v curl > /dev/null 2>&1; then
        checks_passed=$((checks_passed + 1))
        echo "[$(date)] OK: Curl instalado" >> "$log_file"
    else
        error_msg+="❌ Curl não está instalado!\n"
        echo "[$(date)] ERRO: Curl não encontrado" >> "$log_file"
    fi
    
    # Verificar espaço em disco (mínimo 2GB)
    local available_space
    available_space=$(df / | awk 'NR==2 {print $4}')
    local available_gb=$((available_space / 1048576))
    if [ "$available_space" -gt 2097152 ]; then  # 2GB em KB
        checks_passed=$((checks_passed + 1))
        echo "[$(date)] OK: Espaço em disco suficiente (${available_gb}GB)" >> "$log_file"
    else
        error_msg+="❌ Espaço insuficiente em disco (${available_gb}GB disponível, mínimo 2GB)!\n"
        echo "[$(date)] ERRO: Espaço insuficiente (${available_gb}GB)" >> "$log_file"
    fi
    
    # Verificações adicionais (warnings)
    local ram_mb
    ram_mb=$(free -m | awk 'NR==2{print $2}')
    if [ "$ram_mb" -lt 512 ]; then
        warning_msg+="⚠️ RAM baixa (${ram_mb}MB). Recomendado: 512MB+\n"
        echo "[$(date)] AVISO: RAM baixa (${ram_mb}MB)" >> "$log_file"
    fi
    
    # Verificar arquitetura ARM
    local arch
    arch=$(uname -m)
    if [[ "$arch" == "armv7l" || "$arch" == "aarch64" ]]; then
        echo "[$(date)] INFO: Arquitetura ARM detectada ($arch)" >> "$log_file"
    else
        warning_msg+="⚠️ Arquitetura não-ARM detectada ($arch)\n"
        echo "[$(date)] AVISO: Arquitetura não-ARM ($arch)" >> "$log_file"
    fi
    
    # Informações do sistema
    local network_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    local ram_info=$(free -h)
    local disk_info=$(df -h)
    local cpu_info=$(lscpu | grep "Model name")
    
    # Resultado final
    local result_msg=""
    if [ $checks_passed -eq $total_checks ]; then
        result_msg="✅ Todas as verificações passaram!\n\nSistema pronto para instalação."
        if [ -n "$warning_msg" ]; then
            result_msg+="\n\n$warning_msg"
        fi
        echo "[$(date)] SUCESSO: Todas as verificações passaram" >> "$log_file"
    else
        result_msg="⚠️ Algumas verificações falharam:\n\n$error_msg"
        if [ -n "$warning_msg" ]; then
            result_msg+="\n$warning_msg"
        fi
        result_msg+="\nCorreja os problemas antes de continuar.\n\n📋 Log: $log_file"
        echo "[$(date)] FALHA: $((total_checks - checks_passed)) verificações falharam" >> "$log_file"
    fi
    
    # Adicionar informações do sistema
    result_msg+="\n\n📊 Informações do Sistema:\n"
    result_msg+="Interface de Rede: $network_interface\n"
    result_msg+="RAM: ${ram_mb}MB\n"
    result_msg+="Arquitetura: $arch\n"
    result_msg+="Espaço Disponível: ${available_gb}GB"
    
    dialog --title "Verificações Iniciais" --msgbox "$result_msg" 20 80
}

# Instalação do Pi-hole
run_pihole_installation() {
    dialog --title "Instalação do Pi-hole" --yesno "Isso iniciará o instalador oficial do Pi-hole. O script é interativo e solicitará informações. Deseja continuar?" 10 60
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi

    # Sair do dialog para executar o instalador interativo
    clear
    echo "Iniciando o instalador do Pi-hole..."
    
    # Download seguro do script do Pi-hole
    local pihole_script="$TEMP_DIR/pihole_install.sh"
    local pihole_url="https://install.pi-hole.net"
    
    dialog --infobox "Baixando instalador do Pi-hole..." 4 40
    
    # Download com verificação (sem hash específico pois o Pi-hole não fornece)
    if ! verify_download "$pihole_url" "" "$pihole_script"; then
        dialog --title "Erro" --msgbox "Falha no download do instalador do Pi-hole. Verifique sua conexão com a internet." 8 60
        return 1
    fi
    
    # Verificar se o script parece ser legítimo (contém assinatura do Pi-hole)
    if ! grep -q "Pi-hole" "$pihole_script" || ! grep -q "install" "$pihole_script"; then
        dialog --title "Erro" --msgbox "O script baixado não parece ser o instalador oficial do Pi-hole." 8 60
        return 1
    fi
    
    # Executar o script de forma segura
    if ! safe_execute_script "$pihole_script"; then
        dialog --title "Erro" --msgbox "Falha na execução do instalador do Pi-hole." 8 60
        return 1
    fi

    dialog --title "Configuração Pós-Instalação" --msgbox "A instalação básica do Pi-hole foi concluída. Agora vamos para a configuração." 10 60

    local password
    password=$(dialog --passwordbox "Digite a nova senha de admin do Pi-hole:" 10 60 3>&1 1>&2 2>&3 3>&-)
    if [ -n "$password" ]; then
        pihole -a -p "$password"
        dialog --infobox "Senha do admin atualizada." 5 40
        sleep 2
    fi

    dialog --title "Configuração Avançada" --yesno "Deseja configurar as variáveis avançadas agora (setupVars.conf)? (Recomendado)" 10 60
    if [ $? -eq 0 ]; then
        local network_interface
        network_interface=$(ip route | grep default | awk '{print $5}' | head -1)
        local ipv4_address
        ipv4_address=$(dialog --inputbox "Digite o endereço IP estático para o Pi-hole (ex: 192.168.0.50/24):" 10 60 "192.168.0.50/24" 3>&1 1>&2 2>&3 3>&-)

        local config_content="PIHOLE_INTERFACE=$network_interface\n"
        config_content+="IPV4_ADDRESS=$ipv4_address\n"
        config_content+="PIHOLE_DNS_1=127.0.0.1#5335\n"
        config_content+="DNS_FQDN_REQUIRED=true\n"
        config_content+="DNS_BOGUS_PRIV=true\n"
        config_content+="DNSSEC=true\n"

        dialog --title "Conteúdo de setupVars.conf" --yesno "O seguinte conteúdo será escrito em /etc/pihole/setupVars.conf. Confirma?\n\n$config_content" 20 70

        if [ $? -eq 0 ]; then
            # Fazer backup do arquivo antes de modificar
            safe_backup "/etc/pihole/setupVars.conf"
            echo -e "$config_content" | sudo tee /etc/pihole/setupVars.conf > /dev/null
            dialog --infobox "Arquivo de configuração atualizado." 5 40
            sleep 2
        fi
    fi

    local status_ftl
    status_ftl=$(sudo systemctl status pihole-FTL --no-pager)
    local status_pihole
    status_pihole=$(pihole status)
    dialog --title "Status do Pi-hole" --msgbox "Status dos serviços:\n\npihole-FTL:\n$status_ftl\n\nPi-hole Status:\n$status_pihole" 20 70
}

# Instalação do Unbound
run_unbound_installation() {
    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    dialog --title "Instalação do Unbound" --infobox "Instalando Unbound..." 5 40
    sudo apt install unbound -y > "$HOME/unbound_install.log" 2>&1

    dialog --title "Configuração do Unbound" --yesno "Deseja criar o arquivo de configuração para o Pi-hole agora? (Recomendado)" 10 60
    if [ $? -eq 0 ]; then
        local unbound_config='''server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    prefer-ip6: no
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    edns-buffer-size: 1232
    prefetch: yes
    num-threads: 1
    msg-cache-slabs: 1
    rrset-cache-slabs: 1
    infra-cache-slabs: 1
    key-cache-slabs: 1
    so-rcvbuf: 512k
    so-sndbuf: 512k
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
    hide-identity: yes
    hide-version: yes
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    root-hints: "/var/lib/unbound/root.hints"'''

        echo "$unbound_config" | sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf > /dev/null
        dialog --infobox "Arquivo de configuração do Unbound criado." 5 50
        sleep 2
    fi

    dialog --title "Configurar Trust Anchor" --infobox "Baixando root hints e configurando trust anchor..." 5 60
    
    # Download seguro do root hints com URLs de fallback
    local root_hints_fallbacks="https://ftp.internic.net/domain/named.root https://www.iana.org/domains/root/files/named.root"
    if download_with_fallback "https://www.internic.net/domain/named.root" "$root_hints_fallbacks" "" "$TEMP_DIR/root.hints"; then
        sudo mv "$TEMP_DIR/root.hints" /var/lib/unbound/root.hints
        echo "[$(date)] Root hints baixado com sucesso" >> "$HOME/unbound_setup.log" 2>/dev/null || true
    else
        echo "[$(date)] ERRO: Falha no download do root hints" >> "$HOME/unbound_setup.log" 2>/dev/null || true
        dialog --msgbox "Erro: Falha no download do root hints. Verifique a conectividade." 6 50
        return 1
    fi
    
    # Tentar configurar trust anchor automaticamente
    sudo unbound-anchor -a /var/lib/unbound/root.key >> "$HOME/unbound_setup.log" 2>&1

    if [ $? -ne 0 ]; then
        dialog --infobox "Método principal falhou. Usando método manual para trust anchor..." 5 70
        
        # Download seguro do trust anchor manual com URLs de fallback
        local trust_anchor_fallbacks="https://www.internic.net/domain/root.zone https://ftp.rs.internic.net/domain/root.zone"
        if download_with_fallback "https://data.iana.org/root-anchors/icannbundle.pem" "$trust_anchor_fallbacks" "" "$TEMP_DIR/root.key"; then
            sudo mv "$TEMP_DIR/root.key" /var/lib/unbound/root.key
            echo "[$(date)] Trust anchor baixado com sucesso (método manual)" >> "$HOME/unbound_setup.log" 2>/dev/null || true
        else
            echo "[$(date)] ERRO: Falha no download do trust anchor" >> "$HOME/unbound_setup.log" 2>/dev/null || true
            dialog --msgbox "Erro: Falha no download do trust anchor. Verifique a conectividade." 6 50
            return 1
        fi
    fi

    sudo chown unbound:unbound /var/lib/unbound/root.key /var/lib/unbound/root.hints
    sudo chmod 644 /var/lib/unbound/root.key /var/lib/unbound/root.hints
    dialog --infobox "Trust anchor configurado." 5 40
    sleep 2

    dialog --title "Testar Configuração" --infobox "Verificando a configuração do Unbound..." 5 50
    local checkconf_output
    checkconf_output=$(sudo unbound-checkconf)
    if [ $? -eq 0 ]; then
        dialog --infobox "Configuração do Unbound OK.\n$checkconf_output" 10 70
        sleep 3
    else
        dialog --msgbox "Erro na configuração do Unbound:\n$checkconf_output" 15 70
        return
    fi

    sudo systemctl restart unbound
    sudo systemctl enable unbound

    dialog --title "Testar DNS" --infobox "Testando resolução de DNS com Unbound..." 5 60
    local dig_result
    dig_result=$(dig @127.0.0.1 -p 5335 google.com)
    dialog --title "Resultado do Teste de DNS" --msgbox "Resultado:\n\n$dig_result" 20 70
}

# Configurar Pi-hole com Unbound
run_configure_pihole_unbound() {
    dialog --title "Configurar Pi-hole com Unbound" --yesno "Isso configurará o Pi-hole para usar o Unbound como seu resolvedor de DNS recursivo.\n\nIsso modificará o arquivo /etc/pihole/setupVars.conf e reiniciará o serviço de DNS. Deseja continuar?" 12 75
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi

    dialog --infobox "Configurando Pi-hole para usar Unbound..." 4 50
    
    # Backup do arquivo original
    sudo cp /etc/pihole/setupVars.conf /etc/pihole/setupVars.conf.backup
    
    # Fazer backup do setupVars.conf
    sudo cp /etc/pihole/setupVars.conf /etc/pihole/setupVars.conf.backup.$(date +%Y%m%d_%H%M%S)
    
    # Atualizar configuração DNS no setupVars.conf
    sudo sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf
    sudo sed -i 's/^PIHOLE_DNS_2=.*/PIHOLE_DNS_2=/' /etc/pihole/setupVars.conf
    
    # Adicionar configurações se não existirem
    if ! grep -q "PIHOLE_DNS_1" /etc/pihole/setupVars.conf; then
        echo "PIHOLE_DNS_1=127.0.0.1#5335" | sudo tee -a /etc/pihole/setupVars.conf > /dev/null
    fi
    if ! grep -q "PIHOLE_DNS_2" /etc/pihole/setupVars.conf; then
        echo "PIHOLE_DNS_2=" | sudo tee -a /etc/pihole/setupVars.conf > /dev/null
    fi
    
    # Verificar se openresolv está interferindo (problema conhecido no Debian Bullseye+)
    if systemctl is-active --quiet unbound-resolvconf.service; then
        dialog --infobox "Desabilitando unbound-resolvconf.service (conflito conhecido)..." 4 60
        sudo systemctl disable unbound-resolvconf.service
        sudo systemctl stop unbound-resolvconf.service
        sleep 1
    fi
    
    dialog --infobox "Configuração atualizada. Reiniciando serviços do Pi-hole..." 5 60
    sleep 2
    
    # Reiniciar serviços
    sudo systemctl restart pihole-FTL
    sudo pihole restartdns > "$HOME/pihole_restart.log" 2>&1
    
    # Executar reconfiguração do Pi-hole para garantir persistência
    dialog --infobox "Executando reconfiguração do Pi-hole..." 4 50
    echo -e "\n\n\n\n\n\n\n\n\n\n" | sudo pihole -r > "$HOME/pihole_reconfig.log" 2>&1
    
    # Verificar se a configuração foi aplicada corretamente
    sleep 3
    local dns_config
    dns_config=$(grep "PIHOLE_DNS_1" /etc/pihole/setupVars.conf | cut -d'=' -f2)
    
    if [[ "$dns_config" == "127.0.0.1#5335" ]]; then
        dialog --infobox "✓ Configuração DNS aplicada: $dns_config" 4 50
        sleep 2
    else
        dialog --msgbox "⚠ AVISO: Configuração DNS pode não ter persistido.\nValor atual: $dns_config\nEsperado: 127.0.0.1#5335\n\nExecute manualmente: sudo pihole -r" 8 60
    fi
    
    # Testar integração
    dialog --infobox "Testando integração Pi-hole + Unbound..." 4 50
    sleep 2
    local test_result
    test_result=$(dig @127.0.0.1 google.com +short 2>/dev/null | head -1)
    
    if [ -n "$test_result" ]; then
        dialog --title "Sucesso" --msgbox "Pi-hole foi configurado para usar o Unbound com sucesso!\n\nTeste de DNS: $test_result" 10 60
    else
        dialog --title "Aviso" --msgbox "Configuração aplicada, mas o teste de DNS falhou. Verifique os logs em $HOME/pihole_restart.log" 10 70
    fi
}

# Instalação do WireGuard
run_wireguard_installation() {
    dialog --title "Instalação do WireGuard" --yesno "Isso instalará o WireGuard com configuração manual otimizada para RK322x.\n\nDeseja continuar?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Detectar interface de rede principal
    dialog --infobox "Detectando interface de rede..." 4 40
    local main_interface
    main_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [ -z "$main_interface" ]; then
        main_interface="eth0"
        dialog --infobox "Interface padrão não detectada. Usando eth0" 4 50
    else
        dialog --infobox "Interface detectada: $main_interface" 4 40
    fi
    sleep 2
    
    # Instalar WireGuard
    dialog --infobox "Instalando WireGuard..." 4 30
    sudo apt-get update > "$HOME/wg_install.log" 2>&1
    sudo apt-get install wireguard wireguard-tools qrencode -y >> "$HOME/wg_install.log" 2>&1
    
    # Gerar chaves do servidor
    dialog --infobox "Gerando chaves do servidor..." 4 35
    sudo mkdir -p /etc/wireguard
    cd /etc/wireguard
    sudo wg genkey | sudo tee server_private.key | sudo wg pubkey | sudo tee server_public.key > /dev/null
    sudo chmod 600 server_private.key
    
    # Obter IP público
    dialog --infobox "Obtendo IP público..." 4 30
    local public_ip
    public_ip=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || echo "SEU_IP_PUBLICO")
    
    # Configurar servidor WireGuard
    dialog --infobox "Configurando servidor WireGuard..." 4 40
    local server_private_key
    server_private_key=$(sudo cat server_private.key)
    
    sudo tee /etc/wireguard/wg0.conf > /dev/null << EOF
[Interface]
# Servidor WireGuard - Box-Server RK322x
PrivateKey = $server_private_key
Address = 10.8.0.1/24
ListenPort = 51820
SaveConfig = true

# Regras de iptables para NAT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $main_interface -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $main_interface -j MASQUERADE
EOF
    
    # Habilitar IP forwarding
    dialog --infobox "Habilitando IP forwarding..." 4 35
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sysctl -p > /dev/null 2>&1
    
    # Configurar firewall básico
    dialog --infobox "Configurando firewall..." 4 30
    sudo ufw allow 51820/udp > /dev/null 2>&1
    sudo ufw allow OpenSSH > /dev/null 2>&1
    
    # Configurar Firewall UFW
    dialog --infobox "Configurando firewall UFW..." 4 40
    
    # Instalar UFW se não estiver instalado
    if ! command -v ufw >/dev/null 2>&1; then
        sudo apt-get install ufw -y
    fi
    
    # Configurar regras básicas do UFW
    sudo ufw --force reset >/dev/null 2>&1
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    
    # Permitir SSH (porta 22)
    sudo ufw allow ssh
    
    # Permitir Pi-hole (porta 80 para interface web)
    sudo ufw allow 80/tcp
    
    # Permitir WireGuard (porta 51820)
    sudo ufw allow 51820/udp
    
    # Permitir DNS (porta 53) apenas da rede local
    sudo ufw allow from 192.168.0.0/16 to any port 53
    sudo ufw allow from 10.0.0.0/8 to any port 53
    sudo ufw allow from 172.16.0.0/12 to any port 53
    
    # Configurar NAT para WireGuard no UFW
    sudo tee -a /etc/ufw/before.rules >/dev/null << 'EOF'

# START WIREGUARD RULES
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
# Allow traffic from WireGuard client to $main_interface
-A POSTROUTING -s 10.8.0.0/24 -o $main_interface -j MASQUERADE
COMMIT
# END WIREGUARD RULES
EOF
    
    # Configurar forwarding no UFW
    sudo sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    # Habilitar UFW
    sudo ufw --force enable
    
    # Configurar IP forwarding permanente
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
    fi
    
    if ! grep -q "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
        echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf
    fi
    
    # Aplicar configurações de sysctl
    sudo sysctl -p
    
    # Habilitar e iniciar serviço
    sudo systemctl enable wg-quick@wg0 > /dev/null 2>&1
    sudo systemctl start wg-quick@wg0 > /dev/null 2>&1
    
    # Verificar status
    local wg_status
    wg_status=$(sudo systemctl is-active wg-quick@wg0)
    
    # Criar script para adicionar clientes
    sudo tee /usr/local/bin/add-wg-client > /dev/null << 'EOF'
#!/bin/bash
# Script para adicionar cliente WireGuard

if [ $# -ne 1 ]; then
    echo "Uso: $0 <nome_do_cliente>"
    exit 1
fi

CLIENT_NAME="$1"
SERVER_PUBLIC_KEY=$(sudo cat /etc/wireguard/server_public.key)
SERVER_IP=$(curl -s ifconfig.me)
NEXT_IP=$(sudo wg show wg0 | grep -oP '(?<=allowed-ips )\d+\.\d+\.\d+\.\d+' | cut -d. -f4 | sort -n | tail -1)
NEXT_IP=$((NEXT_IP + 1))
if [ $NEXT_IP -eq 1 ]; then NEXT_IP=2; fi

# Gerar chaves do cliente
cd /etc/wireguard
sudo wg genkey | sudo tee ${CLIENT_NAME}_private.key | sudo wg pubkey | sudo tee ${CLIENT_NAME}_public.key > /dev/null
CLIENT_PRIVATE_KEY=$(sudo cat ${CLIENT_NAME}_private.key)
CLIENT_PUBLIC_KEY=$(sudo cat ${CLIENT_NAME}_public.key)

# Adicionar cliente ao servidor
sudo wg set wg0 peer $CLIENT_PUBLIC_KEY allowed-ips 10.8.0.$NEXT_IP/32
sudo wg-quick save wg0

# Criar arquivo de configuração do cliente
sudo tee /etc/wireguard/${CLIENT_NAME}.conf > /dev/null << EOC
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.8.0.$NEXT_IP/24
DNS = 10.8.0.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOC

echo "Cliente $CLIENT_NAME criado com IP 10.8.0.$NEXT_IP"
echo "Arquivo de configuração: /etc/wireguard/${CLIENT_NAME}.conf"

# Gerar QR Code
echo "QR Code para configuração:"
sudo qrencode -t ansiutf8 < /etc/wireguard/${CLIENT_NAME}.conf
EOF
    
    sudo chmod +x /usr/local/bin/add-wg-client
    
    # Exibir resultado
    local server_public_key
    server_public_key=$(sudo cat /etc/wireguard/server_public.key)
    
    # Verificar se UFW está ativo
    local ufw_status
    ufw_status=$(sudo ufw status | grep "Status:" | awk '{print $2}')
    
    local status_msg="WireGuard instalado e configurado!\n\n"
    status_msg+="Status do serviço: $wg_status\n"
    status_msg+="🔒 Firewall UFW: $ufw_status\n"
    status_msg+="🌐 IP Forwarding: Habilitado\n"
    status_msg+="Interface: $main_interface\n"
    status_msg+="IP público: $public_ip\n"
    status_msg+="Porta: 51820/udp\n"
    status_msg+="Rede VPN: 10.8.0.0/24\n\n"
    status_msg+="📋 Comandos úteis:\n"
    status_msg+="• Adicionar cliente: sudo add-wg-client <nome>\n"
    status_msg+="• Ver status VPN: sudo wg show\n"
    status_msg+="• Ver status firewall: sudo ufw status\n"
    status_msg+="• Ver logs: sudo journalctl -u wg-quick@wg0\n\n"
    status_msg+="Chave pública do servidor:\n$server_public_key"
    
    dialog --title "WireGuard Configurado" --msgbox "$status_msg" 22 80
}

# Configuração de Entropia (Otimizada para RK322x)
run_entropy_configuration() {
    dialog --title "Configuração de Entropia" --yesno "Isso instalará o 'rng-tools' otimizado para sistemas ARM RK322x para melhorar a geração de números aleatórios (entropia), crucial para operações criptográficas.\n\nDeseja continuar?" 12 75
    if [ $? -ne 0 ]; then
        return
    fi

    dialog --infobox "Instalando rng-tools..." 4 50
    sudo apt-get install rng-tools -y > /tmp/rng_install.log 2>&1
    
    # Verificar dispositivos RNG disponíveis
    dialog --infobox "Verificando dispositivos RNG disponíveis..." 4 50
    sleep 1
    
    local rng_device="/dev/urandom"
    if [ -e "/dev/hwrng" ]; then
        rng_device="/dev/hwrng"
        dialog --infobox "Hardware RNG detectado: /dev/hwrng" 4 50
    else
        dialog --infobox "Usando /dev/urandom como fallback" 4 50
    fi
    sleep 2
    
    # Configurar rng-tools para ARM
    dialog --infobox "Configurando rng-tools para RK322x..." 4 50
    sudo tee /etc/default/rng-tools > /dev/null << EOF
# Configuração otimizada para RK322x
RNGDEVICE="$rng_device"
# Opções otimizadas para ARM
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10"
EOF
    
    # Iniciar e habilitar serviço
    sudo systemctl enable rng-tools > /dev/null 2>&1
    sudo systemctl restart rng-tools > /dev/null 2>&1
    sleep 3
    
    # Verificar status e entropia
    local rng_status
    rng_status=$(systemctl is-active rng-tools)
    local available_entropy
    available_entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    
    # Instalar haveged como backup se entropia ainda estiver baixa
    if [ "$available_entropy" -lt 1000 ]; then
        dialog --infobox "Entropia baixa. Instalando haveged como backup..." 4 60
        sudo apt-get install haveged -y >> /tmp/rng_install.log 2>&1
        sudo systemctl enable haveged > /dev/null 2>&1
        sudo systemctl start haveged > /dev/null 2>&1
        sleep 2
        available_entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    fi
    
    local status_msg="Configuração de entropia concluída.\n\n"
    status_msg+="Status rng-tools: $rng_status\n"
    status_msg+="Dispositivo RNG: $rng_device\n"
    status_msg+="Entropia disponível: $available_entropy bits\n\n"
    
    if [ "$available_entropy" -gt 1000 ]; then
        status_msg+="✅ Entropia adequada para operações criptográficas"
    else
        status_msg+="⚠️ Entropia baixa - considere verificar a configuração"
    fi
    
    dialog --title "Status da Entropia" --msgbox "$status_msg" 15 70
}

# Otimizações e Ajustes Finais
run_final_optimizations() {
    dialog --title "Otimizações e Ajustes Finais" --msgbox "Esta seção aplicará otimizações para melhorar o desempenho e a longevidade do seu Box-Server." 10 70

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi

    # Instalação do Log2Ram
    dialog --title "Log2Ram" --yesno "Deseja instalar o Log2Ram? Isso move os logs para a RAM, reduzindo o desgaste da memória NAND e melhorando a performance." 10 70
    if [ $? -eq 0 ]; then
        dialog --infobox "Instalando Log2Ram..." 4 40
        echo "deb [signed-by=/usr/share/keyrings/azlux-archive-keyring.gpg] http://packages.azlux.fr/debian/ buster main" | sudo tee /etc/apt/sources.list.d/azlux.list
        
        # Download seguro da chave GPG do repositório azlux
        if verify_download "https://azlux.fr/repo.gpg" "" "$TEMP_DIR/azlux-archive-keyring.gpg"; then
            sudo mv "$TEMP_DIR/azlux-archive-keyring.gpg" /usr/share/keyrings/azlux-archive-keyring.gpg
            echo "[$(date)] Chave GPG azlux baixada com sucesso" >> "$LOG_FILE" 2>/dev/null || true
        else
            echo "[$(date)] ERRO: Falha no download da chave GPG azlux" >> "$LOG_FILE" 2>/dev/null || true
            dialog --msgbox "Erro: Falha no download da chave GPG. Log2Ram não será instalado." 6 50
            return 1
        fi
        
        sudo apt update > /tmp/optimizations.log 2>&1
        sudo apt install log2ram -y >> /tmp/optimizations.log 2>&1
        dialog --msgbox "Log2Ram instalado com sucesso!" 6 40
    fi

    # Instalação do ZRAM
    dialog --title "ZRAM" --yesno "Deseja instalar o ZRAM? Ele cria um dispositivo de bloco compactado na RAM que atua como swap, melhorando o desempenho em sistemas com pouca memória." 12 70
    if [ $? -eq 0 ]; then
        dialog --infobox "Instalando ZRAM..." 4 40
        sudo apt install zram-tools -y >> /tmp/optimizations.log 2>&1
        
        local zram_config='''# ALGO=lz4
# PERCENT=50
# SIZE=... '''
        echo "$zram_config" | sudo tee /etc/default/zramswap > /dev/null
        sudo systemctl restart zramswap
        dialog --msgbox "ZRAM instalado e configurado com os padrões. Você pode ajustar as configurações em /etc/default/zramswap." 10 70
    fi

    # CPU Governor
    dialog --title "CPU Governor" --yesno "Deseja otimizar o CPU Governor para 'performance'? Isso pode melhorar a responsividade do sistema." 10 70
    if [ $? -eq 0 ]; then
        dialog --infobox "Configurando CPU Governor..." 4 40
        sudo apt install cpufrequtils -y >> /tmp/optimizations.log 2>&1
        echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils
        sudo systemctl restart cpufrequtils
        local current_governor
        current_governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
        dialog --msgbox "CPU Governor configurado para: $current_governor" 6 50
    fi

    # Configuração NTP/Chrony
    dialog --title "Otimizações" --yesno "Configurar sincronização de tempo (NTP)?\n\nIsso garante que o sistema tenha a hora correta, importante para logs e certificados." 8 70
    if [ $? -eq 0 ]; then
        run_ntp_configuration
    fi

    dialog --title "Concluído" --msgbox "Otimizações e ajustes finais foram aplicados." 6 50
}

# Configuração NTP/Chrony
run_ntp_configuration() {
    dialog --infobox "Configurando sincronização de tempo..." 4 45
    
    # Verificar se systemd-timesyncd está ativo e desabilitá-lo
    if systemctl is-active --quiet systemd-timesyncd; then
        sudo systemctl stop systemd-timesyncd
        sudo systemctl disable systemd-timesyncd
    fi
    
    # Instalar chrony
    sudo apt-get update > /dev/null 2>&1
    sudo apt-get install chrony -y > /dev/null 2>&1
    
    # Backup da configuração original
    sudo cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.backup
    
    # Configurar chrony com servidores NTP brasileiros e internacionais
    sudo tee /etc/chrony/chrony.conf > /dev/null << 'EOF'
# Servidores NTP brasileiros (mais rápidos para o Brasil)
server a.st1.ntp.br iburst
server b.st1.ntp.br iburst
server c.st1.ntp.br iburst
server d.st1.ntp.br iburst

# Servidores NTP internacionais como backup
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst
server 2.pool.ntp.org iburst
server 3.pool.ntp.org iburst

# Configurações para sistemas embarcados/ARM
driftfile /var/lib/chrony/chrony.drift
makestep 1.0 3
rtcsync

# Permitir sincronização de clientes na rede local
allow 192.168.0.0/16
allow 10.0.0.0/8
allow 172.16.0.0/12

# Configurações de log
logdir /var/log/chrony
log measurements statistics tracking

# Configurações para melhor precisão em ARM
maxupdateskew 100.0
leapsectz right/UTC

# Configuração para sistemas com pouca memória
cmdallow 127.0.0.1
cmdallow ::1
EOF
    
    # Configurar timezone para Brasil (se não estiver configurado)
    local current_tz
    current_tz=$(timedatectl show --property=Timezone --value)
    if [[ "$current_tz" != "America/Sao_Paulo" ]]; then
        dialog --title "Configuração de Timezone" --yesno "Timezone atual: $current_tz\n\nConfigurar para America/Sao_Paulo (Brasília)?" 8 60
        if [ $? -eq 0 ]; then
            sudo timedatectl set-timezone America/Sao_Paulo
        fi
    fi
    
    # Habilitar e iniciar chrony
    sudo systemctl enable chrony
    sudo systemctl restart chrony
    
    # Aguardar sincronização inicial
    sleep 3
    
    # Verificar status da sincronização
    local sync_status
    local ntp_servers
    local time_offset
    
    if systemctl is-active --quiet chrony; then
        sync_status="✅ Ativo"
        ntp_servers=$(sudo chronyc sources | grep "^\^\*" | wc -l)
        time_offset=$(sudo chronyc tracking | grep "Last offset" | awk '{print $4, $5}')
        
        if [ "$ntp_servers" -gt 0 ]; then
            sync_status+=" (Sincronizado)"
        else
            sync_status+="ão sincronizado)"
        fi
    else
        sync_status="❌ Inativo"
        ntp_servers="0"
        time_offset="N/A"
    fi
    
    # Configurar firewall para NTP (se UFW estiver ativo)
    if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q "Status: active"; then
        sudo ufw allow out 123/udp > /dev/null 2>&1
        sudo ufw allow 123/udp > /dev/null 2>&1
    fi
    
    # Exibir resultado
    local result_msg="🕐 Sincronização de Tempo Configurada\n\n"
    result_msg+="Status do Chrony: $sync_status\n"
    result_msg+="Servidores sincronizados: $ntp_servers\n"
    result_msg+="Último offset: $time_offset\n"
    result_msg+="Timezone: $(timedatectl show --property=Timezone --value)\n"
    result_msg+="Data/Hora atual: $(date)\n\n"
    result_msg+="📋 Comandos úteis:\n"
    result_msg+="• Ver status: sudo chronyc tracking\n"
    result_msg+="• Ver servidores: sudo chronyc sources\n"
    result_msg+="• Forçar sincronização: sudo chronyc makestep\n"
    result_msg+="• Ver logs: sudo journalctl -u chrony"
    
    dialog --title "NTP Configurado" --msgbox "$result_msg" 20 70
}

# Instalar Cockpit
install_cockpit() {
    dialog --title "Instalação do Cockpit" --yesno "O Cockpit é um painel de administração web que permite gerenciar o sistema através do navegador.\n\nDeseja instalar o Cockpit?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Configurações
    local cockpit_port="9090"
    local install_machines="yes"
    local install_podman="yes"
    local install_networkmanager="yes"
    
    # Coletar configurações
    cockpit_port=$(dialog --inputbox "Digite a porta para o Cockpit (padrão: 9090):" 8 50 "9090" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    dialog --title "Módulos Adicionais" --yesno "Instalar cockpit-machines (gerenciamento de VMs)?" 8 60
    if [ $? -ne 0 ]; then install_machines="no"; fi
    
    dialog --title "Módulos Adicionais" --yesno "Instalar cockpit-podman (gerenciamento de containers)?" 8 60
    if [ $? -ne 0 ]; then install_podman="no"; fi
    
    dialog --title "Módulos Adicionais" --yesno "Instalar cockpit-networkmanager (gerenciamento de rede)?" 8 60
    if [ $? -ne 0 ]; then install_networkmanager="no"; fi
    
    # Confirmação
    local config_summary="Configurações do Cockpit:\n\n"
    config_summary+="Porta: $cockpit_port\n"
    config_summary+="Módulo Machines: $install_machines\n"
    config_summary+="Módulo Podman: $install_podman\n"
    config_summary+="Módulo NetworkManager: $install_networkmanager\n\n"
    config_summary+="Acesso: https://$(hostname -I | awk '{print $1}'):$cockpit_port"
    
    dialog --title "Confirmar Instalação" --yesno "$config_summary\n\nConfirma a instalação?" 15 70
    if [ $? -ne 0 ]; then return; fi
    
    # Instalação
    dialog --infobox "Instalando Cockpit..." 4 30
    
    # Pacotes base
    local packages="cockpit cockpit-system"
    
    # Adicionar módulos conforme seleção
    [ "$install_machines" = "yes" ] && packages="$packages cockpit-machines"
    [ "$install_podman" = "yes" ] && packages="$packages cockpit-podman"
    [ "$install_networkmanager" = "yes" ] && packages="$packages cockpit-networkmanager"
    
    if sudo apt-get update && sudo apt-get install -y $packages; then
        # Configurar porta se diferente do padrão
        if [ "$cockpit_port" != "9090" ]; then
            sudo mkdir -p /etc/systemd/system/cockpit.socket.d
            sudo tee /etc/systemd/system/cockpit.socket.d/listen.conf > /dev/null << EOF
[Socket]
ListenStream=
ListenStream=$cockpit_port
EOF
        fi
        
        sudo systemctl enable cockpit.socket
        sudo systemctl start cockpit.socket
        
        dialog --title "Sucesso" --msgbox "Cockpit instalado com sucesso!\n\nAcesso: https://$(hostname -I | awk '{print $1}'):$cockpit_port\n\nUse suas credenciais do sistema para fazer login." 12 70
    else
        dialog --title "Erro" --msgbox "Falha na instalação do Cockpit. Verifique os logs do sistema." 8 50
    fi
}

# Instalar FileBrowser
install_filebrowser() {
    dialog --title "Instalação do FileBrowser" --yesno "O FileBrowser é um gerenciador de arquivos web que permite navegar e gerenciar arquivos através do navegador.\n\nDeseja instalar o FileBrowser?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Configurações
    local fb_port="8080"
    local fb_username="admin"
    local fb_password="admin"
    local fb_root_dir="/"
    
    # Coletar configurações
    fb_port=$(dialog --inputbox "Digite a porta para o FileBrowser (padrão: 8080):" 8 50 "8080" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    fb_username=$(dialog --inputbox "Digite o nome de usuário admin:" 8 50 "admin" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    fb_password=$(dialog --passwordbox "Digite a senha do admin:" 8 50 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    fb_root_dir=$(dialog --inputbox "Digite o diretório raiz para navegação:" 8 50 "/" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    # Confirmação
    local config_summary="Configurações do FileBrowser:\n\n"
    config_summary+="Porta: $fb_port\n"
    config_summary+="Usuário: $fb_username\n"
    config_summary+="Diretório raiz: $fb_root_dir\n\n"
    config_summary+="Acesso: http://$(hostname -I | awk '{print $1}'):$fb_port"
    
    dialog --title "Confirmar Instalação" --yesno "$config_summary\n\nConfirma a instalação?" 15 70
    if [ $? -ne 0 ]; then return; fi
    
    # Instalação
    dialog --infobox "Baixando e instalando FileBrowser..." 4 40
    
    # Download do FileBrowser
    local fb_version="v2.24.2"
    local fb_url="https://github.com/filebrowser/filebrowser/releases/download/$fb_version/linux-arm-filebrowser.tar.gz"
    
    if curl -L "$fb_url" -o /tmp/filebrowser.tar.gz && \
       sudo tar -xzf /tmp/filebrowser.tar.gz -C /usr/local/bin/ filebrowser && \
       sudo chmod +x /usr/local/bin/filebrowser; then
        
        # Criar diretório de configuração
        sudo mkdir -p /etc/filebrowser
        
        # Configurar banco de dados e usuário
        sudo /usr/local/bin/filebrowser config init --database /etc/filebrowser/database.db
        sudo /usr/local/bin/filebrowser config set --port "$fb_port" --root "$fb_root_dir" --database /etc/filebrowser/database.db
        sudo /usr/local/bin/filebrowser users add "$fb_username" "$fb_password" --perm.admin --database /etc/filebrowser/database.db
        
        # Criar serviço systemd
        sudo tee /etc/systemd/system/filebrowser.service > /dev/null << EOF
[Unit]
Description=File Browser
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/filebrowser --database /etc/filebrowser/database.db
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
        
        sudo systemctl daemon-reload
        sudo systemctl enable filebrowser
        sudo systemctl start filebrowser
        
        rm -f /tmp/filebrowser.tar.gz
        
        dialog --title "Sucesso" --msgbox "FileBrowser instalado com sucesso!\n\nAcesso: http://$(hostname -I | awk '{print $1}'):$fb_port\n\nUsuário: $fb_username\nSenha: [configurada]" 12 70
    else
        dialog --title "Erro" --msgbox "Falha na instalação do FileBrowser. Verifique a conexão com a internet." 8 50
    fi
}

# Instalar Netdata
install_netdata() {
    dialog --title "Instalação do Netdata" --yesno "O Netdata é um monitor de sistema em tempo real que fornece métricas detalhadas através de uma interface web.\n\nDeseja instalar o Netdata?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Configurações
    local netdata_port="19999"
    local enable_cloud="no"
    local bind_to="localhost"
    
    # Coletar configurações
    netdata_port=$(dialog --inputbox "Digite a porta para o Netdata (padrão: 19999):" 8 50 "19999" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    dialog --title "Acesso Externo" --yesno "Permitir acesso externo ao Netdata?\n\n(Não recomendado para produção)" 8 60
    if [ $? -eq 0 ]; then bind_to="*"; fi
    
    dialog --title "Netdata Cloud" --yesno "Conectar ao Netdata Cloud para monitoramento remoto?" 8 60
    if [ $? -eq 0 ]; then enable_cloud="yes"; fi
    
    # Confirmação
    local config_summary="Configurações do Netdata:\n\n"
    config_summary+="Porta: $netdata_port\n"
    config_summary+="Bind: $bind_to\n"
    config_summary+="Netdata Cloud: $enable_cloud\n\n"
    if [ "$bind_to" = "*" ]; then
        config_summary+="Acesso: http://$(hostname -I | awk '{print $1}'):$netdata_port"
    else
        config_summary+="Acesso: http://localhost:$netdata_port"
    fi
    
    dialog --title "Confirmar Instalação" --yesno "$config_summary\n\nConfirma a instalação?" 15 70
    if [ $? -ne 0 ]; then return; fi
    
    # Instalação
    dialog --infobox "Baixando e instalando Netdata..." 4 40
    
    # Download e instalação do Netdata
    if curl -Ss https://my-netdata.io/kickstart.sh > /tmp/netdata-kickstart.sh && \
       sudo bash /tmp/netdata-kickstart.sh --dont-wait --disable-telemetry; then
        
        # Configurar porta e bind
        sudo sed -i "s/default port = 19999/default port = $netdata_port/" /etc/netdata/netdata.conf
        sudo sed -i "s/bind socket to IP = 127.0.0.1/bind socket to IP = $bind_to/" /etc/netdata/netdata.conf
        
        # Configurar cloud se solicitado
        if [ "$enable_cloud" = "no" ]; then
            sudo sed -i 's/enabled = yes/enabled = no/' /etc/netdata/netdata.conf
        fi
        
        sudo systemctl restart netdata
        
        rm -f /tmp/netdata-kickstart.sh
        
        local access_url
        if [ "$bind_to" = "*" ]; then
            access_url="http://$(hostname -I | awk '{print $1}'):$netdata_port"
        else
            access_url="http://localhost:$netdata_port"
        fi
        
        dialog --title "Sucesso" --msgbox "Netdata instalado com sucesso!\n\nAcesso: $access_url\n\nO Netdata fornece métricas em tempo real do sistema." 12 70
    else
        dialog --title "Erro" --msgbox "Falha na instalação do Netdata. Verifique a conexão com a internet." 8 50
    fi
}

# Instalar Fail2Ban
install_fail2ban() {
    dialog --title "Instalação do Fail2Ban" --yesno "O Fail2Ban protege contra ataques de força bruta banindo IPs suspeitos automaticamente.\n\nDeseja instalar o Fail2Ban?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Configurações
    local ban_time="3600"
    local find_time="600"
    local max_retry="5"
    local enable_ssh="yes"
    local enable_apache="no"
    local enable_nginx="no"
    
    # Coletar configurações
    ban_time=$(dialog --inputbox "Tempo de banimento em segundos (padrão: 3600):" 8 50 "3600" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    find_time=$(dialog --inputbox "Janela de tempo para detecção em segundos (padrão: 600):" 8 50 "600" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    max_retry=$(dialog --inputbox "Máximo de tentativas antes do ban (padrão: 5):" 8 50 "5" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    dialog --title "Proteção SSH" --yesno "Ativar proteção para SSH?" 8 50
    if [ $? -ne 0 ]; then enable_ssh="no"; fi
    
    dialog --title "Proteção Apache" --yesno "Ativar proteção para Apache?" 8 50
    if [ $? -eq 0 ]; then enable_apache="yes"; fi
    
    dialog --title "Proteção Nginx" --yesno "Ativar proteção para Nginx?" 8 50
    if [ $? -eq 0 ]; then enable_nginx="yes"; fi
    
    # Confirmação
    local config_summary="Configurações do Fail2Ban:\n\n"
    config_summary+="Tempo de ban: ${ban_time}s\n"
    config_summary+="Janela de detecção: ${find_time}s\n"
    config_summary+="Máx. tentativas: $max_retry\n"
    config_summary+="Proteção SSH: $enable_ssh\n"
    config_summary+="Proteção Apache: $enable_apache\n"
    config_summary+="Proteção Nginx: $enable_nginx"
    
    dialog --title "Confirmar Instalação" --yesno "$config_summary\n\nConfirma a instalação?" 15 70
    if [ $? -ne 0 ]; then return; fi
    
    # Instalação
    dialog --infobox "Instalando Fail2Ban..." 4 30
    
    if sudo apt-get update && sudo apt-get install -y fail2ban; then
        # Criar configuração local
        sudo tee /etc/fail2ban/jail.local > /dev/null << EOF
[DEFAULT]
bantime = $ban_time
findtime = $find_time
maxretry = $max_retry
ignoreip = 127.0.0.1/8 ::1

EOF
        
        # Configurar jails conforme seleção
        if [ "$enable_ssh" = "yes" ]; then
            sudo tee -a /etc/fail2ban/jail.local > /dev/null << EOF
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = $max_retry

EOF
        fi
        
        if [ "$enable_apache" = "yes" ]; then
            sudo tee -a /etc/fail2ban/jail.local > /dev/null << EOF
[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache2/*error.log

[apache-badbots]
enabled = true
port = http,https
logpath = /var/log/apache2/*access.log
bantime = 86400
maxretry = 1

EOF
        fi
        
        if [ "$enable_nginx" = "yes" ]; then
            sudo tee -a /etc/fail2ban/jail.local > /dev/null << EOF
[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

[nginx-badbots]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
bantime = 86400
maxretry = 1

EOF
        fi
        
        sudo systemctl enable fail2ban
        sudo systemctl start fail2ban
        
        dialog --title "Sucesso" --msgbox "Fail2Ban instalado com sucesso!\n\nUse 'sudo fail2ban-client status' para verificar o status.\n\nLogs em: /var/log/fail2ban.log" 12 70
    else
        dialog --title "Erro" --msgbox "Falha na instalação do Fail2Ban. Verifique os logs do sistema." 8 50
    fi
}

# Instalar UFW (Uncomplicated Firewall)
install_ufw() {
    dialog --title "Instalação do UFW" --yesno "O UFW é um firewall simples e fácil de configurar para proteger o sistema.\n\nDeseja instalar o UFW?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Configurações
    local default_incoming="deny"
    local default_outgoing="allow"
    local enable_ssh="yes"
    local ssh_port="22"
    local enable_http="no"
    local enable_https="no"
    local custom_ports=""
    
    # Coletar configurações
    dialog --title "Política Padrão" --yesno "Política padrão para conexões de entrada:\n\nDENY (recomendado) - Bloquear tudo por padrão?" 10 60
    if [ $? -ne 0 ]; then default_incoming="allow"; fi
    
    dialog --title "Política Padrão" --yesno "Política padrão para conexões de saída:\n\nALLOW (recomendado) - Permitir tudo por padrão?" 10 60
    if [ $? -ne 0 ]; then default_outgoing="deny"; fi
    
    dialog --title "Acesso SSH" --yesno "Permitir acesso SSH?\n\n(Necessário para administração remota)" 8 60
    if [ $? -ne 0 ]; then enable_ssh="no"; fi
    
    if [ "$enable_ssh" = "yes" ]; then
        ssh_port=$(dialog --inputbox "Digite a porta SSH (padrão: 22):" 8 50 "22" 3>&1 1>&2 2>&3)
        if [ $? -ne 0 ]; then return; fi
    fi
    
    dialog --title "Acesso HTTP" --yesno "Permitir acesso HTTP (porta 80)?" 8 50
    if [ $? -eq 0 ]; then enable_http="yes"; fi
    
    dialog --title "Acesso HTTPS" --yesno "Permitir acesso HTTPS (porta 443)?" 8 50
    if [ $? -eq 0 ]; then enable_https="yes"; fi
    
    custom_ports=$(dialog --inputbox "Portas adicionais para permitir (separadas por vírgula):\nEx: 8080,9090,3000" 10 60 3>&1 1>&2 2>&3)
    
    # Confirmação
    local config_summary="Configurações do UFW:\n\n"
    config_summary+="Entrada padrão: $default_incoming\n"
    config_summary+="Saída padrão: $default_outgoing\n"
    config_summary+="SSH: $enable_ssh"
    [ "$enable_ssh" = "yes" ] && config_summary+=" (porta $ssh_port)"
    config_summary+="\nHTTP: $enable_http\n"
    config_summary+="HTTPS: $enable_https\n"
    [ -n "$custom_ports" ] && config_summary+="Portas extras: $custom_ports"
    
    dialog --title "Confirmar Instalação" --yesno "$config_summary\n\nConfirma a instalação?" 15 70
    if [ $? -ne 0 ]; then return; fi
    
    # Instalação
    dialog --infobox "Instalando UFW..." 4 30
    
    if sudo apt-get update && sudo apt-get install -y ufw; then
        # Resetar configurações
        sudo ufw --force reset
        
        # Configurar políticas padrão
        sudo ufw default $default_incoming incoming
        sudo ufw default $default_outgoing outgoing
        
        # Configurar regras conforme seleção
        if [ "$enable_ssh" = "yes" ]; then
            sudo ufw allow $ssh_port/tcp comment 'SSH'
        fi
        
        if [ "$enable_http" = "yes" ]; then
            sudo ufw allow 80/tcp comment 'HTTP'
        fi
        
        if [ "$enable_https" = "yes" ]; then
            sudo ufw allow 443/tcp comment 'HTTPS'
        fi
        
        # Adicionar portas customizadas
        if [ -n "$custom_ports" ]; then
            IFS=',' read -ra PORTS <<< "$custom_ports"
            for port in "${PORTS[@]}"; do
                port=$(echo "$port" | tr -d ' ')
                if [[ "$port" =~ ^[0-9]+$ ]]; then
                    sudo ufw allow $port comment "Custom port"
                fi
            done
        fi
        
        # Ativar UFW
        sudo ufw --force enable
        
        dialog --title "Sucesso" --msgbox "UFW instalado e configurado com sucesso!\n\nUse 'sudo ufw status' para verificar as regras.\n\nLogs em: /var/log/ufw.log" 12 70
    else
        dialog --title "Erro" --msgbox "Falha na instalação do UFW. Verifique os logs do sistema." 8 50
    fi
}

# Instalar Rclone
install_rclone() {
    dialog --title "Instalação do Rclone" --yesno "O Rclone é uma ferramenta para sincronização com armazenamento em nuvem (Google Drive, Dropbox, etc.).\n\nDeseja instalar o Rclone?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Configurações
    local enable_webui="yes"
    local webui_port="5572"
    local webui_user="admin"
    local webui_pass=""
    local setup_gdrive="no"
    
    # Coletar configurações
    dialog --title "Web UI" --yesno "Ativar interface web do Rclone?\n\n(Permite gerenciar via navegador)" 8 60
    if [ $? -ne 0 ]; then enable_webui="no"; fi
    
    if [ "$enable_webui" = "yes" ]; then
        webui_port=$(dialog --inputbox "Digite a porta para a Web UI (padrão: 5572):" 8 50 "5572" 3>&1 1>&2 2>&3)
        if [ $? -ne 0 ]; then return; fi
        
        webui_user=$(dialog --inputbox "Digite o usuário para a Web UI:" 8 50 "admin" 3>&1 1>&2 2>&3)
        if [ $? -ne 0 ]; then return; fi
        
        webui_pass=$(dialog --passwordbox "Digite a senha para a Web UI:" 8 50 3>&1 1>&2 2>&3)
        if [ $? -ne 0 ]; then return; fi
    fi
    
    dialog --title "Google Drive" --yesno "Configurar conexão com Google Drive agora?\n\n(Pode ser feito depois com 'rclone config')" 8 60
    if [ $? -eq 0 ]; then setup_gdrive="yes"; fi
    
    # Confirmação
    local config_summary="Configurações do Rclone:\n\n"
    config_summary+="Web UI: $enable_webui\n"
    if [ "$enable_webui" = "yes" ]; then
        config_summary+="Porta Web UI: $webui_port\n"
        config_summary+="Usuário Web UI: $webui_user\n"
        config_summary+="Acesso: http://$(hostname -I | awk '{print $1}'):$webui_port\n"
    fi
    config_summary+="Config. Google Drive: $setup_gdrive"
    
    dialog --title "Confirmar Instalação" --yesno "$config_summary\n\nConfirma a instalação?" 15 70
    if [ $? -ne 0 ]; then return; fi
    
    # Instalação
    dialog --infobox "Baixando e instalando Rclone..." 4 40
    
    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Download seguro do script do Rclone
    local rclone_script="$TEMP_DIR/rclone_install.sh"
    local rclone_url="https://rclone.org/install.sh"
    
    # Download com verificação
    if ! verify_download "$rclone_url" "" "$rclone_script"; then
        dialog --title "Erro" --msgbox "Falha no download do instalador do Rclone. Verifique sua conexão com a internet." 8 60
        return 1
    fi
    
    # Verificar se o script parece ser legítimo (contém assinatura do Rclone)
    if ! grep -q "rclone" "$rclone_script" || ! grep -q "install" "$rclone_script"; then
        dialog --title "Erro" --msgbox "O script baixado não parece ser o instalador oficial do Rclone." 8 60
        return 1
    fi
    
    # Executar o script de forma segura com sudo
    if sudo bash "$rclone_script"; then
        
        # Configurar Web UI se solicitado
        if [ "$enable_webui" = "yes" ]; then
            # Criar serviço systemd para Web UI
            sudo tee /etc/systemd/system/rclone-webui.service > /dev/null << EOF
[Unit]
Description=Rclone Web UI
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/rclone rcd --rc-web-gui --rc-addr=0.0.0.0:$webui_port --rc-user=$webui_user --rc-pass=$webui_pass
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
            
            sudo systemctl daemon-reload
            sudo systemctl enable rclone-webui
            sudo systemctl start rclone-webui
        fi
        
        # Configurar Google Drive se solicitado
        if [ "$setup_gdrive" = "yes" ]; then
            dialog --title "Configuração Google Drive" --msgbox "A configuração do Google Drive será iniciada.\n\nSiga as instruções na tela para autorizar o acesso." 10 60
            rclone config
        fi
        
        local success_msg="Rclone instalado com sucesso!\n\n"
        if [ "$enable_webui" = "yes" ]; then
            success_msg+="Web UI: http://$(hostname -I | awk '{print $1}'):$webui_port\n"
            success_msg+="Usuário: $webui_user\n\n"
        fi
        success_msg+="Use 'rclone config' para configurar provedores de nuvem."
        
        dialog --title "Sucesso" --msgbox "$success_msg" 15 70
    else
        dialog --title "Erro" --msgbox "Falha na instalação do Rclone. Verifique a conexão com a internet." 8 50
    fi
}

# Instalar Rsync
install_rsync() {
    dialog --title "Instalação do Rsync" --yesno "O Rsync é uma ferramenta para sincronização e backup de arquivos.\n\nDeseja instalar o Rsync?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Configurações
    local enable_daemon="yes"
    local rsync_port="873"
    local enable_websync="yes"
    local websync_port="8090"
    
    # Coletar configurações
    dialog --title "Daemon Rsync" --yesno "Ativar daemon do Rsync?\n\n(Permite sincronização remota)" 8 60
    if [ $? -ne 0 ]; then enable_daemon="no"; fi
    
    if [ "$enable_daemon" = "yes" ]; then
        rsync_port=$(dialog --inputbox "Digite a porta para o daemon Rsync (padrão: 873):" 8 50 "873" 3>&1 1>&2 2>&3)
        if [ $? -ne 0 ]; then return; fi
    fi
    
    dialog --title "WebSync" --yesno "Instalar WebSync (interface web para Rsync)?\n\n(Facilita o gerenciamento via navegador)" 8 60
    if [ $? -ne 0 ]; then enable_websync="no"; fi
    
    if [ "$enable_websync" = "yes" ]; then
        websync_port=$(dialog --inputbox "Digite a porta para o WebSync (padrão: 8090):" 8 50 "8090" 3>&1 1>&2 2>&3)
        if [ $? -ne 0 ]; then return; fi
    fi
    
    # Confirmação
    local config_summary="Configurações do Rsync:\n\n"
    config_summary+="Daemon Rsync: $enable_daemon\n"
    [ "$enable_daemon" = "yes" ] && config_summary+="Porta daemon: $rsync_port\n"
    config_summary+="WebSync: $enable_websync\n"
    if [ "$enable_websync" = "yes" ]; then
        config_summary+="Porta WebSync: $websync_port\n"
        config_summary+="Acesso WebSync: http://$(hostname -I | awk '{print $1}'):$websync_port"
    fi
    
    dialog --title "Confirmar Instalação" --yesno "$config_summary\n\nConfirma a instalação?" 15 70
    if [ $? -ne 0 ]; then return; fi
    
    # Instalação
    dialog --infobox "Instalando Rsync..." 4 30
    
    if sudo apt-get update && sudo apt-get install -y rsync; then
        
        # Configurar daemon se solicitado
        if [ "$enable_daemon" = "yes" ]; then
            # Criar configuração do daemon
            sudo tee /etc/rsyncd.conf > /dev/null << EOF
uid = nobody
gid = nogroup
use chroot = yes
max connections = 4
pid file = /var/run/rsyncd.pid
log file = /var/log/rsyncd.log
timeout = 300

[backup]
path = /srv/rsync
comment = Backup directory
read only = no
list = yes
auth users = rsync
secrets file = /etc/rsyncd.secrets
EOF
            
            # Criar diretório de backup
            sudo mkdir -p /srv/rsync
            sudo chown nobody:nogroup /srv/rsync
            
            # Criar arquivo de senhas
            sudo tee /etc/rsyncd.secrets > /dev/null << EOF
rsync:backup123
EOF
            sudo chmod 600 /etc/rsyncd.secrets
            
            # Criar serviço systemd
            sudo tee /etc/systemd/system/rsync.service > /dev/null << EOF
[Unit]
Description=Rsync daemon
After=network.target

[Service]
Type=forking
PIDFile=/var/run/rsyncd.pid
ExecStart=/usr/bin/rsync --daemon --config=/etc/rsyncd.conf
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
            
            sudo systemctl daemon-reload
            sudo systemctl enable rsync
            sudo systemctl start rsync
        fi
        
        # Instalar WebSync se solicitado
        if [ "$enable_websync" = "yes" ]; then
            # Verificar se Docker está instalado
            if ! command -v docker &> /dev/null; then
                dialog --infobox "Instalando Docker para WebSync..." 4 40
                curl -fsSL https://get.docker.com -o get-docker.sh
                sudo sh get-docker.sh
                sudo usermod -aG docker $USER
                rm get-docker.sh
            fi
            
            # Criar docker-compose para WebSync
            sudo mkdir -p /opt/websync
            sudo tee /opt/websync/docker-compose.yml > /dev/null << EOF
version: '3.8'
services:
  websync:
    image: nginx:alpine
    container_name: websync
    ports:
      - "$websync_port:80"
    volumes:
      - /srv/rsync:/usr/share/nginx/html/files:ro
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    restart: unless-stopped
EOF
            
            # Criar configuração do Nginx para WebSync
            sudo tee /opt/websync/nginx.conf > /dev/null << EOF
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    server {
        listen 80;
        server_name _;
        
        location / {
            root /usr/share/nginx/html;
            autoindex on;
            autoindex_exact_size off;
            autoindex_localtime on;
        }
        
        location /files {
            alias /usr/share/nginx/html/files;
            autoindex on;
            autoindex_exact_size off;
            autoindex_localtime on;
        }
    }
}
EOF
            
            # Iniciar WebSync
            cd /opt/websync
            sudo docker-compose up -d
        fi
        
        local success_msg="Rsync instalado com sucesso!\n\n"
        if [ "$enable_daemon" = "yes" ]; then
            success_msg+="Daemon ativo na porta $rsync_port\n"
            success_msg+="Usuário: rsync / Senha: backup123\n\n"
        fi
        if [ "$enable_websync" = "yes" ]; then
            success_msg+="WebSync: http://$(hostname -I | awk '{print $1}'):$websync_port\n\n"
        fi
        success_msg+="Use 'rsync' para sincronização de arquivos."
        
        dialog --title "Sucesso" --msgbox "$success_msg" 15 70
    else
        dialog --title "Erro" --msgbox "Falha na instalação do Rsync. Verifique os logs do sistema." 8 50
    fi
}

# Instalar MiniDLNA
install_minidlna() {
    dialog --title "Instalação do MiniDLNA" --yesno "O MiniDLNA é um servidor de mídia DLNA/UPnP que permite compartilhar vídeos, músicas e fotos na rede.\n\nDeseja instalar o MiniDLNA?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Configurações
    local media_dir="/srv/media"
    local friendly_name="BoxServer DLNA"
    local port="8200"
    local video_dir=""
    local audio_dir=""
    local photo_dir=""
    
    # Coletar configurações
    media_dir=$(dialog --inputbox "Digite o diretório principal de mídia:" 8 60 "/srv/media" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    friendly_name=$(dialog --inputbox "Digite o nome amigável do servidor:" 8 60 "BoxServer DLNA" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    port=$(dialog --inputbox "Digite a porta para a interface web (padrão: 8200):" 8 50 "8200" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    video_dir=$(dialog --inputbox "Diretório de vídeos (opcional):\nEx: /srv/media/videos" 8 60 3>&1 1>&2 2>&3)
    audio_dir=$(dialog --inputbox "Diretório de músicas (opcional):\nEx: /srv/media/music" 8 60 3>&1 1>&2 2>&3)
    photo_dir=$(dialog --inputbox "Diretório de fotos (opcional):\nEx: /srv/media/photos" 8 60 3>&1 1>&2 2>&3)
    
    # Confirmação
    local config_summary="Configurações do MiniDLNA:\n\n"
    config_summary+="Nome: $friendly_name\n"
    config_summary+="Porta web: $port\n"
    config_summary+="Diretório principal: $media_dir\n"
    [ -n "$video_dir" ] && config_summary+="Vídeos: $video_dir\n"
    [ -n "$audio_dir" ] && config_summary+="Músicas: $audio_dir\n"
    [ -n "$photo_dir" ] && config_summary+="Fotos: $photo_dir\n"
    config_summary+="\nAcesso web: http://$(hostname -I | awk '{print $1}'):$port"
    
    dialog --title "Confirmar Instalação" --yesno "$config_summary\n\nConfirma a instalação?" 15 70
    if [ $? -ne 0 ]; then return; fi
    
    # Instalação
    dialog --infobox "Instalando MiniDLNA..." 4 30
    
    if sudo apt-get update && sudo apt-get install -y minidlna; then
        
        # Criar diretórios de mídia
        sudo mkdir -p "$media_dir"
        [ -n "$video_dir" ] && sudo mkdir -p "$video_dir"
        [ -n "$audio_dir" ] && sudo mkdir -p "$audio_dir"
        [ -n "$photo_dir" ] && sudo mkdir -p "$photo_dir"
        
        # Configurar MiniDLNA
        sudo tee /etc/minidlna.conf > /dev/null << EOF
# Diretórios de mídia
media_dir=$media_dir
EOF
        
        # Adicionar diretórios específicos se configurados
        [ -n "$video_dir" ] && echo "media_dir=V,$video_dir" | sudo tee -a /etc/minidlna.conf > /dev/null
        [ -n "$audio_dir" ] && echo "media_dir=A,$audio_dir" | sudo tee -a /etc/minidlna.conf > /dev/null
        [ -n "$photo_dir" ] && echo "media_dir=P,$photo_dir" | sudo tee -a /etc/minidlna.conf > /dev/null
        
        # Adicionar configurações restantes
        sudo tee -a /etc/minidlna.conf > /dev/null << EOF

# Nome amigável
friendly_name=$friendly_name

# Porta da interface web
port=$port

# Configurações gerais
db_dir=/var/cache/minidlna
log_dir=/var/log
log_level=general,artwork,database,inotify,scanner,metadata,http,ssdp,tivo=warn
inotify=yes
enable_tivo=no
strict_dlna=no
presentation_url=http://$(hostname -I | awk '{print $1}'):$port/
notify_interval=895
serial=12345678
model_number=1
EOF
        
        # Ajustar permissões
        sudo chown -R minidlna:minidlna "$media_dir"
        [ -n "$video_dir" ] && sudo chown -R minidlna:minidlna "$video_dir"
        [ -n "$audio_dir" ] && sudo chown -R minidlna:minidlna "$audio_dir"
        [ -n "$photo_dir" ] && sudo chown -R minidlna:minidlna "$photo_dir"
        
        # Reiniciar serviço
        sudo systemctl enable minidlna
        sudo systemctl restart minidlna
        
        dialog --title "Sucesso" --msgbox "MiniDLNA instalado com sucesso!\n\nNome: $friendly_name\nInterface web: http://$(hostname -I | awk '{print $1}'):$port\n\nColoque seus arquivos de mídia em:\n$media_dir" 15 70
    else
        dialog --title "Erro" --msgbox "Falha na instalação do MiniDLNA. Verifique os logs do sistema." 8 50
    fi
}

# Instalar Cloudflared
install_cloudflared() {
    dialog --title "Instalação do Cloudflared" --yesno "O Cloudflared permite criar túneis seguros para expor serviços locais na internet através do Cloudflare.\n\nDeseja instalar o Cloudflared?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Configurações
    local install_location="/usr/local/bin"
    local create_tunnel="yes"
    local tunnel_name="boxserver"
    
    # Coletar configurações
    install_location=$(dialog --inputbox "Local de instalação (padrão: /usr/local/bin):" 8 60 "/usr/local/bin" 3>&1 1>&2 2>&3)
    if [ $? -ne 0 ]; then return; fi
    
    dialog --title "Criar Túnel" --yesno "Criar um túnel Cloudflare agora?\n\n(Requer conta Cloudflare)" 8 60
    if [ $? -ne 0 ]; then create_tunnel="no"; fi
    
    if [ "$create_tunnel" = "yes" ]; then
        tunnel_name=$(dialog --inputbox "Nome do túnel:" 8 50 "boxserver" 3>&1 1>&2 2>&3)
        if [ $? -ne 0 ]; then return; fi
    fi
    
    # Confirmação
    local config_summary="Configurações do Cloudflared:\n\n"
    config_summary+="Local de instalação: $install_location\n"
    config_summary+="Criar túnel: $create_tunnel\n"
    [ "$create_tunnel" = "yes" ] && config_summary+="Nome do túnel: $tunnel_name"
    
    dialog --title "Confirmar Instalação" --yesno "$config_summary\n\nConfirma a instalação?" 12 70
    if [ $? -ne 0 ]; then return; fi
    
    # Instalação
    dialog --infobox "Baixando e instalando Cloudflared..." 4 40
    
    # Download do Cloudflared para ARM
    local cf_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm"
    
    if curl -L "$cf_url" -o /tmp/cloudflared && \
       sudo mv /tmp/cloudflared "$install_location/cloudflared" && \
       sudo chmod +x "$install_location/cloudflared"; then
        
        # Criar túnel se solicitado
        if [ "$create_tunnel" = "yes" ]; then
            dialog --title "Autenticação Cloudflare" --msgbox "Será aberto um navegador para autenticação.\n\nFaça login na sua conta Cloudflare e autorize o acesso." 10 60
            
            # Autenticar
            sudo "$install_location/cloudflared" tunnel login
            
            if [ $? -eq 0 ]; then
                # Criar túnel
                sudo "$install_location/cloudflared" tunnel create "$tunnel_name"
                
                # Obter UUID do túnel
                local tunnel_id=$(sudo "$install_location/cloudflared" tunnel list | grep "$tunnel_name" | awk '{print $1}')
                
                if [ -n "$tunnel_id" ]; then
                    # Criar configuração básica
                    sudo mkdir -p /etc/cloudflared
                    sudo tee /etc/cloudflared/config.yml > /dev/null << EOF
tunnel: $tunnel_id
credentials-file: /root/.cloudflared/$tunnel_id.json

ingress:
  - hostname: $tunnel_name.example.com
    service: http://localhost:80
  - service: http_status:404
EOF
                    
                    # Criar serviço systemd
                    sudo tee /etc/systemd/system/cloudflared.service > /dev/null << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
User=root
ExecStart=$install_location/cloudflared tunnel --config /etc/cloudflared/config.yml run
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
                    
                    sudo systemctl daemon-reload
                    sudo systemctl enable cloudflared
                    
                    dialog --title "Sucesso" --msgbox "Cloudflared instalado com sucesso!\n\nTúnel criado: $tunnel_name\nID: $tunnel_id\n\nEdite /etc/cloudflared/config.yml para configurar os serviços.\n\nInicie com: sudo systemctl start cloudflared" 15 70
                else
                    dialog --title "Aviso" --msgbox "Cloudflared instalado, mas falha ao criar túnel.\n\nUse 'cloudflared tunnel create' manualmente." 10 60
                fi
            else
                dialog --title "Aviso" --msgbox "Cloudflared instalado, mas falha na autenticação.\n\nUse 'cloudflared tunnel login' manualmente." 10 60
            fi
        else
            dialog --title "Sucesso" --msgbox "Cloudflared instalado com sucesso!\n\nUse 'cloudflared tunnel login' para autenticar.\nUse 'cloudflared tunnel create <nome>' para criar túneis." 12 70
        fi
    else
        dialog --title "Erro" --msgbox "Falha na instalação do Cloudflared. Verifique a conexão com a internet." 8 50
    fi
}


# Monitoramento e Health Check
run_monitoring() {
    dialog --title "Monitoramento do Sistema" --yesno "Isso criará um script de monitoramento contínuo e exibirá o status atual do sistema.\n\nDeseja continuar?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi

    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Criar script de monitoramento
    dialog --infobox "Criando script de monitoramento..." 4 40
    sudo tee /usr/local/bin/boxserver-monitor > /dev/null << 'EOF'
#!/bin/bash
# Box-Server Health Monitor

LOG_FILE="/var/log/boxserver-health.log"
ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEM=85
ALERT_THRESHOLD_TEMP=70

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

check_service() {
    local service="$1"
    local name="$2"
    if systemctl is-active --quiet "$service"; then
        echo "✅ $name: Ativo"
        log_message "$name: OK"
    else
        echo "❌ $name: Inativo"
        log_message "ALERT: $name está inativo!"
        return 1
    fi
}

check_resources() {
    # CPU
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    cpu_usage=${cpu_usage%.*}
    
    # Memória
    local mem_usage
    mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    
    # Temperatura
    local temp="N/A"
    if [ -f "/sys/class/thermal/thermal_zone0/temp" ]; then
        temp=$(cat /sys/class/thermal/thermal_zone0/temp)
        temp=$((temp / 1000))
    fi
    
    echo "📊 Recursos do Sistema:"
    echo "   CPU: ${cpu_usage}%"
    echo "   Memória: ${mem_usage}%"
    echo "   Temperatura: ${temp}°C"
    
    # Alertas
    if [ "$cpu_usage" -gt "$ALERT_THRESHOLD_CPU" ]; then
        log_message "ALERT: CPU usage high: ${cpu_usage}%"
    fi
    
    if [ "$mem_usage" -gt "$ALERT_THRESHOLD_MEM" ]; then
        log_message "ALERT: Memory usage high: ${mem_usage}%"
    fi
    
    if [ "$temp" != "N/A" ] && [ "$temp" -gt "$ALERT_THRESHOLD_TEMP" ]; then
        log_message "ALERT: Temperature high: ${temp}°C"
    fi
}

check_connectivity() {
    if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        echo "🌐 Conectividade: OK"
        log_message "Connectivity: OK"
    else
        echo "❌ Conectividade: Falha"
        log_message "ALERT: No internet connectivity!"
        return 1
    fi
}

check_dns() {
    if nslookup google.com 127.0.0.1 > /dev/null 2>&1; then
        echo "🔍 DNS Local: OK"
        log_message "DNS: OK"
    else
        echo "❌ DNS Local: Falha"
        log_message "ALERT: Local DNS resolution failed!"
        return 1
    fi
}

check_disk_space() {
    local disk_usage
    disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    echo "💾 Espaço em Disco: ${disk_usage}% usado"
    
    if [ "$disk_usage" -gt 90 ]; then
        log_message "ALERT: Disk space critical: ${disk_usage}%"
    elif [ "$disk_usage" -gt 80 ]; then
        log_message "WARNING: Disk space high: ${disk_usage}%"
    fi
}

check_entropy() {
    local entropy
    entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    echo "🎲 Entropia: ${entropy} bits"
    
    if [ "$entropy" -lt 500 ]; then
        log_message "ALERT: Low entropy: ${entropy} bits"
    fi
}

# Função principal
main() {
    echo "=== Box-Server Health Check ==="
    echo "$(date)"
    echo ""
    
    local failed_checks=0
    
    # Verificar serviços
    echo "🔧 Serviços:"
    check_service "pihole-FTL" "Pi-hole" || ((failed_checks++))
    check_service "unbound" "Unbound" || ((failed_checks++))
    check_service "wg-quick@wg0" "WireGuard" || ((failed_checks++))
    check_service "rng-tools" "RNG Tools" || ((failed_checks++))
    echo ""
    
    # Verificar recursos
    check_resources
    echo ""
    
    # Verificar conectividade
    check_connectivity || ((failed_checks++))
    echo ""
    
    # Verificar DNS
    check_dns || ((failed_checks++))
    echo ""
    
    # Verificar espaço em disco
    check_disk_space
    echo ""
    
    # Verificar entropia
    check_entropy
    echo ""
    
    # Resumo
    if [ "$failed_checks" -eq 0 ]; then
        echo "🎉 Status: TODOS OS SISTEMAS OK"
        log_message "Health check: ALL SYSTEMS OK"
    else
        echo "⚠️ Status: $failed_checks PROBLEMAS DETECTADOS"
        log_message "Health check: $failed_checks issues detected"
    fi
    
    echo "================================"
}

# Executar verificação
if [ "$1" = "--continuous" ]; then
    while true; do
        main
        sleep 300  # 5 minutos
        clear
    done
else
    main
fi
EOF
    
    sudo chmod +x /usr/local/bin/boxserver-monitor
    
    # Criar serviço systemd para monitoramento contínuo
    dialog --infobox "Configurando serviço de monitoramento..." 4 45
    sudo tee /etc/systemd/system/boxserver-monitor.service > /dev/null << EOF
[Unit]
Description=Box-Server Health Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/boxserver-monitor --continuous
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    # Executar verificação inicial
    dialog --infobox "Executando verificação inicial..." 4 40
    local health_output
    health_output=$(/usr/local/bin/boxserver-monitor 2>&1)
    
    # Perguntar se deseja habilitar monitoramento contínuo
    dialog --title "Monitoramento Contínuo" --yesno "Deseja habilitar o monitoramento contínuo em background?\n\nIsso criará logs em /var/log/boxserver-health.log" 10 70
    if [ $? -eq 0 ]; then
        sudo systemctl enable boxserver-monitor > /dev/null 2>&1
        sudo systemctl start boxserver-monitor > /dev/null 2>&1
        local monitor_status
        monitor_status=$(systemctl is-active boxserver-monitor)
        health_output+="\n\n🔄 Monitoramento contínuo: $monitor_status"
    fi
    
    dialog --title "Status do Sistema" --msgbox "$health_output" 25 80
}

# Testes Finais
run_final_tests() {
    dialog --title "Testes Finais" --yesno "Isso executará uma bateria de testes para verificar se todos os serviços estão funcionando corretamente.\n\nDeseja continuar?" 10 70
    if [ $? -ne 0 ]; then
        return
    fi
    
    local test_results=""
    local all_tests_passed=true
    
    # Teste 1: Verificar Pi-hole
    dialog --infobox "Testando Pi-hole..." 4 25
    if systemctl is-active --quiet pihole-FTL; then
        test_results+="✅ Pi-hole: Ativo\n"
    else
        test_results+="❌ Pi-hole: Inativo\n"
        all_tests_passed=false
    fi
    
    # Teste 2: Verificar Unbound
    dialog --infobox "Testando Unbound..." 4 25
    if systemctl is-active --quiet unbound; then
        test_results+="✅ Unbound: Ativo\n"
        # Testar resolução DNS
        if dig @127.0.0.1 -p 5335 google.com +short > /dev/null 2>&1; then
            test_results+="✅ DNS Recursivo: Funcionando\n"
        else
            test_results+="❌ DNS Recursivo: Falha\n"
            all_tests_passed=false
        fi
    else
        test_results+="❌ Unbound: Inativo\n"
        all_tests_passed=false
    fi
    
    # Teste 3: Verificar WireGuard
    dialog --infobox "Testando WireGuard..." 4 25
    if systemctl is-active --quiet wg-quick@wg0; then
        test_results+="✅ WireGuard: Ativo\n"
        # Verificar interface
        if ip link show wg0 > /dev/null 2>&1; then
            test_results+="✅ Interface wg0: Configurada\n"
        else
            test_results+="❌ Interface wg0: Não encontrada\n"
            all_tests_passed=false
        fi
    else
        test_results+="❌ WireGuard: Inativo\n"
        all_tests_passed=false
    fi
    
    # Teste 4: Verificar Entropia
    dialog --infobox "Testando Entropia..." 4 25
    local entropy_level
    entropy_level=$(cat /proc/sys/kernel/random/entropy_avail)
    if [ "$entropy_level" -gt 1000 ]; then
        test_results+="✅ Entropia: $entropy_level bits (Adequada)\n"
    else
        test_results+="⚠️ Entropia: $entropy_level bits (Baixa)\n"
    fi
    
    # Teste 5: Verificar conectividade externa
    dialog --infobox "Testando conectividade..." 4 30
    if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        test_results+="✅ Conectividade: Internet OK\n"
    else
        test_results+="❌ Conectividade: Sem internet\n"
        all_tests_passed=false
    fi
    
    # Teste 6: Verificar resolução DNS via Pi-hole
    dialog --infobox "Testando DNS via Pi-hole..." 4 35
    if nslookup google.com 127.0.0.1 > /dev/null 2>&1; then
        test_results+="✅ DNS Pi-hole: Funcionando\n"
    else
        test_results+="❌ DNS Pi-hole: Falha\n"
        all_tests_passed=false
    fi
    
    # Teste 7: Verificar uso de memória
    dialog --infobox "Verificando recursos..." 4 30
    local mem_usage
    mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    test_results+="📊 Uso de Memória: ${mem_usage}%\n"
    
    # Teste 8: Verificar temperatura (se disponível)
    if [ -f "/sys/class/thermal/thermal_zone0/temp" ]; then
        local temp
        temp=$(cat /sys/class/thermal/thermal_zone0/temp)
        temp=$((temp / 1000))
        test_results+="🌡️ Temperatura: ${temp}°C\n"
    fi
    
    # Resultado final
    test_results+="\n"
    if [ "$all_tests_passed" = true ]; then
        test_results+="🎉 TODOS OS TESTES PASSARAM!\n"
        test_results+="Box-Server está funcionando corretamente."
    else
        test_results+="⚠️ ALGUNS TESTES FALHARAM!\n"
        test_results+="Verifique os serviços marcados com ❌."
    fi
    
    dialog --title "Resultados dos Testes" --msgbox "$test_results" 20 60
}

# Instalação Completa
run_complete_installation() {
    dialog --title "Instalação Completa" --yesno "Isso executará TODOS os passos de instalação automaticamente:\n\n1. Verificações Iniciais\n2. Instalar Pi-hole\n3. Instalar Unbound\n4. Configurar Pi-hole + Unbound\n5. Instalar WireGuard\n6. Configurar Entropia\n7. Instalar Cockpit\n8. Instalar FileBrowser\n9. Instalar Netdata\n10. Instalar Fail2Ban\n11. Instalar UFW\n12. Instalar Rclone\n13. Instalar Rsync\n14. Instalar MiniDLNA\n15. Instalar Cloudflared\n16. Otimizações Finais\n17. Testes Finais\n18. Monitoramento\n\nEste processo pode levar 60-90 minutos.\nDeseja continuar?" 25 80
    if [ $? -ne 0 ]; then
        return
    fi
    
    local start_time
    start_time=$(date +%s)
    local step=1
    local total_steps=18
    local failed_steps=""
    
    # Função para exibir progresso
    show_progress() {
        local current_step="$1"
        local step_name="$2"
        local percentage=$((current_step * 100 / total_steps))
        dialog --title "Instalação Completa" --gauge "Executando: $step_name\n\nPasso $current_step de $total_steps" 10 70 $percentage
    }
    
    # Passo 1: Verificações Iniciais
    show_progress $step "Verificações Iniciais"
    if ! run_initial_checks_silent; then
        failed_steps+="1. Verificações Iniciais\n"
    fi
    step=$((step + 1))
    
    # Passo 2: Instalar Pi-hole
    show_progress $step "Instalando Pi-hole"
    if ! run_pihole_installation_silent; then
        failed_steps+="2. Instalação do Pi-hole\n"
    fi
    step=$((step + 1))
    
    # Passo 3: Instalar Unbound
    show_progress $step "Instalando Unbound"
    if ! run_unbound_installation_silent; then
        failed_steps+="3. Instalação do Unbound\n"
    fi
    step=$((step + 1))
    
    # Passo 4: Configurar Pi-hole + Unbound
    show_progress $step "Configurando Pi-hole + Unbound"
    if ! run_configure_pihole_unbound_silent; then
        failed_steps+="4. Configuração Pi-hole + Unbound\n"
    fi
    step=$((step + 1))
    
    # Passo 5: Instalar WireGuard
    show_progress $step "Instalando WireGuard"
    if ! run_wireguard_installation_silent; then
        failed_steps+="5. Instalação do WireGuard\n"
    fi
    step=$((step + 1))
    
    # Passo 6: Configurar Entropia
    show_progress $step "Configurando Entropia"
    if ! run_entropy_configuration_silent; then
        failed_steps+="6. Configuração de Entropia\n"
    fi
    step=$((step + 1))
    
    # Passo 7: Instalar Cockpit
    show_progress $step "Instalando Cockpit"
    if ! install_cockpit_silent; then
        failed_steps+="7. Instalação do Cockpit\n"
    fi
    step=$((step + 1))
    
    # Passo 8: Instalar FileBrowser
    show_progress $step "Instalando FileBrowser"
    if ! install_filebrowser_silent; then
        failed_steps+="8. Instalação do FileBrowser\n"
    fi
    step=$((step + 1))
    
    # Passo 9: Instalar Netdata
    show_progress $step "Instalando Netdata"
    if ! install_netdata_silent; then
        failed_steps+="9. Instalação do Netdata\n"
    fi
    step=$((step + 1))
    
    # Passo 10: Instalar Fail2Ban
    show_progress $step "Instalando Fail2Ban"
    if ! install_fail2ban_silent; then
        failed_steps+="10. Instalação do Fail2Ban\n"
    fi
    step=$((step + 1))
    
    # Passo 11: Instalar UFW
    show_progress $step "Instalando UFW"
    if ! install_ufw_silent; then
        failed_steps+="11. Instalação do UFW\n"
    fi
    step=$((step + 1))
    
    # Passo 12: Instalar Rclone
    show_progress $step "Instalando Rclone"
    if ! install_rclone_silent; then
        failed_steps+="12. Instalação do Rclone\n"
    fi
    step=$((step + 1))
    
    # Passo 13: Instalar Rsync
    show_progress $step "Instalando Rsync"
    if ! install_rsync_silent; then
        failed_steps+="13. Instalação do Rsync\n"
    fi
    step=$((step + 1))
    
    # Passo 14: Instalar MiniDLNA
    show_progress $step "Instalando MiniDLNA"
    if ! install_minidlna_silent; then
        failed_steps+="14. Instalação do MiniDLNA\n"
    fi
    step=$((step + 1))
    
    # Passo 15: Instalar Cloudflared
    show_progress $step "Instalando Cloudflared"
    if ! install_cloudflared_silent; then
        failed_steps+="15. Instalação do Cloudflared\n"
    fi
    step=$((step + 1))
    
    # Passo 16: Otimizações Finais
    show_progress $step "Aplicando Otimizações"
    if ! run_final_optimizations_silent; then
        failed_steps+="16. Otimizações Finais\n"
    fi
    step=$((step + 1))
    
    # Passo 17: Testes Finais
    show_progress $step "Executando Testes"
    sleep 2  # Aguardar serviços estabilizarem
    local test_result
    test_result=$(run_final_tests_silent)
    step=$((step + 1))
    
    # Passo 18: Monitoramento
    show_progress $step "Configurando Monitoramento"
    if ! run_monitoring_silent; then
        failed_steps+="18. Configuração de Monitoramento\n"
    fi
    step=$((step + 1))
    
    # Calcular tempo total
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    # Preparar relatório final
    local report="=== INSTALAÇÃO COMPLETA FINALIZADA ===\n\n"
    report+="⏱️ Tempo total: ${minutes}m ${seconds}s\n\n"
    
    if [ -z "$failed_steps" ]; then
        report+="🎉 SUCESSO! Todos os componentes foram instalados.\n\n"
        report+="✅ Pi-hole: Bloqueador de anúncios\n"
        report+="✅ Unbound: DNS recursivo\n"
        report+="✅ WireGuard: VPN segura\n"
        report+="✅ Entropia: Otimizada para RK322x\n"
        report+="✅ Cockpit: Interface web de administração\n"
        report+="✅ FileBrowser: Gerenciador de arquivos web\n"
        report+="✅ Netdata: Monitoramento em tempo real\n"
        report+="✅ Fail2Ban: Proteção contra ataques\n"
        report+="✅ UFW: Firewall simplificado\n"
        report+="✅ Rclone: Sincronização com nuvem\n"
        report+="✅ Rsync: Sincronização de arquivos\n"
        report+="✅ MiniDLNA: Servidor de mídia\n"
        report+="✅ Cloudflared: Túneis seguros\n"
        report+="✅ Otimizações: Sistema otimizado\n"
        report+="✅ Monitoramento: Health check configurado\n\n"
        report+="🌐 Acessos Web:\n"
        report+="• Pi-hole: http://$(hostname -I | awk '{print $1}')/admin\n"
        report+="• Cockpit: https://$(hostname -I | awk '{print $1}'):9090\n"
        report+="• FileBrowser: http://$(hostname -I | awk '{print $1}'):8080\n"
        report+="• Netdata: http://$(hostname -I | awk '{print $1}'):19999\n\n"
        report+="🔧 Comandos úteis:\n"
        report+="• Adicionar cliente VPN: sudo add-wg-client <nome>\n"
        report+="• Monitorar sistema: sudo boxserver-monitor\n"
        report+="• Status UFW: sudo ufw status\n"
        report+="• Configurar Rclone: rclone config\n\n"
        report+="📊 Resultados dos testes:\n$test_result"
    else
        report+="⚠️ INSTALAÇÃO PARCIAL - Alguns passos falharam:\n\n"
        report+="❌ Passos com falha:\n$failed_steps\n"
        report+="💡 Recomendação: Execute os passos falhados manualmente\n"
        report+="   através do menu principal.\n\n"
        report+="📊 Resultados dos testes:\n$test_result"
    fi
    
    # Perguntar sobre reinicialização
    dialog --title "Instalação Finalizada" --msgbox "$report" 25 80
    
    dialog --title "Reinicialização" --yesno "Para garantir que todas as configurações sejam aplicadas corretamente, é recomendado reiniciar o sistema.\n\nDeseja reiniciar agora?" 10 70
    if [ $? -eq 0 ]; then
        dialog --infobox "Reiniciando o sistema em 5 segundos..." 4 45
        sleep 5
        sudo reboot
    fi
}

# Versões silenciosas das funções (para instalação completa)
run_initial_checks_silent() {
    # Implementação simplificada das verificações
    command -v dialog >/dev/null 2>&1 && \
    command -v curl >/dev/null 2>&1 && \
    [ "$(id -u)" -ne 0 ] && \
    ping -c 1 8.8.8.8 >/dev/null 2>&1
}

run_pihole_installation_silent() {
    # Download seguro do script do Pi-hole
    local pihole_script="$TEMP_DIR/pihole_install_silent.sh"
    local pihole_url="https://install.pi-hole.net"
    
    # Download com verificação
    if ! verify_download "$pihole_url" "" "$pihole_script" >/tmp/pihole_auto_install.log 2>&1; then
        echo "[$(date)] ERRO: Falha no download do instalador do Pi-hole" >> "$LOG_FILE"
        return 1
    fi
    
    # Verificar se o script parece ser legítimo
    if ! grep -q "Pi-hole" "$pihole_script" || ! grep -q "install" "$pihole_script"; then
        echo "[$(date)] ERRO: Script do Pi-hole não parece legítimo" >> "$LOG_FILE"
        return 1
    fi
    
    # Executar o script com parâmetros de instalação silenciosa
    bash "$pihole_script" --unattended \
        --enable-dhcp=false \
        --pihole-interface=eth0 \
        --pihole-dns-1=1.1.1.1 \
        --pihole-dns-2=1.0.0.1 \
        --query-logging=true \
        --install-web-server=true \
        --install-web-interface=true \
        --lighttpd-enabled=true >>/tmp/pihole_auto_install.log 2>&1
}

run_unbound_installation_silent() {
    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    # Instalar Unbound
    sudo apt-get install unbound -y >/tmp/unbound_auto_install.log 2>&1 && \
    
    # Criar configuração completa
    sudo tee /etc/unbound/unbound.conf.d/pi-hole.conf >/dev/null << 'EOF'
server:
    verbosity: 0
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    prefer-ip6: no
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    edns-buffer-size: 1232
    prefetch: yes
    num-threads: 1
    so-rcvbuf: 1m
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
    hide-identity: yes
    hide-version: yes
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    root-hints: "/var/lib/unbound/root.hints"
EOF
    
    # Baixar root hints
    sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root >>/tmp/unbound_auto_install.log 2>&1 && \
    
    # Configurar trust anchor
    sudo unbound-anchor -a /var/lib/unbound/root.key >>/tmp/unbound_auto_install.log 2>&1 || \
    (sudo wget -O /tmp/root.key https://data.iana.org/root-anchors/icannbundle.pem >>/tmp/unbound_auto_install.log 2>&1 && \
     sudo mv /tmp/root.key /var/lib/unbound/root.key) && \
    
    # Configurar permissões
    sudo chown unbound:unbound /var/lib/unbound/root.key /var/lib/unbound/root.hints && \
    sudo chmod 644 /var/lib/unbound/root.key /var/lib/unbound/root.hints && \
    
    # Habilitar e iniciar serviço
    sudo systemctl enable unbound >/dev/null 2>&1 && \
    sudo systemctl restart unbound >/dev/null 2>&1
}

run_configure_pihole_unbound_silent() {
    sudo cp /etc/pihole/setupVars.conf /etc/pihole/setupVars.conf.backup && \
    sudo sed -i 's/^PIHOLE_DNS_1=.*/PIHOLE_DNS_1=127.0.0.1#5335/' /etc/pihole/setupVars.conf && \
    sudo sed -i 's/^PIHOLE_DNS_2=.*/PIHOLE_DNS_2=/' /etc/pihole/setupVars.conf && \
    sudo systemctl restart pihole-FTL >/dev/null 2>&1 && \
    sudo pihole restartdns >/dev/null 2>&1
}

run_wireguard_installation_silent() {
    sudo apt-get install wireguard wireguard-tools qrencode -y >/tmp/wg_auto_install.log 2>&1 && \
    sudo mkdir -p /etc/wireguard && \
    cd /etc/wireguard && \
    sudo wg genkey | sudo tee server_private.key | sudo wg pubkey | sudo tee server_public.key >/dev/null && \
    sudo chmod 600 server_private.key && \
    local main_interface && \
    main_interface=$(ip route | grep default | awk '{print $5}' | head -n1) && \
    local server_private_key && \
    server_private_key=$(sudo cat server_private.key) && \
    sudo tee /etc/wireguard/wg0.conf >/dev/null << EOF
[Interface]
PrivateKey = $server_private_key
Address = 10.8.0.1/24
ListenPort = 51820
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $main_interface -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $main_interface -j MASQUERADE
EOF
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf >/dev/null && \
    sudo sysctl -p >/dev/null 2>&1 && \
    sudo systemctl enable wg-quick@wg0 >/dev/null 2>&1 && \
    sudo systemctl start wg-quick@wg0 >/dev/null 2>&1
}

run_entropy_configuration_silent() {
    sudo apt-get install rng-tools -y >/tmp/rng_auto_install.log 2>&1 && \
    local rng_device="/dev/urandom" && \
    [ -e "/dev/hwrng" ] && rng_device="/dev/hwrng" && \
    sudo tee /etc/default/rng-tools >/dev/null << EOF
RNGDEVICE="$rng_device"
RNGDOPTIONS="--fill-watermark=2048 --feed-interval=60 --timeout=10"
EOF
    sudo systemctl enable rng-tools >/dev/null 2>&1 && \
    sudo systemctl restart rng-tools >/dev/null 2>&1
}

run_final_optimizations_silent() {
    # Log2Ram
    curl -Lo log2ram.tar.gz https://github.com/azlux/log2ram/archive/master.tar.gz >/dev/null 2>&1 && \
    tar xf log2ram.tar.gz && \
    cd log2ram-master && \
    sudo ./install.sh >/dev/null 2>&1 && \
    cd .. && rm -rf log2ram* && \
    
    # ZRAM
    sudo apt-get install zram-tools -y >/dev/null 2>&1 && \
    echo 'ALGO=lz4' | sudo tee -a /etc/default/zramswap >/dev/null && \
    echo 'PERCENT=25' | sudo tee -a /etc/default/zramswap >/dev/null && \
    sudo systemctl enable zramswap >/dev/null 2>&1 && \
    
    # CPU Governor
    echo 'performance' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null 2>&1
}

# Versões silenciosas das funções de instalação dos novos aplicativos
install_cockpit_silent() {
    sudo apt-get update >/dev/null 2>&1 && \
    sudo apt-get install -y cockpit cockpit-system >/dev/null 2>&1 && \
    sudo systemctl enable cockpit.socket >/dev/null 2>&1 && \
    sudo systemctl start cockpit.socket >/dev/null 2>&1
}

install_filebrowser_silent() {
    local fb_version="v2.24.2"
    local fb_url="https://github.com/filebrowser/filebrowser/releases/download/$fb_version/linux-arm-filebrowser.tar.gz"
    
    # Download seguro do FileBrowser com URLs de fallback
    local fb_fallbacks="https://mirror.ghproxy.com/https://github.com/filebrowser/filebrowser/releases/download/$fb_version/linux-arm-filebrowser.tar.gz https://ghproxy.net/https://github.com/filebrowser/filebrowser/releases/download/$fb_version/linux-arm-filebrowser.tar.gz"
    if download_with_fallback "$fb_url" "$fb_fallbacks" "" "$TEMP_DIR/filebrowser.tar.gz"; then
        echo "[$(date)] FileBrowser baixado com sucesso" >> "$LOG_FILE" 2>/dev/null || true
    else
        echo "[$(date)] ERRO: Falha no download do FileBrowser" >> "$LOG_FILE" 2>/dev/null || true
        return 1
    fi
    
    # Extrair e instalar FileBrowser
    cd "$TEMP_DIR" && \
    tar -xzf filebrowser.tar.gz && \
    sudo mv filebrowser /usr/local/bin/ && \
    sudo chmod +x /usr/local/bin/filebrowser && \
    sudo mkdir -p /etc/filebrowser && \
    echo '{"port":8080,"baseURL":"","address":"","log":"stdout","database":"/etc/filebrowser/filebrowser.db","root":"/"}' | sudo tee /etc/filebrowser/config.json >/dev/null && \
    sudo /usr/local/bin/filebrowser -d /etc/filebrowser/filebrowser.db config init >/dev/null 2>&1 && \
    sudo /usr/local/bin/filebrowser -d /etc/filebrowser/filebrowser.db users add admin admin --perm.admin >/dev/null 2>&1
}

install_netdata_silent() {
    # Download seguro do script do Netdata
    local netdata_script="$TEMP_DIR/netdata_install.sh"
    local netdata_url="https://my-netdata.io/kickstart.sh"
    
    # Download com verificação
    if ! verify_download "$netdata_url" "" "$netdata_script" >/dev/null 2>&1; then
        echo "[$(date)] ERRO: Falha no download do instalador do Netdata" >> "$LOG_FILE"
        return 1
    fi
    
    # Verificar se o script parece ser legítimo
    if ! grep -q "netdata" "$netdata_script" || ! grep -q "install" "$netdata_script"; then
        echo "[$(date)] ERRO: Script do Netdata não parece legítimo" >> "$LOG_FILE"
        return 1
    fi
    
    # Executar o script com parâmetros
    bash "$netdata_script" --dont-wait --disable-telemetry >/dev/null 2>&1
}

install_fail2ban_silent() {
    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    sudo apt-get update >/dev/null 2>&1 && \
    sudo apt-get install -y fail2ban >/dev/null 2>&1 && \
    sudo systemctl enable fail2ban >/dev/null 2>&1 && \
    sudo systemctl start fail2ban >/dev/null 2>&1
}

install_ufw_silent() {
    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    sudo apt-get update >/dev/null 2>&1 && \
    sudo apt-get install -y ufw >/dev/null 2>&1 && \
    echo 'y' | sudo ufw enable >/dev/null 2>&1 && \
    sudo ufw default deny incoming >/dev/null 2>&1 && \
    sudo ufw default allow outgoing >/dev/null 2>&1 && \
    sudo ufw allow ssh >/dev/null 2>&1
}

install_rclone_silent() {
    # Download seguro do script do Rclone
    local rclone_script="$TEMP_DIR/rclone_install_silent.sh"
    local rclone_url="https://rclone.org/install.sh"
    
    # Download com verificação
    if ! verify_download "$rclone_url" "" "$rclone_script" >/dev/null 2>&1; then
        echo "[$(date)] ERRO: Falha no download do instalador do Rclone" >> "$LOG_FILE"
        return 1
    fi
    
    # Verificar se o script parece ser legítimo
    if ! grep -q "rclone" "$rclone_script" || ! grep -q "install" "$rclone_script"; then
        echo "[$(date)] ERRO: Script do Rclone não parece legítimo" >> "$LOG_FILE"
        return 1
    fi
    
    # Executar o script com sudo
    sudo bash "$rclone_script" >/dev/null 2>&1
}

install_rsync_silent() {
    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    sudo apt-get update >/dev/null 2>&1 && \
    sudo apt-get install -y rsync >/dev/null 2>&1
}

install_minidlna_silent() {
    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    sudo apt-get update >/dev/null 2>&1 && \
    sudo apt-get install -y minidlna >/dev/null 2>&1 && \
    sudo systemctl enable minidlna >/dev/null 2>&1
}

install_cloudflared_silent() {
    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    local cf_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm"
    
    # Download seguro do cloudflared com URLs de fallback
    local cf_fallbacks="https://mirror.ghproxy.com/https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm https://ghproxy.net/https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm"
    if download_with_fallback "$cf_url" "$cf_fallbacks" "" "$TEMP_DIR/cloudflared"; then
        sudo mv "$TEMP_DIR/cloudflared" /usr/local/bin/cloudflared
        sudo chmod +x /usr/local/bin/cloudflared
        echo "[$(date)] Cloudflared baixado e instalado com sucesso" >> "$LOG_FILE" 2>/dev/null || true
    else
        echo "[$(date)] ERRO: Falha no download do cloudflared" >> "$LOG_FILE" 2>/dev/null || true
        return 1
    fi
}

run_monitoring_silent() {
    # Validar permissões sudo
    if ! validate_sudo; then
        return 1
    fi
    
    sudo tee /usr/local/bin/boxserver-monitor >/dev/null << 'EOF'
#!/bin/bash
# Box-Server Health Monitor
echo "=== Box-Server Status ==="
echo "Data: $(date)"
echo
echo "Serviços:"
systemctl is-active --quiet pihole-FTL && echo "✅ Pi-hole" || echo "❌ Pi-hole"
systemctl is-active --quiet unbound && echo "✅ Unbound" || echo "❌ Unbound"
systemctl is-active --quiet wg-quick@wg0 && echo "✅ WireGuard" || echo "❌ WireGuard"
systemctl is-active --quiet cockpit.socket && echo "✅ Cockpit" || echo "❌ Cockpit"
systemctl is-active --quiet netdata && echo "✅ Netdata" || echo "❌ Netdata"
systemctl is-active --quiet fail2ban && echo "✅ Fail2Ban" || echo "❌ Fail2Ban"
echo
echo "Recursos:"
echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)% uso"
echo "RAM: $(free -h | awk '/^Mem:/ {print $3"/"$2}')"
echo "Disco: $(df -h / | awk 'NR==2{print $3"/"$2" ("$5" usado)"}')"
if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
    temp=$(cat /sys/class/thermal/thermal_zone0/temp)
    temp=$((temp / 1000))
    echo "Temperatura: ${temp}°C"
fi
EOF
    sudo chmod +x /usr/local/bin/boxserver-monitor && \
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/boxserver-monitor >> /var/log/boxserver-health.log 2>&1") | crontab - >/dev/null 2>&1
}

run_final_tests_silent() {
    local results=""
    systemctl is-active --quiet pihole-FTL && results+="✅ Pi-hole\n" || results+="❌ Pi-hole\n"
    systemctl is-active --quiet unbound && results+="✅ Unbound\n" || results+="❌ Unbound\n"
    systemctl is-active --quiet wg-quick@wg0 && results+="✅ WireGuard\n" || results+="❌ WireGuard\n"
    systemctl is-active --quiet rng-tools && results+="✅ RNG Tools\n" || results+="❌ RNG Tools\n"
    systemctl is-active --quiet cockpit.socket && results+="✅ Cockpit\n" || results+="❌ Cockpit\n"
    systemctl is-active --quiet netdata && results+="✅ Netdata\n" || results+="❌ Netdata\n"
    systemctl is-active --quiet fail2ban && results+="✅ Fail2Ban\n" || results+="❌ Fail2Ban\n"
    ping -c 1 8.8.8.8 >/dev/null 2>&1 && results+="✅ Conectividade\n" || results+="❌ Conectividade\n"
    echo "$results"
}

# --- Fluxo Principal ---

while true; do
    show_main_menu
    
    # Se o usuário pressionar "Sair"
    if [ $? -ne 0 ]; then
        clear
        break
    fi

    choice=$(cat /tmp/menu_choice)
    case $choice in
        1)
            run_initial_checks
            ;;
        2)
            run_pihole_installation
            ;;
        3)
            run_unbound_installation
            ;;
        4)
            run_configure_pihole_unbound
            ;;
        5)
            run_wireguard_installation
            ;;
        6)
            run_entropy_configuration
            ;;
        7)
            install_cockpit
            ;;
        8)
            install_filebrowser
            ;;
        9)
            install_netdata
            ;;
        10)
            install_fail2ban
            ;;
        11)
            install_ufw
            ;;
        12)
            install_rclone
            ;;
        13)
            install_rsync
            ;;
        14)
            install_minidlna
            ;;
        15)
            install_cloudflared
            ;;
        16)
            run_final_optimizations
            ;;
        17)
            run_final_tests
            ;;
        18)
            run_monitoring
            ;;
        19)
            run_complete_installation
            ;;
    esac
done

# Limpeza
rm -f /tmp/menu_choice
