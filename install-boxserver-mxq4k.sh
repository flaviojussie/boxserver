#!/bin/bash
#
# Box-Server TUI Installer
#
# Este script fornece uma interface de usuário de texto (TUI) para instalar e
# configurar os componentes do Box-Server.
#

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
           $DIALOG_HEIGHT $DIALOG_WIDTH 10 \
           1 "Verificações Iniciais" \
           2 "Instalar Pi-hole" \
           3 "Instalar Unbound" \
           4 "Configurar Pi-hole com Unbound" \
           5 "Instalar WireGuard" \
           6 "Configurar Entropia" \
           7 "Otimizações e Ajustes" \
           8 "Testes Finais" \
           9 "Monitoramento (Health Check)" \
           10 "Instalação Completa" \
           2> /tmp/menu_choice

    return $?
}

# Executa as verificações iniciais
run_initial_checks() {
    local log_file="/tmp/boxserver_checks.log"
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

    # Sair do dialog para executar o instalador interativo
    clear
    echo "Iniciando o instalador do Pi-hole..."
    curl -sSL https://install.pi-hole.net | bash

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
    dialog --title "Instalação do Unbound" --infobox "Instalando Unbound..." 5 40
    sudo apt install unbound -y > /tmp/unbound_install.log 2>&1

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
    sudo wget -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.root > /tmp/unbound_setup.log 2>&1
    sudo unbound-anchor -a /var/lib/unbound/root.key >> /tmp/unbound_setup.log 2>&1

    if [ $? -ne 0 ]; then
        dialog --infobox "Método principal falhou. Usando método manual para trust anchor..." 5 70
        sudo wget -O /tmp/root.key https://data.iana.org/root-anchors/icannbundle.pem >> /tmp/unbound_setup.log 2>&1
        sudo mv /tmp/root.key /var/lib/unbound/root.key
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

    dialog --infobox "Configurando Pi-hole para usar Unbound..." 4 50
    
    # Backup do arquivo original
    sudo cp /etc/pihole/setupVars.conf /etc/pihole/setupVars.conf.backup
    
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
    
    dialog --infobox "Configuração atualizada. Reiniciando serviços do Pi-hole..." 5 60
    sleep 2
    
    # Reiniciar serviços
    sudo systemctl restart pihole-FTL
    sudo pihole restartdns > /tmp/pihole_restart.log 2>&1
    
    # Testar integração
    dialog --infobox "Testando integração Pi-hole + Unbound..." 4 50
    sleep 2
    local test_result
    test_result=$(dig @127.0.0.1 google.com +short 2>/dev/null | head -1)
    
    if [ -n "$test_result" ]; then
        dialog --title "Sucesso" --msgbox "Pi-hole foi configurado para usar o Unbound com sucesso!\n\nTeste de DNS: $test_result" 10 60
    else
        dialog --title "Aviso" --msgbox "Configuração aplicada, mas o teste de DNS falhou. Verifique os logs em /tmp/pihole_restart.log" 10 60
    fi
}

# Instalação do WireGuard
run_wireguard_installation() {
    dialog --title "Instalação do WireGuard" --yesno "Isso instalará o WireGuard com configuração manual otimizada para RK322x.\n\nDeseja continuar?" 10 70
    if [ $? -ne 0 ]; then
        return
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
    sudo apt-get update > /tmp/wg_install.log 2>&1
    sudo apt-get install wireguard wireguard-tools qrencode -y >> /tmp/wg_install.log 2>&1
    
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

    # Instalação do Log2Ram
    dialog --title "Log2Ram" --yesno "Deseja instalar o Log2Ram? Isso move os logs para a RAM, reduzindo o desgaste da memória NAND e melhorando a performance." 10 70
    if [ $? -eq 0 ]; then
        dialog --infobox "Instalando Log2Ram..." 4 40
        echo "deb [signed-by=/usr/share/keyrings/azlux-archive-keyring.gpg] http://packages.azlux.fr/debian/ buster main" | sudo tee /etc/apt/sources.list.d/azlux.list
        sudo wget -O /usr/share/keyrings/azlux-archive-keyring.gpg  https://azlux.fr/repo.gpg
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


# Monitoramento e Health Check
run_monitoring() {
    dialog --title "Monitoramento do Sistema" --yesno "Isso criará um script de monitoramento contínuo e exibirá o status atual do sistema.\n\nDeseja continuar?" 10 70
    if [ $? -ne 0 ]; then
        return
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
    dialog --title "Instalação Completa" --yesno "Isso executará TODOS os passos de instalação automaticamente:\n\n1. Verificações Iniciais\n2. Instalar Pi-hole\n3. Instalar Unbound\n4. Configurar Pi-hole + Unbound\n5. Instalar WireGuard\n6. Configurar Entropia\n7. Otimizações Finais\n8. Testes Finais\n\nEste processo pode levar 30-60 minutos.\nDeseja continuar?" 18 75
    if [ $? -ne 0 ]; then
        return
    fi
    
    local start_time
    start_time=$(date +%s)
    local step=1
    local total_steps=8
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
    
    # Passo 7: Otimizações Finais
    show_progress $step "Aplicando Otimizações"
    if ! run_final_optimizations_silent; then
        failed_steps+="7. Otimizações Finais\n"
    fi
    step=$((step + 1))
    
    # Passo 8: Testes Finais
    show_progress $step "Executando Testes"
    sleep 2  # Aguardar serviços estabilizarem
    local test_result
    test_result=$(run_final_tests_silent)
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
        report+="✅ Otimizações: Sistema otimizado\n\n"
        report+="🔧 Comandos úteis:\n"
        report+="• Adicionar cliente VPN: sudo add-wg-client <nome>\n"
        report+="• Monitorar sistema: sudo boxserver-monitor\n"
        report+="• Interface Pi-hole: http://$(hostname -I | awk '{print $1}')/admin\n\n"
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
    curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended \
        --enable-dhcp=false \
        --pihole-interface=eth0 \
        --pihole-dns-1=1.1.1.1 \
        --pihole-dns-2=1.0.0.1 \
        --query-logging=true \
        --install-web-server=true \
        --install-web-interface=true \
        --lighttpd-enabled=true >/tmp/pihole_auto_install.log 2>&1
}

run_unbound_installation_silent() {
    sudo apt-get install unbound -y >/tmp/unbound_auto_install.log 2>&1 && \
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
EOF
    sudo systemctl enable unbound >/dev/null 2>&1 && \
    sudo systemctl start unbound >/dev/null 2>&1
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

run_final_tests_silent() {
    local results=""
    systemctl is-active --quiet pihole-FTL && results+="✅ Pi-hole\n" || results+="❌ Pi-hole\n"
    systemctl is-active --quiet unbound && results+="✅ Unbound\n" || results+="❌ Unbound\n"
    systemctl is-active --quiet wg-quick@wg0 && results+="✅ WireGuard\n" || results+="❌ WireGuard\n"
    systemctl is-active --quiet rng-tools && results+="✅ RNG Tools\n" || results+="❌ RNG Tools\n"
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
            run_final_optimizations
            ;;
        8)
            run_final_tests
            ;;
        9)
            run_monitoring
            ;;
        10)
            run_complete_installation
            ;;
    esac
done

# Limpeza
rm -f /tmp/menu_choice
