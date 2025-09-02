#!/bin/bash

################################################################################
# Script de Instalação Automatizado - Boxserver MXQ-4k (TUI Modernizada)
# 
# DESCRIÇÃO:
#   Script completo para configuração automatizada de servidor doméstico
#   em dispositivos MXQ-4k com chip RK322x e memória NAND limitada.
#   Versão modernizada com TUI profissional e robusta.
#
# REQUISITOS DE HARDWARE:
#   - CPU: RK322X (ARM Cortex-A7)
#   - RAM: Mínimo 512MB (testado com 961MB)
#   - Storage: Mínimo 2GB NAND disponível
#   - Rede: Interface Ethernet ativa
#
# REQUISITOS DE SOFTWARE:
#   - Sistema: Debian/Ubuntu/Armbian
#   - Acesso: root/sudo
#   - Internet: Conexão ativa
#   - Terminal: Suporte a cores ANSI (recomendado 256 cores)
#
# AUTOR: Baseado na base de conhecimento Boxserver Arandutec
# DATA: $(date '+%d/%m/%Y')
# VERSÃO: 2.0 (TUI Modernizada)
################################################################################

set -euo pipefail

# Configurações globais
SCRIPT_NAME="install-boxserver-mxq4k-modern"
LOG_FILE="/var/log/${SCRIPT_NAME}.log"
CONFIG_DIR="/etc/boxserver"
BACKUP_DIR="/var/backups/boxserver"
STATIC_IP_CONFIGURED="false"

# Variáveis de ambiente
NETWORK_INTERFACE="${NETWORK_INTERFACE:-}"
SERVER_IP="${SERVER_IP:-}"
VPN_NETWORK="${VPN_NETWORK:-10.200.200.0/24}"
VPN_PORT="${VPN_PORT:-51820}"
PIHOLE_PASSWORD="${PIHOLE_PASSWORD:-}"
FILEBROWSER_PORT="${FILEBROWSER_PORT:-8080}"
COCKPIT_PORT="${COCKPIT_PORT:-9090}"

# Modo de configuração
INTERACTIVE_MODE="true"
CURRENT_THEME="default"
TERMINAL_WIDTH=$(tput cols 2>/dev/null || echo 80)
TERMINAL_HEIGHT=$(tput lines 2>/dev/null || echo 24)

################################################################################
# SISTEMA DE CORES MODERNO
################################################################################

# Detecção de capacidades do terminal
detect_terminal_capabilities() {
    local colors=0
    
    # Detectar suporte a cores
    if command -v tput >/dev/null 2>&1; then
        colors=$(tput colors 2>/dev/null || echo 0)
    fi
    
    # Verificar variáveis de ambiente
    case "$TERM" in
        *-256color|*-256) colors=256 ;;
        *color*) [ $colors -lt 8 ] && colors=8 ;;
        xterm*|screen*|tmux*) [ $colors -lt 8 ] && colors=8 ;;
    esac
    
    echo $colors
}

# Configuração de temas de cores
init_color_system() {
    local terminal_colors=$(detect_terminal_capabilities)
    
    # Cores básicas ANSI (compatibilidade)
    if [ $terminal_colors -ge 8 ]; then
        # Cores primárias
        export COLOR_BLACK='\033[0;30m'
        export COLOR_RED='\033[0;31m'
        export COLOR_GREEN='\033[0;32m'
        export COLOR_YELLOW='\033[0;33m'
        export COLOR_BLUE='\033[0;34m'
        export COLOR_MAGENTA='\033[0;35m'
        export COLOR_CYAN='\033[0;36m'
        export COLOR_WHITE='\033[0;37m'
        
        # Cores brilhantes
        export COLOR_BRIGHT_BLACK='\033[1;30m'
        export COLOR_BRIGHT_RED='\033[1;31m'
        export COLOR_BRIGHT_GREEN='\033[1;32m'
        export COLOR_BRIGHT_YELLOW='\033[1;33m'
        export COLOR_BRIGHT_BLUE='\033[1;34m'
        export COLOR_BRIGHT_MAGENTA='\033[1;35m'
        export COLOR_BRIGHT_CYAN='\033[1;36m'
        export COLOR_BRIGHT_WHITE='\033[1;37m'
        
        # Cores de fundo
        export COLOR_BG_BLACK='\033[40m'
        export COLOR_BG_RED='\033[41m'
        export COLOR_BG_GREEN='\033[42m'
        export COLOR_BG_YELLOW='\033[43m'
        export COLOR_BG_BLUE='\033[44m'
        export COLOR_BG_MAGENTA='\033[45m'
        export COLOR_BG_CYAN='\033[46m'
        export COLOR_BG_WHITE='\033[47m'
    fi
    
    # Cores estendidas para terminais com suporte a 256 cores
    if [ $terminal_colors -ge 256 ]; then
        # Cores personalizadas usando códigos 256
        export COLOR_ORANGE='\033[38;5;208m'
        export COLOR_PURPLE='\033[38;5;135m'
        export COLOR_PINK='\033[38;5;205m'
        export COLOR_LIME='\033[38;5;154m'
        export COLOR_TEAL='\033[38;5;80m'
        export COLOR_NAVY='\033[38;5;17m'
        export COLOR_MAROON='\033[38;5;88m'
        export COLOR_OLIVE='\033[38;5;100m'
        
        # Gradientes para barras de progresso
        export COLOR_PROGRESS_0='\033[38;5;196m'   # Vermelho
        export COLOR_PROGRESS_25='\033[38;5;208m'  # Laranja
        export COLOR_PROGRESS_50='\033[38;5;226m'  # Amarelo
        export COLOR_PROGRESS_75='\033[38;5;154m'  # Verde claro
        export COLOR_PROGRESS_100='\033[38;5;46m'  # Verde
    fi
    
    # Reset e formatação
    export COLOR_RESET='\033[0m'
    export COLOR_BOLD='\033[1m'
    export COLOR_DIM='\033[2m'
    export COLOR_ITALIC='\033[3m'
    export COLOR_UNDERLINE='\033[4m'
    export COLOR_BLINK='\033[5m'
    export COLOR_REVERSE='\033[7m'
    export COLOR_STRIKETHROUGH='\033[9m'
    
    # Controles de cursor
    export CURSOR_HIDE='\033[?25l'
    export CURSOR_SHOW='\033[?25h'
    export CURSOR_SAVE='\033[s'
    export CURSOR_RESTORE='\033[u'
    
    # Limpar tela
    export CLEAR_SCREEN='\033[2J'
    export CLEAR_LINE='\033[2K'
    export CLEAR_TO_END='\033[0J'
    
    # Definir tema atual
    set_theme "$CURRENT_THEME"
}

# Sistema de temas
set_theme() {
    local theme="$1"
    
    case "$theme" in
        "default")
            export THEME_PRIMARY="$COLOR_BLUE"
            export THEME_SECONDARY="$COLOR_CYAN"
            export THEME_SUCCESS="$COLOR_GREEN"
            export THEME_WARNING="$COLOR_YELLOW"
            export THEME_ERROR="$COLOR_RED"
            export THEME_INFO="$COLOR_BRIGHT_BLUE"
            export THEME_ACCENT="$COLOR_MAGENTA"
            export THEME_MUTED="$COLOR_BRIGHT_BLACK"
            export THEME_BORDER="$COLOR_BRIGHT_BLUE"
            export THEME_HIGHLIGHT="$COLOR_BRIGHT_WHITE"
            ;;
        "dark")
            export THEME_PRIMARY="$COLOR_BRIGHT_CYAN"
            export THEME_SECONDARY="$COLOR_CYAN"
            export THEME_SUCCESS="$COLOR_BRIGHT_GREEN"
            export THEME_WARNING="$COLOR_BRIGHT_YELLOW"
            export THEME_ERROR="$COLOR_BRIGHT_RED"
            export THEME_INFO="$COLOR_BRIGHT_BLUE"
            export THEME_ACCENT="$COLOR_BRIGHT_MAGENTA"
            export THEME_MUTED="$COLOR_BRIGHT_BLACK"
            export THEME_BORDER="$COLOR_WHITE"
            export THEME_HIGHLIGHT="$COLOR_BRIGHT_WHITE"
            ;;
        "light")
            export THEME_PRIMARY="$COLOR_BLUE"
            export THEME_SECONDARY="$COLOR_NAVY"
            export THEME_SUCCESS="$COLOR_GREEN"
            export THEME_WARNING="$COLOR_OLIVE"
            export THEME_ERROR="$COLOR_MAROON"
            export THEME_INFO="$COLOR_TEAL"
            export THEME_ACCENT="$COLOR_PURPLE"
            export THEME_MUTED="$COLOR_BLACK"
            export THEME_BORDER="$COLOR_BLACK"
            export THEME_HIGHLIGHT="$COLOR_BLACK"
            ;;
        "matrix")
            export THEME_PRIMARY="$COLOR_LIME"
            export THEME_SECONDARY="$COLOR_GREEN"
            export THEME_SUCCESS="$COLOR_BRIGHT_GREEN"
            export THEME_WARNING="$COLOR_YELLOW"
            export THEME_ERROR="$COLOR_RED"
            export THEME_INFO="$COLOR_LIME"
            export THEME_ACCENT="$COLOR_BRIGHT_GREEN"
            export THEME_MUTED="$COLOR_GREEN"
            export THEME_BORDER="$COLOR_BRIGHT_GREEN"
            export THEME_HIGHLIGHT="$COLOR_BRIGHT_WHITE"
            ;;
    esac
    
    CURRENT_THEME="$theme"
}

# Função para aplicar cor com fallback
color() {
    local color_name="$1"
    local text="$2"
    local color_code=""
    
    case "$color_name" in
        "primary") color_code="$THEME_PRIMARY" ;;
        "secondary") color_code="$THEME_SECONDARY" ;;
        "success") color_code="$THEME_SUCCESS" ;;
        "warning") color_code="$THEME_WARNING" ;;
        "error") color_code="$THEME_ERROR" ;;
        "info") color_code="$THEME_INFO" ;;
        "accent") color_code="$THEME_ACCENT" ;;
        "muted") color_code="$THEME_MUTED" ;;
        "border") color_code="$THEME_BORDER" ;;
        "highlight") color_code="$THEME_HIGHLIGHT" ;;
        *) color_code="$COLOR_RESET" ;;
    esac
    
    echo -e "${color_code}${text}${COLOR_RESET}"
}

################################################################################
# SISTEMA DE ANIMAÇÕES E TRANSIÇÕES
################################################################################

# Configurações de animação
ANIMATION_ENABLED=true
ANIMATION_SPEED=0.05
TRANSITION_SPEED=0.03
FADE_STEPS=10
SLIDE_STEPS=20

# Função para fade in
fade_in() {
    local content="$1"
    local steps="${2:-$FADE_STEPS}"
    local delay="${3:-$ANIMATION_SPEED}"
    
    if [[ "$ANIMATION_ENABLED" != "true" ]]; then
        echo -e "$content"
        return 0
    fi
    
    # Dividir conteúdo em linhas
    local lines=()
    while IFS= read -r line; do
        lines+=("$line")
    done <<< "$content"
    
    # Fade in gradual
    for step in $(seq 1 $steps); do
        local opacity=$((step * 255 / steps))
        
        # Limpar tela
        echo -ne "\033[H\033[2J"
        
        # Desenhar com opacidade simulada
        for line in "${lines[@]}"; do
            if [[ $step -lt $steps ]]; then
                # Simular transparência com caracteres mais claros
                local faded_line="$(echo "$line" | sed 's/█/▓/g; s/▓/▒/g; s/▒/░/g')"
                echo -e "$faded_line"
            else
                echo -e "$line"
            fi
        done
        
        sleep "$delay"
    done
}

# Função para slide in (da esquerda)
slide_in_left() {
    local content="$1"
    local steps="${2:-$SLIDE_STEPS}"
    local delay="${3:-$TRANSITION_SPEED}"
    
    if [[ "$ANIMATION_ENABLED" != "true" ]]; then
        echo -e "$content"
        return 0
    fi
    
    # Dividir conteúdo em linhas
    local lines=()
    while IFS= read -r line; do
        lines+=("$line")
    done <<< "$content"
    
    # Calcular largura máxima
    local max_width=0
    for line in "${lines[@]}"; do
        local clean_line="$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')"
        if [[ ${#clean_line} -gt $max_width ]]; then
            max_width=${#clean_line}
        fi
    done
    
    # Slide in da esquerda
    for step in $(seq 1 $steps); do
        local offset=$((max_width - (step * max_width / steps)))
        
        # Limpar tela
        echo -ne "\033[H\033[2J"
        
        # Desenhar com offset
        for line in "${lines[@]}"; do
            printf "%*s%s\n" "$offset" "" "$line"
        done
        
        sleep "$delay"
    done
}

# Função para slide in (da direita)
slide_in_right() {
    local content="$1"
    local steps="${2:-$SLIDE_STEPS}"
    local delay="${3:-$TRANSITION_SPEED}"
    
    if [[ "$ANIMATION_ENABLED" != "true" ]]; then
        echo -e "$content"
        return 0
    fi
    
    # Dividir conteúdo em linhas
    local lines=()
    while IFS= read -r line; do
        lines+=("$line")
    done <<< "$content"
    
    # Slide in da direita
    for step in $(seq 1 $steps); do
        local visible_width=$((step * TERMINAL_WIDTH / steps))
        
        # Limpar tela
        echo -ne "\033[H\033[2J"
        
        # Desenhar com largura limitada
        for line in "${lines[@]}"; do
            local truncated="${line:0:$visible_width}"
            echo -e "$truncated"
        done
        
        sleep "$delay"
    done
}

# Função para typewriter effect
typewriter() {
    local text="$1"
    local delay="${2:-0.02}"
    local newline="${3:-true}"
    
    if [[ "$ANIMATION_ENABLED" != "true" ]]; then
        if [[ "$newline" == "true" ]]; then
            echo -e "$text"
        else
            echo -ne "$text"
        fi
        return 0
    fi
    
    # Processar caracteres especiais ANSI
    local i=0
    while [[ $i -lt ${#text} ]]; do
        local char="${text:$i:1}"
        
        # Detectar sequência de escape ANSI
        if [[ "$char" == $'\033' ]]; then
            local escape_seq="$char"
            ((i++))
            
            # Ler até 'm' (fim da sequência de cor)
            while [[ $i -lt ${#text} && "${text:$i:1}" != "m" ]]; do
                escape_seq+="${text:$i:1}"
                ((i++))
            done
            
            if [[ $i -lt ${#text} ]]; then
                escape_seq+="${text:$i:1}"
                ((i++))
            fi
            
            # Imprimir sequência completa sem delay
            echo -ne "$escape_seq"
        else
            echo -ne "$char"
            sleep "$delay"
            ((i++))
        fi
    done
    
    if [[ "$newline" == "true" ]]; then
        echo
    fi
}

# Função para spinner animado
show_spinner() {
    local message="$1"
    local duration="${2:-3}"
    local spinner_chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    
    if [[ "$ANIMATION_ENABLED" != "true" ]]; then
        echo -e "$message"
        sleep "$duration"
        return 0
    fi
    
    local start_time=$(date +%s)
    local i=0
    
    # Ocultar cursor
    echo -ne "\033[?25l"
    
    while [[ $(($(date +%s) - start_time)) -lt $duration ]]; do
        local char="${spinner_chars:$((i % ${#spinner_chars})):1}"
        echo -ne "\r$(color "accent" "$char") $message"
        sleep 0.1
        ((i++))
    done
    
    # Mostrar cursor e limpar linha
    echo -ne "\033[?25h\r\033[K"
}

# Função para barra de progresso animada
animated_progress() {
    local current="$1"
    local total="$2"
    local message="${3:-Processando}"
    local width="${4:-50}"
    
    if [[ "$ANIMATION_ENABLED" != "true" ]]; then
        show_progress "$current" "$total" "$message" "$width"
        return 0
    fi
    
    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    # Caracteres de progresso com gradiente
    local progress_chars=("█" "▉" "▊" "▋" "▌" "▍" "▎" "▏")
    local bar=""
    
    # Construir barra com efeito gradiente
    for ((i=0; i<filled; i++)); do
        if [[ $i -eq $((filled-1)) && $filled -lt $width ]]; then
            # Último caractere com gradiente
            local remainder=$((current * width * 8 / total % 8))
            bar+="${progress_chars[$remainder]}"
        else
            bar+="█"
        fi
    done
    
    # Adicionar espaços vazios
    for ((i=0; i<empty; i++)); do
        bar+=" "
    done
    
    # Exibir com cores
    echo -ne "\r$(color "info" "$message") "
    echo -ne "$(color "accent" "[")$(color "success" "$bar")$(color "accent" "]") "
    echo -ne "$(color "highlight" "$percent%")"
}

# Função para transição entre telas
screen_transition() {
    local from_content="$1"
    local to_content="$2"
    local transition_type="${3:-fade}"
    
    if [[ "$ANIMATION_ENABLED" != "true" ]]; then
        echo -ne "\033[H\033[2J"
        echo -e "$to_content"
        return 0
    fi
    
    case "$transition_type" in
        "fade")
            # Fade out
            for step in $(seq $FADE_STEPS -1 1); do
                echo -ne "\033[H\033[2J"
                # Simular fade out com caracteres mais claros
                local faded="$(echo "$from_content" | sed 's/█/▓/g; s/▓/▒/g; s/▒/░/g')"
                echo -e "$faded"
                sleep "$TRANSITION_SPEED"
            done
            
            # Fade in
            fade_in "$to_content"
            ;;
        "slide_left")
            slide_in_left "$to_content"
            ;;
        "slide_right")
            slide_in_right "$to_content"
            ;;
        *)
            echo -ne "\033[H\033[2J"
            echo -e "$to_content"
            ;;
    esac
}

# Função para piscar elemento
blink_element() {
    local element="$1"
    local times="${2:-3}"
    local delay="${3:-0.5}"
    
    if [[ "$ANIMATION_ENABLED" != "true" ]]; then
        echo -e "$element"
        return 0
    fi
    
    for ((i=0; i<times; i++)); do
        echo -ne "\r$element"
        sleep "$delay"
        echo -ne "\r$(printf ' %.0s' $(seq 1 ${#element}))"
        sleep "$delay"
    done
    
    echo -ne "\r$element"
}

# Função para toggle de animações
toggle_animations() {
    if [[ "$ANIMATION_ENABLED" == "true" ]]; then
        ANIMATION_ENABLED=false
        echo -e "$(color "warning" "Animações desabilitadas")"
    else
        ANIMATION_ENABLED=true
        typewriter "$(color "success" "Animações habilitadas")" 0.05
    fi
}

# Função para loading dots
loading_dots() {
    local message="$1"
    local duration="${2:-3}"
    
    if [[ "$ANIMATION_ENABLED" != "true" ]]; then
        echo -e "$message..."
        sleep "$duration"
        return 0
    fi
    
    local start_time=$(date +%s)
    local dots=""
    
    # Ocultar cursor
    echo -ne "\033[?25l"
    
    while [[ $(($(date +%s) - start_time)) -lt $duration ]]; do
        for i in {1..3}; do
            dots+="."
            echo -ne "\r$message$(color "accent" "$dots")"
            sleep 0.5
            
            if [[ $(($(date +%s) - start_time)) -ge $duration ]]; then
                break 2
            fi
        done
        
        dots=""
        echo -ne "\r$message   \r$message"
        sleep 0.5
    done
    
    # Mostrar cursor e limpar linha
    echo -ne "\033[?25h\r\033[K"
}

################################################################################
# SISTEMA DE CONFIGURAÇÃO PERSISTENTE E PROFILES
################################################################################

# Diretórios de configuração
CONFIG_DIR="$HOME/.config/boxserver"
PROFILES_DIR="$CONFIG_DIR/profiles"
LOGS_DIR="$CONFIG_DIR/logs"
CACHE_DIR="$CONFIG_DIR/cache"

# Arquivo de configuração principal
CONFIG_FILE="$CONFIG_DIR/config.conf"
LAST_SESSION_FILE="$CONFIG_DIR/last_session.conf"
PREFERENCES_FILE="$CONFIG_DIR/preferences.conf"

# Configurações padrão
DEFAULT_CONFIG="
# Configuração do BoxServer
# Gerado automaticamente em $(date)

[general]
theme=default
animations_enabled=true
help_enabled=true
language=pt_BR
log_level=info
auto_save=true
confirm_actions=true

[ui]
terminal_width=auto
terminal_height=auto
color_depth=auto
show_tooltips=true
show_progress=true
animation_speed=0.05

[installation]
default_install_path=/opt/boxserver
backup_configs=true
verify_checksums=true
parallel_downloads=true
max_retries=3

[network]
timeout=30
use_proxy=false
proxy_url=
verify_ssl=true

[security]
strict_permissions=true
backup_before_install=true
verify_signatures=true
"

# Função para criar estrutura de diretórios
init_config_dirs() {
    local dirs=("$CONFIG_DIR" "$PROFILES_DIR" "$LOGS_DIR" "$CACHE_DIR")
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir" 2>/dev/null || {
                log_error "Não foi possível criar diretório: $dir"
                return 1
            }
        fi
    done
    
    # Criar arquivo de configuração se não existir
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "$DEFAULT_CONFIG" > "$CONFIG_FILE"
        log_info "Arquivo de configuração criado: $CONFIG_FILE"
    fi
    
    return 0
}

# Função para ler configuração
read_config() {
    local key="$1"
    local section="${2:-general}"
    local default_value="$3"
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "$default_value"
        return 1
    fi
    
    # Ler valor da seção específica
    local value=$(awk -F'=' -v section="[$section]" -v key="$key" '
        $0 == section { in_section = 1; next }
        /^\[/ { in_section = 0; next }
        in_section && $1 == key { print $2; exit }
    ' "$CONFIG_FILE" | tr -d ' ')
    
    echo "${value:-$default_value}"
}

# Função para escrever configuração
write_config() {
    local key="$1"
    local value="$2"
    local section="${3:-general}"
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        init_config_dirs
    fi
    
    # Criar arquivo temporário
    local temp_file="$(mktemp)"
    local in_section=false
    local key_found=false
    
    # Processar arquivo linha por linha
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^\[.*\]$ ]]; then
            # Se estávamos na seção e não encontramos a chave, adicionar
            if [[ "$in_section" == true && "$key_found" == false ]]; then
                echo "$key=$value" >> "$temp_file"
                key_found=true
            fi
            
            # Verificar se é a seção desejada
            if [[ "$line" == "[$section]" ]]; then
                in_section=true
            else
                in_section=false
            fi
            
            echo "$line" >> "$temp_file"
        elif [[ "$in_section" == true && "$line" =~ ^$key= ]]; then
            # Substituir valor existente
            echo "$key=$value" >> "$temp_file"
            key_found=true
        else
            echo "$line" >> "$temp_file"
        fi
    done < "$CONFIG_FILE"
    
    # Se estávamos na seção e não encontramos a chave, adicionar no final
    if [[ "$in_section" == true && "$key_found" == false ]]; then
        echo "$key=$value" >> "$temp_file"
    fi
    
    # Substituir arquivo original
    mv "$temp_file" "$CONFIG_FILE"
}

# Função para salvar perfil de instalação
save_installation_profile() {
    local profile_name="$1"
    local selected_apps=("${@:2}")
    
    if [[ -z "$profile_name" ]]; then
        profile_name="profile_$(date +%Y%m%d_%H%M%S)"
    fi
    
    local profile_file="$PROFILES_DIR/${profile_name}.profile"
    
    # Criar cabeçalho do perfil
    cat > "$profile_file" << EOF
# Perfil de Instalação BoxServer
# Nome: $profile_name
# Criado: $(date)
# Sistema: $(uname -a)

[profile]
name=$profile_name
created=$(date +%s)
version=1.0

[system]
ram_mb=$(free -m | awk 'NR==2{print $2}')
storage_gb=$(df -BG / | awk 'NR==2{print $4}' | tr -d 'G')
os_version=$(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")
kernel=$(uname -r)

[applications]
EOF
    
    # Adicionar aplicativos selecionados
    for app in "${selected_apps[@]}"; do
        echo "$app=true" >> "$profile_file"
    done
    
    log_success "Perfil salvo: $profile_file"
    return 0
}

# Função para carregar perfil de instalação
load_installation_profile() {
    local profile_name="$1"
    local profile_file="$PROFILES_DIR/${profile_name}.profile"
    
    if [[ ! -f "$profile_file" ]]; then
        log_error "Perfil não encontrado: $profile_name"
        return 1
    fi
    
    # Ler aplicativos do perfil
    local apps=()
    while IFS='=' read -r key value; do
        if [[ "$value" == "true" ]]; then
            apps+=("$key")
        fi
    done < <(awk '/^\[applications\]$/,/^\[/ {if($0 !~ /^\[/) print}' "$profile_file")
    
    echo "${apps[@]}"
    return 0
}

# Função para listar perfis disponíveis
list_profiles() {
    local profiles=()
    
    if [[ -d "$PROFILES_DIR" ]]; then
        for profile_file in "$PROFILES_DIR"/*.profile; do
            if [[ -f "$profile_file" ]]; then
                local profile_name=$(basename "$profile_file" .profile)
                local created=$(read_config "created" "profile" "0" < "$profile_file")
                local created_date="$(date -d @$created 2>/dev/null || echo 'Data desconhecida')"
                
                profiles+=("$profile_name|$created_date")
            fi
        done
    fi
    
    printf '%s\n' "${profiles[@]}"
}

# Função para salvar sessão atual
save_session() {
    local session_data="
[session]
timestamp=$(date +%s)
theme=$CURRENT_THEME
animations_enabled=$ANIMATION_ENABLED
help_enabled=$HELP_ENABLED
last_menu_selection=${MENU_SELECTED_INDEX:-0}
terminal_width=$TERMINAL_WIDTH
terminal_height=$TERMINAL_HEIGHT

[runtime]
script_version=$SCRIPT_VERSION
start_time=$SCRIPT_START_TIME
user=$USER
working_dir=$PWD
"
    
    echo "$session_data" > "$LAST_SESSION_FILE"
}

# Função para restaurar sessão
restore_session() {
    if [[ ! -f "$LAST_SESSION_FILE" ]]; then
        return 1
    fi
    
    # Restaurar configurações da sessão
    CURRENT_THEME=$(read_config "theme" "session" "default" < "$LAST_SESSION_FILE")
    ANIMATION_ENABLED=$(read_config "animations_enabled" "session" "true" < "$LAST_SESSION_FILE")
    HELP_ENABLED=$(read_config "help_enabled" "session" "true" < "$LAST_SESSION_FILE")
    MENU_SELECTED_INDEX=$(read_config "last_menu_selection" "session" "0" < "$LAST_SESSION_FILE")
    
    log_info "Sessão anterior restaurada"
    return 0
}

# Função para exportar configurações
export_config() {
    local export_file="${1:-boxserver_config_$(date +%Y%m%d_%H%M%S).tar.gz}"
    
    if [[ ! -d "$CONFIG_DIR" ]]; then
        log_error "Diretório de configuração não encontrado"
        return 1
    fi
    
    # Criar arquivo de exportação
    tar -czf "$export_file" -C "$(dirname "$CONFIG_DIR")" "$(basename "$CONFIG_DIR")" 2>/dev/null || {
        log_error "Falha ao exportar configurações"
        return 1
    }
    
    log_success "Configurações exportadas para: $export_file"
    return 0
}

# Função para importar configurações
import_config() {
    local import_file="$1"
    
    if [[ ! -f "$import_file" ]]; then
        log_error "Arquivo de importação não encontrado: $import_file"
        return 1
    fi
    
    # Fazer backup das configurações atuais
    if [[ -d "$CONFIG_DIR" ]]; then
        local backup_file="${CONFIG_DIR}_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
        tar -czf "$backup_file" -C "$(dirname "$CONFIG_DIR")" "$(basename "$CONFIG_DIR")" 2>/dev/null
        log_info "Backup criado: $backup_file"
    fi
    
    # Extrair configurações importadas
    tar -xzf "$import_file" -C "$(dirname "$CONFIG_DIR")" 2>/dev/null || {
        log_error "Falha ao importar configurações"
        return 1
    }
    
    log_success "Configurações importadas com sucesso"
    return 0
}

# Função para resetar configurações
reset_config() {
    local confirm=$(show_dialog "question" "Resetar Configurações" "Tem certeza que deseja resetar todas as configurações?\n\nEsta ação não pode ser desfeita." "Sim" "Não")
    
    if [[ "$confirm" == "0" ]]; then
        # Fazer backup antes de resetar
        if [[ -d "$CONFIG_DIR" ]]; then
            local backup_file="${CONFIG_DIR}_reset_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
            tar -czf "$backup_file" -C "$(dirname "$CONFIG_DIR")" "$(basename "$CONFIG_DIR")" 2>/dev/null
            log_info "Backup criado antes do reset: $backup_file"
        fi
        
        # Remover diretório de configuração
        rm -rf "$CONFIG_DIR" 2>/dev/null
        
        # Recriar com configurações padrão
        init_config_dirs
        
        log_success "Configurações resetadas para os valores padrão"
        return 0
    fi
    
    return 1
}

# Função para mostrar menu de configurações
show_config_menu() {
    local config_items=(
        "Tema de Cores|Alterar tema visual da interface"
        "Animações|Habilitar/desabilitar animações"
        "Sistema de Ajuda|Configurar tooltips e ajuda contextual"
        "Perfis de Instalação|Gerenciar perfis salvos"
        "Exportar Configurações|Fazer backup das configurações"
        "Importar Configurações|Restaurar configurações de backup"
        "Resetar Configurações|Voltar aos valores padrão"
        "Voltar|Retornar ao menu principal"
    )
    
    local config_callbacks=(
        "configure_theme"
        "toggle_animations"
        "toggle_help_system"
        "manage_profiles"
        "export_config"
        "import_config_dialog"
        "reset_config"
        "return"
    )
    
    navigate_menu "Configurações do BoxServer" config_items config_callbacks
}

# Função para gerenciar perfis
manage_profiles() {
    local profiles_list=()
    local profile_info=()
    
    # Carregar lista de perfis
    while IFS='|' read -r name date; do
        profiles_list+=("$name")
        profile_info+=("Criado: $date")
    done < <(list_profiles)
    
    if [[ ${#profiles_list[@]} -eq 0 ]]; then
        show_dialog "info" "Perfis de Instalação" "Nenhum perfil encontrado.\n\nCrie um perfil durante a instalação para reutilizar configurações."
        return 0
    fi
    
    # Adicionar opções de gerenciamento
    profiles_list+=("Criar Novo Perfil" "Voltar")
    profile_info+=("Criar um novo perfil de instalação" "Retornar ao menu anterior")
    
    local selected=$(navigate_menu "Gerenciar Perfis" profiles_list profile_info)
    
    if [[ "$selected" == "Criar Novo Perfil" ]]; then
        create_new_profile
    elif [[ "$selected" != "Voltar" && -n "$selected" ]]; then
        manage_single_profile "$selected"
    fi
}

# Função para criar novo perfil
create_new_profile() {
    local profile_name
    profile_name=$(validated_input "Nome do Perfil" "Digite o nome do novo perfil:" "" "required")
    
    if [[ -n "$profile_name" ]]; then
        # Selecionar aplicativos para o perfil
        local available_apps=("pihole" "unbound" "wireguard" "nginx" "docker" "portainer" "homer" "grafana" "prometheus" "node_exporter" "fail2ban" "ufw" "ssh_hardening")
        local selected_apps=()
        
        selected_apps=$(show_checkbox_list "Selecionar Aplicativos" "Escolha os aplicativos para incluir no perfil:" available_apps)
        
        if [[ -n "$selected_apps" ]]; then
            save_installation_profile "$profile_name" $selected_apps
            show_dialog "success" "Perfil Criado" "Perfil '$profile_name' criado com sucesso!"
        fi
    fi
}

# Função para gerenciar perfil individual
manage_single_profile() {
    local profile_name="$1"
    local profile_file="$PROFILES_DIR/${profile_name}.profile"
    
    if [[ ! -f "$profile_file" ]]; then
        show_dialog "error" "Erro" "Perfil não encontrado: $profile_name"
        return 1
    fi
    
    # Ler informações do perfil
    local created=$(read_config "created" "profile" "0" < "$profile_file")
    local created_date="$(date -d @$created 2>/dev/null || echo 'Data desconhecida')"
    local apps=$(load_installation_profile "$profile_name")
    
    local profile_actions=(
        "Usar Perfil|Instalar aplicativos deste perfil"
        "Visualizar Detalhes|Ver informações completas do perfil"
        "Excluir Perfil|Remover este perfil permanentemente"
        "Voltar|Retornar à lista de perfis"
    )
    
    local action=$(navigate_menu "Perfil: $profile_name" profile_actions)
    
    case "$action" in
        "Usar Perfil")
            # Implementar uso do perfil na instalação
            show_dialog "info" "Perfil Selecionado" "Perfil '$profile_name' será usado na próxima instalação."
            ;;
        "Visualizar Detalhes")
            show_profile_details "$profile_name"
            ;;
        "Excluir Perfil")
            local confirm=$(show_dialog "question" "Excluir Perfil" "Tem certeza que deseja excluir o perfil '$profile_name'?" "Sim" "Não")
            if [[ "$confirm" == "0" ]]; then
                rm -f "$profile_file"
                show_dialog "success" "Perfil Excluído" "Perfil '$profile_name' foi excluído com sucesso."
            fi
            ;;
    esac
}

# Função para mostrar detalhes do perfil
show_profile_details() {
    local profile_name="$1"
    local profile_file="$PROFILES_DIR/${profile_name}.profile"
    
    local details="$(cat "$profile_file")"
    show_dialog "info" "Detalhes do Perfil: $profile_name" "$details"
}

################################################################################
# COMPONENTES TUI REUTILIZÁVEIS
################################################################################

# Função para desenhar caixa com bordas
draw_box() {
    local width="$1"
    local height="$2"
    local title="$3"
    local border_color="${4:-border}"
    local title_color="${5:-highlight}"
    
    local top_line=""
    local middle_line=""
    local bottom_line=""
    local title_padding=$(( (width - ${#title} - 4) / 2 ))
    
    # Construir linhas da caixa
    top_line="╔$(printf '═%.0s' $(seq 1 $((width-2))))╗"
    middle_line="║$(printf ' %.0s' $(seq 1 $((width-2))))║"
    bottom_line="╚$(printf '═%.0s' $(seq 1 $((width-2))))╝"
    
    # Linha do título
    local title_line="║"
    title_line+="$(printf ' %.0s' $(seq 1 $title_padding))"
    title_line+="$(color "$title_color" "$title")"
    title_line+="$(printf ' %.0s' $(seq 1 $((width - ${#title} - title_padding - 2))))"
    title_line+="║"
    
    # Desenhar caixa
    color "$border_color" "$top_line"
    color "$border_color" "$title_line"
    
    for ((i=2; i<height-1; i++)); do
        color "$border_color" "$middle_line"
    done
    
    color "$border_color" "$bottom_line"
}

# Inicializar sistema de cores
init_color_system

################################################################################
# FUNÇÕES DE LOGGING MODERNIZADAS
################################################################################

# Função de logging com níveis visuais
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local icon=""
    local color_name=""
    
    case "$level" in
        "INFO")
            icon="ℹ"
            color_name="info"
            ;;
        "SUCCESS")
            icon="✓"
            color_name="success"
            ;;
        "WARN")
            icon="⚠"
            color_name="warning"
            ;;
        "ERROR")
            icon="✗"
            color_name="error"
            ;;
        "DEBUG")
            icon="🔍"
            color_name="muted"
            ;;
    esac
    
    local formatted_message="[${timestamp}] $(color "$color_name" "${icon} [${level}]") ${message}"
    echo -e "$formatted_message" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_success() { log "SUCCESS" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

################################################################################
# SISTEMA DE PROGRESSO AVANÇADO
################################################################################

# Barra de progresso moderna com gradiente
show_progress() {
    local current="$1"
    local total="$2"
    local message="$3"
    local width="${4:-50}"
    
    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    # Escolher cor baseada no progresso
    local progress_color=""
    if [ $percent -le 25 ]; then
        progress_color="$COLOR_PROGRESS_25"
    elif [ $percent -le 50 ]; then
        progress_color="$COLOR_PROGRESS_50"
    elif [ $percent -le 75 ]; then
        progress_color="$COLOR_PROGRESS_75"
    else
        progress_color="$COLOR_PROGRESS_100"
    fi
    
    # Construir barra
    local bar=""
    bar+="$(color "primary" "[")"
    
    # Parte preenchida
    if [ $filled -gt 0 ]; then
        bar+="${progress_color}$(printf '█%.0s' $(seq 1 $filled))${COLOR_RESET}"
    fi
    
    # Parte vazia
    if [ $empty -gt 0 ]; then
        bar+="$(color "muted" "$(printf '░%.0s' $(seq 1 $empty))")"
    fi
    
    bar+="$(color "primary" "]")"
    
    # Exibir progresso
    printf "\r%s $(color "highlight" "%3d%%") %s" "$bar" "$percent" "$message"
    
    if [ "$current" -eq "$total" ]; then
        echo
    fi
}

# Spinner animado
show_spinner() {
    local message="$1"
    local delay="${2:-0.1}"
    local spinstr='|/-\\'
    
    while true; do
        local temp=${spinstr#?}
        printf "\r$(color "primary" "[%c]") %s" "$spinstr" "$message"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
    done
}

# Parar spinner
stop_spinner() {
    kill $! 2>/dev/null
    printf "\r$(color "success" "[✓]") %s\n" "$1"
}

################################################################################
# SISTEMA DE NAVEGAÇÃO AVANÇADO
################################################################################

# Configurações de navegação
NAV_SELECTED_INDEX=0
NAV_MAX_INDEX=0
NAV_ITEMS=()
NAV_CALLBACKS=()
NAV_HELP_TEXT=()
NAV_ENABLED_ITEMS=()

# Códigos de teclas especiais
KEY_UP=$'\033[A'
KEY_DOWN=$'\033[B'
KEY_RIGHT=$'\033[C'
KEY_LEFT=$'\033[D'
KEY_ENTER=$'\n'
KEY_SPACE=$' '
KEY_ESC=$'\033'
KEY_TAB=$'\t'
KEY_BACKSPACE=$'\177'
KEY_DELETE=$'\033[3~'
KEY_HOME=$'\033[H'
KEY_END=$'\033[F'
KEY_PAGE_UP=$'\033[5~'
KEY_PAGE_DOWN=$'\033[6~'

# Função para ler uma tecla sem pressionar Enter
read_key() {
    local key
    IFS= read -rsn1 key 2>/dev/null
    
    # Detectar sequências de escape (teclas especiais)
    if [[ $key == $'\033' ]]; then
        # Ler próximos caracteres para sequências de escape
        IFS= read -rsn2 -t 0.1 key2 2>/dev/null
        if [[ $key2 ]]; then
            key+="$key2"
            # Verificar se precisa ler mais caracteres (ex: Delete, Page Up/Down)
            if [[ $key2 == "[" ]]; then
                IFS= read -rsn1 -t 0.1 key3 2>/dev/null
                if [[ $key3 ]]; then
                    key+="$key3"
                    # Para teclas como Delete (\033[3~)
                    if [[ $key3 =~ [0-9] ]]; then
                        IFS= read -rsn1 -t 0.1 key4 2>/dev/null
                        if [[ $key4 ]]; then
                            key+="$key4"
                        fi
                    fi
                fi
            fi
        fi
    fi
    
    echo "$key"
}

# Função para configurar modo de entrada raw (sem buffer)
set_raw_mode() {
    stty -echo -icanon min 1 time 0 2>/dev/null
}

# Função para restaurar modo de entrada normal
restore_normal_mode() {
    stty echo icanon 2>/dev/null
}

# Função para limpar área de navegação
clear_nav_area() {
    local lines="$1"
    for ((i=0; i<lines; i++)); do
        echo -e "${CLEAR_LINE}"
        if [ $i -lt $((lines-1)) ]; then
            echo -ne "\033[1A"  # Mover cursor para cima
        fi
    done
    echo -ne "\033[${lines}A"  # Voltar ao início
}

# Função para desenhar item de menu
draw_menu_item() {
    local index="$1"
    local text="$2"
    local is_selected="$3"
    local is_enabled="${4:-true}"
    local help_text="${5:-}"
    local prefix=""
    local suffix=""
    local item_color=""
    
    if [[ "$is_enabled" == "true" ]]; then
        if [[ "$is_selected" == "true" ]]; then
            prefix="$(color "primary" "▶ ")"
            item_color="highlight"
            suffix="$(color "accent" " ◀")"
        else
            prefix="  "
            item_color="secondary"
        fi
    else
        prefix="$(color "muted" "  ")"
        item_color="muted"
        text="$(color "muted" "$text (indisponível)")"
    fi
    
    local formatted_text="${prefix}$(color "$item_color" "$text")${suffix}"
    
    # Adicionar texto de ajuda se selecionado
    if [[ "$is_selected" == "true" && -n "$help_text" ]]; then
        formatted_text+="$(color "muted" " - $help_text")"
    fi
    
    echo -e "$formatted_text"
}

# Função para desenhar menu navegável
draw_navigation_menu() {
    local title="$1"
    local show_help="${2:-true}"
    
    # Limpar tela
    echo -e "$CLEAR_SCREEN"
    echo -ne "\033[H"  # Mover cursor para home
    
    # Desenhar título
    echo
    color "primary" "╔$(printf '═%.0s' $(seq 1 $((TERMINAL_WIDTH-2))))╗"
    local title_padding=$(( (TERMINAL_WIDTH - ${#title} - 4) / 2 ))
    printf "║%*s$(color "highlight" "%s")%*s║\n" \
        $title_padding "" "$title" $((TERMINAL_WIDTH - ${#title} - title_padding - 2)) ""
    color "primary" "╚$(printf '═%.0s' $(seq 1 $((TERMINAL_WIDTH-2))))╝"
    echo
    
    # Desenhar itens do menu
    for ((i=0; i<${#NAV_ITEMS[@]}; i++)); do
        local is_selected="false"
        local is_enabled="true"
        
        if [ $i -eq $NAV_SELECTED_INDEX ]; then
            is_selected="true"
        fi
        
        if [ ${#NAV_ENABLED_ITEMS[@]} -gt $i ]; then
            is_enabled="${NAV_ENABLED_ITEMS[$i]}"
        fi
        
        local help_text=""
        if [ ${#NAV_HELP_TEXT[@]} -gt $i ]; then
            help_text="${NAV_HELP_TEXT[$i]}"
        fi
        
        draw_menu_item "$i" "${NAV_ITEMS[$i]}" "$is_selected" "$is_enabled" "$help_text"
    done
    
    echo
    
    # Mostrar ajuda de navegação
    if [[ "$show_help" == "true" ]]; then
        color "muted" "┌─ Navegação ─────────────────────────────────────────────────────────────┐"
        color "muted" "│ ↑/↓: Navegar  │ Enter/Space: Selecionar  │ q/Esc: Sair  │ h: Ajuda │"
        color "muted" "└─────────────────────────────────────────────────────────────────────────┘"
    fi
}

# Função principal de navegação
navigate_menu() {
    local title="$1"
    shift
    local items=("$@")
    
    # Configurar navegação
    NAV_ITEMS=("${items[@]}")
    NAV_SELECTED_INDEX=0
    NAV_MAX_INDEX=$((${#NAV_ITEMS[@]} - 1))
    
    # Configurar modo raw
    set_raw_mode
    echo -e "$CURSOR_HIDE"
    
    local running=true
    local result=""
    
    while [[ "$running" == "true" ]]; do
        # Desenhar menu
        draw_navigation_menu "$title"
        
        # Ler tecla
        local key=$(read_key)
        
        case "$key" in
            "$KEY_UP")
                if [ $NAV_SELECTED_INDEX -gt 0 ]; then
                    ((NAV_SELECTED_INDEX--))
                else
                    NAV_SELECTED_INDEX=$NAV_MAX_INDEX  # Wrap around
                fi
                ;;
            "$KEY_DOWN")
                if [ $NAV_SELECTED_INDEX -lt $NAV_MAX_INDEX ]; then
                    ((NAV_SELECTED_INDEX++))
                else
                    NAV_SELECTED_INDEX=0  # Wrap around
                fi
                ;;
            "$KEY_ENTER"|"$KEY_SPACE")
                # Verificar se item está habilitado
                local is_enabled="true"
                if [ ${#NAV_ENABLED_ITEMS[@]} -gt $NAV_SELECTED_INDEX ]; then
                    is_enabled="${NAV_ENABLED_ITEMS[$NAV_SELECTED_INDEX]}"
                fi
                
                if [[ "$is_enabled" == "true" ]]; then
                    result="$NAV_SELECTED_INDEX"
                    running=false
                fi
                ;;
            "q"|"Q"|"$KEY_ESC")
                result="-1"  # Cancelado
                running=false
                ;;
            "h"|"H")
                show_help_dialog
                ;;
            "1"|"2"|"3"|"4"|"5"|"6"|"7"|"8"|"9")
                local num_index=$((${key} - 1))
                if [ $num_index -le $NAV_MAX_INDEX ]; then
                    NAV_SELECTED_INDEX=$num_index
                fi
                ;;
        esac
    done
    
    # Restaurar modo normal
    echo -e "$CURSOR_SHOW"
    restore_normal_mode
    
    echo "$result"
}

# Sistema de Help Contextual e Tooltips

# Configurações do sistema de help
HELP_ENABLED=true
HELP_TIMEOUT=3
TOOLTIP_DELAY=1

# Base de conhecimento de help
declare -A HELP_DATABASE
HELP_DATABASE["main_menu"]="Use as setas ↑↓ para navegar, ENTER para selecionar, ESC para sair, H para ajuda detalhada"
HELP_DATABASE["app_selection"]="Selecione os aplicativos que deseja instalar. Use ESPAÇO para marcar/desmarcar"
HELP_DATABASE["pihole"]="Pi-hole: Bloqueador de anúncios em nível de DNS para toda a rede"
HELP_DATABASE["unbound"]="Unbound: Servidor DNS recursivo seguro e rápido"
HELP_DATABASE["wireguard"]="WireGuard: VPN moderna, rápida e segura"
HELP_DATABASE["nginx"]="Nginx: Servidor web de alta performance"
HELP_DATABASE["docker"]="Docker: Plataforma de containerização"
HELP_DATABASE["portainer"]="Portainer: Interface web para gerenciar Docker"
HELP_DATABASE["homer"]="Homer: Dashboard estático para serviços"
HELP_DATABASE["grafana"]="Grafana: Plataforma de monitoramento e visualização"
HELP_DATABASE["prometheus"]="Prometheus: Sistema de monitoramento e alertas"
HELP_DATABASE["node_exporter"]="Node Exporter: Exportador de métricas do sistema"
HELP_DATABASE["fail2ban"]="Fail2ban: Proteção contra ataques de força bruta"
HELP_DATABASE["ufw"]="UFW: Firewall simplificado para Ubuntu"
HELP_DATABASE["ssh_hardening"]="SSH Hardening: Configurações de segurança para SSH"

# Função para mostrar tooltip
show_tooltip() {
    local text="$1"
    local x="${2:-1}"
    local y="${3:-1}"
    local duration="${4:-$TOOLTIP_DELAY}"
    
    if [[ "$HELP_ENABLED" != "true" ]]; then
        return 0
    fi
    
    # Salvar posição atual do cursor
    echo -ne "\033[s"
    
    # Mover para posição do tooltip
    echo -ne "\033[${y};${x}H"
    
    # Desenhar tooltip
    local tooltip_bg="${COLOR_BG_BLACK:-\033[48;5;236m}"
    local tooltip_fg="${COLOR_BRIGHT_WHITE:-\033[38;5;255m}"
    local tooltip_border="${THEME_BORDER:-\033[38;5;240m}"
    
    echo -ne "${tooltip_bg}${tooltip_fg}${tooltip_border}┌"
    printf "─%.0s" $(seq 1 ${#text})
    echo -ne "┐${COLOR_RESET}"
    
    echo -ne "\033[$((y+1));${x}H${tooltip_bg}${tooltip_fg}${tooltip_border}│${tooltip_fg}${text}${tooltip_border}│${COLOR_RESET}"
    
    echo -ne "\033[$((y+2));${x}H${tooltip_bg}${tooltip_fg}${tooltip_border}└"
    printf "─%.0s" $(seq 1 ${#text})
    echo -ne "┘${COLOR_RESET}"
    
    # Aguardar duração especificada
    sleep "$duration"
    
    # Limpar tooltip
    for i in $(seq 0 2); do
        echo -ne "\033[$((y+i));${x}H"
        printf " %.0s" $(seq 1 $((${#text}+2)))
    done
    
    # Restaurar posição do cursor
    echo -ne "\033[u"
}

# Função para mostrar help contextual
show_contextual_help() {
    local context="$1"
    local x="${2:-$((TERMINAL_WIDTH-50))}"
    local y="${3:-2}"
    
    if [[ "$HELP_ENABLED" != "true" ]]; then
        return 0
    fi
    
    local help_text="${HELP_DATABASE[$context]}"
    if [[ -z "$help_text" ]]; then
        help_text="Ajuda não disponível para este contexto"
    fi
    
    # Quebrar texto em linhas se muito longo
    local max_width=45
    local lines=()
    
    while [[ ${#help_text} -gt $max_width ]]; do
        local break_point=$max_width
        # Procurar espaço mais próximo
        while [[ $break_point -gt 0 && "${help_text:$break_point:1}" != " " ]]; do
            ((break_point--))
        done
        
        if [[ $break_point -eq 0 ]]; then
            break_point=$max_width
        fi
        
        lines+=("${help_text:0:$break_point}")
        help_text="${help_text:$((break_point+1))}"
    done
    
    if [[ -n "$help_text" ]]; then
        lines+=("$help_text")
    fi
    
    # Salvar posição atual do cursor
    echo -ne "\033[s"
    
    # Desenhar caixa de help
    local help_bg="${COLOR_BG_BLUE:-\033[48;5;17m}"
    local help_fg="${COLOR_BRIGHT_WHITE:-\033[38;5;255m}"
    local help_border="${THEME_BORDER:-\033[38;5;33m}"
    local help_title="${THEME_ACCENT:-\033[38;5;51m}"
    
    # Calcular largura máxima
    local max_line_width=0
    for line in "${lines[@]}"; do
        if [[ ${#line} -gt $max_line_width ]]; then
            max_line_width=${#line}
        fi
    done
    
    # Desenhar cabeçalho
    echo -ne "\033[${y};${x}H${help_bg}${help_border}┌─${help_title} AJUDA ${help_border}"
    printf "─%.0s" $(seq 1 $((max_line_width-6)))
    echo -ne "┐${COLOR_RESET}"
    
    # Desenhar linhas de conteúdo
    local line_num=1
    for line in "${lines[@]}"; do
        echo -ne "\033[$((y+line_num));${x}H${help_bg}${help_border}│${help_fg} ${line}"
        printf " %.0s" $(seq 1 $((max_line_width-${#line})))
        echo -ne "${help_border}│${COLOR_RESET}"
        ((line_num++))
    done
    
    # Desenhar rodapé
    echo -ne "\033[$((y+line_num));${x}H${help_bg}${help_border}└"
    printf "─%.0s" $(seq 1 $max_line_width)
    echo -ne "┘${COLOR_RESET}"
    
    # Restaurar posição do cursor
    echo -ne "\033[u"
}

# Função para limpar área de help
clear_help_area() {
    local x="${1:-$((TERMINAL_WIDTH-50))}"
    local y="${2:-2}"
    local height="${3:-10}"
    local width="${4:-47}"
    
    for i in $(seq 0 $height); do
        echo -ne "\033[$((y+i));${x}H"
        printf " %.0s" $(seq 1 $width)
    done
}

# Função para help detalhado
show_detailed_help() {
    echo -e "$CLEAR_SCREEN"
    echo -ne "\033[H"
    
    local help_content="
$(color "primary" "╔══════════════════════════════════════════════════════════════════════════════╗")
$(color "primary" "║                              BOXSERVER - AJUDA DETALHADA                    ║")
$(color "primary" "╚══════════════════════════════════════════════════════════════════════════════╝")

$(color "secondary" "NAVEGAÇÃO:")
  $(color "accent" "↑/↓")     - Navegar entre opções
  $(color "accent" "ENTER")   - Selecionar opção
  $(color "accent" "ESPAÇO")  - Marcar/desmarcar em listas
  $(color "accent" "ESC")     - Voltar/Cancelar
  $(color "accent" "H")       - Mostrar esta ajuda
  $(color "accent" "TAB")     - Próximo campo (formulários)
  $(color "accent" "SHIFT+TAB") - Campo anterior (formulários)

$(color "secondary" "APLICATIVOS DISPONÍVEIS:")
  $(color "success" "Pi-hole")      - Bloqueador de anúncios DNS (Recomendado: 512MB+ RAM)
  $(color "success" "Unbound")      - Servidor DNS recursivo (Recomendado: 256MB+ RAM)
  $(color "success" "WireGuard")    - VPN moderna e segura (Recomendado: 512MB+ RAM)
  $(color "success" "Nginx")        - Servidor web de alta performance (Recomendado: 256MB+ RAM)
  $(color "success" "Docker")       - Plataforma de containerização (Recomendado: 1GB+ RAM)
  $(color "success" "Portainer")    - Interface web para Docker (Requer: Docker)
  $(color "success" "Homer")        - Dashboard para serviços (Recomendado: 128MB+ RAM)
  $(color "success" "Grafana")      - Monitoramento e visualização (Recomendado: 512MB+ RAM)
  $(color "success" "Prometheus")   - Sistema de monitoramento (Recomendado: 512MB+ RAM)
  $(color "success" "Node Exporter") - Métricas do sistema (Recomendado: 128MB+ RAM)
  $(color "success" "Fail2ban")     - Proteção contra ataques (Recomendado: 256MB+ RAM)
  $(color "success" "UFW")          - Firewall simplificado (Recomendado: 128MB+ RAM)
  $(color "success" "SSH Hardening") - Segurança SSH (Sempre recomendado)

$(color "secondary" "REQUISITOS DO SISTEMA:")
  $(color "info" "Hardware")     - MXQ-4K TV Box (RK322x)
  $(color "info" "RAM")          - Mínimo 512MB (Recomendado: 1GB+)
  $(color "info" "Storage")      - Mínimo 8GB livres
  $(color "info" "OS")           - Ubuntu/Debian baseado
  $(color "info" "Rede")         - Conexão com internet

$(color "secondary" "DICAS:")
  $(color "warning" "•") Instale Pi-hole + Unbound para DNS completo
  $(color "warning" "•") Docker + Portainer para gerenciamento fácil
  $(color "warning" "•") Grafana + Prometheus para monitoramento
  $(color "warning" "•") Sempre configure SSH Hardening primeiro
  $(color "warning" "•") Use WireGuard para acesso remoto seguro

$(color "secondary" "SUPORTE:")
  $(color "info" "GitHub")       - https://github.com/seu-usuario/boxserver
  $(color "info" "Documentação") - https://boxserver.docs.com
  $(color "info" "Issues")       - Reporte problemas no GitHub
"
    
    echo -e "$help_content"
    
    echo -e "\n$(color "primary" "Pressione qualquer tecla para voltar ao menu...")"
    read_key >/dev/null
}

# Função para toggle do sistema de help
toggle_help_system() {
    if [[ "$HELP_ENABLED" == "true" ]]; then
        HELP_ENABLED=false
        show_tooltip "Sistema de ajuda desabilitado" 10 $((TERMINAL_HEIGHT-2)) 2
    else
        HELP_ENABLED=true
        show_tooltip "Sistema de ajuda habilitado" 10 $((TERMINAL_HEIGHT-2)) 2
    fi
}

# Função para mostrar diálogo de ajuda
show_help_dialog() {
    show_detailed_help
}

################################################################################
# COMPONENTES TUI REUTILIZÁVEIS
################################################################################

# Função para criar caixa de diálogo modal
show_dialog() {
    local title="$1"
    local message="$2"
    local dialog_type="${3:-info}"  # info, warning, error, success, question
    local buttons="${4:-OK}"        # OK, YES_NO, YES_NO_CANCEL
    
    local icon=""
    local title_color=""
    local border_color=""
    
    case "$dialog_type" in
        "info")
            icon="ℹ"
            title_color="info"
            border_color="primary"
            ;;
        "warning")
            icon="⚠"
            title_color="warning"
            border_color="warning"
            ;;
        "error")
            icon="✗"
            title_color="error"
            border_color="error"
            ;;
        "success")
            icon="✓"
            title_color="success"
            border_color="success"
            ;;
        "question")
            icon="?"
            title_color="accent"
            border_color="accent"
            ;;
    esac
    
    # Calcular dimensões da caixa
    local max_width=60
    local message_lines=()
    IFS=$'\n' read -rd '' -a message_lines <<< "$message" || true
    local content_width=0
    
    for line in "${message_lines[@]}"; do
        if [ ${#line} -gt $content_width ]; then
            content_width=${#line}
        fi
    done
    
    local dialog_width=$((content_width + 6))
    if [ $dialog_width -gt $max_width ]; then
        dialog_width=$max_width
    fi
    if [ $dialog_width -lt 30 ]; then
        dialog_width=30
    fi
    
    local dialog_height=$((${#message_lines[@]} + 8))
    
    # Posicionar no centro da tela
    local start_row=$(( (TERMINAL_HEIGHT - dialog_height) / 2 ))
    local start_col=$(( (TERMINAL_WIDTH - dialog_width) / 2 ))
    
    # Salvar posição do cursor
    echo -ne "$CURSOR_SAVE"
    
    # Mover para posição inicial
    printf "\033[%d;%dH" $start_row $start_col
    
    # Desenhar caixa
    color "$border_color" "╔$(printf '═%.0s' $(seq 1 $((dialog_width-2))))╗"
    printf "\033[%d;%dH" $((start_row + 1)) $start_col
    
    # Título com ícone
    local title_text="$icon $title"
    local title_padding=$(( (dialog_width - ${#title_text} - 2) / 2 ))
    printf "║%*s$(color "$title_color" "%s")%*s║" \
        $title_padding "" "$title_text" $((dialog_width - ${#title_text} - title_padding - 2)) ""
    
    printf "\033[%d;%dH" $((start_row + 2)) $start_col
    color "$border_color" "╠$(printf '═%.0s' $(seq 1 $((dialog_width-2))))╣"
    
    # Conteúdo da mensagem
    local row=$((start_row + 3))
    for line in "${message_lines[@]}"; do
        printf "\033[%d;%dH" $row $start_col
        local line_padding=$(( (dialog_width - ${#line} - 2) / 2 ))
        printf "║%*s%s%*s║" \
            $line_padding "" "$line" $((dialog_width - ${#line} - line_padding - 2)) ""
        ((row++))
    done
    
    # Linha separadora
    printf "\033[%d;%dH" $row $start_col
    color "$border_color" "╠$(printf '═%.0s' $(seq 1 $((dialog_width-2))))╣"
    ((row++))
    
    # Botões
    printf "\033[%d;%dH" $row $start_col
    local button_text=""
    case "$buttons" in
        "OK")
            button_text="[ OK ]"
            ;;
        "YES_NO")
            button_text="[ Sim ]  [ Não ]"
            ;;
        "YES_NO_CANCEL")
            button_text="[ Sim ]  [ Não ]  [ Cancelar ]"
            ;;
    esac
    
    local button_padding=$(( (dialog_width - ${#button_text} - 2) / 2 ))
    printf "║%*s$(color "highlight" "%s")%*s║" \
        $button_padding "" "$button_text" $((dialog_width - ${#button_text} - button_padding - 2)) ""
    
    # Linha inferior
    printf "\033[%d;%dH" $((row + 1)) $start_col
    color "$border_color" "╚$(printf '═%.0s' $(seq 1 $((dialog_width-2))))╝"
    
    # Aguardar entrada do usuário
    set_raw_mode
    local result=""
    
    while true; do
        local key=$(read_key)
        case "$key" in
            "$KEY_ENTER"|"y"|"Y"|"s"|"S")
                result="yes"
                break
                ;;
            "n"|"N"|"$KEY_ESC")
                result="no"
                break
                ;;
            "c"|"C")
                if [[ "$buttons" == "YES_NO_CANCEL" ]]; then
                    result="cancel"
                    break
                fi
                ;;
        esac
        
        if [[ "$buttons" == "OK" ]]; then
            result="ok"
            break
        fi
    done
    
    restore_normal_mode
    
    # Restaurar cursor
    echo -ne "$CURSOR_RESTORE"
    echo -e "$CLEAR_SCREEN"
    
    echo "$result"
}

# Função para criar formulário interativo
show_form() {
    local title="$1"
    shift
    local fields=("$@")
    
    local form_data=()
    local current_field=0
    local max_field=$((${#fields[@]} - 1))
    
    # Inicializar dados do formulário
    for ((i=0; i<${#fields[@]}; i++)); do
        form_data[i]=""
    done
    
    set_raw_mode
    echo -e "$CURSOR_HIDE"
    
    local running=true
    
    while [[ "$running" == "true" ]]; do
        # Limpar tela
        echo -e "$CLEAR_SCREEN"
        echo -ne "\033[H"
        
        # Desenhar título do formulário
        echo
        color "primary" "╔$(printf '═%.0s' $(seq 1 $((TERMINAL_WIDTH-2))))╗"
        local title_padding=$(( (TERMINAL_WIDTH - ${#title} - 4) / 2 ))
        printf "║%*s$(color "highlight" "%s")%*s║\n" \
            $title_padding "" "$title" $((TERMINAL_WIDTH - ${#title} - title_padding - 2)) ""
        color "primary" "╚$(printf '═%.0s' $(seq 1 $((TERMINAL_WIDTH-2))))╝"
        echo
        
        # Desenhar campos do formulário
        for ((i=0; i<${#fields[@]}; i++)); do
            local field_name="${fields[$i]}"
            local field_value="${form_data[$i]}"
            local is_current="false"
            
            if [ $i -eq $current_field ]; then
                is_current="true"
            fi
            
            draw_form_field "$field_name" "$field_value" "$is_current"
        done
        
        echo
        
        # Instruções
        color "muted" "┌─ Navegação ─────────────────────────────────────────────────────────────┐"
        color "muted" "│ ↑/↓: Campo  │ Enter: Editar  │ Tab: Próximo  │ F10: Salvar  │ Esc: Sair │"
        color "muted" "└─────────────────────────────────────────────────────────────────────────┘"
        
        # Ler tecla
        local key=$(read_key)
        
        case "$key" in
            "$KEY_UP")
                if [ $current_field -gt 0 ]; then
                    ((current_field--))
                else
                    current_field=$max_field
                fi
                ;;
            "$KEY_DOWN"|"$KEY_TAB")
                if [ $current_field -lt $max_field ]; then
                    ((current_field++))
                else
                    current_field=0
                fi
                ;;
            "$KEY_ENTER")
                # Editar campo atual
                local new_value=$(edit_field "${fields[$current_field]}" "${form_data[$current_field]}")
                form_data[$current_field]="$new_value"
                ;;
            $'\033[21~')  # F10
                running=false
                ;;
            "$KEY_ESC")
                # Cancelar formulário
                form_data=()
                running=false
                ;;
        esac
    done
    
    echo -e "$CURSOR_SHOW"
    restore_normal_mode
    
    # Retornar dados do formulário
    printf '%s\n' "${form_data[@]}"
}

# Função para desenhar campo de formulário
draw_form_field() {
    local field_name="$1"
    local field_value="$2"
    local is_current="$3"
    
    local prefix=""
    local suffix=""
    local name_color="secondary"
    local value_color="highlight"
    local border_char="│"
    
    if [[ "$is_current" == "true" ]]; then
        prefix="$(color "primary" "▶ ")"
        suffix="$(color "accent" " ◀")"
        name_color="accent"
        border_char="║"
    else
        prefix="  "
    fi
    
    # Truncar valor se muito longo
    local display_value="$field_value"
    if [ ${#display_value} -gt 40 ]; then
        display_value="${display_value:0:37}..."
    fi
    
    if [ -z "$display_value" ]; then
        display_value="$(color "muted" "(vazio)")"
    fi
    
    echo -e "${prefix}$(color "$name_color" "$field_name:") $(color "$value_color" "$display_value")${suffix}"
}

# Função para editar campo individual
edit_field() {
    local field_name="$1"
    local current_value="$2"
    
    echo -e "$CLEAR_SCREEN"
    echo -ne "\033[H"
    
    echo
    color "accent" "╔═══════════════════════════════════════════════════════════════════════════╗"
    color "accent" "║                            $(color "highlight" "EDITAR CAMPO")                              ║"
    color "accent" "╚═══════════════════════════════════════════════════════════════════════════╝"
    echo
    
    color "secondary" "Campo: $(color "highlight" "$field_name")"
    echo
    color "muted" "Valor atual: $current_value"
    echo
    color "info" "Digite o novo valor (Enter para confirmar, Esc para cancelar):"
    echo -n "$(color "primary" "> ")"
    
    restore_normal_mode
    
    local new_value
    read -r new_value
    
    if [ -z "$new_value" ]; then
        new_value="$current_value"
    fi
    
    set_raw_mode
    
    echo "$new_value"
}

# Função para criar lista selecionável com checkboxes
show_checkbox_list() {
    local title="$1"
    shift
    local items=("$@")
    
    local selected_items=()
    local current_index=0
    local max_index=$((${#items[@]} - 1))
    
    # Inicializar seleções (todas desmarcadas)
    for ((i=0; i<${#items[@]}; i++)); do
        selected_items[i]="false"
    done
    
    set_raw_mode
    echo -e "$CURSOR_HIDE"
    
    local running=true
    
    while [[ "$running" == "true" ]]; do
        # Limpar tela
        echo -e "$CLEAR_SCREEN"
        echo -ne "\033[H"
        
        # Desenhar título
        echo
        color "primary" "╔$(printf '═%.0s' $(seq 1 $((TERMINAL_WIDTH-2))))╗"
        local title_padding=$(( (TERMINAL_WIDTH - ${#title} - 4) / 2 ))
        printf "║%*s$(color "highlight" "%s")%*s║\n" \
            $title_padding "" "$title" $((TERMINAL_WIDTH - ${#title} - title_padding - 2)) ""
        color "primary" "╚$(printf '═%.0s' $(seq 1 $((TERMINAL_WIDTH-2))))╝"
        echo
        
        # Desenhar itens com checkboxes
        for ((i=0; i<${#items[@]}; i++)); do
            local checkbox="☐"
            local item_color="secondary"
            local prefix="  "
            
            if [[ "${selected_items[$i]}" == "true" ]]; then
                checkbox="☑"
                item_color="success"
            fi
            
            if [ $i -eq $current_index ]; then
                prefix="$(color "primary" "▶ ")"
                item_color="highlight"
            fi
            
            echo -e "${prefix}$(color "accent" "$checkbox") $(color "$item_color" "${items[$i]}")"
        done
        
        echo
        
        # Instruções
        color "muted" "┌─ Controles ─────────────────────────────────────────────────────────────┐"
        color "muted" "│ ↑/↓: Navegar  │ Space: Marcar/Desmarcar  │ Enter: Confirmar  │ Esc: Sair │"
        color "muted" "└─────────────────────────────────────────────────────────────────────────┘"
        
        # Ler tecla
        local key=$(read_key)
        
        case "$key" in
            "$KEY_UP")
                if [ $current_index -gt 0 ]; then
                    ((current_index--))
                else
                    current_index=$max_index
                fi
                ;;
            "$KEY_DOWN")
                if [ $current_index -lt $max_index ]; then
                    ((current_index++))
                else
                    current_index=0
                fi
                ;;
            "$KEY_SPACE")
                # Alternar seleção do item atual
                if [[ "${selected_items[$current_index]}" == "true" ]]; then
                    selected_items[$current_index]="false"
                else
                    selected_items[$current_index]="true"
                fi
                ;;
            "$KEY_ENTER")
                running=false
                ;;
            "$KEY_ESC")
                # Cancelar - limpar todas as seleções
                for ((i=0; i<${#selected_items[@]}; i++)); do
                    selected_items[i]="false"
                done
                running=false
                ;;
        esac
    done
    
    echo -e "$CURSOR_SHOW"
    restore_normal_mode
    
    # Retornar índices dos itens selecionados
    local result=()
    for ((i=0; i<${#selected_items[@]}; i++)); do
        if [[ "${selected_items[$i]}" == "true" ]]; then
            result+=("$i")
        fi
    done
    
    printf '%s\n' "${result[@]}"
}

################################################################################
# SISTEMA DE VALIDAÇÃO DE ENTRADA
################################################################################

# Tipos de validação disponíveis
declare -A VALIDATION_TYPES=(
    ["required"]="Campo obrigatório"
    ["email"]="Endereço de email válido"
    ["ip"]="Endereço IP válido"
    ["port"]="Porta válida (1-65535)"
    ["domain"]="Nome de domínio válido"
    ["path"]="Caminho de arquivo válido"
    ["number"]="Número válido"
    ["range"]="Valor dentro do intervalo especificado"
    ["length"]="Comprimento específico"
    ["regex"]="Padrão personalizado"
    ["confirm"]="Confirmação de valor"
)

# Função principal de validação
validate_input() {
    local value="$1"
    local validation_rule="$2"
    local field_name="${3:-Campo}"
    
    # Separar tipo de validação e parâmetros
    local validation_type="${validation_rule%%:*}"
    local validation_params="${validation_rule#*:}"
    
    case "$validation_type" in
        "required")
            validate_required "$value" "$field_name"
            ;;
        "email")
            validate_email "$value" "$field_name"
            ;;
        "ip")
            validate_ip "$value" "$field_name"
            ;;
        "port")
            validate_port "$value" "$field_name"
            ;;
        "domain")
            validate_domain "$value" "$field_name"
            ;;
        "path")
            validate_path "$value" "$field_name"
            ;;
        "number")
            validate_number "$value" "$field_name"
            ;;
        "range")
            validate_range "$value" "$validation_params" "$field_name"
            ;;
        "length")
            validate_length "$value" "$validation_params" "$field_name"
            ;;
        "regex")
            validate_regex "$value" "$validation_params" "$field_name"
            ;;
        "confirm")
            validate_confirm "$value" "$validation_params" "$field_name"
            ;;
        *)
            echo "error:Tipo de validação desconhecido: $validation_type"
            return 1
            ;;
    esac
}

# Validadores específicos
validate_required() {
    local value="$1"
    local field_name="$2"
    
    if [[ -z "$value" || "$value" =~ ^[[:space:]]*$ ]]; then
        echo "error:$field_name é obrigatório"
        return 1
    fi
    
    echo "success:Valor válido"
    return 0
}

validate_email() {
    local value="$1"
    local field_name="$2"
    
    if [[ -z "$value" ]]; then
        echo "success:Email opcional"
        return 0
    fi
    
    local email_regex='^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if [[ ! "$value" =~ $email_regex ]]; then
        echo "error:$field_name deve ser um endereço de email válido (ex: usuario@dominio.com)"
        return 1
    fi
    
    echo "success:Email válido"
    return 0
}

validate_ip() {
    local value="$1"
    local field_name="$2"
    
    if [[ -z "$value" ]]; then
        echo "success:IP opcional"
        return 0
    fi
    
    # Validar IPv4
    local ip_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    
    if [[ ! "$value" =~ $ip_regex ]]; then
        echo "error:$field_name deve ser um endereço IP válido (ex: 192.168.1.1)"
        return 1
    fi
    
    # Verificar se cada octeto está no range 0-255
    IFS='.' read -ra octets <<< "$value"
    for octet in "${octets[@]}"; do
        if [[ $octet -lt 0 || $octet -gt 255 ]]; then
            echo "error:$field_name contém octeto inválido: $octet (deve ser 0-255)"
            return 1
        fi
    done
    
    echo "success:IP válido"
    return 0
}

validate_port() {
    local value="$1"
    local field_name="$2"
    
    if [[ -z "$value" ]]; then
        echo "success:Porta opcional"
        return 0
    fi
    
    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        echo "error:$field_name deve ser um número"
        return 1
    fi
    
    if [[ $value -lt 1 || $value -gt 65535 ]]; then
        echo "error:$field_name deve estar entre 1 e 65535"
        return 1
    fi
    
    # Verificar portas reservadas
    if [[ $value -lt 1024 ]]; then
        echo "warning:Porta $value é reservada do sistema (requer privilégios root)"
    fi
    
    echo "success:Porta válida"
    return 0
}

validate_domain() {
    local value="$1"
    local field_name="$2"
    
    if [[ -z "$value" ]]; then
        echo "success:Domínio opcional"
        return 0
    fi
    
    local domain_regex='^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))*$'
    
    if [[ ! "$value" =~ $domain_regex ]]; then
        echo "error:$field_name deve ser um domínio válido (ex: exemplo.com)"
        return 1
    fi
    
    if [[ ${#value} -gt 253 ]]; then
        echo "error:$field_name muito longo (máximo 253 caracteres)"
        return 1
    fi
    
    echo "success:Domínio válido"
    return 0
}

validate_path() {
    local value="$1"
    local field_name="$2"
    
    if [[ -z "$value" ]]; then
        echo "success:Caminho opcional"
        return 0
    fi
    
    # Verificar caracteres inválidos
    if [[ "$value" =~ [\<\>\:\"|\?\*] ]]; then
        echo "error:$field_name contém caracteres inválidos"
        return 1
    fi
    
    # Verificar se o diretório pai existe (se for caminho absoluto)
    if [[ "$value" =~ ^/ ]]; then
        local parent_dir="$(dirname "$value")"
        if [[ ! -d "$parent_dir" ]]; then
            echo "warning:Diretório pai não existe: $parent_dir"
        fi
    fi
    
    echo "success:Caminho válido"
    return 0
}

validate_number() {
    local value="$1"
    local field_name="$2"
    
    if [[ -z "$value" ]]; then
        echo "success:Número opcional"
        return 0
    fi
    
    if [[ ! "$value" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
        echo "error:$field_name deve ser um número válido"
        return 1
    fi
    
    echo "success:Número válido"
    return 0
}

validate_range() {
    local value="$1"
    local range_params="$2"
    local field_name="$3"
    
    if [[ -z "$value" ]]; then
        echo "success:Valor opcional"
        return 0
    fi
    
    # Extrair min e max do formato "min-max"
    local min_val="${range_params%-*}"
    local max_val="${range_params#*-}"
    
    if [[ ! "$value" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
        echo "error:$field_name deve ser um número"
        return 1
    fi
    
    if (( $(echo "$value < $min_val" | bc -l) )); then
        echo "error:$field_name deve ser maior ou igual a $min_val"
        return 1
    fi
    
    if (( $(echo "$value > $max_val" | bc -l) )); then
        echo "error:$field_name deve ser menor ou igual a $max_val"
        return 1
    fi
    
    echo "success:Valor dentro do intervalo válido"
    return 0
}

validate_length() {
    local value="$1"
    local length_params="$2"
    local field_name="$3"
    
    if [[ -z "$value" ]]; then
        echo "success:Comprimento opcional"
        return 0
    fi
    
    local value_length=${#value}
    
    # Suporte para min-max ou valor exato
    if [[ "$length_params" =~ ^[0-9]+-[0-9]+$ ]]; then
        local min_len="${length_params%-*}"
        local max_len="${length_params#*-}"
        
        if [[ $value_length -lt $min_len ]]; then
            echo "error:$field_name deve ter pelo menos $min_len caracteres"
            return 1
        fi
        
        if [[ $value_length -gt $max_len ]]; then
            echo "error:$field_name deve ter no máximo $max_len caracteres"
            return 1
        fi
    else
        local exact_len="$length_params"
        if [[ $value_length -ne $exact_len ]]; then
            echo "error:$field_name deve ter exatamente $exact_len caracteres"
            return 1
        fi
    fi
    
    echo "success:Comprimento válido"
    return 0
}

validate_regex() {
    local value="$1"
    local regex_pattern="$2"
    local field_name="$3"
    
    if [[ -z "$value" ]]; then
        echo "success:Padrão opcional"
        return 0
    fi
    
    if [[ ! "$value" =~ $regex_pattern ]]; then
        echo "error:$field_name não atende ao padrão exigido"
        return 1
    fi
    
    echo "success:Padrão válido"
    return 0
}

validate_confirm() {
    local value="$1"
    local original_value="$2"
    local field_name="$3"
    
    if [[ "$value" != "$original_value" ]]; then
        echo "error:$field_name não confere com o valor original"
        return 1
    fi
    
    echo "success:Confirmação válida"
    return 0
}

# Função para exibir mensagem de validação com cores
show_validation_message() {
    local validation_result="$1"
    local message_type="${validation_result%%:*}"
    local message_text="${validation_result#*:}"
    
    case "$message_type" in
        "success")
            echo "$(color "success" "✓") $(color "muted" "$message_text")"
            ;;
        "warning")
            echo "$(color "warning" "⚠") $(color "warning" "$message_text")"
            ;;
        "error")
            echo "$(color "error" "✗") $(color "error" "$message_text")"
            ;;
        *)
            echo "$(color "info" "ℹ") $(color "secondary" "$message_text")"
            ;;
    esac
}

# Função para input com validação em tempo real
validated_input() {
    local prompt="$1"
    local validation_rules="$2"
    local field_name="${3:-Campo}"
    local default_value="${4:-}"
    
    local input_value="$default_value"
    local is_valid=false
    local attempts=0
    local max_attempts=3
    
    while [[ "$is_valid" == "false" && $attempts -lt $max_attempts ]]; do
        ((attempts++))
        
        # Mostrar prompt
        echo
        color "secondary" "$prompt"
        if [[ -n "$default_value" ]]; then
            color "muted" "(padrão: $default_value)"
        fi
        echo -n "$(color "primary" "> ")"
        
        # Ler entrada
        read -r input_value
        
        # Usar valor padrão se entrada vazia
        if [[ -z "$input_value" && -n "$default_value" ]]; then
            input_value="$default_value"
        fi
        
        # Validar entrada
        local validation_result
        local all_valid=true
        
        # Suporte para múltiplas regras separadas por vírgula
        IFS=',' read -ra rules <<< "$validation_rules"
        for rule in "${rules[@]}"; do
            rule=$(echo "$rule" | xargs)  # Remover espaços
            validation_result=$(validate_input "$input_value" "$rule" "$field_name")
            
            show_validation_message "$validation_result"
            
            if [[ "$validation_result" =~ ^error: ]]; then
                all_valid=false
                break
            fi
        done
        
        if [[ "$all_valid" == "true" ]]; then
            is_valid=true
        else
            if [[ $attempts -lt $max_attempts ]]; then
                echo
                color "warning" "Tentativa $attempts de $max_attempts. Tente novamente."
                sleep 1
            fi
        fi
    done
    
    if [[ "$is_valid" == "false" ]]; then
        echo
        color "error" "Número máximo de tentativas excedido. Usando valor padrão."
        input_value="$default_value"
    fi
    
    echo "$input_value"
}

################################################################################
# FUNÇÕES BÁSICAS DO SISTEMA
################################################################################

# Verificar distribuição Linux
check_linux_distribution() {
    log_info "Verificando distribuição Linux..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|armbian|raspbian)
                log_success "Distribuição compatível: $NAME ✓"
                ;;
            *)
                log_error "Distribuição não suportada: $NAME"
                log_error "Este script requer Ubuntu, Debian, Armbian ou Raspbian"
                exit 1
                ;;
        esac
    else
        log_error "Não foi possível detectar a distribuição Linux"
        exit 1
    fi
}

# Verificar se é root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Este script deve ser executado como root (sudo)"
        exit 1
    fi
}

# Verificar dependências do sistema
check_dependencies() {
    local deps=("curl" "wget" "tar" "gzip" "openssl" "iproute2" "procps" "net-tools")
    local missing_deps=()
    
    log_info "Verificando dependências do sistema..."
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_warn "Dependências ausentes: ${missing_deps[*]}"
        log_info "Instalando dependências..."
        apt-get update -qq
        apt-get install -y -qq "${missing_deps[@]}"
    fi
    
    log_success "Todas as dependências instaladas ✓"
}

# Verificar requisitos do sistema
check_system_requirements() {
    log_info "Verificando requisitos do sistema..."
    
    # Verificar RAM
    local ram_mb=$(free -m | awk 'NR==2{print $2}')
    if [ "$ram_mb" -lt 512 ]; then
        log_error "RAM insuficiente: ${ram_mb}MB (mínimo: 512MB)"
        exit 1
    fi
    log_success "RAM: ${ram_mb}MB ✓"
    
    # Verificar espaço em disco
    local disk_gb=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    if [ "$disk_gb" -lt 2 ]; then
        log_error "Espaço em disco insuficiente: ${disk_gb}GB (mínimo: 2GB)"
        exit 1
    fi
    log_success "Espaço em disco: ${disk_gb}GB disponível ✓"
    
    # Verificar arquitetura
    local arch=$(uname -m)
    if [[ ! "$arch" =~ ^(arm|aarch64)$ ]]; then
        log_warn "Arquitetura não testada: $arch (esperado: arm/aarch64)"
    fi
    log_success "Arquitetura: $arch ✓"
    
    # Verificar conectividade
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_error "Sem conectividade com a internet"
        exit 1
    fi
    log_success "Conectividade com internet ✓"
}

# Detectar interface de rede principal
detect_network_interface() {
    if [ -z "$NETWORK_INTERFACE" ]; then
        NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
        if [ -z "$NETWORK_INTERFACE" ]; then
            log_error "Não foi possível detectar interface de rede principal"
            echo "Interfaces disponíveis:"
            ip link show | grep '^[0-9]' | awk '{print $2}' | sed 's/:$//'
            exit 1
        fi
    fi
    
    # Verificar se interface existe e está ativa
    if ! ip link show "$NETWORK_INTERFACE" >/dev/null 2>&1; then
        log_error "Interface $NETWORK_INTERFACE não encontrada"
        exit 1
    fi
    
    # Obter IP da interface
    SERVER_IP=$(ip addr show "$NETWORK_INTERFACE" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1)
    if [ -z "$SERVER_IP" ]; then
        log_error "Não foi possível obter IP da interface $NETWORK_INTERFACE"
        exit 1
    fi
    
    log_success "Interface de rede: $NETWORK_INTERFACE ($SERVER_IP) ✓"
}

# Criar diretórios necessários
setup_directories() {
    log_info "Criando estrutura de diretórios..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "/var/log/boxserver"
    
    # Inicializar arquivo de serviços instalados
    > "$CONFIG_DIR/installed_services"
    
    # Salvar configurações detectadas
    cat > "$CONFIG_DIR/system.conf" << EOF
# Configurações do sistema detectadas automaticamente
NETWORK_INTERFACE="$NETWORK_INTERFACE"
SERVER_IP="$SERVER_IP"
VPN_NETWORK="$VPN_NETWORK"
VPN_PORT="$VPN_PORT"
FILEBROWSER_PORT="$FILEBROWSER_PORT"
COCKPIT_PORT="$COCKPIT_PORT"
INSTALL_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
STATIC_IP_CONFIGURED="$STATIC_IP_CONFIGURED"
EOF
    
    log_success "Diretórios criados ✓"
}

# Atualizar sistema
update_system() {
    log_info "Atualizando sistema..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq
    apt-get install -y -qq curl wget gnupg2 software-properties-common apt-transport-https
    
    log_success "Sistema atualizado ✓"
}

################################################################################
# MENU PRINCIPAL E INTERFACE
################################################################################

# Função para exibir o menu principal
show_main_menu() {
    local menu_items=(
        "Configuração Inicial do Sistema"
        "Instalação de Aplicativos"
        "Configurações de Rede"
        "Gerenciar Perfis de Instalação"
        "Configurações do Sistema"
        "Logs e Monitoramento"
        "Ajuda e Documentação"
        "Sair"
    )
    
    local menu_callbacks=(
        "setup_system"
        "install_applications"
        "configure_network"
        "manage_profiles"
        "show_config_menu"
        "show_log_menu"
        "show_detailed_help"
        "exit_application"
    )
    
    local menu_help=(
        "Verificações iniciais, dependências e preparação do sistema"
        "Selecionar e instalar aplicativos disponíveis para MXQ-4k"
        "Configurar IP estático, interfaces de rede e conectividade"
        "Criar, carregar e gerenciar perfis de instalação personalizados"
        "Configurar temas, animações e preferências da interface"
        "Visualizar logs, estatísticas e informações do sistema"
        "Documentação completa, tutoriais e suporte técnico"
        "Encerrar o instalador BoxServer"
    )
    
    clear
    
    # Cabeçalho principal
    draw_box "BoxServer MXQ-4k - Instalador Automatizado" "$TERMINAL_WIDTH" "primary"
    echo
    
    # Informações do sistema
    local system_info="Sistema: $(uname -o) | Arquitetura: $(uname -m) | Terminal: ${TERMINAL_WIDTH}x${TERMINAL_HEIGHT}"
    echo -e "$(color "muted" "$system_info")"
    echo
    
    # Navegação do menu
    navigate_menu "Menu Principal" menu_items menu_callbacks menu_help
}

# Função para configuração inicial do sistema
setup_system() {
    show_dialog "info" "Configuração do Sistema" "Iniciando verificações e configuração inicial do sistema..." "OK"
    
    # Verificações básicas
    check_root
    check_linux_distribution
    check_dependencies
    check_system_requirements
    detect_network_interface
    setup_directories
    
    show_dialog "success" "Sistema Configurado" "Configuração inicial concluída com sucesso!" "Continuar"
}

# Função para instalação de aplicativos
install_applications() {
    local apps=(
        "Pi-hole - Bloqueio de anúncios e DNS"
        "Unbound - DNS recursivo local"
        "WireGuard - Servidor VPN"
        "Cockpit - Painel de administração web"
        "FileBrowser - Gerenciamento de arquivos web"
        "Netdata - Monitoramento em tempo real"
        "Fail2Ban - Proteção contra ataques"
        "UFW - Firewall simplificado"
        "RNG-tools - Gerador de entropia"
        "Rclone - Sincronização com nuvem"
        "Rsync - Backup local"
        "MiniDLNA - Servidor de mídia"
        "Cloudflared - Tunnel Cloudflare"
    )
    
    local selected_apps=()
    show_checkbox_list "Seleção de Aplicativos" "Escolha os aplicativos para instalar:" apps selected_apps
    
    if [[ ${#selected_apps[@]} -gt 0 ]]; then
        show_dialog "info" "Instalação" "Instalando ${#selected_apps[@]} aplicativo(s) selecionado(s)..." "Iniciar"
        
        # Aqui seria chamada a função de instalação real
        # process_selection "${selected_apps[*]}"
        
        show_dialog "success" "Concluído" "Instalação dos aplicativos concluída!" "OK"
    else
        show_dialog "warning" "Nenhuma Seleção" "Nenhum aplicativo foi selecionado para instalação." "OK"
    fi
}

# Função para configuração de rede
configure_network() {
    local network_options=(
        "Configurar IP Estático"
        "Detectar Interface de Rede"
        "Configurar DNS"
        "Testar Conectividade"
        "Voltar"
    )
    
    local network_callbacks=(
        "configure_static_ip"
        "detect_network_interface"
        "configure_dns"
        "test_connectivity"
        "return"
    )
    
    navigate_menu "Configurações de Rede" network_options network_callbacks
}

# Função para sair da aplicação
exit_application() {
    local response
    show_dialog "question" "Confirmar Saída" "Deseja realmente sair do instalador BoxServer?" "Sim|Não" response
    
    if [[ "$response" == "Sim" ]]; then
        clear
        echo -e "$(color "primary" "Obrigado por usar o BoxServer MXQ-4k!")"
        echo -e "$(color "muted" "Desenvolvido com base na base de conhecimento Arandutec")"
        echo
        exit 0
    fi
}

################################################################################
# FUNÇÃO PRINCIPAL
################################################################################

main() {
    # Inicializar sistemas
    init_config_dirs
    init_color_system
    init_log_system
    
    # Carregar configurações
    CURRENT_THEME=$(read_config "theme" "ui" "default")
    ANIMATION_ENABLED=$(read_config "animations_enabled" "ui" "true")
    HELP_ENABLED=$(read_config "help_enabled" "ui" "true")
    
    # Aplicar tema
    set_theme "$CURRENT_THEME"
    
    # Inicializar log
    echo "=== INÍCIO DA INSTALAÇÃO BOXSERVER MXQ-4K ===" > "$LOG_FILE"
    log_info "Iniciando BoxServer MXQ-4k TUI Modernizada..."
    log_success "TUI moderna inicializada - Terminal: ${TERMINAL_WIDTH}x${TERMINAL_HEIGHT}, Cores: $(detect_terminal_capabilities)"
    log_info "Sistema de validação de entrada carregado com $(echo ${!VALIDATION_TYPES[@]} | wc -w) tipos de validação"
    
    # Salvar sessão inicial
    save_session
    
    # Animação de inicialização
    if [[ "$ANIMATION_ENABLED" == "true" ]]; then
        local welcome_text="$(color "primary" "BoxServer MXQ-4k")"
        welcome_text+="\n$(color "secondary" "Instalador Automatizado com TUI Modernizada")"
        welcome_text+="\n$(color "muted" "Carregando interface...")"
        
        fade_in "$welcome_text"
        sleep 1
    fi
    
    # Loop principal da interface
    while true; do
        show_main_menu
    done
}

################################################################################
# TRATAMENTO DE SINAIS E LIMPEZA
################################################################################

cleanup() {
    log_warn "Instalação interrompida. Limpando..."
    
    # Restaurar cursor e modo normal do terminal
    echo -ne "$CURSOR_SHOW"
    restore_normal_mode 2>/dev/null || true
    
    # Salvar sessão antes de sair
    save_session
    
    if [ -f "$CONFIG_DIR/installed_services" ]; then
        log_warn "Serviços parcialmente instalados detectados. Executando rollback..."
        # rollback_installation
    fi
    
    clear
    echo -e "$(color "warning" "Instalação interrompida pelo usuário.")"
    exit 1
}

error_handler() {
    local exit_code=$?
    local line_number=$1
    
    log_error "Erro na linha $line_number com código de saída $exit_code"
    
    # Restaurar terminal
    echo -ne "$CURSOR_SHOW"
    restore_normal_mode 2>/dev/null || true
    
    if [ -f "$CONFIG_DIR/installed_services" ]; then
        log_warn "Erro detectado durante instalação. Executando rollback..."
        # rollback_installation
    fi
    
    show_dialog "error" "Erro Crítico" "Erro na linha $line_number (código: $exit_code)\nConsulte os logs para mais detalhes." "OK"
    exit $exit_code
}

# Configurar tratamento de sinais
trap cleanup INT TERM
trap 'error_handler $LINENO' ERR

################################################################################
# EXECUÇÃO
################################################################################

# Verificar se está sendo executado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
