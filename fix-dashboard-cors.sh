#!/bin/bash

# =============================================================================
# BoxServer Dashboard CORS/Port Fix Script
# =============================================================================
# Descrição: Script focado em resolver EXCLUSIVAMENTE problemas de CORS
#            e configuração de portas do Dashboard
# =============================================================================

set -euo pipefail

# Configurações
readonly SCRIPT_VERSION="1.0"
readonly SERVER_IP="192.168.0.100"
readonly LOG_FILE="/var/log/dashboard-fix.log"

# Cores
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"
}

show_header() {
    clear
    cat << 'EOF'
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   🔧 BoxServer Dashboard CORS/Port Fix Script v1.0           │
│                                                             │
│   Script focado em resolver problemas de:                    │
│   • Erros de CORS no frontend                               │
│   • Configuração incorreta de portas                        │
│   • NetworkError ao acessar a API                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
EOF
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script deve ser executado como root"
        log_info "Use: sudo $0"
        exit 1
    fi
}

diagnose_current_state() {
    log_step "Diagnosticando estado atual do sistema"

    local issues_found=0

    # Verificar qual API está rodando
    log_info "Verificando serviços Dashboard API..."
    if systemctl is-active --quiet dashboard-api; then
        log_success "✅ Serviço dashboard-api está ativo"

        # Verificar arquivo being used
        local api_file=$(systemctl show dashboard-api.service -p ExecStart | cut -d= -f2)
        log_info "📁 Arquivo da API: $api_file"

        # Verificar porta
        local api_port=$(grep -o "port.*[0-9]*" "$api_file" 2>/dev/null | tail -1 | grep -o '[0-9]*' || echo "desconhecida")
        log_info "🔌 Porta da API: $api_port"

        if [[ "$api_port" != "8081" ]]; then
            log_error "❌ API está rodando na porta $api_port (deveria ser 8081)"
            ((issues_found++))
        fi
    else
        log_warning "⚠️  Serviço dashboard-api não está ativo"
        ((issues_found++))
    fi

    # Verificar frontend
    log_info "Verificando servidor web (frontend)..."
    if systemctl is-active --quiet lighttpd; then
        log_success "✅ Lighttpd está ativo na porta 80"
    elif systemctl is-active --quiet nginx; then
        log_success "✅ Nginx está ativo na porta 80"
    elif systemctl is-active --quiet apache2; then
        log_success "✅ Apache2 está ativo na porta 80"
    else
        log_warning "⚠️  Nenhum servidor web padrão encontrado na porta 80"
        ((issues_found++))
    fi

    # Verificar arquivos
    log_info "Verificando arquivos do Dashboard..."
    if [[ -f "/var/www/html/dashboard.html" ]]; then
        log_success "✅ dashboard.html encontrado"
    else
        log_error "❌ dashboard.html não encontrado"
        ((issues_found++))
    fi

    if [[ -f "/var/www/html/dashboard-api.py" ]]; then
        log_success "✅ dashboard-api.py encontrado"
    else
        log_error "❌ dashboard-api.py não encontrado"
        ((issues_found++))
    fi

    # Testar acesso
    log_info "Testando acesso aos endpoints..."
    if curl -s http://localhost:8081/health 2>/dev/null | grep -q "healthy"; then
        log_success "✅ API na porta 8081 está respondendo"
    else
        log_error "❌ API na porta 8081 não está respondendo"
        ((issues_found++))
    fi

    if [[ $issues_found -eq 0 ]]; then
        log_success "✅ Nenhum problema de CORS/portas detectado"
        return 0
    else
        log_warning "⚠️  $issues_found problemas encontrados que precisam ser corrigidos"
        return 1
    fi
}

fix_api_configuration() {
    log_step "Corrigindo configuração da API"

    # Parar serviço atual
    systemctl stop dashboard-api 2>/dev/null || true

    # Garantir que temos o arquivo API correto
    if [[ ! -f "/var/www/html/dashboard-api.py" ]]; then
        log_error "Arquivo dashboard-api.py não encontrado"
        return 1
    fi

    # Verificar e corrigir porta no arquivo API
    if grep -q "port = 80" /var/www/html/dashboard-api.py; then
        log_info "Corrigindo porta da API de 80 para 8081..."
        sed -i 's/port = 80/port = 8081/g' /var/www/html/dashboard-api.py
        sed -i "s/('', 80)/('', 8081)/g" /var/www/html/dashboard-api.py
        log_success "✅ Porta da API corrigida para 8081"
    fi

    # Garantir permissões corretas
    chown www-data:www-data /var/www/html/dashboard-api.py
    chmod +x /var/www/html/dashboard-api.py

    # Recriar serviço systemd se necessário
    cat > /etc/systemd/system/dashboard-api.service << 'EOF'
[Unit]
Description=BoxServer Dashboard API
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/html
ExecStart=/usr/bin/python3 /var/www/html/dashboard-api.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
MemoryMax=100M
CPUQuota=30%

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dashboard-api

    log_success "✅ Serviço da API reconfigurado"
}

fix_firewall_rules() {
    log_step "Verificando e configurando regras de firewall"

    # Garantir que porta 8081 está aberta
    if command -v ufw &> /dev/null; then
        if ! ufw status | grep -q "8081"; then
            log_info "Adicionando regra de firewall para porta 8081..."
            ufw allow 8081/tcp comment "Dashboard API"
            log_success "✅ Porta 8081 aberta no firewall"
        else
            log_info "✅ Porta 8081 já está aberta no firewall"
        fi
    fi

    # Verificar iptables como fallback
    if ! iptables -L INPUT | grep -q "8081"; then
        log_info "Adicionando regra iptables para porta 8081..."
        iptables -A INPUT -p tcp --dport 8081 -j ACCEPT
        log_success "✅ Regra iptables adicionada"
    fi
}

verify_frontend_configuration() {
    log_step "Verificando configuração do frontend"

    # Garantir que dashboard.html existe e está correto
    if [[ ! -f "/var/www/html/index.html" ]] && [[ -f "/var/www/html/dashboard.html" ]]; then
        log_info "Configurando dashboard.html como página principal..."
        cp /var/www/html/dashboard.html /var/www/html/index.html
        chown www-data:www-data /var/www/html/index.html
        log_success "✅ Dashboard configurado como página principal"
    fi

    # Verificar se o frontend espera a API na porta correta
    if [[ -f "/var/www/html/index.html" ]]; then
        if grep -q ":8081" /var/www/html/index.html; then
            log_success "✅ Frontend configurado para acessar API na porta 8081"
        else
            log_warning "⚠️  Frontend pode não estar configurado para porta 8081"
        fi
    fi
}

restart_services() {
    log_step "Reiniciando serviços"

    # Reiniciar API
    systemctl restart dashboard-api
    sleep 3

    if systemctl is-active --quiet dashboard-api; then
        log_success "✅ Dashboard API reiniciado com sucesso"
    else
        log_error "❌ Falha ao reiniciar Dashboard API"
        return 1
    fi

    # Reiniciar servidor web se necessário
    if systemctl is-active --quiet lighttpd; then
        systemctl restart lighttpd
        log_info "Lighttpd reiniciado"
    elif systemctl is-active --quiet nginx; then
        systemctl restart nginx
        log_info "Nginx reiniciado"
    fi
}

final_verification() {
    log_step "Verificação final"

    local tests_passed=0
    local total_tests=3

    # Testar 1: API health check
    log_info "Test 1: API Health Check"
    if curl -s http://localhost:8081/health | grep -q "healthy"; then
        log_success "✅ API na porta 8081 está funcionando"
        ((tests_passed++))
    else
        log_error "❌ API na porta 8081 não está respondendo"
    fi

    # Testar 2: API services endpoint
    log_info "Test 2: API Services Endpoint"
    if curl -s http://localhost:8081/api/services | grep -q "services"; then
        log_success "✅ Endpoint /api/services está funcionando"
        ((tests_passed++))
    else
        log_error "❌ Endpoint /api/services não está respondendo"
    fi

    # Testar 3: Frontend accessibility
    log_info "Test 3: Frontend Accessibility"
    if curl -s http://localhost:80/ | grep -q "BoxServer Dashboard"; then
        log_success "✅ Frontend está acessível na porta 80"
        ((tests_passed++))
    else
        log_error "❌ Frontend não está acessível na porta 80"
    fi

    echo ""
    if [[ $tests_passed -eq $total_tests ]]; then
        log_success "🎉 TODOS OS TESTES PASSARAM! Problemas de CORS/portas resolvidos."
        echo ""
        echo "📋 Resumo da configuração:"
        echo "   • Frontend (Dashboard): http://${SERVER_IP}/"
        echo "   • API: http://${SERVER_IP}:8081/"
        echo "   • Health Check: http://${SERVER_IP}:8081/health"
        echo ""
        echo "✨ O erro 'NetworkError when attempting to fetch resource' foi corrigido!"
        return 0
    else
        log_error "❌ $((total_tests - tests_passed)) testes falharam"
        log_info "Verifique o log para detalhes: $LOG_FILE"
        return 1
    fi
}

# Função principal
main() {
    show_header
    check_root

    # Criar log
    touch "$LOG_FILE"

    echo "🔍 Iniciando diagnóstico e correção de problemas CORS/portas..."
    echo ""

    # Diagnosticar problemas
    if ! diagnose_current_state; then
        echo ""
        log_step "Iniciando correção dos problemas identificados"

        # Aplicar correções
        fix_api_configuration
        fix_firewall_rules
        verify_frontend_configuration
        restart_services

        echo ""
        log_step "Aplicando correções... Aguarde 5 segundos"
        sleep 5
    else
        echo ""
        log_info "Nenhuma correção necessária, pulando para verificação final..."
        sleep 2
    fi

    # Verificação final
    echo ""
    if final_verification; then
        echo ""
        log_success "🎊 Script concluído com SUCESSO!"
        echo "   Os problemas de CORS e configuração de portas foram resolvidos."
        exit 0
    else
        echo ""
        log_error "❌ Alguns problemas não puderam ser resolvidos automaticamente."
        echo "   Verifique o log: $LOG_FILE"
        exit 1
    fi
}

# Executar função principal
main "$@"