#!/bin/bash
# Script para corrigir o dashboard - porta 80 e conflitos

echo "=== CORRIGINDO DASHBOARD ==="

# 1. Executar função de instalação do dashboard
echo "1. Reinstalando dashboard com correções..."
cd /media/flavio/01DAC199049658D0/BOXSERVER

# Carregar funções do script
source install.sh

# 2. Reinstalar o dashboard
echo "2. Reinstalando dashboard..."
install_dashboard

# 3. Verificar status
echo "3. Verificando status..."
systemctl status dashboard-api --no-pager

# 4. Testar acesso
echo "4. Testando acesso local..."
sleep 3
curl -s http://localhost | head -5

echo ""
echo "=== DASHBOARD CONFIGURADO ==="
echo "Acesse: http://$(hostname -I | awk '{print $1}')"
echo "Porta: 80"
