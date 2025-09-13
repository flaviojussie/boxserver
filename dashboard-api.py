#!/usr/bin/env python3
"""
BoxServer Dashboard API
Monitoramento inteligente de serviços em tempo real
"""

import subprocess
import json
import socket
import requests
import os
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import threading
import time
import logging

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/dashboard-api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ServiceMonitor:
    def __init__(self):
        self.services = {
            'pihole': {
                'name': 'Pi-hole',
                'port': 8090,
                'service': 'pihole-FTL',
                'icon': 'fas fa-shield-alt',
                'description': 'Bloqueador de anúncios e rastreadores em toda a rede',
                'url': 'http://{{BOXSERVER_IP}}:8090/admin/'
            },
            'filebrowser': {
                'name': 'FileBrowser',
                'port': 8082,
                'service': 'filebrowser',
                'icon': 'fas fa-folder-open',
                'description': 'Gerenciador de arquivos web intuitivo',
                'url': 'http://{{BOXSERVER_IP}}:8082/'
            },
            'samba': {
                'name': 'Samba',
                'port': 445,
                'service': 'smbd',
                'icon': 'fas fa-share-alt',
                'description': 'Compartilhamento de arquivos na rede local',
                'url': '\\\\{{BOXSERVER_IP}}\\shared'
            },
            'nginx': {
                'name': 'Nginx Dashboard',
                'port': 80,
                'service': 'nginx',
                'icon': 'fas fa-tachometer-alt',
                'description': 'Dashboard principal do servidor',
                'url': 'http://{{BOXSERVER_IP}}/'
            },
            'qbittorrent': {
                'name': 'qBittorrent',
                'port': 9091,
                'service': 'qbittorrent',
                'icon': 'fas fa-download',
                'description': 'Cliente BitTorrent rápido e leve',
                'url': 'http://{{BOXSERVER_IP}}:9091/'
            },
            'syncthing': {
                'name': 'Syncthing',
                'port': 8384,
                'service': 'syncthing',
                'icon': 'fas fa-sync-alt',
                'description': 'Sincronização contínua de arquivos',
                'url': 'http://{{BOXSERVER_IP}}:8384/'
            },
            'wireguard': {
                'name': 'WireGuard-UI',
                'port': 5000,
                'service': 'wireguard-ui',
                'icon': 'fas fa-shield-virus',
                'description': 'Interface web moderna para gerenciamento VPN',
                'url': 'http://{{BOXSERVER_IP}}:5000'
            }
        }
        logger.info(f"Monitor inicializado com {len(self.services)} serviços")

    def check_service_status(self, service_name):
        service = self.services.get(service_name)
        if not service:
            return None

        status = {
            'name': service['name'],
            'icon': service['icon'],
            'description': service['description'],
            'url': service['url'],
            'status': 'offline',
            'response_time': None,
            'cpu': None,
            'memory': None
        }

        try:
            # Verificar se o serviço systemd está rodando
            systemctl_result = subprocess.run(
                ['systemctl', 'is-active', service['service']],
                capture_output=True, text=True, timeout=5
            )
            service_running = systemctl_result.stdout.strip() == 'active'
            logger.debug(f"Serviço {service_name} systemd: {service_running}")
        except Exception as e:
            service_running = False
            logger.debug(f"Erro ao verificar systemd para {service_name}: {e}")

        try:
            # Verificar se a porta está respondendo
            port_open = False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', service['port']))
            port_open = result == 0
            sock.close()
            logger.debug(f"Porta {service['port']} para {service_name}: {'aberta' if port_open else 'fechada'}")
        except Exception as e:
            port_open = False
            logger.debug(f"Erro ao verificar porta {service['port']} para {service_name}: {e}")

        # Para serviços web, verificar HTTP response
        http_response = False
        if service['port'] in [8090, 8082, 9091, 8384, 5000]:
            try:
                response = requests.get(f"http://127.0.0.1:{service['port']}", timeout=3)
                http_response = response.status_code == 200
                logger.debug(f"HTTP response para {service_name}: {http_response}")
            except Exception as e:
                http_response = False
                logger.debug(f"Erro ao verificar HTTP para {service_name}: {e}")

        # Para WireGuard, verificar também a porta UDP
        udp_response = False
        if service_name == 'wireguard':
            try:
                # Verificar se a interface wg0 existe e está ativa
                result = subprocess.run(['wg', 'show'], capture_output=True, text=True, timeout=5)
                udp_response = 'interface: wg0' in result.stdout.lower()
                logger.debug(f"WireGuard interface status: {udp_response}")
            except Exception as e:
                udp_response = False
                logger.debug(f"Erro ao verificar WireGuard: {e}")

        # Determinar status final
        if service_running and (port_open or http_response or udp_response):
            status['status'] = 'online'
        elif service_running or port_open:
            status['status'] = 'warning'

        # Obter métricas de recursos
        try:
            # Tentar obter processo por nome do serviço
            service_name_clean = service['service'].replace('@*', '')
            ps_result = subprocess.run(
                ['pgrep', '-f', service_name_clean],
                capture_output=True, text=True
            )

            if ps_result.returncode == 0:
                pids = ps_result.stdout.strip().split('\n')
                if pids and pids[0]:
                    pid = pids[0]

                    # Obter uso de CPU e memória do processo
                    ps_stat = subprocess.run(
                        ['ps', '-p', pid, '-o', '%cpu,%mem', '--no-headers'],
                        capture_output=True, text=True
                    )

                    if ps_stat.stdout.strip():
                        cpu_mem = ps_stat.stdout.strip().split()
                        if len(cpu_mem) >= 2:
                            try:
                                status['cpu'] = float(cpu_mem[0])
                                status['memory'] = float(cpu_mem[1])
                                logger.debug(f"Métricas para {service_name}: CPU={status['cpu']}%, MEM={status['memory']}%")
                            except ValueError:
                                pass
        except Exception as e:
            logger.debug(f"Erro ao obter métricas para {service_name}: {e}")

        return status

    def get_system_stats(self):
        try:
            # Uso de CPU
            cpu_usage = "0%"
            try:
                cpu_result = subprocess.run(['top', '-bn1'], capture_output=True, text=True, timeout=5)
                for line in cpu_result.stdout.split('\n'):
                    if 'Cpu(s)' in line and 'us' in line:
                        cpu_parts = line.split()
                        for i, part in enumerate(cpu_parts):
                            if 'us' in part and i > 0:
                                cpu_usage = cpu_parts[i-1].rstrip('%')
                                break
                        break
            except Exception as e:
                logger.error(f"Erro ao obter CPU: {e}")

            # Uso de memória
            memory_info = {'total': 'N/A', 'used': 'N/A', 'free': 'N/A', 'percent': 'N/A'}
            try:
                mem_result = subprocess.run(['free', '-h'], capture_output=True, text=True, timeout=5)
                for line in mem_result.stdout.split('\n'):
                    if line.startswith('Mem:'):
                        parts = line.split()
                        if len(parts) >= 7:
                            memory_info = {
                                'total': parts[1],
                                'used': parts[2],
                                'free': parts[3],
                                'percent': parts[4].rstrip('%')
                            }
                        break
            except Exception as e:
                logger.error(f"Erro ao obter memória: {e}")

            # Temperatura
            temperature = 'N/A'
            try:
                temp_paths = [
                    '/sys/class/thermal/thermal_zone0/temp',
                    '/sys/class/hwmon/hwmon0/temp1_input'
                ]
                for temp_path in temp_paths:
                    if os.path.exists(temp_path):
                        with open(temp_path, 'r') as f:
                            temp = int(f.read().strip()) / 1000
                            temperature = f"{temp:.1f}°C"
                            break
            except Exception as e:
                logger.error(f"Erro ao obter temperatura: {e}")

            # Uptime
            uptime = 'N/A'
            try:
                uptime_result = subprocess.run(['uptime', '-p'], capture_output=True, text=True, timeout=5)
                uptime = uptime_result.stdout.strip().replace('up ', '')
            except Exception as e:
                logger.error(f"Erro ao obter uptime: {e}")

            stats = {
                'cpu': cpu_usage,
                'memory': memory_info,
                'temperature': temperature,
                'uptime': uptime,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            logger.debug(f"Estatísticas do sistema: {stats}")
            return stats

        except Exception as e:
            logger.error(f"Erro crítico ao obter estatísticas do sistema: {e}")
            return {
                'cpu': 'N/A',
                'memory': {'total': 'N/A', 'used': 'N/A', 'free': 'N/A', 'percent': 'N/A'},
                'temperature': 'N/A',
                'uptime': 'N/A',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'error': str(e)
            }

class DashboardAPI(BaseHTTPRequestHandler):
    def __init__(self, *args, monitor=None, **kwargs):
        self.monitor = monitor or ServiceMonitor()
        super().__init__(*args, **kwargs)

    def do_GET(self):
        try:
            if self.path == '/api/services':
                self.send_services_status()
            elif self.path == '/api/system':
                self.send_system_stats()
            elif self.path == '/':
                self.serve_dashboard()
            elif self.path == '/health':
                self.send_health_check()
            else:
                self.send_error(404)
        except Exception as e:
            logger.error(f"Erro ao processar requisição {self.path}: {e}")
            self.send_error(500)

    def send_services_status(self):
        try:
            services_status = {}
            for service_name in self.monitor.services:
                status = self.monitor.check_service_status(service_name)
                if status:
                    services_status[service_name] = status

            logger.info(f"Status de {len(services_status)} serviços enviado")
            self.send_json_response(services_status)
        except Exception as e:
            logger.error(f"Erro ao enviar status dos serviços: {e}")
            self.send_error(500)

    def send_system_stats(self):
        try:
            system_stats = self.monitor.get_system_stats()
            logger.info("Estatísticas do sistema enviadas")
            self.send_json_response(system_stats)
        except Exception as e:
            logger.error(f"Erro ao enviar estatísticas do sistema: {e}")
            self.send_error(500)

    def send_health_check(self):
        health_data = {
            'status': 'healthy',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'services_count': len(self.monitor.services)
        }
        self.send_json_response(health_data)

    def serve_dashboard(self):
        try:
            dashboard_path = '/var/www/html/dashboard.html'
            if not os.path.exists(dashboard_path):
                dashboard_path = '/var/www/html/index.html'

            with open(dashboard_path, 'r') as f:
                dashboard_content = f.read()

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(dashboard_content.encode())
        except Exception as e:
            logger.error(f"Erro ao servir dashboard: {e}")
            self.send_error(500)

    def send_json_response(self, data):
        try:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode())
        except Exception as e:
            logger.error(f"Erro ao enviar resposta JSON: {e}")
            self.send_error(500)

    def log_message(self, format, *args):
        # Silenciar logs do servidor HTTP para evitar poluição
        pass

def run_server():
    monitor = ServiceMonitor()

    def handler(*args, **kwargs):
        DashboardAPI(*args, monitor=monitor, **kwargs)

    try:
        server = HTTPServer(('0.0.0.0', 8081), handler)
        logger.info("Dashboard API Server iniciado em http://0.0.0.0:8081")
        logger.info("Endpoints disponíveis:")
        logger.info("  GET /api/services - Status dos serviços")
        logger.info("  GET /api/system - Estatísticas do sistema")
        logger.info("  GET /health - Health check")
        logger.info("  GET / - Dashboard HTML")

        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Servidor interrompido pelo usuário")
    except Exception as e:
        logger.error(f"Erro fatal no servidor: {e}")
        sys.exit(1)

if __name__ == '__main__':
    run_server()
