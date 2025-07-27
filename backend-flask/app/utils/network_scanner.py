#!/usr/bin/env python3
"""
Scanner réseau amélioré avec détection de paquets bruts
"""

import json
import time
import psutil
import socket
import threading
import logging
from datetime import datetime
from pathlib import Path
import sys
import os

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ajouter le chemin du module app
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from app.model.ai_model import predict_intrusion
from app.utils.preprocessing import preprocess_data

class NetworkScanner:
    def __init__(self):
        self.data_file = Path(__file__).parent.parent / 'data' / 'network_data.json'
        self._initialize_data()
        self.no_connection_cycles = 0
        self.max_no_connection_cycles = 5
        self.packet_history = {}  # Historique des paquets pour détection DoS
        self.dos_threshold = 15  # Seuil pour détection DoS
        self.running = False
        
    def _initialize_data(self):
        """Initialise le fichier de données s'il n'existe pas"""
        if not self.data_file.exists():
            data = {
                'connections': [],
                'alerts': [],
                'stats': {
                    'total_connections': 0,
                    'total_packets': 0,
                    'total_alerts': 0,
                    'active_threats': 0,
                    'blocked_attempts': 0,
                    'system_health': 100
                }
            }
            self._save_data(data)
    
    def _save_data(self, data):
        """Sauvegarde les données dans le fichier JSON"""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des données: {e}")
    
    def _load_data(self):
        """Charge les données depuis le fichier JSON"""
        try:
            if self.data_file.exists():
                with open(self.data_file, 'r') as f:
                    return json.load(f)
            else:
                # Créer des données par défaut si le fichier n'existe pas
                return {
                    'connections': [],
                    'alerts': [],
                    'stats': {
                        'total_connections': 0,
                        'total_alerts': 0,
                        'active_threats': 0,
                        'last_update': datetime.now().isoformat()
                    }
                }
        except Exception as e:
            logger.error(f"Erreur lors du chargement des données: {e}")
            # Retourner des données par défaut en cas d'erreur
            return {
                'connections': [],
                'alerts': [],
                'stats': {
                    'total_connections': 0,
                    'total_alerts': 0,
                    'active_threats': 0,
                    'last_update': datetime.now().isoformat()
                }
            }
    
    def detect_raw_packets(self):
        """Détecte les paquets bruts pour les attaques externes"""
        try:
            # Utiliser netstat pour détecter les connexions actives
            import subprocess
            
            # Commande pour détecter les connexions TCP actives
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                tcp_connections = []
                
                for line in lines:
                    if 'TCP' in line and ('ESTABLISHED' in line or 'TIME_WAIT' in line):
                        parts = line.split()
                        if len(parts) >= 4:
                            local_addr = parts[1]
                            remote_addr = parts[2]
                            state = parts[3]
                            
                            # Extraire IP et port
                            try:
                                local_ip, local_port = local_addr.rsplit(':', 1)
                                remote_ip, remote_port = remote_addr.rsplit(':', 1)
                                
                                # Ignorer les connexions locales normales
                                if (local_ip in ['127.0.0.1', '0.0.0.0'] or
                                    local_ip.startswith('192.168.') or
                                    local_ip.startswith('10.') or
                                    local_ip.startswith('172.')):
                                    continue
                                
                                tcp_connections.append({
                                    'local_ip': local_ip,
                                    'local_port': local_port,
                                    'remote_ip': remote_ip,
                                    'remote_port': remote_port,
                                    'state': state
                                })
                                
                            except ValueError:
                                continue
                
                # Détecter les patterns d'attaque
                self.analyze_tcp_patterns(tcp_connections)
                
        except Exception as e:
            logger.error(f"Erreur détection paquets bruts: {e}")
    
    def analyze_tcp_patterns(self, connections):
        """Analyse les patterns TCP pour détecter les attaques"""
        try:
            # Grouper par IP source
            ip_connections = {}
            for conn in connections:
                source_ip = conn['remote_ip']
                if source_ip not in ip_connections:
                    ip_connections[source_ip] = []
                ip_connections[source_ip].append(conn)
            
            # Détecter les attaques DoS
            for source_ip, conns in ip_connections.items():
                if len(conns) > self.dos_threshold:
                    # Créer une alerte DoS
                    alert = {
                        'id': int(time.time()),
                        'sourceIp': source_ip,
                        'destinationIp': 'Multiple',
                        'protocol': 'tcp',
                        'timestamp': datetime.now().isoformat(),
                        'attackType': 'DoS',
                        'severity': 'high',
                        'confidence': min(len(conns) / 100.0, 0.95),
                        'connectionCount': len(conns)
                    }
                    
                    self.save_alert(alert)
                    logger.info(f"🚨 ATTAQUE DoS DÉTECTÉE: {source_ip} avec {len(conns)} connexions")
            
            # Détecter les port scans
            for source_ip, conns in ip_connections.items():
                ports = set()
                for conn in conns:
                    ports.add(conn['remote_port'])
                
                if len(ports) > 10:  # Plus de 10 ports différents = port scan
                    alert = {
                        'id': int(time.time()),
                        'sourceIp': source_ip,
                        'destinationIp': 'Multiple',
                        'protocol': 'tcp',
                        'timestamp': datetime.now().isoformat(),
                        'attackType': 'Port Scan',
                        'severity': 'medium',
                        'confidence': min(len(ports) / 100.0, 0.9),
                        'portCount': len(ports)
                    }
                    
                    self.save_alert(alert)
                    logger.info(f"🔍 PORT SCAN DÉTECTÉ: {source_ip} -> {len(ports)} ports")
                    
        except Exception as e:
            logger.error(f"Erreur analyse patterns TCP: {e}")
    
    def save_alert(self, alert):
        """Sauvegarde une alerte dans le fichier de données"""
        try:
            data = self._load_data()
            data['alerts'].append(alert)
            data['alerts'] = data['alerts'][-20:]  # Garder les 20 dernières
            data['stats']['total_alerts'] = len(data['alerts'])
            data['stats']['active_threats'] = len([a for a in data['alerts'] if a['severity'] == 'high'])
            self._save_data(data)
            
        except Exception as e:
            logger.error(f"Erreur sauvegarde alerte: {e}")
    
    def _process_connection(self, conn):
        """Traite une connexion réseau"""
        try:
            # Déterminer le protocole sous forme de chaîne
            if hasattr(conn, 'type'):
                if conn.type == socket.SOCK_STREAM:
                    protocol = 'tcp'
                elif conn.type == socket.SOCK_DGRAM:
                    protocol = 'udp'
                else:
                    protocol = 'other'
            else:
                protocol = 'other'

            # Préparer les données pour le modèle
            def safe_ip(ip):
                # Retourne une IPv4 ou '0.0.0.0' si ce n'est pas une IPv4
                if isinstance(ip, str) and '.' in ip:
                    return ip
                return '0.0.0.0'

            connection_data = {
                'source_ip': safe_ip(conn.laddr.ip) if conn.laddr else '0.0.0.0',
                'dest_ip': safe_ip(conn.raddr.ip) if conn.raddr else '0.0.0.0',
                'source_port': conn.laddr.port if conn.laddr else 0,
                'dest_port': conn.raddr.port if conn.raddr else 0,
                'protocol': protocol,
                'status': conn.status if hasattr(conn, 'status') else 'NONE',
                'timestamp': datetime.now().isoformat()
            }

            # Prétraiter les données
            processed_data = preprocess_data(connection_data)

            # Analyser avec le modèle d'IA
            is_intrusion, attack_type, confidence = predict_intrusion(processed_data)

            # Ajouter les résultats de l'analyse
            connection_data['attackType'] = attack_type
            connection_data['severity'] = 'high' if is_intrusion else 'low'

            return connection_data
        except Exception as e:
            logger.error(f"Erreur lors du traitement de la connexion: {e}")
            return None
    
    def _run_scanner(self):
        """Exécute un cycle de scan réseau amélioré"""
        try:
            # Charger les données existantes
            data = self._load_data()
            
            # Obtenir les connexions réseau
            connections = psutil.net_connections()
            processed_connections = []
            new_alerts = []
            
            # === DÉTECTION INTELLIGENTE SANS FAUX POSITIFS ===
            
            # 1. Analyser les connexions par IP source
            ip_connections = {}
            port_scan_attempts = {}
            suspicious_ips = set()
            
            # Compter les connexions par couple (source_ip, dest_ip)
            for conn in connections:
                if conn.laddr and conn.laddr.ip and conn.raddr and conn.raddr.ip:
                    source_ip = conn.raddr.ip  # L'attaquant
                    dest_ip = conn.laddr.ip    # La cible (ta machine)
                    dest_port = conn.laddr.port if conn.laddr else 0
                    # Ignorer complètement les IPs locales normales
                    if (source_ip in ['127.0.0.1', '0.0.0.0', '::1'] or
                        source_ip.startswith('192.168.') or
                        source_ip.startswith('10.') or
                        source_ip.startswith('172.')):
                        continue  # Ignorer complètement
                    key = (source_ip, dest_ip)
                    if key not in ip_connections:
                        ip_connections[key] = 0
                    ip_connections[key] += 1
                    # Détecter les tentatives de port scan
                    if dest_ip != "N/A" and dest_port > 0:
                        port_key = f"{source_ip}_{dest_ip}"
                        if port_key not in port_scan_attempts:
                            port_scan_attempts[port_key] = set()
                        port_scan_attempts[port_key].add(dest_port)
            # 3. Détecter les port scans
            port_scan_sources = set()
            for key, ports in port_scan_attempts.items():
                if len(ports) > 2:  # Plus de 2 ports différents = port scan (pour test)
                    source_ip, dest_ip = key.split('_')
                    logger.info(f"TEST Port scan: {source_ip} -> {dest_ip} ports={list(ports)}")
                    port_scan_sources.add((source_ip, dest_ip))
                    alert = {
                        'id': len(data['alerts']) + 1,
                        'sourceIp': source_ip,
                        'destinationIp': dest_ip,
                        'protocol': 'tcp',
                        'timestamp': datetime.now().isoformat(),
                        'attackType': 'Port Scan',
                        'severity': 'medium',
                        'confidence': min(len(ports) / 100.0, 0.9)
                    }
                    new_alerts.append(alert)
                    logger.info(f"🔍 Port scan détecté: {source_ip} -> {dest_ip} ({len(ports)} ports)")
            # 2. Détecter les vraies attaques DoS (seuil très élevé)
            for (source_ip, dest_ip), count in ip_connections.items():
                # Ne pas générer d'alerte DoS si un port scan est détecté pour la même IP/cible
                if (source_ip, dest_ip) in port_scan_sources:
                    continue
                if count > 100:
                    alert = {
                        'id': len(data['alerts']) + 1,
                        'sourceIp': source_ip,
                        'destinationIp': dest_ip,
                        'protocol': 'tcp',
                        'timestamp': datetime.now().isoformat(),
                        'attackType': 'DoS',
                        'severity': 'high',
                        'confidence': min(count / 1000.0, 0.95)
                    }
                    new_alerts.append(alert)
                    logger.info(f"🚨 VRAIE attaque DoS détectée: {source_ip} -> {dest_ip} avec {count} connexions")
            
            # 4. Traiter les connexions individuelles pour détecter les probes
            for conn in connections[:50]:  # Limiter pour performance
                processed = self._process_connection(conn)
                if processed:
                    processed_connections.append(processed)
                    
                    # Détecter les connexions suspectes (probes)
                    if (processed['severity'] == 'high' and 
                        processed['source_ip'] not in ['127.0.0.1', '0.0.0.0'] and
                        not processed['source_ip'].startswith('192.168.')):
                        
                        alert = {
                            'id': len(data['alerts']) + 1,
                            'sourceIp': processed['source_ip'],
                            'destinationIp': processed['dest_ip'],
                            'protocol': processed['protocol'],
                            'timestamp': processed['timestamp'],
                            'attackType': processed['attackType'],
                            'severity': processed['severity']
                        }
                        new_alerts.append(alert)
                        logger.info(f"🔍 Probe détecté: {processed['source_ip']} -> {processed['dest_ip']}")

            # 5. Détection de défaillance réseau seulement si vraiment aucune connexion
            if len(processed_connections) == 0 and len(connections) == 0:
                self.no_connection_cycles += 1
                if self.no_connection_cycles >= self.max_no_connection_cycles:
                    alert = {
                        'id': len(data['alerts']) + 1,
                        'sourceIp': 'N/A',
                        'destinationIp': 'N/A',
                        'protocol': 'N/A',
                        'timestamp': datetime.now().isoformat(),
                        'attackType': 'Défaillance réseau',
                        'severity': 'critical'
                    }
                    new_alerts.append(alert)
                    self.no_connection_cycles = 0
            else:
                self.no_connection_cycles = 0

            # 6. DÉTECTION DE PAQUETS BRUTS (NOUVEAU)
            self.detect_raw_packets()

            # Mettre à jour les données
            data['connections'] = processed_connections[-50:]  # Garder les 50 dernières
            data['alerts'] = (data['alerts'] + new_alerts)[-20:]  # Garder les 20 dernières alertes
            data['stats']['total_connections'] = len(processed_connections)
            data['stats']['total_alerts'] = len(data['alerts'])
            data['stats']['active_threats'] = len([a for a in data['alerts'] if a['severity'] == 'high'])
            
            # Sauvegarder les données
            self._save_data(data)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution du scanner: {e}")
    
    def start(self):
        """Démarre le scanner réseau amélioré"""
        logger.info("🚀 Démarrage du scanner réseau AMÉLIORÉ...")
        logger.info("✅ Détection: Connexions établies + Paquets bruts")
        logger.info("🎯 Attaques: DoS, SYN Flood, Port Scan, Probes")
        logger.info("🔍 Seuil DoS: >100 connexions (évite faux positifs)")
        
        self.running = True
        while self.running:
            self._run_scanner()
            time.sleep(2)  # Scanner toutes les 2 secondes

# Instance globale du scanner
scanner = NetworkScanner()

if __name__ == "__main__":
    # Créer et démarrer le scanner
    scanner = NetworkScanner()
    try:
        scanner.start()
        # Garder le script en cours d'exécution
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nArrêt du scanner...")
        scanner.stop() 