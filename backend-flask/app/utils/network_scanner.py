#!/usr/bin/env python3
"""
Scanner réseau amélioré avec détection IA corrigée pour DoS/Probe
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
from app.utils.preprocessing import preprocess_data, create_dos_test_data, create_probe_test_data

class NetworkScanner:
    def __init__(self, interface=None):
        self.interface = interface
        if self.interface:
            logger.info(f"[NetworkScanner] Interface réseau sélectionnée : {self.interface}")
        self.data_file = Path(__file__).parent.parent / 'data' / 'network_data.json'
        self._initialize_data()
        self.no_connection_cycles = 0
        self.max_no_connection_cycles = 5
        self.dos_threshold = 50  # Seuil réduit pour détecter plus tôt
        self.probe_threshold = 10  # Seuil pour port scan
        self.running = False
        self.connection_history = {}  # Historique pour analyse temporelle
        
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
    
    def test_ai_model(self):
        """NOUVEAU - Teste le modèle IA avec des données connues"""
        logger.info("🧪 Test du modèle IA...")
        
        # Test DoS
        dos_data = create_dos_test_data(200, 80)
        logger.info(f"🔥 Test DoS: {dos_data}")
        processed_dos = preprocess_data(dos_data)
        is_intrusion, attack_type, confidence = predict_intrusion(processed_dos)
        logger.info(f"Résultat DoS: intrusion={is_intrusion}, type={attack_type}, conf={confidence}")
        
        # Test Probe
        probe_data = create_probe_test_data(25, 22)
        logger.info(f"🔍 Test Probe: {probe_data}")
        processed_probe = preprocess_data(probe_data)
        is_intrusion, attack_type, confidence = predict_intrusion(processed_probe)
        logger.info(f"Résultat Probe: intrusion={is_intrusion}, type={attack_type}, conf={confidence}")
    
    def analyze_connection_patterns(self, connections):
        """
        NOUVEAU - Analyse intelligente des patterns de connexion
        """
        # Grouper les connexions par IP source
        ip_analysis = {}
        port_analysis = {}
        
        current_time = time.time()
        
        for conn in connections:
            if not (conn.laddr and conn.raddr):
                continue
                
            try:
                source_ip = conn.raddr.ip
                dest_ip = conn.laddr.ip
                dest_port = conn.laddr.port
                
                # Ignorer les connexions locales/internes
                if (source_ip in ['127.0.0.1', '0.0.0.0', '::1'] or
                    dest_ip in ['127.0.0.1', '0.0.0.0', '::1']):
                    continue
                
                # Analyser par IP source
                key = f"{source_ip}->{dest_ip}"
                if key not in ip_analysis:
                    ip_analysis[key] = {
                        'source_ip': source_ip,
                        'dest_ip': dest_ip,
                        'connections': 0,
                        'ports': set(),
                        'status_counts': {},
                        'first_seen': current_time
                    }
                
                ip_analysis[key]['connections'] += 1
                ip_analysis[key]['ports'].add(dest_port)
                
                # Compter les statuts
                status = getattr(conn, 'status', 'UNKNOWN')
                if status not in ip_analysis[key]['status_counts']:
                    ip_analysis[key]['status_counts'][status] = 0
                ip_analysis[key]['status_counts'][status] += 1
                
            except (AttributeError, ValueError) as e:
                continue
        
        return ip_analysis
    
    def create_attack_data_for_ai(self, source_ip, dest_ip, analysis):
        """
        NOUVEAU - Crée des données structurées pour l'analyse IA
        """
        connections_count = analysis['connections']
        ports = analysis['ports']
        status_counts = analysis['status_counts']
        
        # Déterminer le port principal et le flag principal
        if ports:
            dest_port = min(ports)  # Port le plus bas (souvent le premier ciblé)
        else:
            dest_port = 80
        
        # Déterminer le flag basé sur les statuts et le pattern
        if 'ESTABLISHED' in status_counts:
            flag = 'SF'  # Connexion réussie
        elif (status_counts.get('SYN_SENT', 0) > 10 and len(ports) == 1):
            flag = 'S0'  # SYN flood (DoS) sur un port unique
        elif (len(ports) > 10 and status_counts.get('SYN_SENT', 0) > 5):
            flag = 'S1'  # Port scan (SYN sur beaucoup de ports)
        elif 'TIME_WAIT' in status_counts:
            flag = 'SF'  # Connexion fermée normalement
        else:
            flag = 'REJ'  # Probablement rejeté
        
        # Estimer les bytes basés sur le nombre de connexions
        bytes_sent = connections_count * 64  # Estimation conservative
        
        # Calculer les taux d'erreur basés sur les patterns
        total_conns = sum(status_counts.values())
        error_conns = status_counts.get('SYN_SENT', 0) + status_counts.get('TIME_WAIT', 0)
        serror_rate = error_conns / total_conns if total_conns > 0 else 0.0
        
        return {
            'source_ip': source_ip,
            'destination_ip': dest_ip,
            'connections_count': connections_count,
            'dest_port': dest_port,
            'protocol': 'tcp',
            'flag': flag,
            'bytes_sent': bytes_sent,
            'bytes_received': 0,
            'duration': 0,
            'serror_rate': min(serror_rate, 1.0),
            'srv_serror_rate': min(serror_rate, 1.0),
            'rerror_rate': 0.1,
            'srv_rerror_rate': 0.1,
            'port_count': len(ports),
            'status_pattern': dict(status_counts)
        }
    
    def save_alert_with_ai_info(self, source_ip, dest_ip, attack_type, confidence, extra_info=None):
        """NOUVEAU - Sauvegarde une alerte avec informations IA"""
        try:
            data = self._load_data()
            
            alert = {
                'id': int(time.time() * 1000),  # ID unique basé sur timestamp
                'sourceIp': source_ip,
                'destinationIp': dest_ip,
                'protocol': 'tcp',
                'timestamp': datetime.now().isoformat(),
                'attackType': attack_type,
                'severity': 'high' if attack_type == 'DoS' else 'medium',
                'confidence': confidence,
                'detectionMethod': 'AI + Rules',
                'extraInfo': extra_info or {}
            }
            
            data['alerts'].append(alert)
            data['alerts'] = data['alerts'][-20:]  # Garder les 20 dernières
            
            # Mettre à jour les stats
            if 'stats' not in data:
                data['stats'] = {}
            data['stats']['total_alerts'] = len(data['alerts'])
            data['stats']['active_threats'] = len([a for a in data['alerts'] if a['severity'] == 'high'])
            data['stats']['last_update'] = datetime.now().isoformat()
            # Correction : incrémenter total_connections et calculer detection_rate
            data['stats']['total_connections'] = data['stats'].get('total_connections', 0) + (extra_info.get('connections_count', 0) if extra_info else 0)
            if data['stats']['total_connections'] > 0:
                data['stats']['detection_rate'] = round(data['stats']['total_alerts'] / data['stats']['total_connections'] * 100, 2)
            else:
                data['stats']['detection_rate'] = 0.0
            
            self._save_data(data)
            
            logger.info(f"🚨 ALERTE {attack_type}: {source_ip} -> {dest_ip} (confiance: {confidence:.2f})")
            
        except Exception as e:
            logger.error(f"Erreur sauvegarde alerte: {e}")
    
    def _run_scanner(self):
        """
        VERSION CORRIGÉE - Scanner principal avec IA améliorée
        """
        try:
            logger.info("🔍 Début du scan réseau avec IA...")
            
            # Obtenir les connexions réseau
            connections = psutil.net_connections()

            # DEBUG: Log toutes les connexions détectées
            for conn in connections:
                try:
                    if conn.laddr and conn.raddr:
                        logger.info(f"[DEBUG] Connexion: {conn.raddr.ip} -> {conn.laddr.ip}:{conn.laddr.port} (status={getattr(conn, 'status', 'UNKNOWN')})")
                except Exception:
                    pass
            
            if not connections:
                logger.info("Aucune connexion détectée")
                return
            
            # Analyser les patterns de connexion
            ip_analysis = self.analyze_connection_patterns(connections)
            
            if not ip_analysis:
                logger.info("Aucune connexion externe détectée")
                return
            
            logger.info(f"📊 Analyse: {len(ip_analysis)} pairs IP détectées")
            
            # Analyser chaque pair IP avec l'IA
            for key, analysis in ip_analysis.items():
                source_ip = analysis['source_ip']
                dest_ip = analysis['dest_ip']
                connections_count = analysis['connections']
                port_count = len(analysis['ports'])
                
                logger.info(f"🔍 Analyse {source_ip} -> {dest_ip}: {connections_count} conn, {port_count} ports")
                
                # Filtrer les connexions trop faibles
                if connections_count < 3:
                    continue
                
                # Créer des données pour l'IA
                attack_data = self.create_attack_data_for_ai(source_ip, dest_ip, analysis)
                
                # Analyser avec l'IA
                try:
                    processed_data = preprocess_data(attack_data)
                    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
                    
                    logger.info(f"🤖 IA Résultat: intrusion={is_intrusion}, type={attack_type}, conf={confidence:.3f}")
                    
                    # Sauvegarder l'alerte si intrusion détectée
                    if is_intrusion and attack_type != "Normal":
                        extra_info = {
                            'connections_count': connections_count,
                            'port_count': port_count,
                            'ports': list(analysis['ports'])[:10],  # Max 10 ports pour éviter overflow
                            'status_pattern': analysis['status_counts']
                        }
                        
                        self.save_alert_with_ai_info(
                            source_ip, dest_ip, attack_type, confidence, extra_info
                        )
                        
                        # Log détaillé
                        logger.info(f"🎯 DÉTECTION {attack_type}:")
                        logger.info(f"   Source: {source_ip}")
                        logger.info(f"   Destination: {dest_ip}")
                        logger.info(f"   Connexions: {connections_count}")
                        logger.info(f"   Ports: {port_count}")
                        logger.info(f"   Confiance: {confidence:.3f}")
                    
                except Exception as e:
                    logger.error(f"❌ Erreur analyse IA pour {source_ip}: {e}")
                    
                    # Fallback sur règles simples
                    if connections_count > 100:
                        self.save_alert_with_ai_info(source_ip, dest_ip, "DoS", 0.7)
                    elif connections_count > 10 and port_count > 5:
                        self.save_alert_with_ai_info(source_ip, dest_ip, "Probe", 0.6)
            
            logger.info("✅ Scan terminé")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'exécution du scanner: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
    
    def start(self):
        """Démarre le scanner réseau avec IA corrigée"""
        logger.info("🚀 Démarrage du scanner réseau avec IA CORRIGÉE...")
        logger.info("🤖 Détection: IA + Règles pour DoS/Probe/R2L/U2R")
        logger.info("🔧 Seuils: DoS=0.6, Probe=0.5 (plus sensibles)")
        logger.info("📊 Analyse: Patterns de connexion + Features NSL-KDD")
        
        # Test initial du modèle IA
        self.test_ai_model()
        
        self.running = True
        while self.running:
            self._run_scanner()
            time.sleep(3)  # Scanner toutes les 3 secondes
    
    def stop(self):
        """Arrête le scanner"""
        self.running = False
        logger.info("🛑 Scanner arrêté")

# Instance globale du scanner
scanner = NetworkScanner()

if __name__ == "__main__":
    try:
        scanner = NetworkScanner()
        scanner.start()
    except KeyboardInterrupt:
        print("\n🛑 Arrêt du scanner...")
        scanner.stop()
    except Exception as e:
        logger.error(f"❌ Erreur fatale: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")