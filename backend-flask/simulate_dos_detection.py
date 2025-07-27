#!/usr/bin/env python3
"""
Script pour simuler et détecter une attaque DoS en temps réel
"""

import json
import time
import psutil
import socket
from datetime import datetime
from pathlib import Path
import sys
import os

# Ajouter le chemin du module app
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.model.ai_model import predict_intrusion
from app.utils.preprocessing import extract_features, normalize_features

class DOSDetector:
    def __init__(self):
        self.data_file = Path(__file__).parent / 'app' / 'data' / 'network_data.json'
        self.dos_threshold = 20  # Nombre de connexions pour déclencher une alerte DoS
        self.connection_history = {}  # Historique des connexions par IP
        
    def detect_dos_attack(self, connections):
        """Détecte une attaque DoS basée sur le nombre de connexions"""
        ip_connections = {}
        
        # Compter les connexions par IP source
        for conn in connections:
            if conn.laddr and conn.laddr.ip:
                source_ip = conn.laddr.ip
                if source_ip not in ip_connections:
                    ip_connections[source_ip] = 0
                ip_connections[source_ip] += 1
        
        # Détecter les IPs avec trop de connexions
        dos_ips = []
        for ip, count in ip_connections.items():
            if count > self.dos_threshold:
                dos_ips.append((ip, count))
                print(f"🚨 ATTENTION: IP {ip} a {count} connexions (seuil: {self.dos_threshold})")
        
        return dos_ips
    
    def analyze_connection(self, conn):
        """Analyse une connexion individuelle"""
        try:
            # Extraire les informations de connexion
            source_ip = conn.laddr.ip if conn.laddr else '0.0.0.0'
            dest_ip = conn.raddr.ip if conn.raddr else '0.0.0.0'
            source_port = conn.laddr.port if conn.laddr else 0
            dest_port = conn.raddr.port if conn.raddr else 0
            
            # Déterminer le protocole
            if hasattr(conn, 'type'):
                if conn.type == socket.SOCK_STREAM:
                    protocol = 'tcp'
                elif conn.type == socket.SOCK_DGRAM:
                    protocol = 'udp'
                else:
                    protocol = 'other'
            else:
                protocol = 'other'
            
            # Préparer les données pour l'analyse
            connection_data = {
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'source_port': source_port,
                'dest_port': dest_port,
                'protocol': protocol,
                'status': conn.status if hasattr(conn, 'status') else 'NONE',
                'timestamp': datetime.now().isoformat(),
                'connections_count': 1  # À ajuster selon le contexte
            }
            
            # Analyser avec le modèle d'IA
            is_intrusion, attack_type, confidence = predict_intrusion(connection_data)
            
            return {
                'source_ip': source_ip,
                'dest_ip': dest_ip,
                'source_port': source_port,
                'dest_port': dest_port,
                'protocol': protocol,
                'status': conn.status if hasattr(conn, 'status') else 'NONE',
                'timestamp': datetime.now().isoformat(),
                'attackType': attack_type,
                'severity': 'high' if is_intrusion else 'low',
                'confidence': confidence
            }
            
        except Exception as e:
            print(f"Erreur lors de l'analyse de la connexion: {e}")
            return None
    
    def update_network_data(self, new_connections, dos_ips):
        """Met à jour le fichier de données réseau"""
        try:
            # Lire les données existantes
            if self.data_file.exists():
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
            else:
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
            
            # Ajouter les nouvelles connexions
            data['connections'].extend(new_connections)
            
            # Garder seulement les 100 dernières connexions
            data['connections'] = data['connections'][-100:]
            
            # Créer des alertes pour les attaques DoS détectées
            for ip, count in dos_ips:
                alert = {
                    'id': len(data['alerts']) + 1,
                    'sourceIp': ip,
                    'destinationIp': 'Multiple',
                    'protocol': 'tcp',
                    'timestamp': datetime.now().isoformat(),
                    'attackType': 'DoS',
                    'severity': 'high',
                    'confidence': min(count / 100.0, 0.95)  # Confiance basée sur le nombre de connexions
                }
                data['alerts'].append(alert)
                print(f"🚨 ALERTE DoS créée pour {ip} avec {count} connexions")
            
            # Garder seulement les 50 dernières alertes
            data['alerts'] = data['alerts'][-50:]
            
            # Mettre à jour les statistiques
            data['stats']['total_connections'] = len(data['connections'])
            data['stats']['total_alerts'] = len(data['alerts'])
            data['stats']['active_threats'] = len([a for a in data['alerts'] if a['severity'] == 'high'])
            
            # Sauvegarder les données
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"✅ Données mises à jour: {len(new_connections)} connexions, {len(dos_ips)} attaques DoS détectées")
            
        except Exception as e:
            print(f"Erreur lors de la mise à jour des données: {e}")
    
    def monitor_network(self, duration=60):
        """Surveille le réseau pendant une durée donnée"""
        print(f"🔍 Surveillance du réseau pendant {duration} secondes...")
        print("Lancez votre attaque DoS maintenant!")
        
        start_time = time.time()
        scan_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Obtenir les connexions réseau
                connections = psutil.net_connections()
                
                # Détecter les attaques DoS
                dos_ips = self.detect_dos_attack(connections)
                
                # Analyser les connexions
                new_connections = []
                for conn in connections[:50]:  # Limiter à 50 connexions pour éviter la surcharge
                    analyzed = self.analyze_connection(conn)
                    if analyzed:
                        new_connections.append(analyzed)
                
                # Mettre à jour les données
                self.update_network_data(new_connections, dos_ips)
                
                scan_count += 1
                print(f"Scan #{scan_count}: {len(connections)} connexions détectées")
                
                # Attendre 2 secondes avant le prochain scan
                time.sleep(2)
                
            except KeyboardInterrupt:
                print("\n⏹️ Surveillance arrêtée par l'utilisateur")
                break
            except Exception as e:
                print(f"Erreur lors de la surveillance: {e}")
                time.sleep(2)
        
        print(f"✅ Surveillance terminée après {scan_count} scans")

def main():
    """Fonction principale"""
    print("🚨 Détecteur d'attaques DoS")
    print("=" * 40)
    
    detector = DOSDetector()
    
    # Démarrer la surveillance
    detector.monitor_network(duration=120)  # 2 minutes
    
    print("\n📊 Résumé:")
    print("Vérifiez le fichier network_data.json pour voir les alertes générées")
    print("Le frontend devrait maintenant afficher les alertes DoS")

if __name__ == "__main__":
    main() 