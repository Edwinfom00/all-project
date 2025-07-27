#!/usr/bin/env python3
"""
Détecteur d'attaques DoS compatible Windows utilisant scapy
"""

import json
import time
import threading
from datetime import datetime
from pathlib import Path
import sys
import os
from collections import defaultdict, deque

# Ajouter le chemin du module app
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

try:
    from scapy.all import *
except ImportError:
    print("❌ ERREUR: scapy n'est pas installé!")
    print("   Installez avec: pip install scapy")
    sys.exit(1)

class WindowsDOSDetector:
    def __init__(self):
        self.data_file = Path(__file__).parent / 'app' / 'data' / 'network_data.json'
        self.dos_threshold = 15  # Seuil plus bas pour Windows
        self.packet_history = defaultdict(lambda: deque(maxlen=50))
        self.alert_cooldown = {}
        self.running = False
        
    def packet_callback(self, packet):
        """Callback appelé pour chaque paquet capturé"""
        try:
            if IP in packet and TCP in packet:
                source_ip = packet[IP].src
                dest_ip = packet[IP].dst
                source_port = packet[TCP].sport
                dest_port = packet[TCP].dport
                tcp_flags = packet[TCP].flags
                
                # Détecter les paquets SYN (SYN flood)
                if tcp_flags & 0x02:  # SYN flag
                    self.detect_syn_flood(source_ip, dest_ip, source_port, dest_port)
                
                # Détecter les attaques sur le port 80 (HTTP)
                if dest_port == 80:
                    self.detect_port_flood(source_ip, dest_ip, dest_port)
                    
        except Exception as e:
            pass  # Ignorer les paquets malformés
    
    def detect_syn_flood(self, source_ip, dest_ip, source_port, dest_port):
        """Détecte les attaques SYN flood"""
        key = f"{source_ip}:{dest_ip}:{dest_port}"
        
        # Ajouter le paquet à l'historique
        self.packet_history[key].append({
            'timestamp': time.time(),
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'source_port': source_port,
            'dest_port': dest_port,
            'type': 'SYN'
        })
        
        # Vérifier le nombre de paquets SYN récents
        recent_packets = [p for p in self.packet_history[key] 
                         if time.time() - p['timestamp'] < 10]  # 10 secondes
        
        if len(recent_packets) > self.dos_threshold:
            self.create_dos_alert(source_ip, dest_ip, 'SYN Flood', len(recent_packets))
    
    def detect_port_flood(self, source_ip, dest_ip, dest_port):
        """Détecte les attaques de flood sur un port spécifique"""
        key = f"{source_ip}:{dest_port}"
        
        # Ajouter le paquet à l'historique
        self.packet_history[key].append({
            'timestamp': time.time(),
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'dest_port': dest_port,
            'type': 'PORT_FLOOD'
        })
        
        # Vérifier le nombre de paquets récents
        recent_packets = [p for p in self.packet_history[key] 
                         if time.time() - p['timestamp'] < 10]  # 10 secondes
        
        if len(recent_packets) > self.dos_threshold:
            self.create_dos_alert(source_ip, dest_ip, 'Port Flood', len(recent_packets))
    
    def create_dos_alert(self, source_ip, dest_ip, attack_type, packet_count):
        """Crée une alerte DoS"""
        # Éviter les alertes répétitives
        alert_key = f"{source_ip}:{attack_type}"
        if alert_key in self.alert_cooldown:
            if time.time() - self.alert_cooldown[alert_key] < 30:  # 30 secondes de cooldown
                return
        
        self.alert_cooldown[alert_key] = time.time()
        
        # Créer l'alerte
        alert = {
            'id': int(time.time()),  # ID unique basé sur le timestamp
            'sourceIp': source_ip,
            'destinationIp': dest_ip,
            'protocol': 'tcp',
            'timestamp': datetime.now().isoformat(),
            'attackType': attack_type,
            'severity': 'high',
            'confidence': min(packet_count / 100.0, 0.95),
            'packetCount': packet_count
        }
        
        # Sauvegarder l'alerte
        self.save_alert(alert)
        
        print(f"🚨 ALERTE {attack_type}: {source_ip} -> {dest_ip} ({packet_count} paquets)")
    
    def save_alert(self, alert):
        """Sauvegarde une alerte dans le fichier de données"""
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
            
            # Ajouter l'alerte
            data['alerts'].append(alert)
            
            # Garder seulement les 50 dernières alertes
            data['alerts'] = data['alerts'][-50:]
            
            # Mettre à jour les statistiques
            data['stats']['total_alerts'] = len(data['alerts'])
            data['stats']['active_threats'] = len([a for a in data['alerts'] if a['severity'] == 'high'])
            
            # Sauvegarder
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            print(f"Erreur lors de la sauvegarde de l'alerte: {e}")
    
    def start_monitoring(self, duration=300):
        """Démarre la surveillance des attaques externes"""
        print("🚨 Détecteur d'attaques DoS Windows")
        print("=" * 50)
        print(f"⏱️  Surveillance pendant {duration} secondes")
        print("📡 Capture des paquets avec scapy")
        print("🎯 Détection: SYN Flood, Port Flood")
        print()
        
        self.running = True
        
        try:
            # Démarrer la capture de paquets
            print("🔍 Démarrage de la capture de paquets...")
            print("Lancez votre attaque DoS maintenant!")
            
            # Capturer les paquets TCP
            sniff(
                prn=self.packet_callback,
                filter="tcp",
                store=0,
                timeout=duration
            )
            
        except KeyboardInterrupt:
            print("\n⏹️ Surveillance arrêtée par l'utilisateur")
        except Exception as e:
            print(f"Erreur lors de la capture: {e}")
        finally:
            self.running = False
            print("\n✅ Surveillance terminée")

def main():
    """Fonction principale"""
    detector = WindowsDOSDetector()
    
    try:
        detector.start_monitoring(duration=300)  # 5 minutes
    except KeyboardInterrupt:
        print("\n⏹️ Surveillance arrêtée par l'utilisateur")

if __name__ == "__main__":
    main() 