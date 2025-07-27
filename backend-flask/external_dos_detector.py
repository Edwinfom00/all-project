#!/usr/bin/env python3
"""
Détecteur d'attaques DoS externes utilisant la capture de paquets réseau
"""

import json
import time
import socket
import struct
import threading
from datetime import datetime
from pathlib import Path
import sys
import os
from collections import defaultdict, deque

# Ajouter le chemin du module app
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

class ExternalDOSDetector:
    def __init__(self):
        self.data_file = Path(__file__).parent / 'app' / 'data' / 'network_data.json'
        self.dos_threshold = 20  # Nombre de paquets pour déclencher une alerte
        self.packet_history = defaultdict(lambda: deque(maxlen=100))  # Historique des paquets par IP
        self.alert_cooldown = {}  # Éviter les alertes répétitives
        self.running = False
        
    def capture_packets(self):
        """Capture les paquets réseau bruts"""
        try:
            # Créer un socket raw pour capturer tous les paquets
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.bind(('', 0))
            
            print("🔍 Capture de paquets réseau démarrée...")
            print("Lancez votre attaque DoS maintenant!")
            
            while self.running:
                try:
                    # Recevoir un paquet
                    packet, addr = sock.recvfrom(65535)
                    
                    # Analyser le paquet
                    self.analyze_packet(packet, addr)
                    
                except Exception as e:
                    print(f"Erreur lors de la capture: {e}")
                    continue
                    
        except PermissionError:
            print("❌ ERREUR: Besoin de privilèges administrateur!")
            print("   Lancez avec: sudo python external_dos_detector.py")
            return False
        except Exception as e:
            print(f"Erreur lors de la création du socket: {e}")
            return False
    
    def analyze_packet(self, packet, addr):
        """Analyse un paquet réseau"""
        try:
            # Extraire l'en-tête IP
            ip_header = packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            source_ip = socket.inet_ntoa(iph[8])
            dest_ip = socket.inet_ntoa(iph[9])
            
            # Extraire l'en-tête TCP
            tcp_header = packet[20:40]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            source_port = tcph[0]
            dest_port = tcph[1]
            tcp_flags = tcph[5]
            
            # Détecter les paquets SYN (attaque DoS)
            if tcp_flags & 0x02:  # SYN flag
                self.detect_syn_flood(source_ip, dest_ip, source_port, dest_port)
            
            # Détecter les paquets avec le même port de destination (DoS)
            if dest_port == 80:  # HTTP
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
        print("🚨 Détecteur d'attaques DoS externes")
        print("=" * 50)
        print(f"⏱️  Surveillance pendant {duration} secondes")
        print("📡 Capture des paquets réseau bruts")
        print("🎯 Détection: SYN Flood, Port Flood")
        print()
        
        self.running = True
        
        # Démarrer la capture dans un thread séparé
        capture_thread = threading.Thread(target=self.capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        # Attendre la durée spécifiée
        time.sleep(duration)
        
        self.running = False
        print("\n✅ Surveillance terminée")

def main():
    """Fonction principale"""
    detector = ExternalDOSDetector()
    
    try:
        detector.start_monitoring(duration=300)  # 5 minutes
    except KeyboardInterrupt:
        print("\n⏹️ Surveillance arrêtée par l'utilisateur")
        detector.running = False

if __name__ == "__main__":
    main() 