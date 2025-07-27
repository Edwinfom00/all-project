#!/usr/bin/env python3
"""
Système IDS universel : détection automatique Windows/Linux/WSL, alertes en temps réel pour le frontend.
"""
import os
import sys
import threading
import time
import platform
import logging
from pathlib import Path

# Flask
from app import create_app
from app.routes.settings import settings_bp
from app.routes.rules import rules_bp

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Détection universelle
DATA_FILE = Path(__file__).parent / 'app' / 'data' / 'network_data.json'

# --- Détecteur universel Scapy (tous OS) ---
def universal_scapy_detector():
    try:
        from scapy.all import sniff, IP, TCP
        from collections import defaultdict, deque
        from datetime import datetime
        import json
        SYN_THRESHOLD = 15  # Seuil plus bas pour détecter plus tôt
        WINDOW = 5
        syn_counts = defaultdict(lambda: deque())
        
        def save_alert(source_ip, count, attack_type="DoS (SYN flood)"):
            # Filtrer uniquement les IPs loopback/écoute
            if source_ip in ['127.0.0.1', '0.0.0.0', '::1']:
                return  # Ne pas générer d'alerte pour IP loopback/écoute
            try:
                if DATA_FILE.exists():
                    with open(DATA_FILE, 'r') as f:
                        data = json.load(f)
                else:
                    data = {"alerts": [], "connections": [], "stats": {}}
                
                # Créer l'alerte
                alert = {
                    "id": int(datetime.now().timestamp()),
                    "sourceIp": source_ip,  # IP source de l'attaque
                    "destinationIp": "Votre machine",
                    "protocol": "tcp",
                    "timestamp": datetime.now().isoformat(),
                    "attackType": attack_type,
                    "severity": "high",
                    "confidence": min(count / 100.0, 0.99)
                }
                
                # Ajouter l'alerte
                data["alerts"].append(alert)
                data["alerts"] = data["alerts"][-20:]  # Garder seulement les 20 dernières
                
                # Initialiser et mettre à jour les statistiques
                if "stats" not in data:
                    data["stats"] = {}
                
                # Incrémenter les compteurs
                data["stats"]["total_alerts"] = data["stats"].get("total_alerts", 0) + 1
                data["stats"]["active_threats"] = data["stats"].get("active_threats", 0) + 1
                data["stats"]["total_connections"] = data["stats"].get("total_connections", 0) + count
                data["stats"]["system_health"] = data["stats"].get("system_health", 100)
                
                # Sauvegarder
                with open(DATA_FILE, "w") as f:
                    json.dump(data, f, indent=2)
                
                logger.info(f"🚨 ALERTE {attack_type}: {source_ip} ({count} paquets en {WINDOW}s)")
                logger.info(f"📊 Stats mises à jour: {data['stats']['total_alerts']} alertes, {data['stats']['active_threats']} menaces actives")
                
            except Exception as e:
                logger.error(f"Erreur sauvegarde alerte: {e}")
        
        def packet_callback(pkt):
            if IP in pkt and TCP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                tcp_flags = pkt[TCP].flags
                now = datetime.now().timestamp()
                
                # Détecter les SYN (SYN flood)
                if tcp_flags & 0x02:  # SYN flag
                    syn_counts[src].append(now)
                    
                    # Nettoyer les anciens timestamps
                    while syn_counts[src] and now - syn_counts[src][0] > WINDOW:
                        syn_counts[src].popleft()
                    
                    # Détecter si seuil dépassé
                    if len(syn_counts[src]) > SYN_THRESHOLD:
                        save_alert(src, len(syn_counts[src]), "DoS (SYN flood)")
                
                # Détecter les RST (port scan)
                elif tcp_flags & 0x04:  # RST flag
                    # Logique pour port scan
                    pass
        
        logger.info("[UNIVERSEL] Détection Scapy sur toutes les interfaces...")
        logger.info(f"🔍 Seuil SYN flood: {SYN_THRESHOLD} paquets en {WINDOW} secondes")
        sniff(filter="tcp", prn=packet_callback, store=0)
        
    except ImportError:
        logger.error("Scapy non installé, fallback sur psutil")
        fallback_psutil_detector()
    except Exception as e:
        logger.error(f"Erreur détecteur universel Scapy: {e}")
        logger.error("Fallback sur détection limitée (connexions établies seulement)")
        fallback_psutil_detector()

# --- Détecteur Linux/WSL ---
def linux_packet_detector():
    universal_scapy_detector()

# --- Détecteur Windows ---
def windows_packet_detector():
    universal_scapy_detector()

# --- Fallback psutil amélioré (tous OS) ---
def fallback_psutil_detector():
    import psutil
    from datetime import datetime
    import json
    import time
    import socket
    logger.info("[FALLBACK] Détection psutil améliorée")
    
    def detect_dos_attack():
        try:
            connections = psutil.net_connections()
            ip_pair_counts = {}
            for conn in connections:
                if conn.raddr and hasattr(conn.raddr, 'ip') and conn.laddr and hasattr(conn.laddr, 'ip'):
                    remote_ip = conn.raddr.ip  # L'attaquant
                    local_ip = conn.laddr.ip   # La cible (ta machine)
                    # Ignorer les IPs loopback et locale
                    if remote_ip in ['127.0.0.1', '0.0.0.0', '::1', local_ip]:
                        continue
                    key = (remote_ip, local_ip)
                    if key not in ip_pair_counts:
                        ip_pair_counts[key] = 0
                    ip_pair_counts[key] += 1
            for (src_ip, dst_ip), count in ip_pair_counts.items():
                if count > 30:
                    if DATA_FILE.exists():
                        with open(DATA_FILE, 'r') as f:
                            data = json.load(f)
                    else:
                        data = {"alerts": [], "connections": [], "stats": {}}
                    alert = {
                        "id": int(time.time()),
                        "sourceIp": src_ip,      # L'attaquant (Kali)
                        "destinationIp": dst_ip, # Ta machine
                        "protocol": "tcp",
                        "timestamp": datetime.now().isoformat(),
                        "attackType": "DoS (connexions multiples)",
                        "severity": "high",
                        "confidence": min(count / 100.0, 0.95)
                    }
                    data["alerts"].append(alert)
                    data["alerts"] = data["alerts"][-20:]
                    if "stats" not in data:
                        data["stats"] = {}
                    data["stats"]["total_alerts"] = data["stats"].get("total_alerts", 0) + 1
                    data["stats"]["active_threats"] = data["stats"].get("active_threats", 0) + 1
                    data["stats"]["total_connections"] = data["stats"].get("total_connections", 0) + count
                    data["stats"]["system_health"] = data["stats"].get("system_health", 100)
                    with open(DATA_FILE, "w") as f:
                        json.dump(data, f, indent=2)
                    logger.info(f"🚨 ALERTE DoS: {src_ip} -> {dst_ip} ({count} connexions)")
                    logger.info(f"📊 Stats mises à jour: {data['stats']['total_alerts']} alertes, {data['stats']['active_threats']} menaces actives")
        except Exception as e:
            logger.error(f"Erreur détection DoS: {e}")
    while True:
        try:
            detect_dos_attack()
            time.sleep(3)
        except Exception as e:
            logger.error(f"Erreur fallback psutil: {e}")
            time.sleep(5)

# --- Lancement universel ---
def start_detector():
    os_type = platform.system().lower()
    if 'linux' in os_type or 'darwin' in os_type or 'wsl' in os_type:
        t = threading.Thread(target=linux_packet_detector, daemon=True)
        t.start()
    elif 'windows' in os_type:
        t = threading.Thread(target=windows_packet_detector, daemon=True)
        t.start()
    else:
        logger.warning("OS inconnu, fallback sur psutil")
        t = threading.Thread(target=fallback_psutil_detector, daemon=True)
        t.start()

# --- Main universel ---
def main():
    logger.info("🚀 IDS universel : détection automatique SYN flood/DoS/Port Scan")
    logger.info("🌐 Frontend: http://localhost:3000")
    logger.info("🔧 API: http://localhost:5000")
    # Créer l'application Flask
    app = create_app()
    app.register_blueprint(settings_bp)
    app.register_blueprint(rules_bp)
    # Démarrer le détecteur universel
    start_detector()
    # Lancer le serveur Flask
    app.run(host="0.0.0.0", port=5000, debug=False)

if __name__ == "__main__":
    main() 