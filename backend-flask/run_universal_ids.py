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
import threading
from app.utils.network_scanner import NetworkScanner

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
            port_scan_attempts = {}
            
            for conn in connections:
                if conn.raddr and hasattr(conn.raddr, 'ip') and conn.laddr and hasattr(conn.laddr, 'ip'):
                    remote_ip = conn.raddr.ip  # L'attaquant
                    local_ip = conn.laddr.ip   # La cible (ta machine)
                    local_port = conn.laddr.port if conn.laddr else 0
                    
                    # IGNORER LES CONNEXIONS NORMALES ET LOCALES
                    if (remote_ip in ['127.0.0.1', '0.0.0.0', '::1', local_ip] or
                        local_ip in ['127.0.0.1', '0.0.0.0', '::1']):
                        continue
                    
                    # PERMETTRE LES TESTS DEPUIS LA MACHINE VIRTUELLE
                    # Ne pas ignorer les IPs du réseau local pour les tests
                    # if (remote_ip.startswith('192.168.') or
                    #     remote_ip.startswith('10.') or
                    #     remote_ip.startswith('172.') or
                    #     local_ip.startswith('192.168.') or
                    #     local_ip.startswith('10.') or
                    #     local_ip.startswith('172.')):
                    #     continue
                    
                    # IGNORER LES CONNEXIONS ÉTABLIES NORMALES
                    if hasattr(conn, 'status') and conn.status == 'ESTABLISHED':
                        continue
                    
                    # IGNORER LES PORTS DE SERVICE NORMAUX (mais permettre les tests)
                    # if local_port in [22, 80, 443, 53, 25, 110, 143, 993, 995]:
                    #     continue
                    
                    # SEULEMENT COMPTER LES CONNEXIONS SUSPECTES
                    key = (remote_ip, local_ip)
                    if key not in ip_pair_counts:
                        ip_pair_counts[key] = 0
                    ip_pair_counts[key] += 1
                    
                    # Détecter les tentatives de port scan
                    if local_port > 0:
                        port_key = f"{remote_ip}_{local_ip}"
                        if port_key not in port_scan_attempts:
                            port_scan_attempts[port_key] = set()
                        port_scan_attempts[port_key].add(local_port)
            
            # DÉTECTER D'ABORD LES DoS, PUIS LES PORT SCANS
            dos_sources = set()
            port_scan_sources = set()
            
            # ÉTAPE 1: Détecter les DoS (priorité haute)
            for (src_ip, dst_ip), count in ip_pair_counts.items():
                if count > 50:  # Seuil pour DoS
                    # Vérifier si c'est vers peu de ports (DoS) ou beaucoup de ports (Port Scan)
                    ports_for_pair = set()
                    for conn in connections:
                        # Corriger l'accès aux propriétés des connexions psutil
                        try:
                            remote_ip = conn.raddr.ip if hasattr(conn, 'raddr') and conn.raddr else None
                            local_ip = conn.laddr.ip if hasattr(conn, 'laddr') and conn.laddr else None
                            local_port = conn.laddr.port if hasattr(conn, 'laddr') and conn.laddr else None
                            
                            if remote_ip == src_ip and local_ip == dst_ip and local_port:
                                ports_for_pair.add(local_port)
                        except AttributeError:
                            # Ignorer les connexions sans propriétés valides
                            continue
                    
                    if len(ports_for_pair) <= 5:  # DoS: peu de ports, beaucoup de connexions
                        dos_sources.add((src_ip, dst_ip))
                        logger.info(f"🚨 DoS détecté: {src_ip} -> {dst_ip} ({count} connexions, {len(ports_for_pair)} ports)")
                        
                        # Créer alerte DoS
                        if DATA_FILE.exists():
                            with open(DATA_FILE, 'r') as f:
                                data = json.load(f)
                        else:
                            data = {"alerts": [], "connections": [], "stats": {}}
                        
                        alert = {
                            "id": int(time.time()),
                            "sourceIp": src_ip,
                            "destinationIp": dst_ip,
                            "protocol": "tcp",
                            "timestamp": datetime.now().isoformat(),
                            "attackType": "DoS",
                            "severity": "high",
                            "confidence": min(count / 1000.0, 0.95)
                        }
                        data["alerts"].append(alert)
                        data["alerts"] = data["alerts"][-20:]
                        if "stats" not in data:
                            data["stats"] = {}
                        data["stats"]["total_alerts"] = data["stats"].get("total_alerts", 0) + 1
                        data["stats"]["active_threats"] = data["stats"].get("active_threats", 0) + 1
                        data["stats"]["total_connections"] = data["stats"].get("total_connections", 0) + count
                        with open(DATA_FILE, "w") as f:
                            json.dump(data, f, indent=2)
                        logger.info(f"🚨 ALERTE DoS: {src_ip} -> {dst_ip} ({count} connexions)")
            
            # ÉTAPE 2: Détecter les Port Scans (seulement si pas déjà détecté comme DoS)
            for key, ports in port_scan_attempts.items():
                if len(ports) > 2:  # Seuil pour port scan
                    remote_ip, local_ip = key.split('_')
                    
                    # Ne pas détecter comme port scan si déjà détecté comme DoS
                    if (remote_ip, local_ip) in dos_sources:
                        logger.info(f"⚠️ Ignorer Port Scan pour {remote_ip} -> {local_ip} (déjà détecté comme DoS)")
                        continue
                    
                    # Vraie détection de port scan
                    port_scan_sources.add((remote_ip, local_ip))
                    logger.info(f"🔍 Port scan détecté: {remote_ip} -> {local_ip} ({len(ports)} ports)")
                    
                    if DATA_FILE.exists():
                        with open(DATA_FILE, 'r') as f:
                            data = json.load(f)
                    else:
                        data = {"alerts": [], "connections": [], "stats": {}}
                    
                    alert = {
                        "id": int(time.time()),
                        "sourceIp": remote_ip,
                        "destinationIp": local_ip,
                        "protocol": "tcp",
                        "timestamp": datetime.now().isoformat(),
                        "attackType": "Port Scan",
                        "severity": "medium",
                        "confidence": min(len(ports) / 100.0, 0.9)
                    }
                    data["alerts"].append(alert)
                    data["alerts"] = data["alerts"][-20:]
                    if "stats" not in data:
                        data["stats"] = {}
                    data["stats"]["total_alerts"] = data["stats"].get("total_alerts", 0) + 1
                    data["stats"]["active_threats"] = data["stats"].get("active_threats", 0) + 1
                    with open(DATA_FILE, "w") as f:
                        json.dump(data, f, indent=2)
                    logger.info(f"🔍 ALERTE Port Scan: {remote_ip} -> {local_ip} ({len(ports)} ports)")
            
            # ÉTAPE 3: Classification IA pour les cas ambigus
            for (src_ip, dst_ip), count in ip_pair_counts.items():
                # Ignorer si déjà détecté comme DoS ou Port Scan
                if (src_ip, dst_ip) in dos_sources or (src_ip, dst_ip) in port_scan_sources:
                    continue
                
                # Utiliser l'IA pour classifier les cas ambigus
                try:
                    from app.model.ai_model import predict_intrusion
                    from app.utils.preprocessing import preprocess_data
                    
                    # Préparer les données pour l'IA
                    attack_data = {
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'connections_count': count,
                        'bytes_sent': count * 100,  # Estimation
                        'bytes_received': 0,
                        'flag': 'S',  # SYN flag
                        'duration': 0,
                        'serror_rate': 0.3 if count > 10 else 0.1,
                        'srv_serror_rate': 0.3 if count > 10 else 0.1,
                        'rerror_rate': 0.1,
                        'srv_rerror_rate': 0.1
                    }
                    
                    # Analyser avec l'IA
                    processed_data = preprocess_data(attack_data)
                    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
                    
                    # Créer l'alerte basée sur la classification de l'IA
                    if is_intrusion:
                        if DATA_FILE.exists():
                            with open(DATA_FILE, 'r') as f:
                                data = json.load(f)
                        else:
                            data = {"alerts": [], "connections": [], "stats": {}}
                        
                        alert = {
                            "id": int(time.time()),
                            "sourceIp": src_ip,
                            "destinationIp": dst_ip,
                            "protocol": "tcp",
                            "timestamp": datetime.now().isoformat(),
                            "attackType": attack_type,  # Utiliser la classification de l'IA
                            "severity": "high" if attack_type == "DoS" else "medium",
                            "confidence": confidence
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
                        
                        logger.info(f"🤖 ALERTE {attack_type} (IA): {src_ip} -> {dst_ip} ({count} connexions, confiance: {confidence:.2f})")
                        logger.info(f"📊 Stats mises à jour: {data['stats']['total_alerts']} alertes, {data['stats']['active_threats']} menaces actives")
                    
                except Exception as e:
                    logger.error(f"Erreur classification IA: {e}")
                    # Fallback sur la détection simple pour les cas non classifiés
                    if count > 20:
                        if DATA_FILE.exists():
                            with open(DATA_FILE, 'r') as f:
                                data = json.load(f)
                        else:
                            data = {"alerts": [], "connections": [], "stats": {}}
                        alert = {
                            "id": int(time.time()),
                            "sourceIp": src_ip,
                            "destinationIp": dst_ip,
                            "protocol": "tcp",
                            "timestamp": datetime.now().isoformat(),
                            "attackType": "DoS",
                            "severity": "high",
                            "confidence": min(count / 1000.0, 0.95)
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
                        logger.info(f"🚨 ALERTE DoS (fallback): {src_ip} -> {dst_ip} ({count} connexions)")
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

# --- Lancement universel (restauré) ---
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

# --- Lancement universel amélioré ---
def start_all_services():
    logger.info("🚀 Lancement de tous les services backend IDS...")
    # 1. Lancer le backend Flask en thread
    def flask_thread():
        app = create_app()
        app.register_blueprint(settings_bp)
        app.register_blueprint(rules_bp)
        from app.routes.alerts import alerts_bp
        app.register_blueprint(alerts_bp)
        app.run(host="0.0.0.0", port=5000, debug=False)
    t_flask = threading.Thread(target=flask_thread, daemon=True)
    t_flask.start()
    logger.info("🌐 Backend Flask lancé sur http://localhost:5000")

    # 2. Lancer le scanner réseau IA (NetworkScanner)
    def scanner_thread():
        scanner = NetworkScanner()
        scanner.start()
    t_scanner = threading.Thread(target=scanner_thread, daemon=True)
    t_scanner.start()
    logger.info("🤖 Scanner réseau IA lancé")

    # 3. Lancer la détection universelle (Scapy/psutil)
    start_detector()  # déjà en thread
    logger.info("🔬 Détection universelle (Scapy/psutil) lancée")

    logger.info("✅ Tous les services IDS sont démarrés !")

# --- Main universel amélioré ---
def main():
    logger.info("🚀 IDS universel : détection automatique SYN flood/DoS/Port Scan + backend complet")
    logger.info("🌐 Frontend: http://localhost:3000")
    logger.info("🔧 API: http://localhost:5000")
    start_all_services()
    # Boucle principale pour garder le script vivant
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("Arrêt demandé par l'utilisateur.")

if __name__ == "__main__":
    main() 