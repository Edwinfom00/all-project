#!/usr/bin/env python3
"""
Version complète qui détecte les attaques internes ET externes
"""

from app import create_app
import logging
from app.routes.settings import settings_bp
from app.routes.rules import rules_bp
import threading
import time
import os
import sys
from pathlib import Path

# Ajouter le chemin du module app
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CompleteIDSSystem:
    """Système IDS complet qui détecte tout"""
    
    def __init__(self):
        self.running = False
        self.threads = []
        
    def start_network_scanner(self):
        """Démarre le scanner réseau (connexions établies)"""
        try:
            from app.utils import network_scanner
            
            def scanner_loop():
                try:
                    while self.running:
                        try:
                            network_scanner.scanner._run_scanner()
                            time.sleep(5)
                        except Exception as e:
                            logger.error(f"Erreur scan réseau: {e}")
                            time.sleep(5)
                except Exception as e:
                    logger.error(f"Erreur scanner réseau: {e}")
            
            scanner_thread = threading.Thread(target=scanner_loop, daemon=True)
            scanner_thread.start()
            self.threads.append(scanner_thread)
            logger.info("🚀 Scanner réseau (connexions établies) démarré")
            
        except Exception as e:
            logger.error(f"Erreur démarrage scanner: {e}")
    
    def start_external_detector(self):
        """Démarre le détecteur d'attaques externes (paquets bruts)"""
        try:
            from external_dos_detector import ExternalDOSDetector
            
            detector = ExternalDOSDetector()
            detector.running = True
            
            def capture_loop():
                try:
                    logger.info("🚀 Détecteur d'attaques externes démarré")
                    detector.capture_packets()
                except Exception as e:
                    logger.error(f"Erreur capture externe: {e}")
            
            capture_thread = threading.Thread(target=capture_loop, daemon=True)
            capture_thread.start()
            self.threads.append(capture_thread)
            logger.info("🚀 Détecteur d'attaques externes (paquets bruts) démarré")
            
        except Exception as e:
            logger.warning(f"Détecteur externe non disponible: {e}")
    
    def start_windows_detector(self):
        """Démarre le détecteur Windows (avec scapy)"""
        try:
            from windows_dos_detector import WindowsDOSDetector
            
            detector = WindowsDOSDetector()
            detector.running = True
            
            def capture_loop():
                try:
                    logger.info("🚀 Détecteur Windows démarré")
                    detector.start_monitoring(duration=3600)
                except Exception as e:
                    logger.error(f"Erreur capture Windows: {e}")
            
            capture_thread = threading.Thread(target=capture_loop, daemon=True)
            capture_thread.start()
            self.threads.append(capture_thread)
            logger.info("🚀 Détecteur Windows (scapy) démarré")
            
        except Exception as e:
            logger.warning(f"Détecteur Windows non disponible: {e}")
    
    def start_alert_monitor(self):
        """Démarre le moniteur d'alertes"""
        try:
            from check_alerts import check_alerts
            
            def monitor_loop():
                try:
                    logger.info("🚀 Moniteur d'alertes démarré")
                    check_alerts()
                except Exception as e:
                    logger.error(f"Erreur moniteur d'alertes: {e}")
            
            monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
            monitor_thread.start()
            self.threads.append(monitor_thread)
            logger.info("🚀 Moniteur d'alertes démarré")
            
        except Exception as e:
            logger.warning(f"Moniteur d'alertes non disponible: {e}")
    
    def detect_os_and_start_services(self):
        """Détecte l'OS et démarre les services appropriés"""
        import platform
        
        os_name = platform.system().lower()
        logger.info(f"🖥️ Système détecté: {os_name}")
        
        # Services communs
        self.start_network_scanner()
        self.start_alert_monitor()
        
        # Services spécifiques à l'OS
        if os_name in ['linux', 'darwin']:
            # Linux/Mac - Démarrer le détecteur externe
            self.start_external_detector()
        elif os_name == 'windows':
            # Windows - Démarrer le détecteur Windows
            self.start_windows_detector()
        else:
            logger.warning(f"OS non reconnu: {os_name}, services de base seulement")
    
    def start_all_services(self):
        """Démarre tous les services de détection"""
        logger.info("🚀 Démarrage du système IDS COMPLET...")
        logger.info("=" * 60)
        logger.info("🔍 Détection: Connexions établies + Paquets externes")
        logger.info("🎯 Attaques: DoS, SYN Flood, Port Flood")
        logger.info("=" * 60)
        
        self.running = True
        
        # Démarrer tous les services
        self.detect_os_and_start_services()
        
        # Attendre que tous les threads démarrent
        time.sleep(3)
        
        logger.info("✅ Tous les services de détection sont démarrés!")
        logger.info("📡 Le système détecte maintenant:")
        logger.info("   - Connexions établies (127.0.0.1, 0.0.0.0)")
        logger.info("   - Paquets externes (votre attaque Kali)")
        logger.info("🌐 Frontend: http://localhost:3000")
        logger.info("🔧 API: http://localhost:5000")
        logger.info("=" * 60)
    
    def stop_all_services(self):
        """Arrête tous les services"""
        logger.info("🛑 Arrêt du système IDS...")
        self.running = False
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        logger.info("✅ Tous les services arrêtés")

def main():
    """Fonction principale"""
    # Créer l'application Flask
    app = create_app()
    app.register_blueprint(settings_bp)
    app.register_blueprint(rules_bp)
    
    # Créer le système IDS
    ids_system = CompleteIDSSystem()
    
    try:
        # Démarrer tous les services de détection
        ids_system.start_all_services()
        
        # Lancer le serveur Flask
        logger.info("🌐 Démarrage du serveur Flask...")
        app.run(host="0.0.0.0", port=5000, debug=False)
        
    except KeyboardInterrupt:
        logger.info("\n⏹️ Arrêt du système...")
        ids_system.stop_all_services()
    except Exception as e:
        logger.error(f"Erreur système: {e}")
        ids_system.stop_all_services()

if __name__ == "__main__":
    main() 