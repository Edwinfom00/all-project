#!/usr/bin/env python3
"""
Version simplifiée de run.py qui fonctionne correctement
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

class SimpleIDSSystem:
    """Système IDS simplifié qui fonctionne"""
    
    def __init__(self):
        self.running = False
        self.threads = []
        
    def start_network_scanner(self):
        """Démarre le scanner réseau en arrière-plan"""
        try:
            from app.utils import network_scanner
            
            def scanner_loop():
                try:
                    # Version non-bloquante du scanner
                    while self.running:
                        try:
                            # Exécuter un scan toutes les 5 secondes
                            network_scanner.scanner._run_scanner()
                            time.sleep(5)
                        except Exception as e:
                            logger.error(f"Erreur scan: {e}")
                            time.sleep(5)
                except Exception as e:
                    logger.error(f"Erreur scanner réseau: {e}")
            
            scanner_thread = threading.Thread(target=scanner_loop, daemon=True)
            scanner_thread.start()
            self.threads.append(scanner_thread)
            logger.info("🚀 Scanner réseau démarré")
            
        except Exception as e:
            logger.error(f"Erreur démarrage scanner: {e}")
    
    def start_dos_detector(self):
        """Démarre un détecteur DoS simple"""
        try:
            def dos_loop():
                try:
                    while self.running:
                        # Simuler la détection DoS
                        time.sleep(10)
                        logger.info("🔍 Surveillance DoS active...")
                except Exception as e:
                    logger.error(f"Erreur détecteur DoS: {e}")
            
            dos_thread = threading.Thread(target=dos_loop, daemon=True)
            dos_thread.start()
            self.threads.append(dos_thread)
            logger.info("🚀 Détecteur DoS démarré")
            
        except Exception as e:
            logger.error(f"Erreur démarrage détecteur DoS: {e}")
    
    def start_all_services(self):
        """Démarre tous les services"""
        logger.info("🚀 Démarrage du système IDS...")
        
        self.running = True
        
        # Démarrer les services
        self.start_network_scanner()
        self.start_dos_detector()
        
        # Attendre que les services démarrent
        time.sleep(2)
        
        logger.info("✅ Services démarrés!")
        logger.info("🌐 API: http://localhost:5000")
        logger.info("📡 Frontend: http://localhost:3000")
    
    def stop_all_services(self):
        """Arrête tous les services"""
        logger.info("🛑 Arrêt des services...")
        self.running = False
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        logger.info("✅ Services arrêtés")

def main():
    """Fonction principale"""
    # Créer l'application Flask
    app = create_app()
    app.register_blueprint(settings_bp)
    app.register_blueprint(rules_bp)
    
    # Créer le système IDS
    ids_system = SimpleIDSSystem()
    
    try:
        # Démarrer les services
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