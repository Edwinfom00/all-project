#!/usr/bin/env python3
"""
Version qui fonctionne vraiment
"""

from app import create_app
import logging
from app.routes.settings import settings_bp
from app.routes.rules import rules_bp
import threading
import time

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def start_background_scanner():
    """Démarre le scanner en arrière-plan"""
    def scanner_loop():
        try:
            from app.utils import network_scanner
            logger.info("🚀 Scanner réseau démarré en arrière-plan")
            
            # Version non-bloquante
            while True:
                try:
                    network_scanner.scanner._run_scanner()
                    time.sleep(5)  # Scan toutes les 5 secondes
                except Exception as e:
                    logger.error(f"Erreur scan: {e}")
                    time.sleep(5)
        except Exception as e:
            logger.error(f"Erreur scanner: {e}")
    
    # Démarrer dans un thread séparé
    scanner_thread = threading.Thread(target=scanner_loop, daemon=True)
    scanner_thread.start()
    return scanner_thread

def main():
    """Fonction principale"""
    logger.info("🚀 Démarrage du système IDS...")
    
    # Créer l'application Flask
    app = create_app()
    app.register_blueprint(settings_bp)
    app.register_blueprint(rules_bp)
    
    # Démarrer le scanner en arrière-plan
    scanner_thread = start_background_scanner()
    
    # Attendre un peu
    time.sleep(2)
    
    logger.info("✅ Système prêt!")
    logger.info("🌐 API: http://localhost:5000")
    logger.info("📡 Frontend: http://localhost:3000")
    
    # Lancer le serveur Flask
    try:
        app.run(host="0.0.0.0", port=5000, debug=False)
    except KeyboardInterrupt:
        logger.info("\n⏹️ Arrêt du système...")
    except Exception as e:
        logger.error(f"Erreur serveur: {e}")

if __name__ == "__main__":
    main() 