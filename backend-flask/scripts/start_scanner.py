import sys
import os
import logging

# Ajouter le répertoire parent au PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.network_scanner import scanner

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    try:
        logger.info("Démarrage du scanner réseau...")
        scanner.start()
        
        # Garder le script en cours d'exécution
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Arrêt du scanner...")
        scanner.stop()
    except Exception as e:
        logger.error(f"Erreur: {e}")
        scanner.stop() 