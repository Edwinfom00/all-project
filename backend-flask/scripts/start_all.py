#!/usr/bin/env python3
import subprocess
import sys
import os
import time
import logging
from pathlib import Path

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def start_scanner():
    """Démarre le scanner réseau"""
    scanner_path = Path(__file__).parent / 'start_scanner.py'
    return subprocess.Popen([sys.executable, str(scanner_path)])

def start_flask():
    """Démarre le serveur Flask"""
    run_path = Path(__file__).parent.parent / 'run.py'
    return subprocess.Popen([sys.executable, str(run_path)])

def main():
    try:
        # Démarrer le scanner
        logger.info("Démarrage du scanner réseau...")
        scanner_process = start_scanner()
        
        # Attendre que le scanner soit prêt
        time.sleep(2)
        
        # Démarrer Flask
        logger.info("Démarrage du serveur Flask...")
        flask_process = start_flask()
        
        # Garder le script en cours d'exécution
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Arrêt des processus...")
        scanner_process.terminate()
        flask_process.terminate()
        logger.info("Processus arrêtés.")

if __name__ == "__main__":
    main() 