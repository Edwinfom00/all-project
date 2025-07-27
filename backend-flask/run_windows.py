#!/usr/bin/env python3
"""
Système IDS Windows optimisé - Détection complète automatique
"""

from app import create_app
import logging
from app.routes.settings import settings_bp
from app.routes.rules import rules_bp
import threading
import time
import os
import sys
import platform
from pathlib import Path

# Ajouter le chemin du module app
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WindowsIDSSystem:
    """Système IDS optimisé pour Windows avec détection complète"""
    
    def __init__(self):
        self.running = False
        self.threads = []
        
    def start_enhanced_scanner(self):
        """Démarre le scanner réseau amélioré qui détecte tout"""
        try:
            from app.utils import network_scanner
            
            def scanner_loop():
                try:
                    logger.info("🚀 Scanner réseau AMÉLIORÉ démarré")
                    logger.info("✅ Détection: Connexions établies + Paquets bruts")
                    logger.info("🎯 Attaques: DoS, SYN Flood, Port Scan, Probes")
                    logger.info("🔍 Seuil DoS: >100 connexions (évite faux positifs)")
                    
                    while self.running:
                        try:
                            network_scanner.scanner._run_scanner()
                            time.sleep(3)  # Scanner toutes les 3 secondes
                        except Exception as e:
                            logger.error(f"Erreur scan réseau: {e}")
                            time.sleep(5)
                except Exception as e:
                    logger.error(f"Erreur scanner réseau: {e}")
            
            scanner_thread = threading.Thread(target=scanner_loop, daemon=True)
            scanner_thread.start()
            self.threads.append(scanner_thread)
            logger.info("🚀 Scanner réseau AMÉLIORÉ démarré avec succès")
            
        except Exception as e:
            logger.error(f"Erreur démarrage scanner: {e}")
    
    def start_all_services(self):
        """Démarre tous les services de détection pour Windows"""
        logger.info("🚀 Démarrage du système IDS WINDOWS AMÉLIORÉ...")
        logger.info("=" * 60)
        logger.info("🔍 Détection: Connexions établies + Paquets bruts")
        logger.info("🎯 Attaques: DoS, SYN Flood, Port Flood, Port Scan")
        logger.info("✅ Optimisé: Évite les faux positifs Windows")
        logger.info("🚨 Seuil DoS: >100 connexions (détection améliorée)")
        logger.info("=" * 60)
        
        self.running = True
        
        # Démarrer le scanner amélioré
        self.start_enhanced_scanner()
        
        # Attendre que le thread démarre
        time.sleep(3)
        
        logger.info("✅ Système de détection AMÉLIORÉ démarré!")
        logger.info("📡 Le système détecte maintenant:")
        logger.info("   - Connexions établies (seuil >100, évite 127.0.0.1)")
        logger.info("   - Paquets bruts (votre attaque Kali)")
        logger.info("   - Patterns TCP suspects")
        logger.info("   - Port scans et probes")
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
    # Vérifier l'OS
    if platform.system().lower() != 'windows':
        logger.warning("⚠️ Ce script est optimisé pour Windows")
    
    # Créer l'application Flask
    app = create_app()
    app.register_blueprint(settings_bp)
    app.register_blueprint(rules_bp)
    
    # Créer le système IDS
    ids_system = WindowsIDSSystem()
    
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