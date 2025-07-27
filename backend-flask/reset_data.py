#!/usr/bin/env python3
"""
Script pour complètement réinitialiser le fichier de données
"""

import json
import os
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def reset_data_file():
    """Réinitialise complètement le fichier de données"""
    data_file = "app/data/network_data.json"
    
    # Créer un fichier de données complètement propre
    clean_data = {
        "connections": [],
        "alerts": [],
        "stats": {
            "total_connections": 0,
            "total_alerts": 0,
            "active_threats": 0,
            "last_update": datetime.now().isoformat()
        }
    }
    
    try:
        # Sauvegarder le nouveau fichier
        with open(data_file, 'w') as f:
            json.dump(clean_data, f, indent=2)
        
        logger.info("🧹 Fichier de données complètement réinitialisé!")
        logger.info("✅ Toutes les anciennes données supprimées")
        logger.info("✨ Système prêt pour de nouvelles détections")
        
    except Exception as e:
        logger.error(f"Erreur lors de la réinitialisation: {e}")

def main():
    """Fonction principale"""
    logger.info("🔄 Réinitialisation complète du système IDS...")
    logger.info("=" * 50)
    
    # Réinitialiser le fichier de données
    reset_data_file()
    
    logger.info("=" * 50)
    logger.info("✅ Réinitialisation terminée!")
    logger.info("🚀 Vous pouvez maintenant redémarrer le système:")
    logger.info("   python run_windows.py")
    logger.info("=" * 50)

if __name__ == "__main__":
    main() 