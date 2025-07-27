#!/usr/bin/env python3
"""
Script pour nettoyer les anciennes alertes et redémarrer proprement
"""

import json
import os
import time
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def clean_old_alerts():
    """Nettoie les anciennes alertes de faux positifs"""
    data_file = "app/data/network_data.json"
    
    try:
        # Charger les données actuelles
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        # Filtrer les alertes pour garder seulement les vraies attaques
        old_alerts = data.get('alerts', [])
        new_alerts = []
        
        for alert in old_alerts:
            source_ip = alert.get('sourceIp', '')
            
            # Garder seulement les vraies attaques (pas les IPs locales)
            if (source_ip not in ['127.0.0.1', '0.0.0.0', '::1'] and
                not source_ip.startswith('192.168.') and
                not source_ip.startswith('10.') and
                not source_ip.startswith('172.') and
                source_ip != 'N/A'):
                new_alerts.append(alert)
        
        # Mettre à jour les données
        data['alerts'] = new_alerts
        data['stats']['total_alerts'] = len(new_alerts)
        data['stats']['active_threats'] = len([a for a in new_alerts if a.get('severity') == 'high'])
        
        # Sauvegarder
        with open(data_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"🧹 Nettoyage terminé: {len(old_alerts)} -> {len(new_alerts)} alertes")
        logger.info("✅ Supprimé tous les faux positifs (127.0.0.1, 0.0.0.0, 192.168.x.x)")
        
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage: {e}")

def create_clean_data():
    """Crée un fichier de données propre"""
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
    
    data_file = "app/data/network_data.json"
    
    try:
        with open(data_file, 'w') as f:
            json.dump(clean_data, f, indent=2)
        
        logger.info("✨ Fichier de données propre créé")
        
    except Exception as e:
        logger.error(f"Erreur lors de la création: {e}")

def main():
    """Fonction principale"""
    logger.info("🧹 Début du nettoyage du système IDS...")
    logger.info("=" * 50)
    
    # 1. Nettoyer les anciennes alertes
    clean_old_alerts()
    
    # 2. Créer un fichier de données propre
    create_clean_data()
    
    logger.info("=" * 50)
    logger.info("✅ Nettoyage terminé!")
    logger.info("🚀 Vous pouvez maintenant redémarrer le système:")
    logger.info("   python run_windows.py")
    logger.info("=" * 50)

if __name__ == "__main__":
    main() 