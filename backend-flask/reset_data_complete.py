#!/usr/bin/env python3
"""
Script pour réinitialiser complètement le fichier network_data.json
avec toutes les clés nécessaires pour éviter les KeyError
"""

import json
from pathlib import Path
import sys

def reset_data_file():
    """Réinitialise le fichier network_data.json avec une structure complète"""
    
    # Chemin vers le fichier de données
    DATA_FILE = Path(__file__).parent / 'app' / 'data' / 'network_data.json'
    
    # Structure complète avec toutes les clés nécessaires
    clean_data = {
        "connections": [],
        "alerts": [],
        "stats": {
            "total_connections": 0,
            "total_alerts": 0,
            "active_threats": 0,
            "system_health": 100
        }
    }
    
    try:
        # Créer le dossier parent s'il n'existe pas
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        # Écrire le fichier avec la structure complète
        with open(DATA_FILE, "w", encoding='utf-8') as f:
            json.dump(clean_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Fichier {DATA_FILE} réinitialisé avec succès !")
        print("📊 Structure créée :")
        print("   - connections: []")
        print("   - alerts: []")
        print("   - stats.total_connections: 0")
        print("   - stats.total_alerts: 0")
        print("   - stats.active_threats: 0")
        print("   - stats.system_health: 100")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors de la réinitialisation : {e}")
        return False

if __name__ == "__main__":
    print("🔄 Réinitialisation du fichier network_data.json...")
    success = reset_data_file()
    
    if success:
        print("\n🎉 Réinitialisation terminée !")
        print("💡 Vous pouvez maintenant relancer le script universel :")
        print("   python backend-flask/run_universal_ids.py")
    else:
        print("\n💥 Échec de la réinitialisation")
        sys.exit(1) 