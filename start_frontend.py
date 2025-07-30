#!/usr/bin/env python3
"""
Script pour démarrer le frontend Next.js automatiquement
"""

import subprocess
import time
import os
import sys
from pathlib import Path

def start_frontend():
    """Démarre le frontend Next.js"""
    frontend_dir = Path(__file__).parent / 'frontend-next'
    
    if not frontend_dir.exists():
        print("❌ Dossier frontend-next non trouvé!")
        return False
    
    print("🚀 Démarrage du frontend Next.js...")
    print(f"📁 Dossier: {frontend_dir}")
    
    try:
        # Changer vers le dossier frontend
        os.chdir(frontend_dir)
        
        # Vérifier si node_modules existe
        if not Path('node_modules').exists():
            print("📦 Installation des dépendances...")
            subprocess.run(['npm', 'install'], check=True)
        
        # Démarrer le serveur de développement
        print("🌐 Démarrage du serveur de développement...")
        subprocess.run(['npm', 'run', 'dev'], check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors du démarrage du frontend: {e}")
        return False
    except KeyboardInterrupt:
        print("\n⏹️ Frontend arrêté")
        return True
    except Exception as e:
        print(f"❌ Erreur inattendue: {e}")
        return False

if __name__ == "__main__":
    start_frontend() 