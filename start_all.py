#!/usr/bin/env python3
"""
Script principal pour démarrer tout le système IDS
"""

import subprocess
import threading
import time
import os
import sys
from pathlib import Path

def start_backend():
    """Démarre le backend Flask avec tous les services"""
    print("🚀 Démarrage du backend Flask...")
    
    backend_dir = Path(__file__).parent / 'backend-flask'
    os.chdir(backend_dir)
    
    try:
        # Démarrer le backend
        subprocess.run(['python', 'run.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur backend: {e}")
    except KeyboardInterrupt:
        print("\n⏹️ Backend arrêté")

def start_frontend():
    """Démarre le frontend Next.js"""
    print("🚀 Démarrage du frontend Next.js...")
    
    frontend_dir = Path(__file__).parent / 'frontend-next'
    os.chdir(frontend_dir)
    
    try:
        # Vérifier les dépendances
        if not Path('node_modules').exists():
            print("📦 Installation des dépendances frontend...")
            subprocess.run(['npm', 'install'], check=True)
        
        # Démarrer le frontend
        subprocess.run(['npm', 'run', 'dev'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur frontend: {e}")
    except KeyboardInterrupt:
        print("\n⏹️ Frontend arrêté")

def main():
    """Fonction principale"""
    print("🚀 SYSTÈME IDS COMPLET")
    print("=" * 50)
    print("🔧 Backend: http://localhost:5000")
    print("🌐 Frontend: http://localhost:3000")
    print("📡 Tous les détecteurs seront automatiquement démarrés")
    print("=" * 50)
    
    # Démarrer le backend dans un thread
    backend_thread = threading.Thread(target=start_backend, daemon=True)
    backend_thread.start()
    
    # Attendre que le backend démarre
    print("⏳ Attente du démarrage du backend...")
    time.sleep(5)
    
    # Démarrer le frontend
    start_frontend()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⏹️ Arrêt du système complet")
    except Exception as e:
        print(f"❌ Erreur système: {e}") 