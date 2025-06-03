#!/usr/bin/env python3
import os
import sys
import argparse

# Ajouter le répertoire parent au PYTHONPATH
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from app.utils.network_scanner import NetworkScanner

def main():
    parser = argparse.ArgumentParser(description='Démarre le scanner réseau pour la détection d\'intrusions')
    parser.add_argument('-i', '--interface', default=None,
                      help='Interface réseau à surveiller (optionnel)')
    
    args = parser.parse_args()
    
    # Créer et démarrer le scanner
    scanner = NetworkScanner(interface=args.interface)
    try:
        print("Démarrage du scanner réseau...")
        scanner.start()
        print("Scanner démarré. Appuyez sur Ctrl+C pour arrêter.")
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nArrêt du scanner...")
        scanner.stop()
        print("Scanner arrêté.")

if __name__ == "__main__":
    main() 