#!/usr/bin/env python3
"""
Script pour vérifier les alertes en temps réel
"""

import json
import time
from pathlib import Path
from datetime import datetime

def check_alerts():
    """Vérifie les alertes en temps réel"""
    data_file = Path(__file__).parent / 'app' / 'data' / 'network_data.json'
    
    print("🔍 Surveillance des alertes en temps réel")
    print("=" * 50)
    
    last_alert_count = 0
    
    while True:
        try:
            if data_file.exists():
                with open(data_file, 'r') as f:
                    data = json.load(f)
                
                current_alerts = len(data['alerts'])
                current_connections = len(data['connections'])
                
                # Afficher les nouvelles alertes
                if current_alerts > last_alert_count:
                    new_alerts = data['alerts'][last_alert_count:]
                    print(f"\n🚨 {len(new_alerts)} nouvelles alertes détectées!")
                    
                    for alert in new_alerts:
                        print(f"   📡 {alert['attackType']} depuis {alert['sourceIp']}")
                        print(f"      ⏰ {alert['timestamp']}")
                        print(f"      🔴 Sévérité: {alert['severity']}")
                        if 'confidence' in alert:
                            print(f"      📊 Confiance: {alert['confidence']:.2f}")
                        print()
                    
                    last_alert_count = current_alerts
                
                # Afficher les statistiques
                print(f"\r📊 Connexions: {current_connections} | Alertes: {current_alerts} | Menaces actives: {data['stats']['active_threats']}", end='')
                
            else:
                print("❌ Fichier network_data.json non trouvé")
                break
                
        except KeyboardInterrupt:
            print("\n\n⏹️ Surveillance arrêtée")
            break
        except Exception as e:
            print(f"\n❌ Erreur: {e}")
        
        time.sleep(1)  # Vérifier toutes les secondes

if __name__ == "__main__":
    check_alerts() 