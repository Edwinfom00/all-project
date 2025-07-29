#!/usr/bin/env python3
"""
Test pour vérifier la distinction entre DoS et Port Scan
"""

import time
import json
from datetime import datetime

def test_detection_logic():
    """Test de la logique de détection"""
    
    print("🧪 TEST: Distinction DoS vs Port Scan")
    print("=" * 50)
    
    # Simuler des données d'attaque
    test_cases = [
        {
            "name": "Port Scan (nmap)",
            "ports": 1000,
            "connections": 1000,
            "expected": "Port Scan"
        },
        {
            "name": "DoS (hping3 flood)",
            "ports": 1,
            "connections": 1000,
            "expected": "DoS"
        },
        {
            "name": "DoS (SYN flood)",
            "ports": 3,
            "connections": 500,
            "expected": "DoS"
        },
        {
            "name": "Port Scan léger",
            "ports": 50,
            "connections": 50,
            "expected": "Port Scan"
        }
    ]
    
    for test in test_cases:
        print(f"\n📋 Test: {test['name']}")
        print(f"   Ports: {test['ports']}")
        print(f"   Connexions: {test['connections']}")
        print(f"   Attendu: {test['expected']}")
        
        # Appliquer la logique de détection
        if test['ports'] <= 5 and test['connections'] > 50:
            detected = "DoS"
            reason = "Peu de ports + beaucoup de connexions"
        elif test['ports'] > 2:
            detected = "Port Scan"
            reason = "Beaucoup de ports différents"
        else:
            detected = "Normal"
            reason = "Activité normale"
        
        print(f"   Détecté: {detected}")
        print(f"   Raison: {reason}")
        print(f"   ✅ Correct" if detected == test['expected'] else f"   ❌ Incorrect")

def check_current_alerts():
    """Vérifier les alertes actuelles"""
    
    print("\n🔍 VÉRIFICATION DES ALERTES ACTUELLES")
    print("=" * 50)
    
    try:
        with open('data/alerts.json', 'r') as f:
            data = json.load(f)
        
        alerts = data.get('alerts', [])
        print(f"📊 Total alertes: {len(alerts)}")
        
        # Analyser les types d'attaques
        attack_types = {}
        for alert in alerts[-10:]:  # 10 dernières alertes
            attack_type = alert.get('attackType', 'Unknown')
            if attack_type not in attack_types:
                attack_types[attack_type] = 0
            attack_types[attack_type] += 1
        
        print("\n📈 Répartition des attaques:")
        for attack_type, count in attack_types.items():
            print(f"   {attack_type}: {count}")
            
    except FileNotFoundError:
        print("❌ Fichier alerts.json non trouvé")
    except Exception as e:
        print(f"❌ Erreur: {e}")

if __name__ == "__main__":
    test_detection_logic()
    check_current_alerts()
    
    print("\n💡 INSTRUCTIONS POUR TESTER:")
    print("1. Lancez 'nmap -sS 129.0.60.57' → Doit détecter 'Port Scan'")
    print("2. Lancez 'hping3 -S --flood -p 80 129.0.60.67' → Doit détecter 'DoS'")
    print("3. Vérifiez les logs du système pour confirmer la détection") 