#!/usr/bin/env python3
"""
Test de la nouvelle logique de détection DoS vs Port Scan
"""

def test_new_detection_logic():
    """Test de la nouvelle logique de détection"""
    
    print("🧪 TEST: Nouvelle logique de détection")
    print("=" * 50)
    
    # Simuler des scénarios d'attaque
    test_scenarios = [
        {
            "name": "hping3 --flood (DoS)",
            "connections": 1000,
            "ports": 1,
            "expected": "DoS",
            "description": "Beaucoup de connexions vers un seul port"
        },
        {
            "name": "nmap -sS (Port Scan)",
            "connections": 1000,
            "ports": 1000,
            "expected": "Port Scan",
            "description": "Beaucoup de connexions vers beaucoup de ports"
        },
        {
            "name": "SYN flood (DoS)",
            "connections": 500,
            "ports": 3,
            "expected": "DoS",
            "description": "Beaucoup de connexions vers peu de ports"
        },
        {
            "name": "Port scan léger",
            "connections": 50,
            "ports": 50,
            "expected": "Port Scan",
            "description": "Peu de connexions vers beaucoup de ports"
        }
    ]
    
    for scenario in test_scenarios:
        print(f"\n📋 Test: {scenario['name']}")
        print(f"   Connexions: {scenario['connections']}")
        print(f"   Ports: {scenario['ports']}")
        print(f"   Description: {scenario['description']}")
        print(f"   Attendu: {scenario['expected']}")
        
        # Appliquer la nouvelle logique
        if scenario['connections'] > 50 and scenario['ports'] <= 5:
            detected = "DoS"
            reason = "Beaucoup de connexions vers peu de ports"
        elif scenario['ports'] > 2:
            detected = "Port Scan"
            reason = "Beaucoup de ports différents"
        else:
            detected = "Normal"
            reason = "Activité normale"
        
        print(f"   Détecté: {detected}")
        print(f"   Raison: {reason}")
        print(f"   ✅ Correct" if detected == scenario['expected'] else f"   ❌ Incorrect")

def explain_new_logic():
    """Expliquer la nouvelle logique"""
    
    print("\n🔧 NOUVELLE LOGIQUE DE DÉTECTION")
    print("=" * 50)
    print("ÉTAPE 1: Détecter les DoS (priorité haute)")
    print("   - Si > 50 connexions ET ≤ 5 ports → DoS")
    print("   - Exemple: hping3 --flood -p 80")
    print()
    print("ÉTAPE 2: Détecter les Port Scans")
    print("   - Si > 2 ports ET pas déjà détecté comme DoS → Port Scan")
    print("   - Exemple: nmap -sS")
    print()
    print("ÉTAPE 3: Classification IA pour cas ambigus")
    print("   - Pour les cas non classifiés par les règles")
    print()
    print("🎯 RÉSULTAT ATTENDU:")
    print("   - hping3 --flood → DoS ✅")
    print("   - nmap -sS → Port Scan ✅")

if __name__ == "__main__":
    test_new_detection_logic()
    explain_new_logic()
    
    print("\n💡 POUR TESTER:")
    print("1. Lancez 'hping3 -S --flood -p 80 129.0.60.67'")
    print("2. Vérifiez que c'est détecté comme 'DoS'")
    print("3. Lancez 'nmap -sS 129.0.60.57'")
    print("4. Vérifiez que c'est détecté comme 'Port Scan'") 