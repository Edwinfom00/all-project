#!/usr/bin/env python3
"""
Script de test pour vérifier le système complet
"""

import requests
import time
import json
from pathlib import Path

def test_backend():
    """Teste le backend Flask"""
    print("🔧 Test du backend Flask...")
    
    try:
        response = requests.get('http://localhost:5000/health', timeout=5)
        if response.status_code == 200:
            print("✅ Backend Flask fonctionne")
            return True
        else:
            print(f"❌ Backend répond avec code {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Backend non accessible")
        return False
    except Exception as e:
        print(f"❌ Erreur backend: {e}")
        return False

def test_api_endpoints():
    """Teste les endpoints de l'API"""
    print("\n📡 Test des endpoints API...")
    
    endpoints = [
        '/api/stats/traffic',
        '/api/stats/alerts',
        '/api/stats/model-stats',
        '/api/alerts'
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(f'http://localhost:5000{endpoint}', timeout=5)
            if response.status_code == 200:
                print(f"✅ {endpoint} - OK")
            else:
                print(f"⚠️ {endpoint} - Code {response.status_code}")
        except Exception as e:
            print(f"❌ {endpoint} - Erreur: {e}")

def test_network_data():
    """Teste le fichier de données réseau"""
    print("\n📊 Test du fichier de données...")
    
    data_file = Path('backend-flask/app/data/network_data.json')
    
    if data_file.exists():
        try:
            with open(data_file, 'r') as f:
                data = json.load(f)
            
            alerts_count = len(data.get('alerts', []))
            connections_count = len(data.get('connections', []))
            
            print(f"✅ Fichier de données accessible")
            print(f"   📡 Alertes: {alerts_count}")
            print(f"   🔗 Connexions: {connections_count}")
            
            return True
        except Exception as e:
            print(f"❌ Erreur lecture données: {e}")
            return False
    else:
        print("❌ Fichier de données non trouvé")
        return False

def test_detection_system():
    """Teste le système de détection"""
    print("\n🚨 Test du système de détection...")
    
    # Simuler une attaque DoS
    test_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.5',
        'source_port': 12345,
        'dest_port': 80,
        'protocol': 'tcp',
        'connections_count': 50,  # Nombre élevé pour déclencher DoS
        'bytes_sent': 5000,
        'bytes_received': 0
    }
    
    try:
        response = requests.post('http://localhost:5000/api/detect', 
                               json=test_data, timeout=5)
        
        if response.status_code in [200, 201]:
            result = response.json()
            print(f"✅ Détection testée: {result.get('attackType', 'Unknown')}")
            return True
        else:
            print(f"⚠️ Détection répond avec code {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur test détection: {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🧪 TEST DU SYSTÈME IDS COMPLET")
    print("=" * 50)
    
    tests = [
        test_backend,
        test_api_endpoints,
        test_network_data,
        test_detection_system
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"📊 Résultats: {passed}/{total} tests réussis")
    
    if passed == total:
        print("🎉 Tous les tests sont passés! Le système est opérationnel.")
        print("\n🚀 Pour tester votre attaque DoS:")
        print("1. Lancez: sudo hping3 -S --flood -V -p 80 129.0.60.57")
        print("2. Ouvrez: http://localhost:3000")
        print("3. Vérifiez les alertes en temps réel!")
    else:
        print("⚠️ Certains tests ont échoué. Vérifiez les erreurs ci-dessus.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 