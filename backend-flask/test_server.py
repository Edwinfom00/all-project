#!/usr/bin/env python3
"""
Script pour tester le serveur Flask
"""

import requests
import time
import sys

def test_server():
    """Teste si le serveur Flask fonctionne"""
    try:
        # Test de santé
        response = requests.get('http://localhost:5000/health', timeout=5)
        if response.status_code == 200:
            print("✅ Serveur Flask fonctionne")
            print(f"   Réponse: {response.json()}")
            return True
        else:
            print(f"❌ Serveur répond avec code {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Impossible de se connecter au serveur Flask")
        return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def test_api_endpoints():
    """Teste les endpoints de l'API"""
    endpoints = [
        ('/api/stats/traffic', 'GET'),
        ('/api/stats/alerts', 'GET'),
        ('/api/stats/model-stats', 'GET'),
        ('/api/alerts', 'GET')
    ]
    
    for endpoint, method in endpoints:
        try:
            if method == 'GET':
                response = requests.get(f'http://localhost:5000{endpoint}', timeout=5)
            else:
                response = requests.post(f'http://localhost:5000{endpoint}', timeout=5)
            
            if response.status_code == 200:
                print(f"✅ {endpoint} - OK")
            else:
                print(f"⚠️ {endpoint} - Code {response.status_code}")
        except Exception as e:
            print(f"❌ {endpoint} - Erreur: {e}")

if __name__ == "__main__":
    print("🔍 Test du serveur Flask")
    print("=" * 30)
    
    if test_server():
        print("\n📡 Test des endpoints API:")
        test_api_endpoints()
    else:
        print("❌ Le serveur ne fonctionne pas")
        sys.exit(1) 