#!/usr/bin/env python3
"""
Script de test pour vérifier le fonctionnement du système de détection d'intrusions.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.model.ai_model import predict_intrusion, get_model
from app.utils.preprocessing import extract_features, normalize_features
import json

def test_model_loading():
    """Teste le chargement du modèle"""
    print("=== Test de chargement du modèle ===")
    try:
        model = get_model()
        print("✅ Modèle chargé avec succès")
        print(f"   Input shape: {model.input_shape}")
        print(f"   Output shape: {model.model.output_shape}")
        return True
    except Exception as e:
        print(f"❌ Erreur lors du chargement du modèle: {e}")
        return False

def test_feature_extraction():
    """Teste l'extraction des features"""
    print("\n=== Test d'extraction des features ===")
    
    # Données de test
    test_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.5',
        'source_port': 12345,
        'dest_port': 80,
        'protocol': 'tcp',
        'connections_count': 25,
        'bytes_sent': 1000,
        'bytes_received': 500
    }
    
    try:
        features = extract_features(test_data)
        print(f"✅ Features extraites: {len(features)} features")
        print(f"   Premières 10 features: {features[:10]}")
        
        normalized = normalize_features(features)
        print(f"✅ Features normalisées: {len(normalized)} features")
        print(f"   Premières 10 features normalisées: {normalized[:10]}")
        
        return True
    except Exception as e:
        print(f"❌ Erreur lors de l'extraction des features: {e}")
        return False

def test_prediction():
    """Teste la prédiction"""
    print("\n=== Test de prédiction ===")
    
    # Données de test normales
    normal_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.5',
        'source_port': 12345,
        'dest_port': 80,
        'protocol': 'tcp',
        'connections_count': 2,
        'bytes_sent': 100,
        'bytes_received': 50
    }
    
    # Données de test suspectes (DoS)
    dos_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.5',
        'source_port': 12345,
        'dest_port': 80,
        'protocol': 'tcp',
        'connections_count': 50,
        'bytes_sent': 5000,
        'bytes_received': 0
    }
    
    try:
        # Test avec des données normales
        is_intrusion, attack_type, confidence = predict_intrusion(normal_data)
        print(f"✅ Prédiction normale: intrusion={is_intrusion}, type={attack_type}, confiance={confidence:.2f}")
        
        # Test avec des données suspectes
        is_intrusion, attack_type, confidence = predict_intrusion(dos_data)
        print(f"✅ Prédiction DoS: intrusion={is_intrusion}, type={attack_type}, confiance={confidence:.2f}")
        
        return True
    except Exception as e:
        print(f"❌ Erreur lors de la prédiction: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def test_network_scanner():
    """Teste le scanner réseau"""
    print("\n=== Test du scanner réseau ===")
    
    try:
        from app.utils.network_scanner import NetworkScanner
        scanner = NetworkScanner()
        print("✅ Scanner réseau créé avec succès")
        
        # Test d'une connexion simulée
        import psutil
        connections = psutil.net_connections()
        if connections:
            print(f"✅ Connexions réseau détectées: {len(connections)} connexions")
            return True
        else:
            print("⚠️ Aucune connexion réseau détectée")
            return True
    except Exception as e:
        print(f"❌ Erreur lors du test du scanner: {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🔍 Test du système de détection d'intrusions")
    print("=" * 50)
    
    tests = [
        test_model_loading,
        test_feature_extraction,
        test_prediction,
        test_network_scanner
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"📊 Résultats: {passed}/{total} tests réussis")
    
    if passed == total:
        print("🎉 Tous les tests sont passés! Le système semble fonctionnel.")
    else:
        print("⚠️ Certains tests ont échoué. Vérifiez les erreurs ci-dessus.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 