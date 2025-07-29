#!/usr/bin/env python3
"""
Script de test pour vérifier la classification IA des attaques
"""

import sys
import os
import time
import json
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.model.ai_model import predict_intrusion
from app.utils.preprocessing import preprocess_data

def test_port_scan_classification():
    """Test la classification d'un scan de port"""
    print("🔍 Test: Classification scan de port")
    
    # Données typiques d'un scan de port
    port_scan_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '192.168.1.178',
        'connections_count': 8,  # Peu de connexions
        'bytes_sent': 200,
        'bytes_received': 100,
        'flag': 'S',
        'duration': 0,
        'serror_rate': 0.2,
        'srv_serror_rate': 0.2,
        'rerror_rate': 0.1,
        'srv_rerror_rate': 0.1
    }
    
    processed_data = preprocess_data(port_scan_data)
    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
    
    print(f"   Résultat IA: {attack_type} (confiance: {confidence:.2f})")
    print(f"   Intrusion détectée: {is_intrusion}")
    
    if attack_type in ["Probe", "Port Scan"]:
        print("   ✅ CORRECT: Scan de port bien classifié")
    elif attack_type == "DoS":
        print("   ❌ PROBLÈME: Scan de port classifié comme DoS")
    else:
        print(f"   ⚠️ Résultat inattendu: {attack_type}")
    
    return attack_type

def test_dos_classification():
    """Test la classification d'une attaque DoS"""
    print("\n🚨 Test: Classification attaque DoS")
    
    # Données typiques d'une attaque DoS
    dos_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '192.168.1.178',
        'connections_count': 200,  # Beaucoup de connexions
        'bytes_sent': 15000,
        'bytes_received': 0,
        'flag': 'S0',
        'duration': 0,
        'serror_rate': 0.8,
        'srv_serror_rate': 0.8,
        'rerror_rate': 0.1,
        'srv_rerror_rate': 0.1
    }
    
    processed_data = preprocess_data(dos_data)
    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
    
    print(f"   Résultat IA: {attack_type} (confiance: {confidence:.2f})")
    print(f"   Intrusion détectée: {is_intrusion}")
    
    if attack_type == "DoS":
        print("   ✅ CORRECT: Attaque DoS bien classifiée")
    elif attack_type in ["Probe", "Port Scan"]:
        print("   ❌ PROBLÈME: DoS classifié comme Probe/Port Scan")
    else:
        print(f"   ⚠️ Résultat inattendu: {attack_type}")
    
    return attack_type

def test_normal_traffic_classification():
    """Test la classification du trafic normal"""
    print("\n✅ Test: Classification trafic normal")
    
    # Données typiques de trafic normal
    normal_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '192.168.1.178',
        'connections_count': 2,
        'bytes_sent': 500,
        'bytes_received': 1000,
        'flag': 'SF',
        'duration': 5,
        'serror_rate': 0.0,
        'srv_serror_rate': 0.0,
        'rerror_rate': 0.0,
        'srv_rerror_rate': 0.0
    }
    
    processed_data = preprocess_data(normal_data)
    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
    
    print(f"   Résultat IA: {attack_type} (confiance: {confidence:.2f})")
    print(f"   Intrusion détectée: {is_intrusion}")
    
    if attack_type == "Normal":
        print("   ✅ CORRECT: Trafic normal bien classifié")
    else:
        print(f"   ❌ PROBLÈME: Trafic normal classifié comme {attack_type}")
    
    return attack_type

def test_ai_model_loading():
    """Test le chargement du modèle IA"""
    print("\n🤖 Test: Chargement du modèle IA")
    
    try:
        from app.model.ai_model import get_model
        model = get_model()
        print("   ✅ Modèle IA chargé avec succès")
        return True
    except Exception as e:
        print(f"   ❌ Erreur chargement modèle IA: {e}")
        return False

def test_feature_extraction():
    """Test l'extraction des features"""
    print("\n🔧 Test: Extraction des features")
    
    try:
        test_data = {
            'source_ip': '192.168.1.100',
            'destination_ip': '192.168.1.178',
            'connections_count': 10,
            'bytes_sent': 1000,
            'bytes_received': 500,
            'flag': 'S',
            'duration': 0
        }
        
        features = preprocess_data(test_data)
        print(f"   ✅ Features extraites: {len(features.get('features', []))} features")
        return True
    except Exception as e:
        print(f"   ❌ Erreur extraction features: {e}")
        return False

def main():
    print("🧪 Test de classification IA des attaques")
    print("=" * 50)
    
    # Test 1: Chargement du modèle
    model_loaded = test_ai_model_loading()
    
    # Test 2: Extraction des features
    features_ok = test_feature_extraction()
    
    if model_loaded and features_ok:
        # Test 3: Classification scan de port
        port_result = test_port_scan_classification()
        
        # Test 4: Classification DoS
        dos_result = test_dos_classification()
        
        # Test 5: Classification trafic normal
        normal_result = test_normal_traffic_classification()
        
        print("\n🎯 Résumé des tests IA:")
        if port_result in ["Probe", "Port Scan"]:
            print("   ✅ Scan de port correctement classifié")
        else:
            print(f"   ❌ Scan de port mal classifié: {port_result}")
        
        if dos_result == "DoS":
            print("   ✅ Attaque DoS correctement classifiée")
        else:
            print(f"   ❌ Attaque DoS mal classifiée: {dos_result}")
        
        if normal_result == "Normal":
            print("   ✅ Trafic normal correctement classifié")
        else:
            print(f"   ❌ Trafic normal mal classifié: {normal_result}")
        
        print("\n💡 Le système utilise maintenant l'IA pour classifier les attaques!")
        print("   - Scan de port → Probe/Port Scan")
        print("   - Attaque DoS → DoS")
        print("   - Trafic normal → Normal")
    else:
        print("\n❌ Problème avec le modèle IA ou l'extraction des features")

if __name__ == "__main__":
    main() 