 #!/usr/bin/env python3
"""
Script de test pour vérifier que l'import preprocess_data fonctionne
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

def test_import():
    """Test l'import de preprocess_data"""
    try:
        from app.utils.preprocessing import preprocess_data
        print("✅ Import preprocess_data réussi")
        return True
    except ImportError as e:
        print(f"❌ Erreur import preprocess_data: {e}")
        return False

def test_ai_model_import():
    """Test l'import de predict_intrusion"""
    try:
        from app.model.ai_model import predict_intrusion
        print("✅ Import predict_intrusion réussi")
        return True
    except ImportError as e:
        print(f"❌ Erreur import predict_intrusion: {e}")
        return False

def test_preprocessing():
    """Test le préprocessing des données"""
    try:
        from app.utils.preprocessing import preprocess_data
        
        # Données de test
        test_data = {
            'source_ip': '192.168.1.100',
            'destination_ip': '192.168.1.178',
            'connections_count': 10,
            'bytes_sent': 1000,
            'bytes_received': 500,
            'flag': 'S',
            'duration': 0
        }
        
        # Test du préprocessing
        processed_data = preprocess_data(test_data)
        print(f"✅ Préprocessing réussi: {len(processed_data.get('features', []))} features")
        return True
    except Exception as e:
        print(f"❌ Erreur préprocessing: {e}")
        return False

def test_prediction():
    """Test la prédiction avec l'IA"""
    try:
        from app.model.ai_model import predict_intrusion
        from app.utils.preprocessing import preprocess_data
        
        # Données de test
        test_data = {
            'source_ip': '192.168.1.100',
            'destination_ip': '192.168.1.178',
            'connections_count': 10,
            'bytes_sent': 1000,
            'bytes_received': 500,
            'flag': 'S',
            'duration': 0
        }
        
        # Test de la prédiction
        processed_data = preprocess_data(test_data)
        is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
        print(f"✅ Prédiction IA réussie: {attack_type} (confiance: {confidence:.2f})")
        return True
    except Exception as e:
        print(f"❌ Erreur prédiction IA: {e}")
        return False

def main():
    print("🧪 Test des imports et du préprocessing")
    print("=" * 40)
    
    # Test 1: Import preprocess_data
    import_ok = test_import()
    
    # Test 2: Import predict_intrusion
    ai_import_ok = test_ai_model_import()
    
    if import_ok and ai_import_ok:
        # Test 3: Préprocessing
        preprocessing_ok = test_preprocessing()
        
        if preprocessing_ok:
            # Test 4: Prédiction IA
            prediction_ok = test_prediction()
            
            if prediction_ok:
                print("\n🎉 TOUS LES TESTS RÉUSSIS!")
                print("✅ Le système IA fonctionne correctement")
            else:
                print("\n❌ Problème avec la prédiction IA")
        else:
            print("\n❌ Problème avec le préprocessing")
    else:
        print("\n❌ Problème avec les imports")

if __name__ == "__main__":
    main()