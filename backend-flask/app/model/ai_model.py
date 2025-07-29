import random
from typing import Tuple, Dict, Any, List
import numpy as np
import os
import json
from .tf_model import IDSModel, ATTACK_TYPES
from ..utils.preprocessing import extract_features, normalize_features

# Chemins des fichiers du modèle
MODEL_DIR = os.path.join(os.path.dirname(__file__), "../../../data/models")
LATEST_MODEL = None  # Sera chargé à la première utilisation

# SEUILS CORRIGÉS - Plus bas pour détecter plus d'attaques
DETECTION_THRESHOLDS = {
    "DoS": 0.6,      # Réduit de 0.8 à 0.6
    "Probe": 0.5,    # Réduit de 0.7 à 0.5
    "R2L": 0.65,
    "U2R": 0.7,
    "Normal": 0.4,   # Réduit de 0.9 à 0.4
    "Unknown": 0.3   # Réduit pour éviter les fausses alertes
}

def detect_dos_with_rules(data: Dict[str, Any]) -> Tuple[bool, float]:
    """Détecte une attaque DoS basée sur des règles simples - VERSION CORRIGÉE"""
    connections_count = data.get('connections_count', 0)
    bytes_sent = data.get('bytes_sent', 0)
    dest_port = data.get('dest_port', 0)
    flag = data.get('flag', '')
    
    # RÈGLES CORRIGÉES pour DoS
    # Vraie attaque DoS : beaucoup de connexions vers service
    if connections_count > 100 and dest_port in [80, 443, 22, 21, 25]:
        return True, 0.9  # DoS vers service critique
    
    if connections_count > 80 and flag in ['S0', 'S']:
        return True, 0.95  # SYN flood évident
    
    if connections_count > 60 and bytes_sent > 5000:
        return True, 0.85  # DoS volumétrique
    
    if connections_count > 150:  # Seuil très élevé pour DoS certain
        return True, 0.9
    
    # Ne pas interférer avec les port scans (10-50 connexions)
    # Laisser l'IA décider pour ces cas
    return False, 0.0

def detect_probe_with_rules(data: Dict[str, Any]) -> Tuple[bool, float]:
    """Détecte une attaque Probe basée sur des règles simples - NOUVEAU"""
    connections_count = data.get('connections_count', 0)
    dest_port = data.get('dest_port', 0)
    flag = data.get('flag', '')
    
    # Port scan typique : connexions modérées, ports variés
    if 10 <= connections_count <= 60:
        # Ports de scan typiques
        if dest_port in [22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 1433, 3389]:
            return True, 0.8
        
        # Flags typiques de scan
        if flag in ['REJ', 'S0', 'RSTO']:
            return True, 0.75
    
    # Scan rapide avec peu de connexions mais ciblé
    if 5 <= connections_count <= 15 and flag in ['REJ', 'RSTO']:
        return True, 0.7
    
    return False, 0.0

def load_latest_model() -> IDSModel:
    """Charge le dernier modèle entraîné."""
    try:
        model_dirs = [d for d in os.listdir(MODEL_DIR) if d.startswith("ids_model_")]
        if not model_dirs:
            raise FileNotFoundError("Aucun modèle trouvé. Veuillez entraîner le modèle d'abord.")
        
        latest_dir = sorted(model_dirs)[-1]
        model_path = os.path.join(MODEL_DIR, latest_dir, "model")
        scaler_path = os.path.join(MODEL_DIR, latest_dir, "scaler.npy")
        encoder_path = os.path.join(MODEL_DIR, latest_dir, "label_encoder.json")
        return IDSModel.load(model_path, scaler_path, encoder_path)
    except Exception as e:
        print(f"Erreur lors du chargement du modèle: {e}")
        return IDSModel(input_shape=(145, 1), num_classes=len(ATTACK_TYPES))

def get_model() -> IDSModel:
    """Retourne l'instance du modèle, la charge si nécessaire."""
    global LATEST_MODEL
    if LATEST_MODEL is None:
        try:
            LATEST_MODEL = load_latest_model()
        except Exception:
            LATEST_MODEL = IDSModel(input_shape=(145, 1), num_classes=len(ATTACK_TYPES))
    return LATEST_MODEL

def debug_prediction(data, features_normalized, predictions):
    import numpy as np
    print("🔍 DEBUG PRÉDICTION:")
    print(f"Connexions: {data.get('connections_count')}")
    print(f"Port destination: {data.get('dest_port', 0)}")
    print(f"Flag: {data.get('flag', '')}")
    print(f"Features [20-25]: {features_normalized[20:25]}")
    print("Prédictions brutes:")
    for i, label in ATTACK_TYPES.items():
        print(f"  {label}: {predictions[0][i]:.3f}")
    pred_idx = int(np.argmax(predictions[0]))
    if pred_idx in ATTACK_TYPES:
        print(f"Classe prédite: {ATTACK_TYPES[pred_idx]}")
    else:
        print(f"❌ Classe prédite inconnue (index={pred_idx}) ! ATTACK_TYPES keys: {list(ATTACK_TYPES.keys())}")

def predict_intrusion(data: Dict[str, Any]) -> Tuple[bool, str, float]:
    """VERSION COMPLÈTEMENT CORRIGÉE de predict_intrusion"""
    try:
        # Vérifier d'abord avec les règles de détection DoS
        is_dos, dos_confidence = detect_dos_with_rules(data)
        if is_dos:
            print(f"✅ DoS détecté par règles avec confiance {dos_confidence}")
            return True, "DoS", dos_confidence
        
        # Vérifier avec les règles de détection Probe
        is_probe, probe_confidence = detect_probe_with_rules(data)
        if is_probe:
            print(f"✅ Probe détecté par règles avec confiance {probe_confidence}")
            return True, "Probe", probe_confidence
        
        # Extraction et normalisation des features
        features = extract_features(data)
        
        if len(features) != 145:
            if len(features) < 145:
                features.extend([0.0] * (145 - len(features)))
            else:
                features = features[:145]
        
        features_normalized = normalize_features(features)
        
        if len(features_normalized) != 145:
            print(f"❌ ERREUR: Taille après normalisation: {len(features_normalized)}")
            # Fallback simple
            connections_count = data.get('connections_count', 0)
            if connections_count > 100:
                return True, "DoS", 0.7
            elif connections_count > 10:
                return True, "Probe", 0.6
            return False, "Normal", 0.5
        
        # Reshape pour le modèle
        X = np.array(features_normalized, dtype=np.float32).reshape(1, 145, 1)

        # Prédiction IA
        model = get_model()
        predictions = model.predict(X)
        predicted_class = np.argmax(predictions[0])
        confidence = float(np.max(predictions[0]))
        
        # Afficher le debug
        debug_prediction(data, features_normalized, predictions)
        
        # Conversion en résultat
        if predicted_class < len(ATTACK_TYPES):
            attack_type = ATTACK_TYPES[predicted_class]
        else:
            attack_type = "Normal"
        
        # NOUVELLE LOGIQUE : Renforcer les prédictions évidentes
        connections_count = data.get('connections_count', 0)
        dest_port = data.get('dest_port', 0)
        
        # Renforcer DoS si évident
        if attack_type == "DoS" and connections_count > 80:
            confidence = min(confidence + 0.2, 0.95)
            print(f"🔥 Confiance DoS renforcée: {confidence}")
        
        # Renforcer Probe si évident  
        elif attack_type == "Probe" and 10 <= connections_count <= 60:
            confidence = min(confidence + 0.15, 0.90)
            print(f"🔍 Confiance Probe renforcée: {confidence}")
        
        # Correction basée sur les patterns évidents
        elif attack_type == "Normal":
            if connections_count > 100:
                attack_type = "DoS"
                confidence = 0.8
                print(f"🔄 Correction: Normal -> DoS (connexions: {connections_count})")
            elif 15 <= connections_count <= 50:
                attack_type = "Probe" 
                confidence = 0.7
                print(f"🔄 Correction: Normal -> Probe (connexions: {connections_count})")
        
        # Appliquer les seuils de détection
        threshold = DETECTION_THRESHOLDS.get(attack_type, 0.5)
        print(f"🎯 Seuil pour {attack_type}: {threshold}, Confiance: {confidence}")
        
        # Si confiance insuffisante, utiliser les règles de fallback
        if confidence < threshold:
            print(f"⚠️ Confiance {confidence} < seuil {threshold}")
            
            # Règles de fallback intelligentes
            if connections_count > 100:
                attack_type = "DoS"
                confidence = 0.7
                print(f"🔄 Fallback -> DoS")
            elif 10 <= connections_count <= 60:
                attack_type = "Probe"
                confidence = 0.6
                print(f"🔄 Fallback -> Probe")
            else:
                attack_type = "Normal"
                confidence = 0.5
                print(f"🔄 Fallback -> Normal")
        
        is_intrusion = attack_type != "Normal"
        print(f"🎯 RÉSULTAT FINAL: {attack_type}, Intrusion: {is_intrusion}, Confiance: {confidence}")
        return is_intrusion, attack_type, confidence

    except Exception as e:
        print(f"❌ Erreur lors de la prédiction : {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        
        # Fallback simple en cas d'erreur
        connections_count = data.get('connections_count', 0)
        if connections_count > 100:
            return True, "DoS", 0.7
        elif connections_count > 10:
            return True, "Probe", 0.6
        return False, "Normal", 0.5

def preprocess_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Prétraite les données pour le modèle : extrait et normalise les features."""
    try:
        features = extract_features(data)
        if len(features) != 145:
            if len(features) < 145:
                features.extend([0.0] * (145 - len(features)))
            else:
                features = features[:145]
        
        features_normalized = normalize_features(features)
        data['features'] = features_normalized
        data['features_count'] = len(features_normalized)
        return data
    except Exception as e:
        print(f"Erreur lors du préprocessing: {str(e)}")
        data['features'] = [0.0] * 145
        data['features_count'] = 145
        return data

def validate_features(features: List[float]) -> bool:
    """Valide que les features sont dans le bon format."""
    if not isinstance(features, list):
        return False
    if len(features) != 145:
        return False
    if not all(isinstance(f, (int, float)) for f in features):
        return False
    return True

def debug_features(data: Dict[str, Any]) -> Dict[str, Any]:
    """Fonction de debug pour analyser les features extraites."""
    features = extract_features(data)
    
    debug_info = {
        'input_data': data,
        'features_count': len(features),
        'features_sample': features[:10] if features else [],
        'features_tail': features[-10:] if len(features) >= 10 else [],
        'non_zero_features': sum(1 for f in features if f != 0.0),
        'feature_sum': sum(features),
        'feature_max': max(features) if features else 0,
        'feature_min': min(features) if features else 0
    }
    
    return debug_info

def load_model(model_path=None, scaler_path=None, encoder_path=None):
    """Charge le modèle ML depuis le fichier."""
    if model_path is None:
        return load_latest_model()
    return IDSModel.load(model_path, scaler_path, encoder_path)

def save_model(model, model_path, scaler_path=None, encoder_path=None):
    """Sauvegarde le modèle ML dans un fichier."""
    model.save(model_path, scaler_path, encoder_path)