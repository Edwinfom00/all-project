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

# Seuils de détection pour différents types d'attaques
DETECTION_THRESHOLDS = {
    "DoS": 0.6,      # Seuil plus bas pour les DoS pour augmenter la sensibilité
    "Probe": 0.7,
    "R2L": 0.75,
    "U2R": 0.8,
    "Normal": 0.9,   # Seuil élevé pour éviter les faux négatifs
    "Unknown": 0.5   # Seuil bas pour "Unknown" pour éviter les fausses alertes
}

# Règles de détection basées sur les caractéristiques du trafic
def detect_dos_with_rules(data: Dict[str, Any]) -> Tuple[bool, float]:
    """Détecte une attaque DoS basée sur des règles simples"""
    # Caractéristiques typiques d'une attaque DoS
    connections_count = data.get('connections_count', 0)
    bytes_sent = data.get('bytes_sent', 0)
    dest_port = data.get('dest_port', 0)
    flag = data.get('flag', '')
    
    # Règles de détection DoS
    if connections_count > 40 and dest_port == 80:
        return True, 0.85  # Forte probabilité de DoS sur HTTP
    
    if connections_count > 30 and flag == 'S0':
        return True, 0.9  # Forte probabilité de SYN flood
    
    if bytes_sent > 3000 and connections_count > 20:
        return True, 0.75  # Possible DoS volumétrique
    
    return False, 0.0
def load_latest_model() -> IDSModel:
    """
    Charge le dernier modèle entraîné.
    """
    # Trouve le dossier de modèle le plus récent
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
        # Retourner un modèle par défaut
        return IDSModel(input_shape=(145, 1), num_classes=len(ATTACK_TYPES))

def get_model() -> IDSModel:
    """
    Retourne l'instance du modèle, la charge si nécessaire.
    """
    global LATEST_MODEL
    if LATEST_MODEL is None:
        try:
            LATEST_MODEL = load_latest_model()
        except Exception:
            # Si pas de modèle, on utilise un modèle simulé
            LATEST_MODEL = IDSModel(input_shape=(145, 1), num_classes=len(ATTACK_TYPES))
    return LATEST_MODEL

def predict_intrusion(data: Dict[str, Any]) -> Tuple[bool, str, float]:
    try:
        # Vérifier d'abord avec les règles de détection DoS
        is_dos, dos_confidence = detect_dos_with_rules(data)
        if is_dos:
            print(f"Attaque DoS détectée par règles avec confiance {dos_confidence}")
            return True, "DoS", dos_confidence
        
        # Extraction des features au format NSL-KDD (145 features)
        features = extract_features(data)
        
        # Vérifier que nous avons bien 145 features
        if len(features) != 145:
            # Ajuster la taille si nécessaire
            if len(features) < 145:
                features.extend([0.0] * (145 - len(features)))
            else:
                features = features[:145]
        
        # Normalisation des features
        features_normalized = normalize_features(features)
        
        # Vérification finale avant reshape
        if len(features_normalized) != 145:
            print(f"ERREUR: Taille après normalisation: {len(features_normalized)}")
            # Si on détecte beaucoup de connexions, c'est probablement un DoS
            if data.get('connections_count', 0) > 30:
                return True, "DoS", 0.7
            return False, "Normal", 0.0
        
        # Reshape pour le modèle (batch_size=1, features=145, channels=1)
        X = np.array(features_normalized, dtype=np.float32).reshape(1, 145, 1)

        # Prédiction
        model = get_model()
        predictions = model.predict(X)
        predicted_class = np.argmax(predictions[0])
        confidence = float(np.max(predictions[0]))
        
        # Conversion en résultat
        if predicted_class < len(ATTACK_TYPES):
            attack_type = ATTACK_TYPES[predicted_class]
        else:
            # Si le trafic a des caractéristiques de DoS mais n'est pas reconnu
            if data.get('connections_count', 0) > 20:
                attack_type = "DoS"
                confidence = 0.7
            else:
                attack_type = "Normal"  # Par défaut, considérer comme normal au lieu de "Unknown"
        
        # Appliquer les seuils de détection
        threshold = DETECTION_THRESHOLDS.get(attack_type, 0.7)
        
        # Si la confiance est inférieure au seuil, considérer comme normal
        if confidence < threshold and attack_type != "Normal":
            # Sauf pour DoS avec beaucoup de connexions
            if attack_type == "DoS" and data.get('connections_count', 0) > 30:
                pass  # Garder comme DoS
            else:
                attack_type = "Normal"
                confidence = 1.0 - confidence  # Inverser la confiance
        
        is_intrusion = attack_type != "Normal"
        return is_intrusion, attack_type, confidence

    except Exception as e:
        print(f"Erreur lors de la prédiction : {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        
        # En cas d'erreur, vérifier quand même si c'est un DoS basé sur les règles
        if data.get('connections_count', 0) > 40:
            return True, "DoS", 0.7
        
        # Sinon, pas d'intrusion
        return False, "Normal", 0.0

def preprocess_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prétraite les données pour le modèle : extrait et normalise les features.
    """
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
        # Retourner des features par défaut en cas d'erreur
        data['features'] = [0.0] * 145
        data['features_count'] = 145
        return data

def validate_features(features: List[float]) -> bool:
    """
    Valide que les features sont dans le bon format.
    """
    if not isinstance(features, list):
        return False
    if len(features) != 145:
        return False
    if not all(isinstance(f, (int, float)) for f in features):
        return False
    return True

def debug_features(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fonction de debug pour analyser les features extraites.
    """
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
    """
    Charge le modèle ML depuis le fichier.
    """
    if model_path is None:
        # Par défaut, charge le dernier modèle
        return load_latest_model()
    return IDSModel.load(model_path, scaler_path, encoder_path)

def save_model(model, model_path, scaler_path=None, encoder_path=None):
    """
    Sauvegarde le modèle ML dans un fichier.
    """
    model.save(model_path, scaler_path, encoder_path)
