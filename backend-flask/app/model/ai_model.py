import random
from typing import Tuple, Dict, Any, List
import numpy as np
import os
from .tf_model import IDSModel, ATTACK_TYPES
from ..utils.preprocessing import extract_features, normalize_features

# Chemins des fichiers du modèle
MODEL_DIR = os.path.join(os.path.dirname(__file__), "../../../data/models")
LATEST_MODEL = None  # Sera chargé à la première utilisation

def load_latest_model() -> IDSModel:
    """
    Charge le dernier modèle entraîné.
    """
    # Trouve le dossier de modèle le plus récent
    model_dirs = [d for d in os.listdir(MODEL_DIR) if d.startswith("ids_model_")]
    if not model_dirs:
        raise FileNotFoundError("Aucun modèle trouvé. Veuillez entraîner le modèle d'abord.")
    
    latest_dir = sorted(model_dirs)[-1]
    model_path = os.path.join(MODEL_DIR, latest_dir, "model")
    scaler_path = os.path.join(MODEL_DIR, latest_dir, "scaler.npy")
    encoder_path = os.path.join(MODEL_DIR, latest_dir, "label_encoder.json")
    
    return IDSModel.load(model_path, scaler_path, encoder_path)

def get_model() -> IDSModel:
    """
    Retourne l'instance du modèle, la charge si nécessaire.
    """
    global LATEST_MODEL
    if LATEST_MODEL is None:
        try:
            LATEST_MODEL = load_latest_model()
        except FileNotFoundError:
            # Si pas de modèle, on utilise un modèle simulé
            LATEST_MODEL = IDSModel(input_shape=(145, 1), num_classes=len(ATTACK_TYPES))
    return LATEST_MODEL

def predict_intrusion(data: Dict[str, Any]) -> Tuple[bool, str, float]:
    try:
        print(f"Données d'entrée: {data}")
        
        # Extraction des features au format NSL-KDD (145 features)
        features = extract_features(data)
        print(f"Features extraites: {len(features)} features")
        
        # Vérifier que nous avons bien 145 features
        if len(features) != 145:
            print(f"ERREUR: Nombre de features incorrect: {len(features)} au lieu de 145")
            # Ajuster la taille si nécessaire
            if len(features) < 145:
                features.extend([0.0] * (145 - len(features)))
            else:
                features = features[:145]
        
        # Normalisation des features
        features_normalized = normalize_features(features)
        print(f"Features normalisées: {len(features_normalized)} features")
        
        # Vérification finale avant reshape
        if len(features_normalized) != 145:
            print(f"ERREUR: Taille après normalisation: {len(features_normalized)}")
            return False, "Error", 0.0
        
        # Reshape pour le modèle (batch_size=1, features=145, channels=1)
        X = np.array(features_normalized, dtype=np.float32).reshape(1, 145, 1)
        print(f"Shape final pour le modèle: {X.shape}")

        # Prédiction
        model = get_model()
        predictions = model.predict(X)
        predicted_class = np.argmax(predictions[0])
        confidence = np.max(predictions[0])
        
        print(f"Classe prédite: {predicted_class}, Confiance: {confidence:.3f}")

        # Conversion en résultat
        if predicted_class in ATTACK_TYPES:
            attack_type = ATTACK_TYPES[predicted_class]
        else:
            attack_type = "Unknown"
            # Loguer le cas inconnu pour analyse future
            with open("unknown_predictions.log", "a") as f:
                f.write(f"{predicted_class},{confidence},{data}\n")
        is_intrusion = attack_type != "Normal"
        return is_intrusion, attack_type, float(confidence)

    except Exception as e:
        print(f"Erreur lors de la prédiction : {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        # En cas d'erreur, on retourne toujours pas d'intrusion
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

# Fonction utilitaire pour tester le preprocessing
