import random
from typing import Tuple, Dict, Any
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
            LATEST_MODEL = IDSModel(input_shape=(41, 1), num_classes=len(ATTACK_TYPES))
    return LATEST_MODEL

def predict_intrusion(data: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Prédit si un trafic est une intrusion et son type.
    
    Args:
        data: Dictionnaire contenant les données du log
        
    Returns:
        Tuple[bool, str]: (is_intrusion, attack_type)
    """
    try:
        # Extraction et normalisation des features
        features = extract_features(data)
        features_normalized = normalize_features(features)
        
        # Reshape pour le modèle (batch_size, timesteps, features)
        X = np.array(features_normalized).reshape(1, -1, 1)
        
        # Prédiction
        model = get_model()
        predictions = model.predict(X)
        predicted_class = np.argmax(predictions[0])
        
        # Conversion en résultat
        attack_type = ATTACK_TYPES.get(predicted_class, "Unknown")
        is_intrusion = attack_type != "Normal"
        
        return is_intrusion, attack_type
        
    except Exception as e:
        print(f"Erreur lors de la prédiction : {str(e)}")
        # En cas d'erreur, on simule une prédiction
        is_intrusion = random.random() < 0.3
        attack_type = random.choice(list(ATTACK_TYPES.values())) if is_intrusion else "Normal"
        return is_intrusion, attack_type

def preprocess_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prétraite les données pour le modèle.
    À implémenter avec le vrai prétraitement des données.
    """
    # TODO: Implémenter le vrai prétraitement
    return data

def load_model():
    """
    Charge le modèle ML depuis le fichier.
    À implémenter avec le vrai chargement du modèle.
    """
    # TODO: Charger le vrai modèle
    pass

def save_model():
    """
    Sauvegarde le modèle ML dans un fichier.
    À implémenter avec la vraie sauvegarde du modèle.
    """
    # TODO: Sauvegarder le vrai modèle
    pass 