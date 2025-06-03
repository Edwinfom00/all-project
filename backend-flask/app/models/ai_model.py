import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class AIModel:
    def __init__(self):
        self.model_path = Path(__file__).parent / 'models' / 'network_model.joblib'
        self.model = self._load_or_create_model()
        
    def _load_or_create_model(self):
        """Charge le modèle existant ou en crée un nouveau"""
        try:
            if self.model_path.exists():
                logger.info("Chargement du modèle existant...")
                return joblib.load(self.model_path)
            else:
                logger.info("Création d'un nouveau modèle...")
                model = RandomForestClassifier(n_estimators=100, random_state=42)
                # Sauvegarder le modèle vide
                self.model_path.parent.mkdir(parents=True, exist_ok=True)
                joblib.dump(model, self.model_path)
                return model
        except Exception as e:
            logger.error(f"Erreur lors du chargement/création du modèle: {e}")
            return RandomForestClassifier(n_estimators=100, random_state=42)
    
    def _preprocess_features(self, features):
        """Prétraite les caractéristiques pour le modèle"""
        # Convertir les adresses IP en nombres
        source_ip = sum(int(x) * (256 ** i) for i, x in enumerate(features['source_ip'].split('.')[::-1]))
        dest_ip = sum(int(x) * (256 ** i) for i, x in enumerate(features['dest_ip'].split('.')[::-1]))
        
        # Convertir le protocole en nombre
        protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
        protocol = protocol_map.get(features['protocol'].lower(), 3)
        
        # Convertir le statut en nombre
        status_map = {'ESTABLISHED': 0, 'LISTEN': 1, 'TIME_WAIT': 2, 'CLOSE_WAIT': 3, 'NONE': 4}
        status = status_map.get(features['status'], 5)
        
        return np.array([[
            source_ip,
            dest_ip,
            features['source_port'],
            features['dest_port'],
            protocol,
            status
        ]])
    
    def predict(self, features):
        """Fait une prédiction sur les caractéristiques données"""
        try:
            # Prétraiter les caractéristiques
            X = self._preprocess_features(features)
            
            # Faire la prédiction
            prediction = self.model.predict(X)[0]
            confidence = self.model.predict_proba(X)[0].max()
            
            return bool(prediction), float(confidence)
        except Exception as e:
            logger.error(f"Erreur lors de la prédiction: {e}")
            return False, 0.0
    
    def get_threat_type(self, features):
        """Détermine le type de menace basé sur les caractéristiques"""
        # Logique simple pour déterminer le type de menace
        if features['dest_port'] in [22, 23, 3389]:
            return 'Suspicious Port Access'
        elif features['protocol'].lower() == 'icmp':
            return 'ICMP Flood'
        elif features['status'] == 'TIME_WAIT':
            return 'Connection Flood'
        else:
            return 'Unknown Threat'
    
    def train(self, X, y):
        """Entraîne le modèle avec de nouvelles données"""
        try:
            self.model.fit(X, y)
            # Sauvegarder le modèle mis à jour
            joblib.dump(self.model, self.model_path)
            logger.info("Modèle entraîné et sauvegardé avec succès")
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement du modèle: {e}") 