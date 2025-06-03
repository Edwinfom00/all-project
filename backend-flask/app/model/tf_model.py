import tensorflow as tf
from tensorflow import keras
from keras import layers
from keras import models
import numpy as np
from typing import Tuple, List, Dict, Any
import os
import json
import pandas as pd

class IDSModel:
    def __init__(self, input_shape: Tuple[int, ...], num_classes: int):
        self.input_shape = input_shape
        self.num_classes = num_classes
        self.model = self._build_model()
        self.label_encoder = None
        self.feature_scaler = None
        
    def _build_model(self) -> tf.keras.Model:
        """
        Construit un modèle CNN-LSTM pour la détection d'intrusions.
        Architecture :
        1. Couche d'entrée
        2. Couches Conv1D pour l'extraction de caractéristiques
        3. Couche LSTM pour la capture des dépendances temporelles
        4. Couches denses pour la classification
        """
        model = models.Sequential([
            # Couche d'entrée
            layers.Input(shape=self.input_shape),
            
            # Couches Conv1D
            layers.Conv1D(64, 3, activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.Conv1D(128, 3, activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(2),
            layers.Dropout(0.25),
            
            # Couche LSTM
            layers.LSTM(128, return_sequences=True),
            layers.Dropout(0.25),
            layers.LSTM(64),
            layers.Dropout(0.25),
            
            # Couches denses
            layers.Dense(128, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.5),
            layers.Dense(64, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.5),
            
            # Couche de sortie
            layers.Dense(self.num_classes, activation='softmax')
        ])
        
        # Compilation du modèle
        model.compile(
            optimizer='adam',
            loss='categorical_crossentropy',
            metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
        )
        
        return model
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray, y_val: np.ndarray,
              epochs: int = 50, batch_size: int = 32) -> tf.keras.callbacks.History:
        """
        Entraîne le modèle sur les données fournies.
        """
        # Callbacks pour l'entraînement
        callbacks = [
            tf.keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=5,
                restore_best_weights=True
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.2,
                patience=3,
                min_lr=1e-6
            )
        ]
        
        # Entraînement du modèle
        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=1
        )
        
        return history
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Fait des prédictions sur les données d'entrée.
        """
        return self.model.predict(X)
    
    def save(self, model_path: str, scaler_path: str = None, encoder_path: str = None):
        """
        Sauvegarde le modèle et les transformateurs.
        """
        # Création du dossier si nécessaire
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # Sauvegarde du modèle
        self.model.save(model_path)
        
        # Sauvegarde du scaler et de l'encoder si fournis
        if self.feature_scaler and scaler_path:
            np.save(scaler_path, self.feature_scaler)
        
        if self.label_encoder and encoder_path:
            with open(encoder_path, 'w') as f:
                json.dump(self.label_encoder, f)
    
    @classmethod
    def load(cls, model_path: str, scaler_path: str = None, encoder_path: str = None) -> 'IDSModel':
        """
        Charge un modèle sauvegardé.
        """
        # Chargement du modèle
        model = tf.keras.models.load_model(model_path)
        
        # Création de l'instance
        instance = cls(model.input_shape[1:], model.output_shape[1])
        instance.model = model
        
        # Chargement du scaler et de l'encoder si disponibles
        if scaler_path and os.path.exists(scaler_path):
            instance.feature_scaler = np.load(scaler_path)
        
        if encoder_path and os.path.exists(encoder_path):
            with open(encoder_path, 'r') as f:
                instance.label_encoder = json.load(f)
        
        return instance

# Mapping des types d'attaques
ATTACK_TYPES = {
    0: 'Normal',
    1: 'DoS',
    2: 'Probe',
    3: 'R2L',
    4: 'U2R',
    5: 'SQL Injection',
    6: 'XSS',
    7: 'Port Scan',
    8: 'Brute Force'
}

def load_data(data_path):
    # Charger les données
    df = pd.read_csv(data_path)
    
    # Séparer features et labels
    X = df.iloc[:, :-1].values  # Toutes les colonnes sauf la dernière
    y = df.iloc[:, -1].values   # Dernière colonne (classe)
    
    return X, y 