import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from keras.utils import to_categorical
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Tuple, Dict
import os
from datetime import datetime

from .tf_model import IDSModel, ATTACK_TYPES

def load_and_preprocess_data(data_path: str) -> Tuple[np.ndarray, np.ndarray, StandardScaler, LabelEncoder]:
    """
    Charge et prétraite les données du dataset NSL-KDD.
    """
    # Chargement des données
    print("Chargement des données...")
    df = pd.read_csv(data_path)
    
    # Séparation features et labels
    y = df.iloc[:, -1]   # Dernière colonne (classe)
    X = df.iloc[:, :-1]  # Toutes les colonnes sauf la dernière
    
    # Conversion des colonnes catégorielles en variables numériques
    print("Conversion des variables catégorielles...")
    categorical_columns = X.select_dtypes(include=['object']).columns
    X = pd.get_dummies(X, columns=categorical_columns)
    
    # Prétraitement des features
    print("Prétraitement des features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Encodage des labels
    print("Encodage des labels...")
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    y_categorical = to_categorical(y_encoded)
    
    return X_scaled, y_categorical, scaler, label_encoder

def plot_training_history(history: Dict, save_path: str):
    """
    Trace et sauvegarde les graphiques d'entraînement.
    """
    # Création du dossier si nécessaire
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    # Configuration du style avec seaborn
    sns.set_style("whitegrid")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 5))
    
    # Graphique de la loss
    sns.lineplot(data=history['loss'], label='Training Loss', ax=ax1)
    sns.lineplot(data=history['val_loss'], label='Validation Loss', ax=ax1)
    ax1.set_title('Model Loss')
    ax1.set_xlabel('Epoch')
    ax1.set_ylabel('Loss')
    
    # Graphique de l'accuracy
    sns.lineplot(data=history['accuracy'], label='Training Accuracy', ax=ax2)
    sns.lineplot(data=history['val_accuracy'], label='Validation Accuracy', ax=ax2)
    ax2.set_title('Model Accuracy')
    ax2.set_xlabel('Epoch')
    ax2.set_ylabel('Accuracy')
    
    # Sauvegarde
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()

def train_ids_model(data_path: str, model_save_path: str):
    """
    Entraîne le modèle IDS et sauvegarde les résultats.
    """
    # Chargement et prétraitement des données
    X, y, scaler, label_encoder = load_and_preprocess_data(data_path)
    
    # Split des données
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y.argmax(axis=1)
    )
    
    # Reshape pour Conv1D (ajoute une dimension pour les features)
    X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
    X_val = X_val.reshape(X_val.shape[0], X_val.shape[1], 1)
    
    # Création et entraînement du modèle
    print("Création du modèle...")
    num_classes = y.shape[1]  # Utilise le nombre réel de classes
    model = IDSModel(input_shape=(X_train.shape[1], 1), num_classes=num_classes)
    
    print(f"Début de l'entraînement avec {num_classes} classes...")
    history = model.train(X_train, y_train, X_val, y_val)
    
    # Sauvegarde du modèle et des transformateurs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_path = os.path.join(model_save_path, f"ids_model_{timestamp}")
    os.makedirs(base_path, exist_ok=True)
    
    model.save(
        model_path=os.path.join(base_path, "model"),
        scaler_path=os.path.join(base_path, "scaler.npy"),
        encoder_path=os.path.join(base_path, "label_encoder.json")
    )
    
    # Sauvegarde des graphiques d'entraînement
    plot_training_history(
        history.history,
        os.path.join(base_path, "training_history.png")
    )
    
    print(f"Modèle et résultats sauvegardés dans : {base_path}")
    return model, scaler, label_encoder

if __name__ == "__main__":
    # Chemins des fichiers
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "../../../"))
    DATA_PATH = os.path.join(PROJECT_ROOT, "data/processed/NSL-KDD-Train.csv")
    MODEL_SAVE_PATH = os.path.join(PROJECT_ROOT, "data/models")
    
    # Entraînement du modèle
    model, scaler, label_encoder = train_ids_model(DATA_PATH, MODEL_SAVE_PATH)

    # --- Calcul des métriques sur le jeu de validation ---
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    import json
    from pathlib import Path
    from datetime import datetime

    # Charger les données de validation
    # (On suppose que X_val, y_val sont encore accessibles, sinon il faut les retourner par train_ids_model)
    # Pour l'exemple, on recharge les données
    X, y, _, _ = load_and_preprocess_data(DATA_PATH)
    from sklearn.model_selection import train_test_split
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y.argmax(axis=1)
    )
    X_val = X_val.reshape(X_val.shape[0], X_val.shape[1], 1)
    y_val_labels = y_val.argmax(axis=1)
    y_pred = model.model.predict(X_val)
    y_pred_labels = y_pred.argmax(axis=1)

    accuracy = accuracy_score(y_val_labels, y_pred_labels)
    precision = precision_score(y_val_labels, y_pred_labels, average='weighted', zero_division=0)
    recall = recall_score(y_val_labels, y_pred_labels, average='weighted', zero_division=0)
    f1 = f1_score(y_val_labels, y_pred_labels, average='weighted', zero_division=0)

    DATA_DIR = Path(__file__).parent.parent / 'data'
    DATA_DIR.mkdir(exist_ok=True)

    # --- Sauvegarde des métriques actuelles ---
    metrics = {
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'last_update': datetime.now().isoformat()
    }
    with open(DATA_DIR / 'model_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)

    # --- Ajout à l'historique d'entraînement ---
    history_file = DATA_DIR / 'training_history.json'
    history = []
    if history_file.exists():
        with open(history_file, 'r') as f:
            history = json.load(f)
    history.append({
        'date': datetime.now().isoformat(),
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1)
    })
    with open(history_file, 'w') as f:
        json.dump(history, f, indent=2)

    # --- (Optionnel) Sauvegarde des logs de tests ---
    test_logs = []
    for i in range(len(y_val_labels)):
        test_logs.append({
            'timestamp': datetime.now().isoformat(),
            'test_type': 'Validation',
            'input': str(X_val[i].flatten().tolist()),
            'prediction': int(y_pred_labels[i]),
            'confidence': float(y_pred[i].max()),
            'true_class': int(y_val_labels[i]),
            'status': 'success' if y_pred_labels[i] == y_val_labels[i] else 'fail'
        })
    with open(DATA_DIR / 'test_logs.json', 'w') as f:
        json.dump(test_logs, f, indent=2) 