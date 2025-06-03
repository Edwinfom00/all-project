# Backend Flask - Système de Détection d'Intrusions avec IA

Ce backend implémente un système de détection d'intrusions (IDS) basé sur l'apprentissage profond, utilisant une architecture hybride CNN-LSTM.

## Architecture du Backend

```
backend-flask/
├── app/
│   ├── model/              # Modèles d'IA et logique de prédiction
│   │   ├── tf_model.py     # Implémentation du modèle CNN-LSTM
│   │   └── train_model.py  # Script d'entraînement
│   ├── routes/             # Routes de l'API
│   │   └── alerts.py       # Endpoints pour les alertes
│   └── __init__.py         # Configuration de l'application
├── data/
│   ├── models/             # Modèles entraînés
│   └── processed/          # Données d'entraînement
└── requirements.txt        # Dépendances Python
```

## Modèle d'IA

### Architecture du Modèle

Le modèle utilise une architecture hybride CNN-LSTM :

1. **Couches CNN (Convolutionnelles)**
   - Extraction de caractéristiques locales
   - 2 couches Conv1D (64 et 128 filtres)
   - BatchNormalization pour stabiliser l'apprentissage
   - MaxPooling1D pour réduire la dimensionnalité
   - Dropout (0.25) pour éviter le surapprentissage

2. **Couches LSTM**
   - Capture des dépendances temporelles
   - 2 couches LSTM (128 et 64 unités)
   - Dropout entre les couches

3. **Couches Denses**
   - Classification finale
   - 2 couches denses (128 et 64 neurones)
   - BatchNormalization et Dropout
   - Couche de sortie avec activation softmax

### Prétraitement des Données

1. **Chargement des données**
   - Utilisation du dataset NSL-KDD
   - Séparation features/labels

2. **Traitement des features**
   - Encodage one-hot des variables catégorielles
   - Standardisation des variables numériques
   - Reshape pour Conv1D

3. **Traitement des labels**
   - Encodage des classes
   - Conversion en format catégorique

### Entraînement

```python
# Configuration
- Optimizer: Adam
- Loss: Categorical Crossentropy
- Metrics: Accuracy, Precision, Recall
- Batch Size: 32
- Epochs: 50 (avec early stopping)
```

**Callbacks**:
- EarlyStopping: Arrêt si pas d'amélioration
- ReduceLROnPlateau: Réduction du learning rate

## Installation

1. Créer un environnement virtuel :
```bash
python -m venv venv
source venv/Scripts/activate  # Windows
source venv/bin/activate      # Linux/Mac
```

2. Installer les dépendances :
```bash
pip install -r requirements.txt
```

## Utilisation

### Entraînement du Modèle

```bash
python -m app.model.train_model
```

Le modèle entraîné sera sauvegardé dans `data/models/` avec :
- Le modèle TensorFlow
- Le scaler pour la normalisation
- L'encodeur de labels

### API Endpoints

#### GET /api/alerts
- Liste les dernières alertes détectées
- Paramètres de filtrage disponibles

#### POST /api/alerts/analyze
- Analyse un paquet réseau
- Retourne la prédiction du modèle

## Performance

Le modèle est évalué sur :
- Accuracy
- Precision
- Recall
- Matrice de confusion

Les graphiques d'entraînement sont sauvegardés automatiquement. 