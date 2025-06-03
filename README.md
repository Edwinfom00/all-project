# IDS AI System

## Présentation

Ce projet est un système de détection d'intrusions (IDS) basé sur l'IA, avec un backend Flask et un frontend Next.js. Il permet :
- L'analyse du trafic réseau en temps réel
- La détection d'attaques grâce à un modèle CNN-LSTM
- L'affichage en temps réel des métriques, de l'historique d'entraînement et des logs de tests sur le dashboard

---

## Architecture

- **Backend** : Flask
  - Analyse réseau avec `psutil`
  - Modèle IA (CNN-LSTM, TensorFlow/Keras)
  - API REST pour exposer les statistiques, métriques, historique, logs
  - Scripts d'entraînement et de gestion
- **Frontend** : Next.js + Tailwind CSS
  - Dashboard en temps réel (métriques, historique, logs)
  - Affichage des alertes et statistiques réseau

---

## Installation

### 1. Prérequis
- Python 3.8+
- Node.js 18+
- pip

### 2. Installation Backend
```bash
cd backend-flask
pip install -r requirements.txt
```

### 3. Installation Frontend
```bash
cd frontend-next
npm install
```

---

## Utilisation

### 1. Lancer le système complet
Dans un terminal :
```bash
cd backend-flask
python scripts/start_all.py
```
Dans un autre terminal :
```bash
cd frontend-next
npm run dev
```

- Le backend lance le scanner réseau et le serveur Flask
- Le frontend est accessible sur [http://localhost:3000](http://localhost:3000)

### 2. Entraîner le modèle IA
Pour entraîner le modèle et mettre à jour les métriques :
```bash
cd backend-flask
python -m app.model.train_model
```
- Les métriques, l'historique et les logs de tests sont automatiquement sauvegardés dans `backend-flask/app/data/`
- Le dashboard frontend affichera les vraies valeurs après chaque entraînement

---

## API Backend

- `GET /api/stats/model-metrics` : métriques du modèle (accuracy, precision, recall, f1_score, last_update)
- `GET /api/stats/training-history` : historique d'entraînement (liste d'objets avec date, scores)
- `GET /api/stats/test-logs` : logs de tests (timestamp, entrée, prédiction, confiance, classe réelle, statut)
- `GET /api/stats/model-stats` : statistiques globales du modèle (performance, distribution des attaques, alertes récentes, statut)
- `GET /api/stats/traffic` : trafic réseau en temps réel
- `GET /api/stats/alerts` : alertes en temps réel

---

## Structure des fichiers de données

- `backend-flask/app/data/model_metrics.json` :
```json
{
  "accuracy": 0.95,
  "precision": 0.94,
  "recall": 0.93,
  "f1_score": 0.92,
  "last_update": "2024-06-03T12:00:00"
}
```
- `backend-flask/app/data/training_history.json` :
```json
[
  { "date": "2024-06-03T12:00:00", "accuracy": 0.95, "precision": 0.94, "recall": 0.93, "f1_score": 0.92 },
  ...
]
```
- `backend-flask/app/data/test_logs.json` :
```json
[
  { "timestamp": "2024-06-03T12:01:00", "test_type": "Validation", "input": "...", "prediction": 1, "confidence": 0.98, "true_class": 1, "status": "success" },
  ...
]
```

---

## Dashboard (Frontend)
- Affiche en temps réel :
  - Les métriques du modèle (accuracy, precision, recall, f1-score)
  - L'historique d'entraînement
  - Les logs de tests
  - Les alertes et statistiques réseau
- Rafraîchissement automatique toutes les secondes

---

## Personnalisation & Développement
- Pour modifier le modèle IA, voir `backend-flask/app/model/tf_model.py`
- Pour ajouter des types d'attaques ou des métriques, adapter les scripts et les routes dans `backend-flask/app/routes/stats.py`
- Pour personnaliser le dashboard, modifier les composants dans `frontend-next/src/app/dashboard/`

---

## Contact
Pour toute question ou contribution, ouvrez une issue ou contactez l'équipe projet.



