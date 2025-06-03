# IDS AI System

## Présentation

Ce projet est un système de détection d'intrusions (IDS) basé sur l'IA, composé de deux parties indépendantes :
- **Backend** : API Flask, analyse réseau, modèle IA, gestion des métriques et logs
- **Frontend** : Next.js, dashboard en temps réel, visualisation des alertes et statistiques

---

## Table des matières
- [Backend (Flask)](#backend-flask)
- [Frontend (Next.js)](#frontend-nextjs)
- [API Backend](#api-backend)
- [Structure des fichiers de données](#structure-des-fichiers-de-donnees)
- [Personnalisation & Développement](#personnalisation--developpement)
- [Contact](#contact)

---

# Backend (Flask)

### Prérequis
- Python 3.8+
- pip

### Installation
```bash
cd backend-flask
pip install -r requirements.txt
```

### Lancer le backend (scanner + API)
```bash
python scripts/start_all.py
```
- L'API sera accessible sur [http://localhost:5000](http://localhost:5000)

### Entraîner le modèle IA
```bash
python -m app.model.train_model
```
- Les métriques, l'historique et les logs de tests sont générés dans `backend-flask/app/data/`

### Structure principale
- `app/` : code source Flask, modèles, routes, utilitaires
- `app/data/` : fichiers générés (métriques, logs, historiques, modèles)
- `requirements.txt` : dépendances Python
- `scripts/` : scripts de gestion (lancement, scanner, etc.)

---

# Frontend (Next.js)

### Prérequis
- Node.js 18+
- npm

### Installation
```bash
cd frontend-next
npm install
```

### Lancer le frontend
```bash
npm run dev
```
- Le dashboard sera accessible sur [http://localhost:3000](http://localhost:3000)

### Structure principale
- `src/app/` : pages Next.js (dont `/dashboard`)
- `src/components/` : composants réutilisables (tableaux, stats, etc.)
- `tailwind.config.js` : configuration Tailwind CSS
- `package.json` : dépendances Node.js

---

# API Backend

- `GET /api/stats/model-metrics` : métriques du modèle (accuracy, precision, recall, f1_score, last_update)
- `GET /api/stats/training-history` : historique d'entraînement
- `GET /api/stats/test-logs` : logs de tests
- `GET /api/stats/model-stats` : statistiques globales du modèle
- `GET /api/stats/traffic` : trafic réseau en temps réel
- `GET /api/stats/alerts` : alertes en temps réel

---

# Structure des fichiers de données

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

# Personnalisation & Développement

## Backend
- Modèle IA : `backend-flask/app/model/tf_model.py`
- Ajout de métriques/routes : `backend-flask/app/routes/stats.py`
- Scripts d'entraînement : `backend-flask/app/model/train_model.py`

## Frontend
- Dashboard : `frontend-next/src/app/dashboard/`
- Composants : `frontend-next/src/components/`
- Thème/UI : `tailwind.config.js`

---

# Contact
Pour toute question ou contribution, ouvrez une issue ou contactez l'équipe projet.

## 📧 Contact
Votre Email - [@Email](edwinfom05@gmail.com)



