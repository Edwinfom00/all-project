# Backend Flask – IDS AI System

## Nouvelles routes API

### 1. `/api/settings` (GET/POST)
- **GET** : retourne la configuration système (seuils d’alerte, modules actifs)
- **POST** : modifie et persiste la configuration (dans `data/settings.json`)
- Utilisé par la page `/settings` du frontend

### 2. `/api/rules` (GET/POST)
- **GET** : retourne la liste des règles de détection
- **POST** : remplace la liste des règles (dans `data/rules.json`)
- Utilisé par la page `/rules` du frontend

## Stockage des paramètres
- Les paramètres sont stockés dans `backend-flask/app/data/settings.json` et `backend-flask/app/data/rules.json`

## Brancher le frontend
- Le frontend doit pointer sur `http://localhost:5000/api/settings` et `/api/rules`
- Les blueprints sont enregistrés dans `app/__init__.py` (centralisation)

## Prérequis
- Redémarrer le serveur Flask après ajout/modification de routes
- Vérifier que les fichiers de données existent ou seront créés automatiquement

## Exemples de requêtes

**Lire la config :**
```bash
curl http://localhost:5000/api/settings
```
**Modifier la config :**
```bash
curl -X POST http://localhost:5000/api/settings \
  -H "Content-Type: application/json" \
  -d '{"thresholds": {"bruteForce": 20}, "modules": {"xss": false}}'
```
**Lire les règles :**
```bash
curl http://localhost:5000/api/rules
```
**Modifier les règles :**
```bash
curl -X POST http://localhost:5000/api/rules \
  -H "Content-Type: application/json" \
  -d '[{"id":1,"name":"Brute Force","description":"...","action":"..."}]'
```

---

Voir aussi le README frontend pour l’intégration UI/UX. 