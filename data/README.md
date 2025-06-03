# Datasets pour l'entraînement du modèle IA

Ce dossier contient les datasets utilisés pour l'entraînement du modèle de détection d'intrusion.

## Datasets recommandés

### 1. NSL-KDD
- **Description** : Version améliorée du dataset KDD Cup 99, sans enregistrements redondants
- **Source** : [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html)
- **Format** : CSV
- **Colonnes principales** :
  - duration
  - protocol_type
  - service
  - flag
  - src_bytes
  - dst_bytes
  - ...
  - class (normal/attack)

### 2. CICIDS2017
- **Description** : Dataset moderne contenant des attaques réseau bénignes et malveillantes
- **Source** : [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Format** : CSV
- **Types d'attaques** :
  - Brute Force
  - DoS
  - DDoS
  - SQL Injection
  - XSS
  - ...

## Structure des fichiers

```
data/
├── raw/                    # Données brutes téléchargées
│   ├── NSL-KDD/
│   └── CICIDS2017/
├── processed/              # Données prétraitées
│   ├── train/
│   └── test/
└── models/                # Modèles entraînés
    └── model.joblib
```

## Prétraitement

1. Télécharger les datasets :
   ```bash
   # NSL-KDD
   wget https://www.unb.ca/cic/datasets/nsl.html -O raw/NSL-KDD/NSL-KDD.zip
   unzip raw/NSL-KDD/NSL-KDD.zip -d raw/NSL-KDD/

   # CICIDS2017
   # Télécharger manuellement depuis le site
   ```

2. Prétraiter les données :
   ```bash
   python scripts/preprocess.py
   ```

## Notes importantes

- Les datasets sont volumineux, ils ne sont pas inclus dans le dépôt
- Utiliser `.gitignore` pour exclure les données brutes
- Conserver uniquement les scripts de prétraitement et la documentation
- Les modèles entraînés peuvent être partagés via Git LFS 