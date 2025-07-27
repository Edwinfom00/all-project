# 🚨 Guide de Test - Détection d'Attaques DoS

## Problème Identifié
Votre attaque DoS avec `hping3` n'est pas détectée car le scanner réseau ne surveille pas correctement les connexions externes en temps réel.

## Solutions Implémentées

### 1. Nouveau Détecteur DoS Amélioré
Le script `simulate_dos_detection.py` surveille activement les connexions réseau et détecte les attaques DoS.

### 2. Scanner Réseau Amélioré
Le `network_scanner.py` a été mis à jour pour détecter les attaques DoS basées sur le nombre de connexions par IP.

## 🧪 Comment Tester Votre Attaque DoS

### Étape 1: Démarrer la Surveillance
```bash
cd backend-flask
python simulate_dos_detection.py
```

### Étape 2: Lancer Votre Attaque DoS
Dans un autre terminal (Linux/WSL):
```bash
sudo hping3 -S --flood -V -p 80 129.0.60.57
```

### Étape 3: Vérifier les Alertes
Dans un troisième terminal:
```bash
cd backend-flask
python check_alerts.py
```

### Étape 4: Vérifier le Frontend
Ouvrez votre navigateur et allez sur `http://localhost:3000` pour voir les alertes en temps réel.

## 🔧 Améliorations Apportées

### 1. Détection DoS Améliorée
- Seuil de détection: 30+ connexions par IP
- Surveillance en temps réel des connexions réseau
- Alertes automatiques pour les attaques DoS

### 2. Mise à Jour des Données
- Le fichier `network_data.json` est mis à jour en temps réel
- Les alertes sont créées automatiquement
- Le frontend reçoit les nouvelles données

### 3. Logging Amélioré
- Messages de détection en temps réel
- Statistiques de connexions
- Alertes détaillées avec confiance

## 📊 Résultats Attendus

Quand vous lancez votre attaque DoS, vous devriez voir:

1. **Dans le terminal de surveillance:**
   ```
   🚨 ATTENTION: IP 192.168.1.178 a 45 connexions (seuil: 20)
   🚨 ALERTE DoS créée pour 192.168.1.178 avec 45 connexions
   ```

2. **Dans le fichier network_data.json:**
   ```json
   {
     "alerts": [
       {
         "id": 52,
         "sourceIp": "192.168.1.178",
         "destinationIp": "Multiple",
         "protocol": "tcp",
         "timestamp": "2025-07-27T10:30:15.123456",
         "attackType": "DoS",
         "severity": "high",
         "confidence": 0.45
       }
     ]
   }
   ```

3. **Dans le frontend:**
   - Nouvelles alertes apparaissent en temps réel
   - Graphiques mis à jour
   - Statistiques de menaces actives

## 🚀 Démarrage Rapide

1. **Terminal 1 - Surveillance:**
   ```bash
   cd backend-flask
   python simulate_dos_detection.py
   ```

2. **Terminal 2 - Attaque:**
   ```bash
   sudo hping3 -S --flood -V -p 80 129.0.60.57
   ```

3. **Terminal 3 - Vérification:**
   ```bash
   cd backend-flask
   python check_alerts.py
   ```

4. **Navigateur:**
   Ouvrir `http://localhost:3000`

## ⚠️ Notes Importantes

- Le seuil de détection DoS est fixé à 30 connexions par IP
- Les données sont mises à jour toutes les 2 secondes
- Le frontend se rafraîchit automatiquement
- Les alertes sont conservées dans `network_data.json`

## 🔍 Dépannage

Si l'attaque n'est pas détectée:

1. **Vérifiez que le script de surveillance fonctionne:**
   ```bash
   python simulate_dos_detection.py
   ```

2. **Vérifiez les connexions réseau:**
   ```bash
   netstat -an | grep :80
   ```

3. **Vérifiez le fichier de données:**
   ```bash
   cat app/data/network_data.json | tail -20
   ```

4. **Redémarrez le backend Flask:**
   ```bash
   python run.py
   ```

## ✅ Résultat Final

Votre système devrait maintenant:
- ✅ Détecter votre attaque DoS en temps réel
- ✅ Créer des alertes automatiquement
- ✅ Mettre à jour le frontend
- ✅ Sauvegarder les données dans `network_data.json` 