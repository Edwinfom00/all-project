# 🚀 GUIDE DE DÉMARRAGE RAPIDE - SYSTÈME IDS

## ✅ **DÉMARRAGE EN UNE COMMANDE**

### **Option 1: Tout le système (Recommandé)**
```bash
python start_all.py
```
**Résultat:** Backend + Frontend + Tous les détecteurs automatiquement

### **Option 2: Backend seulement**
```bash
cd backend-flask
python run.py
```
**Résultat:** Tous les services de détection + API Flask

### **Option 3: Frontend seulement**
```bash
python start_frontend.py
```
**Résultat:** Interface web Next.js

## 📡 **SERVICES AUTOMATIQUEMENT DÉMARRÉS**

Quand vous lancez `python run.py`, le système démarre automatiquement:

### **🔧 Services de Détection:**
- ✅ **Scanner réseau** (connexions établies)
- ✅ **Détecteur d'attaques externes** (paquets bruts - Linux/WSL)
- ✅ **Détecteur Windows** (avec scapy - Windows)
- ✅ **Détecteur amélioré** (simulation et règles)
- ✅ **Moniteur d'alertes** (temps réel)

### **🌐 Services Web:**
- ✅ **API Flask** (http://localhost:5000)
- ✅ **Frontend Next.js** (http://localhost:3000)

## 🧪 **TEST DE VOTRE ATTAQUE DoS**

### **Étape 1: Démarrer le système**
```bash
python start_all.py
```

### **Étape 2: Lancer votre attaque**
```bash
sudo hping3 -S --flood -V -p 80 129.0.60.57
```

### **Étape 3: Voir les résultats**
- **Frontend:** Ouvrir http://localhost:3000
- **API:** http://localhost:5000/api/stats/alerts
- **Logs:** Voir les messages dans le terminal

## 📊 **RÉSULTATS ATTENDUS**

### **Dans le terminal:**
```
🚀 Démarrage du système IDS complet...
🖥️ Système détecté: linux
🚀 Démarrage du scanner réseau...
🚀 Démarrage du détecteur d'attaques externes (Linux)...
🚀 Démarrage du détecteur amélioré...
🚀 Démarrage du moniteur d'alertes...
✅ Tous les services de détection sont démarrés!
🚨 ALERTE SYN Flood: 192.168.1.178 -> 129.0.60.57 (45 paquets)
```

### **Dans le frontend:**
- 📡 Nouvelles alertes en temps réel
- 📊 Graphiques mis à jour
- 🚨 Alertes DoS visibles

### **Dans network_data.json:**
```json
{
  "alerts": [
    {
      "id": 1234567890,
      "sourceIp": "192.168.1.178",
      "destinationIp": "129.0.60.57",
      "protocol": "tcp",
      "timestamp": "2025-07-27T10:30:15.123456",
      "attackType": "SYN Flood",
      "severity": "high",
      "confidence": 0.45,
      "packetCount": 45
    }
  ]
}
```

## 🔧 **CONFIGURATION AVANCÉE**

### **Modifier les seuils de détection:**
```python
# Dans external_dos_detector.py ou windows_dos_detector.py
self.dos_threshold = 20  # Nombre de paquets pour déclencher une alerte
```

### **Changer la durée de surveillance:**
```python
# Dans run.py
detector.start_monitoring(duration=3600)  # 1 heure au lieu de 5 minutes
```

## ⚠️ **NOTES IMPORTANTES**

1. **Privilèges administrateur** requis pour la capture de paquets
2. **Scapy** nécessaire pour Windows: `pip install scapy`
3. **Node.js** nécessaire pour le frontend
4. **Python 3.8+** requis pour le backend

## 🚨 **DÉPANNAGE**

### **Problème: "Permission denied"**
```bash
sudo python start_all.py
```

### **Problème: "scapy not found"**
```bash
pip install scapy
```

### **Problème: "node_modules not found"**
```bash
cd frontend-next
npm install
```

### **Problème: "Port already in use"**
```bash
# Arrêter les processus existants
pkill -f "python run.py"
pkill -f "npm run dev"
```

## ✅ **RÉSULTAT FINAL**

**Votre système est maintenant complet et automatique!**

- ✅ **Une seule commande** pour tout démarrer
- ✅ **Tous les détecteurs** fonctionnent en parallèle
- ✅ **Frontend** mis à jour en temps réel
- ✅ **API** disponible pour les requêtes
- ✅ **Alertes** sauvegardées automatiquement

**Testez votre attaque DoS et vous devriez voir les résultats immédiatement!** 🚀 