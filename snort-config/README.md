# Configuration Snort 3

Ce dossier contient la configuration de base pour Snort 3 dans le cadre du projet IDS-AI.

## Structure

- `snort.lua` : Configuration principale de Snort 3
- `local.rules` : Règles personnalisées pour la détection d'intrusion

## Installation

1. Installer Snort 3 selon votre système d'exploitation :
   ```bash
   # Ubuntu/Debian
   sudo apt-get install snort3

   # Windows
   # Télécharger depuis https://www.snort.org/downloads
   ```

2. Copier les fichiers de configuration :
   ```bash
   sudo cp snort.lua /etc/snort/
   sudo cp local.rules /etc/snort/rules/
   ```

3. Vérifier la configuration :
   ```bash
   snort -c /etc/snort/snort.lua --warn-all
   ```

## Utilisation

1. Lancer Snort en mode IDS :
   ```bash
   sudo snort -c /etc/snort/snort.lua -i <interface> -A alert_fast
   ```

2. Les logs seront générés dans :
   - Alertes : `/var/log/snort/alert.csv`
   - Logs complets : `/var/log/snort/snort.log`

## Règles personnalisées

Les règles dans `local.rules` incluent la détection de :
- Scans de ports
- Injections SQL
- Attaques par force brute SSH
- Injections de commandes
- Attaques DDoS
- Cross-Site Scripting (XSS)

## Intégration avec l'API Flask

Les logs générés par Snort sont envoyés à l'API Flask pour analyse par le modèle IA.
Voir le script `scripts/start_all.sh` pour la configuration de l'intégration. 