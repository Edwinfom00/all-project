#!/bin/bash

# Couleurs pour les logs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Démarrage de l'IDS-AI System...${NC}"

# Vérification de l'existence des dossiers
if [ ! -d "../frontend-next" ] || [ ! -d "../backend-flask" ] || [ ! -d "../snort-config" ]; then
    echo "Erreur: Certains dossiers requis sont manquants"
    exit 1
fi

# Démarrage de Snort (en arrière-plan)
echo -e "${YELLOW}Démarrage de Snort...${NC}"
if command -v snort &> /dev/null; then
    sudo snort -c ../snort-config/snort.lua -i any -A alert_fast &
    SNORT_PID=$!
    echo "Snort démarré avec PID: $SNORT_PID"
else
    echo "Erreur: Snort n'est pas installé"
    exit 1
fi

# Démarrage du backend Flask
echo -e "${YELLOW}Démarrage du backend Flask...${NC}"
cd ../backend-flask
if [ ! -d "venv" ]; then
    echo "Création de l'environnement virtuel Python..."
    python -m venv venv
fi
source venv/bin/activate || source venv/Scripts/activate
pip install -r requirements.txt
python run.py &
FLASK_PID=$!
cd ..

# Démarrage du frontend Next.js
echo -e "${YELLOW}Démarrage du frontend Next.js...${NC}"
cd frontend-next
npm install
npm run dev &
NEXT_PID=$!
cd ..

echo -e "${GREEN}Tous les services sont démarrés !${NC}"
echo "Frontend: http://localhost:3000"
echo "Backend: http://localhost:5000"

# Gestion de l'arrêt propre
cleanup() {
    echo -e "${YELLOW}Arrêt des services...${NC}"
    kill $SNORT_PID 2>/dev/null
    kill $FLASK_PID 2>/dev/null
    kill $NEXT_PID 2>/dev/null
    echo -e "${GREEN}Services arrêtés${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Attendre que l'utilisateur arrête le script
echo "Appuyez sur Ctrl+C pour arrêter tous les services"
wait 