.PHONY: install start stop clean configure-snort check-snort

# Variables pour Windows
ifeq ($(OS),Windows_NT)
    PYTHON=python
    VENV=venv
    PIP=$(VENV)/Scripts/pip
    FLASK=$(VENV)/Scripts/flask
    NPM=npm
    ACTIVATE=source $(VENV)/Scripts/activate
    SNORT_CONFIG=C:\Snort\etc\snort.lua
    SNORT_RULES=C:\Snort\rules
    SNORT_LOG=C:\Snort\log
else
    PYTHON=python3
    VENV=venv
    PIP=$(VENV)/bin/pip
    FLASK=$(VENV)/bin/flask
    NPM=npm
    ACTIVATE=. $(VENV)/bin/activate
    SNORT_CONFIG=/etc/snort/snort.lua
    SNORT_RULES=/etc/snort/rules
    SNORT_LOG=/var/log/snort
endif

# Vérification de Snort
check-snort:
	@echo "Vérification de Snort..."
	@which snort > /dev/null || (echo "Erreur: Snort n'est pas installé" && exit 1)
	@snort -V

# Configuration de Snort
configure-snort: check-snort
	@echo "Configuration de Snort..."
ifeq ($(OS),Windows_NT)
	@if not exist "C:\Snort\rules" mkdir "C:\Snort\rules"
	@if not exist "C:\Snort\log" mkdir "C:\Snort\log"
	@copy /Y snort-config\windows\snort.lua "$(SNORT_CONFIG)"
	@copy /Y snort-config\rules\*.rules "$(SNORT_RULES)"
else
	@sudo mkdir -p $(SNORT_RULES)
	@sudo mkdir -p $(SNORT_LOG)
	@sudo cp snort-config/linux/snort.lua $(SNORT_CONFIG)
	@sudo cp snort-config/rules/*.rules $(SNORT_RULES)
	@sudo chmod -R 755 $(SNORT_RULES)
	@sudo chmod -R 755 $(SNORT_LOG)
endif

# Installation complète
install: check-snort install-backend install-frontend configure-snort

# Installation du backend
install-backend:
	@echo "Installation des dépendances backend..."
	cd backend-flask && $(PYTHON) -m venv $(VENV)
	cd backend-flask && $(ACTIVATE) && $(PIP) install -r requirements.txt

# Installation du frontend
install-frontend:
	@echo "Installation des dépendances frontend..."
	cd frontend-next && $(NPM) install

# Démarrage des services
start: check-snort start-snort start-backend start-frontend

# Démarrage de Snort
start-snort:
	@echo "Démarrage de Snort..."
ifeq ($(OS),Windows_NT)
	@start /B snort -c $(SNORT_CONFIG) -i 1 -A alert_fast -l $(SNORT_LOG)
else
	@sudo snort -c $(SNORT_CONFIG) -i eth0 -A alert_fast -l $(SNORT_LOG) &
endif

# Démarrage du backend (en arrière-plan)
start-backend:
	@echo "Démarrage du backend..."
	cd backend-flask && $(ACTIVATE) && $(FLASK) run --port 5000 &

# Démarrage du frontend (en arrière-plan)
start-frontend:
	@echo "Démarrage du frontend..."
	cd frontend-next && $(NPM) run dev &

# Arrêt des services
stop:
	@echo "Arrêt des services..."
ifeq ($(OS),Windows_NT)
	-taskkill /F /IM snort.exe
else
	-sudo pkill -f snort
endif
	-pkill -f "flask run"
	-pkill -f "next"

# Nettoyage
clean:
	@echo "Nettoyage..."
	-rm -rf backend-flask/$(VENV)
	-rm -rf frontend-next/node_modules
	-rm -rf frontend-next/.next
	-rm -rf data/models/*
	-rm -rf data/logs/*

# Commande pour tout réinitialiser et redémarrer
reset: stop clean install start

# Commande pour voir les logs
logs:
	@echo "Logs de Snort :"
ifeq ($(OS),Windows_NT)
	-type "$(SNORT_LOG)\alert_fast.txt"
else
	-tail -f $(SNORT_LOG)/alert_fast.txt
endif
	@echo "\nLogs du backend :"
	-tail -f backend-flask/logs/app.log

# Aide
help:
	@echo "Commandes disponibles :"
	@echo "  make install      - Installe toutes les dépendances"
	@echo "  make start        - Démarre Snort, le backend et le frontend"
	@echo "  make stop         - Arrête tous les services"
	@echo "  make clean        - Nettoie les fichiers générés"
	@echo "  make reset        - Réinitialise et redémarre tout"
	@echo "  make logs         - Affiche les logs"
	@echo "  make check-snort  - Vérifie l'installation de Snort" 