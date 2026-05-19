#!/bin/bash

echo "========================================================"
echo " DÉMARRAGE DU SOC YANECODE - ENVIRONNEMENT DE PRODUCTION"
echo "========================================================"

# Authentification sudo en premier plan avant de lancer les tâches
echo "[INFO] Vérification des privilèges administrateur..."
sudo -v

# 1. Démarrage de FastAPI (Backend) en arrière-plan
echo "[INFO] Lancement du moteur d'inférence (FastAPI)..."
./venv/bin/python -m uvicorn src.main:app --reload > /dev/null 2>&1 &
API_PID=$!
sleep 2

# 2. Démarrage du Sniffer en arrière-plan
echo "[INFO] Lancement du capteur réseau..."
sudo ./venv/bin/python live_sniffer.py > /dev/null 2>&1 &
SNIFFER_PID=$!
sleep 2

# 3. Lancement de l'Interface Graphique (Frontend)
echo "[INFO] Lancement de la console d'administration SOC..."
./venv/bin/python src/desktop_app.py

# 4. Nettoyage : Arrêt des processus à la fermeture de l'application
echo "[INFO] Interruption détectée. Arrêt des services en cours..."
kill $API_PID
sudo kill $SNIFFER_PID
echo "[OK] Système SOC arrêté avec succès."