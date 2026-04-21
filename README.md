# 🛡️ ML Cyber Threat Detection System

## 📌 Description du projet
Ce projet consiste en la conception et le développement d'un système intelligent de détection et de prédiction des cybermenaces (IDS/IPS), spécialement conçu pour les startups et PME. Le système analyse les journaux d'activité réseau pour détecter en temps réel les comportements malveillants grâce à des modèles d'apprentissage automatique (Machine Learning).

## 🚀 Technologies utilisées
* **Machine Learning :** Scikit-learn, Pandas, Matplotlib, Seaborn
* **Backend :** Python, FastAPI *(À venir)*
* **Frontend :** React.js, TailwindCSS *(À venir)*
* **Déploiement :** Docker *(À venir)*

## 🏗️ Architecture du Système
Voici l'architecture globale et le flux de données de la solution :

```mermaid
flowchart LR
    classDef attacker fill:#ffcccc,stroke:#ff0000,stroke-width:2px;
    classDef server fill:#e6f3ff,stroke:#0066cc,stroke-width:2px;
    classDef ai fill:#e6ffe6,stroke:#009933,stroke-width:2px;
    classDef action fill:#ffe6cc,stroke:#ff9900,stroke-width:2px;

    subgraph Z1["1. Zone Reseau - Attaque et Collecte"]
        A["Internet / Attaquant"] -->|Trafic malveillant| B["Serveur PME - Cible"]
        B -->|Capture des paquets| C["Collecteur de Logs - Wazuh / Script"]
    end

    subgraph Z2["2. Zone Detection - Cerveau IA"]
        C -->|Envoi des donnees reseau| D["Backend FastAPI"]
        D -->|Extraction des features| E["Modele ML - Scikit-Learn"]
        E -->|Prediction| D
        D -->|Archivage| F["Base de donnees PostgreSQL"]
    end

    subgraph Z3["3. Zone Prevention - SOC"]
        E -.->|Alerte menace detectee| D
        D -->|Ordre de blocage IP| G["Firewall / IPS - iptables"]
        G -.->|Coupe la connexion| A
        D -->|Flux temps reel WebSockets| H["Dashboard React - Console SOC"]
    end

    class A attacker
    class B,C,D,F,H server
    class E ai
    class G action