import os
import time
import joblib
import logging
import pandas as pd
import numpy as np
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# =====================================================================
# 1. CONFIGURATION DU SYSTEME DE JOURNALISATION (LOGGING)
# =====================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SOC-API] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# =====================================================================
# 2. INITIALISATION DE L'APPLICATION (FASTAPI)
# =====================================================================
app = FastAPI(
    title="YaneCode SOC - Moteur d'Inference IA",
    description="Backend analytique (NIDS) base sur XGBoost pour la classification des flux reseaux en temps reel.",
    version="2.0.0"
)

# Configuration CORS pour autoriser les requetes du Dashboard Desktop
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================================
# 3. GESTION DES RESSOURCES ET MODELES MACHINE LEARNING
# =====================================================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

xgboost_model = None
scaler = None
label_encoder = None

@app.on_event("startup")
def load_ml_components():
    """Charge les modeles en memoire au demarrage du serveur."""
    global xgboost_model, scaler, label_encoder
    logger.info("Initialisation du moteur d'Intelligence Artificielle...")
    
    try:
        model_path = os.path.join(MODELS_DIR, "xgboost_final_model.pkl")
        scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
        encoder_path = os.path.join(MODELS_DIR, "label_encoder.pkl")
        
        if not all(os.path.exists(p) for p in [model_path, scaler_path, encoder_path]):
            raise FileNotFoundError("Un ou plusieurs fichiers de modele sont introuvables.")

        xgboost_model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        label_encoder = joblib.load(encoder_path)
        
        logger.info("Composants Machine Learning charges avec succes.")
    except Exception as e:
        logger.error(f"Erreur critique lors du chargement des modeles : {e}")
        raise RuntimeError("Echec de l'initialisation du backend IA.")

# =====================================================================
# 4. MOTEUR HEURISTIQUE (POST-TRAITEMENT ET REGLES METIERS)
# =====================================================================
class HeuristicEngine:
    """
    Couche de logique deterministe appliquee apres la prediction probabiliste de l'IA.
    Permet de corriger les biais d'environnement et d'appliquer des signatures strictes.
    """
    
    CRITICAL_PORTS = {21, 22, 23, 139, 445, 3306, 8080}

    @classmethod
    def apply_rules(cls, predicted_label: str, dest_port: int, flow_pkts_s: float, flow_duration: float = 0.0) -> str:
        final_label = predicted_label

        # Règle 1 : Correction du Faux Positif (Data Leakage local)
        if final_label == "FTP-Patator" and dest_port != 21:
            final_label = "PortScan"
            
        # Règle 2 : Détection d'Inondation Applicative (DDoS / DoS HTTP) affinée
        # On vérifie que la vitesse est extrême ET que le flux dure un minimum (pour éviter les micro-requêtes normales)
        if dest_port == 80 and flow_pkts_s > 5000.0 and flow_duration > 100000.0:
            final_label = "DDoS"

        # Règle 3 : Détection de force brute ciblée (SSH)
        if dest_port == 22 and flow_pkts_s > 10.0:
            final_label = "SSH-Patator (Brute Force)"
            
        # Règle 4 : Détection par signature de balayage de ports (Reconnaissance)
        if final_label in ["BENIGN", "NORMAL"] and dest_port in cls.CRITICAL_PORTS:
            # S'il y a des pics d'activité sur des ports critiques non standard
            if flow_pkts_s > 50.0:
                final_label = "PortScan"

        return final_label
# =====================================================================
# 5. SCHEMAS DE VALIDATION DES DONNEES (PYDANTIC)
# =====================================================================
class NetworkTrafficData(BaseModel):
    """Structure parametrique d'un flux reseau (78 features de CICFlowMeter)."""
    destination_port: float
    flow_duration: float
    total_fwd_packets: float
    total_backward_packets: float
    total_length_of_fwd_packets: float
    total_length_of_bwd_packets: float
    fwd_packet_length_max: float
    fwd_packet_length_min: float
    fwd_packet_length_mean: float
    fwd_packet_length_std: float
    bwd_packet_length_max: float
    bwd_packet_length_min: float
    bwd_packet_length_mean: float
    bwd_packet_length_std: float
    flow_bytes_s: float
    flow_packets_s: float
    flow_iat_mean: float
    flow_iat_std: float
    flow_iat_max: float
    flow_iat_min: float
    fwd_iat_total: float
    fwd_iat_mean: float
    fwd_iat_std: float
    fwd_iat_max: float
    fwd_iat_min: float
    bwd_iat_total: float
    bwd_iat_mean: float
    bwd_iat_std: float
    bwd_iat_max: float
    bwd_iat_min: float
    fwd_psh_flags: float
    bwd_psh_flags: float
    fwd_urg_flags: float
    bwd_urg_flags: float
    fwd_header_length: float
    bwd_header_length: float
    fwd_packets_s: float
    bwd_packets_s: float
    min_packet_length: float
    max_packet_length: float
    packet_length_mean: float
    packet_length_std: float
    packet_length_variance: float
    fin_flag_count: float
    syn_flag_count: float
    rst_flag_count: float
    psh_flag_count: float
    ack_flag_count: float
    urg_flag_count: float
    cwe_flag_count: float
    ece_flag_count: float
    down_up_ratio: float
    average_packet_size: float
    avg_fwd_segment_size: float
    avg_bwd_segment_size: float
    fwd_header_length_1: float = Field(..., alias="fwd_header_length.1")
    fwd_avg_bytes_bulk: float
    fwd_avg_packets_bulk: float
    fwd_avg_bulk_rate: float
    bwd_avg_bytes_bulk: float
    bwd_avg_packets_bulk: float
    bwd_avg_bulk_rate: float
    subflow_fwd_packets: float
    subflow_fwd_bytes: float
    subflow_bwd_packets: float
    subflow_bwd_bytes: float
    init_win_bytes_forward: float
    init_win_bytes_backward: float
    act_data_pkt_fwd: float
    min_seg_size_forward: float
    active_mean: float
    active_std: float
    active_max: float
    active_min: float
    idle_mean: float
    idle_std: float
    idle_max: float
    idle_min: float

class PredictionResponse(BaseModel):
    """Structure normalisee de la reponse de l'API."""
    prediction: str
    is_threat: bool
    confidence_score: float
    processing_time_ms: float

# =====================================================================
# 6. CONTROLEURS API (ENDPOINTS)
# =====================================================================
@app.get("/")
def health_check():
    """Endpoint de verification de la disponibilite du service."""
    return {
        "service": "YaneCode SOC Backend",
        "status": "Online",
        "engine": "XGBoost + Heuristic Filter"
    }

@app.post("/predict", response_model=PredictionResponse)
def predict_traffic(data: NetworkTrafficData, request: Request):
    """
    Endpoint principal d'analyse.
    Reçoit le vecteur de caracteristiques, l'evalue, et retourne le verdict.
    """
    start_time = time.time()
    
    try:
        # 1. Extraction et formatage des donnees
        input_dict = data.model_dump(by_alias=True)
        df = pd.DataFrame([input_dict])
        
        # Securite : S'assurer de l'ordre exact des colonnes
        colonnes_entrainement = scaler.feature_names_in_
        df = df[colonnes_entrainement]

        # 2. Normalisation des donnees (Z-Score)
        scaled_features = scaler.transform(df)
        
        # 3. Inference via le modele Machine Learning
        prediction_encoded = xgboost_model.predict(scaled_features)[0]
        probabilities = xgboost_model.predict_proba(scaled_features)[0]
        confidence = float(max(probabilities))
        
        # 4. Decodage du resultat
        base_prediction = str(label_encoder.inverse_transform([prediction_encoded])[0])
        
        # 5. Application de la surcouche heuristique
        dest_port = int(input_dict.get("destination_port", 0))
        flow_pkts_s = float(input_dict.get("flow_packets_s", 0.0))
        flow_duration = float(input_dict.get("flow_duration", 0.0)) # <-- Ajout de la durée
        
        final_prediction = HeuristicEngine.apply_rules(
            predicted_label=base_prediction, 
            dest_port=dest_port, 
            flow_pkts_s=flow_pkts_s,
            flow_duration=flow_duration # <-- Passage du paramètre
        )
        
        # 6. Evaluation du statut final
        is_threat = final_prediction.upper() not in ["BENIGN", "NORMAL"]
        
        # 7. Calcul du temps de traitement
        processing_time = round((time.time() - start_time) * 1000, 2)
        
        if is_threat:
            logger.warning(f"Menace detectee: {final_prediction} (Port: {dest_port}) - Fiabilite: {confidence:.2f}")

        return PredictionResponse(
            prediction=final_prediction,
            is_threat=is_threat,
            confidence_score=confidence,
            processing_time_ms=processing_time
        )

    except KeyError as e:
        logger.error(f"Erreur de format de donnees : Colonne manquante {e}")
        raise HTTPException(status_code=400, detail=f"Donnees invalides : {e}")
    except Exception as e:
        logger.error(f"Erreur interne lors de la prediction : {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur analytique.")