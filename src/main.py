import os
import joblib
import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel, Field

# =====================================================================
# 1. INITIALISATION DE L'APPLICATION (API)
# =====================================================================
app = FastAPI(
    title="API de Détection d'Intrusions (IDS/IPS)",
    description="Backend analytique du SOC utilisant le modèle Machine Learning XGBoost pour la classification du trafic réseau en temps réel.",
    version="1.0"
)

# =====================================================================
# 2. CHARGEMENT DU MODÈLE ET DES OBJETS DE PRÉTRAITEMENT
# =====================================================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

print("⏳ Initialisation du moteur IA en cours...")
try:
    xgboost_model = joblib.load(os.path.join(MODELS_DIR, "xgboost_final_model.pkl"))
    scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
    label_encoder = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
    print("✅ Modèles de Machine Learning chargés avec succès !")
except Exception as e:
    print(f"❌ Erreur lors du chargement des modèles : {e}")

# =====================================================================
# 3. SCHÉMAS DE VALIDATION DES DONNÉES (PYDANTIC)
# =====================================================================
class NetworkTrafficData(BaseModel):
    """
    Structure attendue pour un flux réseau (Flow).
    Comprend les 78 caractéristiques extraites par CICFlowMeter.
    """
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
    # Gestion du nom de colonne spécifique généré par Pandas
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
    """
    Structure de la réponse renvoyée par l'API à l'interface SOC.
    """
    prediction: str
    is_threat: bool
    confidence_score: float

# =====================================================================
# 4. CONTRÔLEURS DE L'API (ENDPOINTS)
# =====================================================================
@app.get("/")
def read_root():
    """
    Point de terminaison pour vérifier l'état du serveur.
    """
    return {"status": "Actif", "message": "Le moteur d'inférence IDS/IPS est opérationnel. 🛡️"}

@app.post("/predict", response_model=PredictionResponse)
def predict_traffic(data: NetworkTrafficData):
    """
    Analyse un flux réseau entrant, applique les transformations nécessaires, 
    et retourne la classification de sécurité (Normal ou Type d'attaque).
    """
    # 1. Extraction des données validées
    input_dict = data.model_dump(by_alias=True)
    
    # 2. Formatage en DataFrame avec l'ordre exact des colonnes attendu par le modèle
    df = pd.DataFrame([input_dict])
    colonnes_entrainement = scaler.feature_names_in_
    df = df[colonnes_entrainement]

    # 3. Standardisation des caractéristiques (Z-score normalization)
    scaled_features = scaler.transform(df)
    
    # 4. Inférence (Prédiction probabiliste via XGBoost)
    prediction_encoded = xgboost_model.predict(scaled_features)[0]
    probabilities = xgboost_model.predict_proba(scaled_features)[0]
    confidence = float(max(probabilities))
    
    # 5. Décodage de la classe prédite
    predicted_label = str(label_encoder.inverse_transform([prediction_encoded])[0])
    
    # --- 🧠 FILTRE HEURISTIQUE SOC (CORRECTION DU BIAIS D'ENVIRONNEMENT) ---
    # Si le modèle détecte une attaque de force brute FTP (FTP-Patator), 
    # mais que le port cible n'est pas 21 (FTP), il s'agit probablement d'un 
    # balayage de ports (PortScan) ou d'un flux massif local.
    dest_port = int(input_dict.get("destination_port", 0))
    if predicted_label == "FTP-Patator" and dest_port != 21:
        predicted_label = "PortScan"
    # -----------------------------------------------------------------------

    # 6. Évaluation du niveau de menace
    is_threat = predicted_label.upper() not in ["BENIGN", "NORMAL"]
    
    # 7. Retourner le verdict
    return PredictionResponse(
        prediction=predicted_label,
        is_threat=is_threat,
        confidence_score=confidence
    )