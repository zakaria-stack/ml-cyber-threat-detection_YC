import os
import joblib
import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel, Field

# ---------------------------------------------------------
# 1. Initialisation de l'application FastAPI
# ---------------------------------------------------------
app = FastAPI(
    title="API de Détection de Cybermenaces",
    description="Serveur backend pour analyser le trafic réseau avec XGBoost",
    version="1.0"
)

# ---------------------------------------------------------
# 2. Configuration des chemins et chargement
# ---------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

print("⏳ Chargement du modèle et des outils en mémoire...")
xgboost_model = joblib.load(os.path.join(MODELS_DIR, "xgboost_final_model.pkl"))
scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
label_encoder = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
print("✅ Modèles chargés avec succès !")

# ---------------------------------------------------------
# 3. Modèles de Données (Pydantic)
# ---------------------------------------------------------
class NetworkTrafficData(BaseModel):
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
    # ⚠️ Voici la correction de l'artefact Pandas :
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
    prediction: str
    is_threat: bool
    confidence_score: float

# ---------------------------------------------------------
# 4. Endpoints (Routes de l'API)
# ---------------------------------------------------------
@app.get("/")
def read_root():
    return {"message": "Serveur IDS/IPS actif. Prêt à analyser le trafic ! 🛡️"}

@app.post("/predict", response_model=PredictionResponse)
def predict_traffic(data: NetworkTrafficData):
    """
    Reçoit un paquet de données réseau, le normalise, et prédit s'il s'agit d'une menace.
    """
    # 1. Convertir les données reçues en dictionnaire (en respectant l'alias pour le .1)
    input_dict = data.model_dump(by_alias=True)
    
    # 2. Convertir en DataFrame 
    df = pd.DataFrame([input_dict])
    colonnes_entrainement = scaler.feature_names_in_
    df = df[colonnes_entrainement]

    # 3. Prétraitement : Normaliser les données avec le StandardScaler
    scaled_features = scaler.transform(df)
    
    # 4. Prédiction avec XGBoost
    # prediction_encoded contient le chiffre prédit (ex: 0, 1, 2...)
    prediction_encoded = xgboost_model.predict(scaled_features)[0]
    
    # Probabilité (confiance) de la prédiction
    probabilities = xgboost_model.predict_proba(scaled_features)[0]
    confidence = float(max(probabilities))
    
    # 5. Traduire le chiffre en texte avec le LabelEncoder (ex: 0 -> 'BENIGN', 1 -> 'DDoS')
    predicted_label = label_encoder.inverse_transform([prediction_encoded])[0]
    
    # 6. Déterminer si c'est une menace (on suppose que BENIGN ou NORMAL veut dire "sans danger")
    is_threat = str(predicted_label).upper() not in ["BENIGN", "NORMAL"]
    
    # 7. Renvoyer la réponse finale !
    return PredictionResponse(
        prediction=str(predicted_label),
        is_threat=is_threat,
        confidence_score=confidence
    )