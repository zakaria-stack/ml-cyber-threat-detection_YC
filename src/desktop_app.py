import customtkinter as ctk
import requests
import threading
import time
import pandas as pd
import numpy as np
import os
import datetime
from dotenv import load_dotenv

# =====================================================================
# Configuration du Thème Global de l'Interface
# =====================================================================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class CyberThreatApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # 1. Configuration de la fenêtre principale
        self.title("YaneCode SOC - System d'Intrusion (NIDS)")
        self.geometry("1200x750")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Variables d'état du système
        self.is_live_running = False
        self.stat_total = 0
        self.stat_normal = 0
        self.stat_threats = 0

        # Initialisation des composants UI
        self._build_sidebar()
        self._build_main_workspace()
        self._build_status_bar()

        self.log_event("Systeme SOC initialise. En attente de trafic...", level="INFO")

    # =====================================================================
    # Construction de l'Interface Graphique (UI)
    # =====================================================================
    def _build_sidebar(self):
        """Construit le panneau de controle lateral."""
        self.sidebar_frame = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color="#1a1a24")
        self.sidebar_frame.grid(row=0, column=0, rowspan=2, sticky="nsew")

        # Titre de l'application
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="YANE-CODE SOC", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 10))
        
        self.subtitle_label = ctk.CTkLabel(self.sidebar_frame, text="Network Intrusion Detection", font=ctk.CTkFont(size=12), text_color="gray")
        self.subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 30))

        # Boutons de controle
        self.test_button = ctk.CTkButton(self.sidebar_frame, text="Test de Connexion API", command=self.send_test_request, height=40)
        self.test_button.grid(row=2, column=0, padx=20, pady=10)

        self.live_button = ctk.CTkButton(self.sidebar_frame, text="Lancer Mode LIVE", command=self.start_live_mode, fg_color="#cc7000", hover_color="#b36200", height=40)
        self.live_button.grid(row=3, column=0, padx=20, pady=10)

        self.stop_button = ctk.CTkButton(self.sidebar_frame, text="Arreter l'Analyse", command=self.stop_live_mode, fg_color="#b32432", hover_color="#991f2b", state="disabled", height=40)
        self.stop_button.grid(row=4, column=0, padx=20, pady=10)

        self.clear_button = ctk.CTkButton(self.sidebar_frame, text="Purger la Console", command=self.clear_console, fg_color="#4d5359", hover_color="#3c4146", height=40)
        self.clear_button.grid(row=5, column=0, padx=20, pady=10)

    def _build_main_workspace(self):
        """Construit l'espace de travail principal (Metriques et Logs)."""
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        # En-tete
        self.title_label = ctk.CTkLabel(self.main_frame, text="Analyse du Trafic Reseau en Temps Reel", font=ctk.CTkFont(size=22, weight="bold"))
        self.title_label.grid(row=0, column=0, sticky="w", pady=(0, 20))

        # Tableau de bord des statistiques (Cartes de metriques)
        self.dashboard_frame = ctk.CTkFrame(self.main_frame, fg_color="#1e1e2f", corner_radius=8)
        self.dashboard_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20), ipady=15)
        self.dashboard_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.lbl_total = ctk.CTkLabel(self.dashboard_frame, text="TOTAL PAQUETS : 0", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_total.grid(row=0, column=0, padx=10, pady=10)

        self.lbl_normal = ctk.CTkLabel(self.dashboard_frame, text="TRAFIC NORMAL : 0", font=ctk.CTkFont(size=14, weight="bold"), text_color="#00cc66")
        self.lbl_normal.grid(row=0, column=1, padx=10, pady=10)

        self.lbl_threat = ctk.CTkLabel(self.dashboard_frame, text="MENACES : 0", font=ctk.CTkFont(size=14, weight="bold"), text_color="#ff4d4d")
        self.lbl_threat.grid(row=0, column=2, padx=10, pady=10)

        self.lbl_last = ctk.CTkLabel(self.dashboard_frame, text="DERNIERE ALERTE : Aucune", font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffb84d")
        self.lbl_last.grid(row=0, column=3, padx=10, pady=10)

        # Console de Logs textuels
        self.result_textbox = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Consolas", size=13), fg_color="#0a0a12", text_color="#e0e0e0", corner_radius=8)
        self.result_textbox.grid(row=2, column=0, sticky="nsew")
        
        # Configuration des couleurs de tags pour la console
        self.result_textbox.tag_config("INFO", foreground="#4da6ff")
        self.result_textbox.tag_config("NORMAL", foreground="#00cc66")
        self.result_textbox.tag_config("ALERT", foreground="#ff4d4d")
        self.result_textbox.tag_config("WARNING", foreground="#ffb84d")

    def _build_status_bar(self):
        """Construit la barre d'etat en bas de la fenetre."""
        self.status_frame = ctk.CTkFrame(self, height=30, corner_radius=0, fg_color="#13131c")
        self.status_frame.grid(row=1, column=1, sticky="ew")
        self.status_frame.grid_columnconfigure(0, weight=1)
        
        self.status_label = ctk.CTkLabel(self.status_frame, text="Etat : Deconnecte | Mode : Veille", font=ctk.CTkFont(size=12))
        self.status_label.grid(row=0, column=0, sticky="w", padx=20)

    # =====================================================================
    # Logique d'Affichage et de Journalisation
    # =====================================================================
    def log_event(self, message, level="INFO"):
        """Affiche un message formaté avec horodatage dans la console."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}\n"
        
        self.result_textbox.insert("end", formatted_message, level)
        self.result_textbox.see("end")

    def update_dashboard(self, is_threat, pred_type):
        """Met à jour les compteurs de sécurité de l'interface."""
        self.stat_total += 1
        self.lbl_total.configure(text=f"TOTAL PAQUETS : {self.stat_total}")
        
        if is_threat:
            self.stat_threats += 1
            self.lbl_threat.configure(text=f"MENACES : {self.stat_threats}")
            self.lbl_last.configure(text=f"DERNIERE ALERTE : {pred_type}")
        else:
            self.stat_normal += 1
            self.lbl_normal.configure(text=f"TRAFIC NORMAL : {self.stat_normal}")

    def clear_console(self):
        """Réinitialise l'affichage de la console de logs."""
        self.result_textbox.delete("1.0", "end")
        self.log_event("Console nettoyee. Historique efface.", level="INFO")

    def update_status(self, text):
        """Met à jour le texte de la barre d'état inférieure."""
        self.status_label.configure(text=text)

    # =====================================================================
    # Gestion des Alertes (Fichier et Telegram)
    # =====================================================================
    def save_alert_to_file(self, message):
        """Sauvegarde les incidents critiques dans un fichier journal d'audit."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open("logs_alertes.txt", "a", encoding="utf-8") as file:
                file.write(f"[{now}] {message}\n")
        except IOError as e:
            print(f"Erreur d'ecriture log local: {e}")

    def send_telegram_alert(self, message):
        """Transmet une alerte de sécurité via l'API Telegram de maniere asynchrone."""
        load_dotenv()
        bot_token = os.getenv("TELEGRAM_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")

        if not bot_token or not chat_id:
            return 

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": "[ALERTE SOC]\n" + message}
        
        # Configuration Proxy (si necessaire dans le reseau d'entreprise)
        USE_PROXY = True
        proxies_config = {
            "http": "http://10.130.27.244:8282",
            "https": "http://10.130.27.244:8282"
        }
        
        def send_request():
            try:
                if USE_PROXY:
                    requests.post(url, json=payload, proxies=proxies_config, timeout=10)
                else:
                    requests.post(url, json=payload, timeout=10)
            except Exception as e:
                print(f"Erreur d'envoi Telegram : {e}")

        # Execution dans un thread separé pour ne pas bloquer l'interface
        threading.Thread(target=send_request, daemon=True).start()      

    # =====================================================================
    # Communication API et Mode Live (Analyse Reseau)
    # =====================================================================
    def send_test_request(self):
        """Verifie la disponibilite du moteur IA backend (FastAPI)."""
        self.log_event("Test de connexion vers le moteur d'inference (API)...", "INFO")
        self.update()
        try:
            response = requests.get("http://127.0.0.1:8000/", timeout=5)
            if response.status_code == 200:
                self.log_event("API contactee avec succes. Service operationnel.", "NORMAL")
            else:
                self.log_event(f"Reponse inattendue de l'API (Status {response.status_code}).", "WARNING")
        except requests.exceptions.RequestException:
            self.log_event("Erreur de connexion. Verifiez que FastAPI est demarre.", "ALERT")

    def get_column_mapping(self):
        """Retourne le dictionnaire de standardisation des colonnes pour le modele XGBoost."""
        return {
            'dst_port': 'destination_port', 'tot_fwd_pkts': 'total_fwd_packets',
            'tot_bwd_pkts': 'total_backward_packets', 'totlen_fwd_pkts': 'total_length_of_fwd_packets',
            'totlen_bwd_pkts': 'total_length_of_bwd_packets', 'fwd_pkt_len_max': 'fwd_packet_length_max',
            'fwd_pkt_len_min': 'fwd_packet_length_min', 'fwd_pkt_len_mean': 'fwd_packet_length_mean',
            'fwd_pkt_len_std': 'fwd_packet_length_std', 'bwd_pkt_len_max': 'bwd_packet_length_max',
            'bwd_pkt_len_min': 'bwd_packet_length_min', 'bwd_pkt_len_mean': 'bwd_packet_length_mean',
            'bwd_pkt_len_std': 'bwd_packet_length_std', 'flow_byts_s': 'flow_bytes_s',
            'flow_pkts_s': 'flow_packets_s', 'fwd_iat_tot': 'fwd_iat_total',
            'bwd_iat_tot': 'bwd_iat_total', 'fwd_header_len': 'fwd_header_length',
            'bwd_header_len': 'bwd_header_length', 'fwd_pkts_s': 'fwd_packets_s',
            'bwd_pkts_s': 'bwd_packets_s', 'pkt_len_min': 'min_packet_length',
            'pkt_len_max': 'max_packet_length', 'pkt_len_mean': 'packet_length_mean',
            'pkt_len_std': 'packet_length_std', 'pkt_len_var': 'packet_length_variance',
            'fin_flag_cnt': 'fin_flag_count', 'syn_flag_cnt': 'syn_flag_count',
            'rst_flag_cnt': 'rst_flag_count', 'psh_flag_cnt': 'psh_flag_count',
            'ack_flag_cnt': 'ack_flag_count', 'urg_flag_cnt': 'urg_flag_count',
            'cwe_flag_cnt': 'cwe_flag_count', 'ece_flag_cnt': 'ece_flag_count',
            'pkt_size_avg': 'average_packet_size', 'fwd_seg_size_avg': 'avg_fwd_segment_size',
            'bwd_seg_size_avg': 'avg_bwd_segment_size', 'fwd_byts_b_avg': 'fwd_avg_bytes_bulk',
            'fwd_pkts_b_avg': 'fwd_avg_packets_bulk', 'fwd_blk_rate_avg': 'fwd_avg_bulk_rate',
            'bwd_byts_b_avg': 'bwd_avg_bytes_bulk', 'bwd_pkts_b_avg': 'bwd_avg_packets_bulk',
            'bwd_blk_rate_avg': 'bwd_avg_bulk_rate', 'subflow_fwd_pkts': 'subflow_fwd_packets',
            'subflow_fwd_byts': 'subflow_fwd_bytes', 'subflow_bwd_pkts': 'subflow_bwd_packets',
            'subflow_bwd_byts': 'subflow_bwd_bytes', 'init_fwd_win_byts': 'init_win_bytes_forward',
            'init_bwd_win_byts': 'init_win_bytes_backward', 'fwd_act_data_pkts': 'act_data_pkt_fwd',
            'fwd_seg_size_min': 'min_seg_size_forward'
        }

    def start_live_mode(self):
        """Initialise et lance le processus de surveillance continue."""
        self.is_live_running = True
        self.live_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.update_status("Etat : Connecte | Mode : LIVE SNIFFING EN COURS")
        
        # Reinitialisation des metriques
        self.stat_total = self.stat_normal = self.stat_threats = 0
        self.lbl_total.configure(text="TOTAL PAQUETS : 0")
        self.lbl_normal.configure(text="TRAFIC NORMAL : 0")
        self.lbl_threat.configure(text="MENACES : 0")
        self.lbl_last.configure(text="DERNIERE ALERTE : Aucune")

        self.log_event("-" * 60, "INFO")
        self.log_event("INITIALISATION DU CAPTEUR LIVE (SNIFFER)...", "INFO")
        self.log_event("Analyse du flux reseau en temps reel demarree.", "INFO")
        self.log_event("-" * 60, "INFO")

        # Demarrage du Thread de traitement
        threading.Thread(target=self.run_live_worker, daemon=True).start()

    def stop_live_mode(self):
        """Arrete le processus de surveillance."""
        self.is_live_running = False
        self.log_event("Analyse en temps reel suspendue par l'administrateur.", "WARNING")
        self.update_status("Etat : Interrompu | Mode : Veille")
        self.live_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def run_live_worker(self):
        """Processus d'arriere-plan charge de lire le trafic et requeter l'IA."""
        api_url = "http://127.0.0.1:8000/predict"
        live_file = "live_traffic.csv"
        last_index = 0  
        waiting_logged = False

        while self.is_live_running:
            try:
                if os.path.exists(live_file):
                    df = pd.read_csv(live_file)
                    
                    if len(df) > last_index:
                        new_rows = df.iloc[last_index:].copy()
                        
                        # Nettoyage et formatage du DataFrame
                        if 'cwe_flag_count' not in new_rows.columns:
                            new_rows['cwe_flag_count'] = 0
                        new_rows.columns = new_rows.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('-', '_').str.replace('/', '_')
                        
                        new_rows.rename(columns=self.get_column_mapping(), inplace=True)
                        new_rows.replace([np.inf, -np.inf], np.nan, inplace=True)
                        new_rows.fillna(0, inplace=True)
                        
                        for index, row in new_rows.iterrows():
                            if not self.is_live_running:
                                break
                            
                            data = row.to_dict()
                            # Ajustement spécifique des features si necessaire
                            if 'fwd_header_length' in data:
                                data['fwd_header_length.1'] = data['fwd_header_length']
                            
                            try:
                                response = requests.post(api_url, json=data)
                                
                                if response.status_code == 200:
                                    result = response.json()
                                    pred = result['prediction']
                                    conf = round(result['confidence_score'] * 100, 2)
                                    
                                    self.after(0, self.update_dashboard, result['is_threat'], pred)
                                    
                                    flow_id = last_index + index
                                    if result['is_threat']:
                                        msg = f"[FLUX ID: {flow_id}] INTRUSION DETECTEE | Type: {pred} | Fiabilite: {conf}%"
                                        self.after(0, self.log_event, msg, "ALERT")
                                        self.save_alert_to_file(msg)
                                        self.send_telegram_alert(msg)    
                                    else:
                                        msg = f"[FLUX ID: {flow_id}] Trafic Normal | Fiabilite: {conf}%"
                                        self.after(0, self.log_event, msg, "NORMAL")
                                        
                            except requests.exceptions.ConnectionError:
                                self.after(0, self.log_event, "Le backend IA est injoignable. Interruption.", "ALERT")
                                self.is_live_running = False
                                break
                            
                            time.sleep(0.1) 
                        
                        last_index = len(df)
                        waiting_logged = False
                else:
                    if not waiting_logged:
                        self.after(0, self.log_event, "Fichier 'live_traffic.csv' introuvable. En attente...", "WARNING")
                        waiting_logged = True
            
            except Exception as e:
                print(f"Erreur Worker: {e}") 
            
            time.sleep(1) # Frequence de balayage du fichier CSV
            
        # Restauration finale de l'UI
        self.after(0, self.stop_button.configure, {"state": "disabled"})
        self.after(0, self.live_button.configure, {"state": "normal"})
        self.after(0, self.update_status, "Etat : Deconnecte | Mode : Arret")

if __name__ == "__main__":
    app = CyberThreatApp()
    app.mainloop()