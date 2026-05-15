import customtkinter as ctk
import requests
import threading
import time
import pandas as pd
import numpy as np
import os
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
        self.title("YaneCode - Console SOC & Détection d'Intrusions")
        self.geometry("1100x700")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Variables d'état du système
        self.is_live_running = False
        self.stat_total = 0
        self.stat_normal = 0
        self.stat_threats = 0

        # =====================================================================
        # Menu Latéral (Sidebar)
        # =====================================================================
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ YaneCode SOC", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 30))

        # Contrôles du SOC
        self.test_button = ctk.CTkButton(self.sidebar_frame, text="🔍 Test de Connexion API", command=self.send_test_request)
        self.test_button.grid(row=1, column=0, padx=20, pady=10)

        self.live_button = ctk.CTkButton(self.sidebar_frame, text="📡 Lancer Mode LIVE", command=self.start_live_mode, fg_color="#ff8c00", hover_color="#e07b00")
        self.live_button.grid(row=2, column=0, padx=20, pady=10)

        self.stop_button = ctk.CTkButton(self.sidebar_frame, text="🛑 Arrêter l'Analyse", command=self.stop_live_mode, fg_color="#dc3545", hover_color="#c82333", state="disabled")
        self.stop_button.grid(row=3, column=0, padx=20, pady=10)

        self.clear_button = ctk.CTkButton(self.sidebar_frame, text="🧹 Effacer la console", command=self.clear_console, fg_color="#6c757d", hover_color="#5a6268")
        self.clear_button.grid(row=4, column=0, padx=20, pady=10)

        # =====================================================================
        # Écran Principal (Dashboard & Logs)
        # =====================================================================
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        self.title_label = ctk.CTkLabel(self.main_frame, text="Analyse du Trafic Réseau en Temps Réel", font=ctk.CTkFont(size=24, weight="bold"))
        self.title_label.grid(row=0, column=0, pady=(0, 20))

        # Tableau de bord des statistiques
        self.dashboard_frame = ctk.CTkFrame(self.main_frame, fg_color="#1e1e2f", corner_radius=10)
        self.dashboard_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20), ipady=10)
        self.dashboard_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.lbl_total = ctk.CTkLabel(self.dashboard_frame, text="📊 Total: 0", font=ctk.CTkFont(size=16, weight="bold"))
        self.lbl_total.grid(row=0, column=0, padx=10, pady=10)

        self.lbl_normal = ctk.CTkLabel(self.dashboard_frame, text="🟢 Normal: 0", font=ctk.CTkFont(size=16, weight="bold"), text_color="#00e676")
        self.lbl_normal.grid(row=0, column=1, padx=10, pady=10)

        self.lbl_threat = ctk.CTkLabel(self.dashboard_frame, text="🚨 Menaces: 0", font=ctk.CTkFont(size=16, weight="bold"), text_color="#ff4444")
        self.lbl_threat.grid(row=0, column=2, padx=10, pady=10)

        self.lbl_last = ctk.CTkLabel(self.dashboard_frame, text="⚠️ Dernière Menace: Aucune", font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffaa00")
        self.lbl_last.grid(row=0, column=3, padx=10, pady=10)

        # Console de Logs textuels
        self.result_textbox = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Consolas", size=14), fg_color="#0d0d16", text_color="#ffffff")
        self.result_textbox.grid(row=2, column=0, sticky="nsew")
        
        self.result_textbox.tag_config("normal_color", foreground="#00e676")
        self.result_textbox.tag_config("threat_color", foreground="#ff4444")
        self.result_textbox.tag_config("system_color", foreground="#00bfff")

        self.write_log("✅ Système SOC initialisé. En attente de trafic...", "system_color")

    # =====================================================================
    # Fonctions Utilitaires et d'Alerte
    # =====================================================================
    def write_log(self, message, tag=None):
        """Affiche un message coloré dans la console avec défilement automatique."""
        if tag:
            self.result_textbox.insert("end", message + "\n", tag)
        else:
            self.result_textbox.insert("end", message + "\n")
        self.result_textbox.see("end")

    def update_dashboard(self, is_threat, pred_type):
        """Met à jour les compteurs de sécurité de l'interface."""
        self.stat_total += 1
        self.lbl_total.configure(text=f"📊 Total: {self.stat_total}")
        
        if is_threat:
            self.stat_threats += 1
            self.lbl_threat.configure(text=f"🚨 Menaces: {self.stat_threats}")
            self.lbl_last.configure(text=f"⚠️ Dernière Menace: {pred_type}")
        else:
            self.stat_normal += 1
            self.lbl_normal.configure(text=f"🟢 Normal: {self.stat_normal}")

    def clear_console(self):
        """Réinitialise l'affichage de la console de logs."""
        self.result_textbox.delete("1.0", "end")
        self.write_log("🧹 Console nettoyée. En attente de nouveau trafic...", "system_color")

    def save_alert_to_file(self, message):
        """Sauvegarde les incidents critiques dans un fichier journal d'audit."""
        import datetime
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("logs_alertes.txt", "a", encoding="utf-8") as file:
            file.write(f"[{now}] {message}\n")

    def send_telegram_alert(self, message):
        """Transmet une alerte de sécurité via l'API Telegram vers l'administrateur SOC."""
        load_dotenv()
        bot_token = os.getenv("TELEGRAM_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")

        if not bot_token or not chat_id:
            return 

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": "🚨 ALERTE SOC YaneCode 🚨\n" + message}
        
        USE_PROXY = True
        mes_proxies = {
            "http": "http://100.68.109.89:8282",
            "https": "http://100.68.109.89:8282"
        }
        
        
        def envoi_asynchrone():
            try:
                if USE_PROXY:
                    response = requests.post(url, json=payload, proxies=mes_proxies, timeout=10)
                else:
                    response = requests.post(url, json=payload, timeout=10)
            except Exception as e:
                print(f"Échec Telegram: {e}")

        threading.Thread(target=envoi_asynchrone, daemon=True).start()      

    # =====================================================================
    # Fonctions de l'Analyse Réseau (LIVE)
    # =====================================================================
    def send_test_request(self):
        self.write_log("\n🔄 Test de connexion vers le moteur d'inférence (API)...", "system_color")
        self.update()
        try:
            response = requests.get("http://127.0.0.1:8000/", timeout=5)
            if response.status_code == 200:
                self.write_log("✅ API contactée avec succès. Le système est prêt.", "system_color")
            else:
                self.write_log("❌ L'API a répondu avec une erreur.", "threat_color")
        except:
            self.write_log("❌ Erreur de connexion : Vérifiez que FastAPI est démarré.", "threat_color")

    def start_live_mode(self):
        self.is_live_running = True
        self.live_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        
        self.stat_total = self.stat_normal = self.stat_threats = 0
        self.lbl_total.configure(text="📊 Total: 0")
        self.lbl_normal.configure(text="🟢 Normal: 0")
        self.lbl_threat.configure(text="🚨 Menaces: 0")
        self.lbl_last.configure(text="⚠️ Dernière Menace: Aucune")

        self.write_log("\n📡 DÉMARRAGE DU CAPTEUR LIVE (SNIFFER)...", "system_color")
        self.write_log("Analyse du flux réseau en cours...", "system_color")
        self.write_log("-" * 80, "system_color")

        threading.Thread(target=self.run_live_thread, daemon=True).start()

    def stop_live_mode(self):
        self.is_live_running = False
        self.write_log("\n🛑 Analyse en temps réel suspendue par l'administrateur.", "system_color")
        self.live_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def run_live_thread(self):
        api_url = "http://127.0.0.1:8000/predict"
        live_file = "live_traffic.csv"
        last_index = 0  
        waiting_message_shown = False # Variable bax n-affichiw l'message mra we7da

        while self.is_live_running:
            try:
                if os.path.exists(live_file):
                    df = pd.read_csv(live_file)
                    
                    if len(df) > last_index:
                        new_rows = df.iloc[last_index:].copy()
                        if 'cwe_flag_count' not in new_rows.columns:
                            new_rows['cwe_flag_count'] = 0
                        new_rows.columns = new_rows.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('-', '_').str.replace('/', '_')
                        
                        rename_map = {
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
                        new_rows.rename(columns=rename_map, inplace=True)
                        new_rows.replace([np.inf, -np.inf], np.nan, inplace=True)
                        new_rows.fillna(0, inplace=True)
                        
                        for index, row in new_rows.iterrows():
                            if not self.is_live_running:
                                break
                            
                            data = row.to_dict()
                            if 'fwd_header_length' in data:
                                data['fwd_header_length.1'] = data['fwd_header_length']
                            
                            try:
                                response = requests.post(api_url, json=data)
                                
                                if response.status_code == 200:
                                    result = response.json()
                                    pred = result['prediction']
                                    conf = round(result['confidence_score'] * 100, 2)
                                    
                                    self.after(0, self.update_dashboard, result['is_threat'], pred)
                                    
                                    if result['is_threat']:
                                        msg = f"[FLUX | ID: {last_index + index}] 🚨 MENACE IDENTIFIÉE | Catégorie: {pred} | Fiabilité: {conf}%"
                                        self.after(0, self.write_log, msg, "threat_color")
                                        self.save_alert_to_file(msg)
                                        self.send_telegram_alert(msg)    
                                    else:
                                        msg = f"[FLUX | ID: {last_index + index}] 🟢 Trafic Normal | Fiabilité: {conf}%"
                                        self.after(0, self.write_log, msg, "normal_color")
                                        
                            except requests.exceptions.ConnectionError:
                                self.after(0, self.write_log, "❌ Le backend d'IA (FastAPI) est indisponible.", "threat_color")
                                self.is_live_running = False
                                break
                            
                            time.sleep(0.1) 
                        
                        last_index = len(df)
                        waiting_message_shown = False # Reset ila l9a data jdida
                else:
                    # Ila l'fichier mazal matcreyach, afficher message yfeker l'utilisateur
                    if not waiting_message_shown:
                        self.after(0, self.write_log, "⏳ En attente de création du fichier 'live_traffic.csv'...", "system_color")
                        self.after(0, self.write_log, "⚠️ N'oubliez pas de lancer CICFlowMeter dans un autre terminal !", "threat_color")
                        waiting_message_shown = True
            
            except Exception as e:
                print(f"Erreur interne: {e}") 
            
            time.sleep(1) # Vérifie les nouveaux paquets toutes les secondes
            
        # Restauration de l'état des boutons si la boucle s'arrête
        self.after(0, self.stop_button.configure, {"state": "disabled"})
        self.after(0, self.live_button.configure, {"state": "normal"})

if __name__ == "__main__":
    app = CyberThreatApp()
    app.mainloop()