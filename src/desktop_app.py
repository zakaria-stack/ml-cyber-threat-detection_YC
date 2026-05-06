import customtkinter as ctk
from tkinter import filedialog
import requests
import threading
import time
import pandas as pd
import numpy as np

# ---------------------------------------------------------
# Configuration du Thème Global
# ---------------------------------------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class CyberThreatApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # 1. Configuration de la fenêtre principale
        self.title("YaneCode - Console SOC & Détection d'Intrusions")
        self.geometry("1100x700")  # Fenêtre plus grande
        
        # Pour que la partie droite prenne tout l'espace disponible
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.is_simulating = False
        
        # Variables pour les statistiques
        self.stat_total = 0
        self.stat_normal = 0
        self.stat_threats = 0

        # ---------------------------------------------------------
        # Sidebar (Menu latéral gauche)
        # ---------------------------------------------------------
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ YaneCode SOC", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 30))

        self.test_button = ctk.CTkButton(self.sidebar_frame, text="🔍 Test de Connexion API", command=self.send_test_request)
        self.test_button.grid(row=1, column=0, padx=20, pady=10)

        # Bouton modifié pour préciser qu'on peut en choisir plusieurs
        self.sim_button = ctk.CTkButton(self.sidebar_frame, text="📁 Lancer Simulation (CSVs)", command=self.start_simulation, fg_color="#28a745", hover_color="#218838")
        self.sim_button.grid(row=2, column=0, padx=20, pady=10)

        self.stop_button = ctk.CTkButton(self.sidebar_frame, text="🛑 Arrêter la simulation", command=self.stop_simulation, fg_color="#dc3545", hover_color="#c82333", state="disabled")
        self.stop_button.grid(row=3, column=0, padx=20, pady=10)

        # Bouton 4 : Effacer la console (Bonus)
        self.clear_button = ctk.CTkButton(self.sidebar_frame, text="🧹 Effacer la console", command=self.clear_console, fg_color="#6c757d", hover_color="#5a6268")
        self.clear_button.grid(row=4, column=0, padx=20, pady=10)
        # ---------------------------------------------------------
        # Main Frame (Écran principal à droite)
        # ---------------------------------------------------------
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1) # La console prendra tout l'espace restant

        # Titre
        self.title_label = ctk.CTkLabel(self.main_frame, text="Analyse du Trafic Réseau en Temps Réel", font=ctk.CTkFont(size=24, weight="bold"))
        self.title_label.grid(row=0, column=0, pady=(0, 20))

        # --- NOUVEAU : DASHBOARD (Statistiques en temps réel) ---
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

        # --- CONSOLE DE LOGS ---
        self.result_textbox = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Consolas", size=14), fg_color="#0d0d16", text_color="#ffffff")
        self.result_textbox.grid(row=2, column=0, sticky="nsew")
        
        # Configuration des couleurs pour le texte de la console
        self.result_textbox.tag_config("normal_color", foreground="#00e676")
        self.result_textbox.tag_config("threat_color", foreground="#ff4444")
        self.result_textbox.tag_config("system_color", foreground="#00bfff")

        self.write_log("✅ Système SOC initialisé. En attente de trafic...", "system_color")

    # ---------------------------------------------------------
    # Fonctions Utilitaires
    # ---------------------------------------------------------
    def write_log(self, message, tag=None):
        """Ajoute un texte coloré dans la console et auto-scroll."""
        if tag:
            self.result_textbox.insert("end", message + "\n", tag)
        else:
            self.result_textbox.insert("end", message + "\n")
        self.result_textbox.see("end")

    def update_dashboard(self, is_threat, pred_type):
        """Met à jour les compteurs du dashboard depuis le Thread."""
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
        """Efface tout le texte de la console."""
        self.result_textbox.delete("1.0", "end")
        self.write_log("🧹 Console nettoyée. En attente de nouveau trafic...", "system_color")

    def save_alert_to_file(self, message):
        """Sauvegarde les alertes rouges dans un fichier texte avec l'heure."""
        import datetime
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Le mode "a" (append) permet d'ajouter à la fin du fichier sans effacer le reste
        with open("logs_alertes.txt", "a", encoding="utf-8") as file:
            file.write(f"[{now}] {message}\n")
    # ---------------------------------------------------------
    # Fonctions de Simulation
    # ---------------------------------------------------------
    def send_test_request(self):
        self.write_log("\n🔄 Test de connexion vers l'API...", "system_color")
        self.update()
        self.write_log("✅ API contactée avec succès (Test).", "system_color")

    def start_simulation(self):
        # ⚠️ NOUVEAU : askopenfilenames (avec un 's') permet de sélectionner plusieurs fichiers d'un coup !
        filepaths = filedialog.askopenfilenames(title="Sélectionner les datasets réseau", filetypes=(("Fichiers CSV", "*.csv"), ("Tous les fichiers", "*.*")))
        
        if not filepaths:
            return

        self.is_simulating = True
        self.sim_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        
        # Remise à zéro des statistiques
        self.stat_total = self.stat_normal = self.stat_threats = 0
        self.update_dashboard(False, "")

        self.write_log(f"\n🚀 DÉMARRAGE DE LA SIMULATION ({len(filepaths)} fichier(s) sélectionné(s))...", "system_color")
        self.write_log("-" * 80, "system_color")

        threading.Thread(target=self.run_simulation_thread, args=(filepaths,), daemon=True).start()

    def stop_simulation(self):
        self.is_simulating = False
        self.write_log("\n🛑 Simulation interrompue par l'utilisateur.", "system_color")
        self.sim_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def run_simulation_thread(self, filepaths):
        api_url = "http://127.0.0.1:8000/predict"
        
        try:
            self.after(0, self.write_log, f"\n⚙️ Lecture et fusion de {len(filepaths)} fichier(s)...", "system_color")
            
            # 1. Lire et fusionner tous les fichiers sélectionnés
            dataframes = []
            for filepath in filepaths:
                df = pd.read_csv(filepath)
                # On ajoute une colonne temporaire pour se rappeler d'où vient la ligne
                df['source_file'] = filepath.split('/')[-1] 
                dataframes.append(df)
            
            # Création du méga-dataset !
            mega_df = pd.concat(dataframes, ignore_index=True)
            
            # 2. Nettoyage global
            mega_df.columns = mega_df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('-', '_').str.replace('/', '_')
            mega_df.replace([np.inf, -np.inf], np.nan, inplace=True)
            mega_df.fillna(0, inplace=True)
            
            # 3. LE GRAND MÉLANGE (Shuffle global de tous les fichiers)
            self.after(0, self.write_log, "🔀 Mélange aléatoire de TOUTES les données en cours...", "system_color")
            mega_df = mega_df.sample(frac=1).reset_index(drop=True)
            
            self.after(0, self.write_log, "✅ Prêt ! Lancement de l'analyse en temps réel.\n", "system_color")
            
            # 4. Lecture ligne par ligne du dataset géant fusionné
            for index, row in mega_df.iterrows():
                if not self.is_simulating:
                    break
                
                # On convertit en dictionnaire
                data = row.to_dict()
                
                # On retire la colonne 'source_file' pour ne pas perturber FastAPI
                original_file = data.pop('source_file', 'Inconnu')
                # Pour alléger l'affichage, on raccourcit le nom du fichier s'il est trop long
                short_file = original_file[:15] + "..." if len(original_file) > 15 else original_file
                
                try:
                    response = requests.post(api_url, json=data)
                    
                    if response.status_code == 200:
                        result = response.json()
                        pred = result['prediction']
                        conf = round(result['confidence_score'] * 100, 2)
                        
                        self.after(0, self.update_dashboard, result['is_threat'], pred)
                        
                        if result['is_threat']:
                            msg = f"[{short_file} | Ligne {index}] 🚨 MENACE BLOQUÉE | Type: {pred} | Conf: {conf}%"
                            self.after(0, self.write_log, msg, "threat_color")
                            self.save_alert_to_file(msg)
                        else:
                            msg = f"[{short_file} | Ligne {index}] 🟢 Trafic autorisé | Type: {pred} | Conf: {conf}%"
                            self.after(0, self.write_log, msg, "normal_color")
                    else:
                        error_detail = response.json().get("detail", "Erreur inconnue")
                        self.after(0, self.write_log, f"❌ Erreur API: {error_detail}", "threat_color")
                        break
                
                except requests.exceptions.ConnectionError:
                    self.after(0, self.write_log, "❌ Erreur : Impossible de contacter FastAPI.", "threat_color")
                    break

                time.sleep(0.5) 

        except Exception as e:
            self.after(0, self.write_log, f"\n❌ Erreur système : {e}", "threat_color")

        self.after(0, self.stop_button.configure, {"state": "disabled"})
        self.after(0, self.sim_button.configure, {"state": "normal"})
        self.is_simulating = False

if __name__ == "__main__":
    app = CyberThreatApp()
    app.mainloop()