from cicflowmeter.sniffer import create_sniffer

interface = "wlp58s0" # L'carte dyalk
fichier_csv = "live_traffic.csv"

print(f"Lancement de CICFlowMeter en direct sur l'interface : {interface}...")

# L'appel S7I7 b les paramètres s7a7 :
sniffer, session = create_sniffer(
    input_file=None,
    input_interface=interface,
    output_mode="csv",
    output=fichier_csv,
    fields=None
)

sniffer.start()

try:
    sniffer.join()
except KeyboardInterrupt:
    print("\n🛑 Arrêt du Sniffer en cours...")
    sniffer.stop()
    sniffer.join()
    print("✅ Sniffing terminé avec succès !")
