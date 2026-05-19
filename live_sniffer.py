import sys
import logging
from cicflowmeter.sniffer import create_sniffer

# =====================================================================
# 1. CONFIGURATION DU SYSTEME DE JOURNALISATION
# =====================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [CAPTEUR] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# =====================================================================
# 2. PARAMETRES DU CAPTEUR RESEAU
# =====================================================================
INTERFACE = "wlp58s0"      # Interface reseau cible
FICHIER_CSV = "live_traffic.csv" # Fichier tampon d'export

def main():
    """Point d'entree principal du capteur reseau."""
    logger.info("=" * 60)
    logger.info("Initialisation du moteur CICFlowMeter (Mode Temps Reel)")
    logger.info(f"Interface d'ecoute : {INTERFACE}")
    logger.info(f"Fichier d'export   : {FICHIER_CSV}")
    logger.info("=" * 60)

    try:
        # Configuration et initialisation du sniffer
        sniffer, session = create_sniffer(
            input_file=None,
            input_interface=INTERFACE,
            output_mode="csv",
            output=FICHIER_CSV,
            fields=None
        )

        # Lancement du processus de capture en arriere-plan
        sniffer.start()
        logger.info("Capture reseau en cours. En attente de trafic...")
        logger.info("(Utilisez Ctrl+C pour interrompre le processus proprement)")

        # Maintien du script actif
        sniffer.join()

    except KeyboardInterrupt:
        logger.warning("Signal d'interruption recu (SIGINT).")
        logger.info("Cloture des sockets et arret du capteur en cours...")
        try:
            sniffer.stop()
            sniffer.join()
        except Exception:
            pass # Ignore les erreurs lors de la fermeture forcee
        logger.info("Capteur reseau arrete avec succes.")
        sys.exit(0)

    except PermissionError:
        logger.error("Privileges administrateur manquants.")
        logger.error("Le sniffer doit etre execute avec 'sudo' pour ecouter l'interface.")
        sys.exit(1)

    except Exception as e:
        logger.error(f"Defaillance critique du capteur : {str(e)}")
        logger.error(f"Veuillez verifier que l'interface '{INTERFACE}' est active.")
        sys.exit(1)

if __name__ == "__main__":
    main()