from app import create_app
import logging
from app.routes.settings import settings_bp
from app.routes.rules import rules_bp
import threading
from app.utils import network_scanner

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    app = create_app()
    app.register_blueprint(settings_bp)
    app.register_blueprint(rules_bp)

    # Démarrer le scanner réseau en arrière-plan
    scanner_thread = threading.Thread(target=network_scanner.scanner.start, daemon=True)
    scanner_thread.start()

    # Lancer le serveur Flask
    app.run(host="0.0.0.0", port=5000, debug=True) 