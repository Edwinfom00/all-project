from app import create_app
import logging
from app.routes.settings import settings_bp
from app.routes.rules import rules_bp

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Création de l'application Flask
app = create_app()
app.register_blueprint(settings_bp)
app.register_blueprint(rules_bp)

if __name__ == '__main__':
    try:
        logger.info("Démarrage du serveur Flask sur localhost:5000...")
        app.run(host='localhost', port=5000, debug=True)
    except Exception as e:
        logger.error(f"Erreur lors du démarrage: {str(e)}")
        raise 