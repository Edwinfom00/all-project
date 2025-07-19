from flask import Flask
from flask_cors import CORS
from .routes.stats import stats_bp
from .routes.rules import rules_bp

def create_app():
    app = Flask(__name__)
    CORS(app)

    # Configuration
    app.config['JSON_AS_ASCII'] = False
    app.config['JSON_SORT_KEYS'] = False

    # Enregistrement des blueprints
    app.register_blueprint(stats_bp, url_prefix='/api/stats')

    @app.route('/health')
    def health_check():
        return {'status': 'ok'}

    return app
