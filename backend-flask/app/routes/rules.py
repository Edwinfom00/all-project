from flask import Blueprint, jsonify, request
import json
from pathlib import Path

rules_bp = Blueprint('rules', __name__)

RULES_FILE = Path(__file__).parent.parent / 'data' / 'rules.json'

DEFAULT_RULES = [
    {
        "id": 1,
        "name": "Brute Force",
        "description": "Plus de 10 tentatives de connexion échouées en moins de 5 minutes depuis la même IP.",
        "action": "Générer une alerte Brute Force"
    },
    {
        "id": 2,
        "name": "DoS",
        "description": "Nombre de requêtes sur le port 80 dépasse 1000 en 1 minute.",
        "action": "Générer une alerte DoS"
    }
]

def load_rules():
    if not RULES_FILE.exists():
        return DEFAULT_RULES.copy()
    try:
        with open(RULES_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return DEFAULT_RULES.copy()

def save_rules(rules):
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(RULES_FILE, 'w') as f:
        json.dump(rules, f, indent=2)

@rules_bp.route('/api/rules', methods=['GET'])
def get_rules():
    return jsonify(load_rules())

@rules_bp.route('/api/rules', methods=['POST'])
def update_rules():
    data = request.get_json()
    if not data or not isinstance(data, list):
        return jsonify({"error": "Format attendu : liste de règles"}), 400
    save_rules(data)
    return jsonify(load_rules()) 