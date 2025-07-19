from flask import Blueprint, jsonify, request
import os
import json
from pathlib import Path

settings_bp = Blueprint('settings', __name__)

SETTINGS_FILE = Path(__file__).parent.parent / 'data' / 'settings.json'

DEFAULT_SETTINGS = {
    "thresholds": {
        "bruteForce": 10,
        "dos": 1000
    },
    "modules": {
        "dos": True,
        "bruteforce": True,
        "probe": True,
        "sql_injection": True,
        "xss": True,
        "port_scan": True,
        "r2l": True,
        "u2r": True
    }
}

def load_settings():
    if not SETTINGS_FILE.exists():
        return DEFAULT_SETTINGS.copy()
    try:
        with open(SETTINGS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return DEFAULT_SETTINGS.copy()

def save_settings(settings):
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=2)

@settings_bp.route('/api/settings', methods=['GET'])
def get_settings():
    settings = load_settings()
    return jsonify(settings)

@settings_bp.route('/api/settings', methods=['POST'])
def update_settings():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Aucune donnée reçue"}), 400
    settings = load_settings()
    # Met à jour les champs existants uniquement
    if 'thresholds' in data:
        settings['thresholds'].update(data['thresholds'])
    if 'modules' in data:
        settings['modules'].update(data['modules'])
    save_settings(settings)
    return jsonify(settings) 