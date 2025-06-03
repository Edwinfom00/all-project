from flask import Blueprint, jsonify
from datetime import datetime
import psutil
import os
import json
from pathlib import Path
import logging

stats_bp = Blueprint('stats', __name__)
logger = logging.getLogger(__name__)

# Chemin vers le dossier de stockage des données
DATA_DIR = Path(__file__).parent.parent / 'data'
DATA_FILE = DATA_DIR / 'network_data.json'
METRICS_FILE = DATA_DIR / 'model_metrics.json'
HISTORY_FILE = DATA_DIR / 'training_history.json'
TEST_LOGS_FILE = DATA_DIR / 'test_logs.json'

def get_network_data():
    """Récupère les données réseau depuis le fichier JSON"""
    try:
        if not DATA_FILE.exists():
            return {
                'connections': [],
                'alerts': [],
                'stats': {
                    'total_connections': 0,
                    'total_packets': 0,
                    'total_alerts': 0,
                    'active_threats': 0,
                    'blocked_attempts': 0,
                    'system_health': 100
                }
            }
        
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Erreur lors de la lecture des données: {e}")
        return None

@stats_bp.route('/traffic', methods=['GET'])
def get_traffic():
    """Route pour récupérer les données de trafic"""
    data = get_network_data()
    if data is None:
        return jsonify({'error': 'Erreur lors de la récupération des données'}), 500
    return jsonify(data)

@stats_bp.route('/alerts', methods=['GET'])
def get_alerts():
    """Route pour récupérer les alertes"""
    data = get_network_data()
    if data is None:
        return jsonify({'error': 'Erreur lors de la récupération des données'}), 500
    return jsonify(data['alerts'])

@stats_bp.route('/model-stats', methods=['GET'])
def get_model_stats():
    """Route pour récupérer les statistiques du modèle d'IA"""
    data = get_network_data()
    if data is None:
        return jsonify({'error': 'Erreur lors de la récupération des données'}), 500
    
    # Calculer les statistiques du modèle
    total_connections = data['stats']['total_connections']
    total_alerts = data['stats']['total_alerts']
    active_threats = data['stats']['active_threats']
    
    # Calculer le taux de détection
    detection_rate = (total_alerts / total_connections * 100) if total_connections > 0 else 0
    
    # Analyser les types d'attaques détectées
    attack_types = {}
    for alert in data['alerts']:
        attack_type = alert['attackType']
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
    
    # Préparer les statistiques
    model_stats = {
        'performance': {
            'total_connections': total_connections,
            'total_alerts': total_alerts,
            'active_threats': active_threats,
            'detection_rate': round(detection_rate, 2),
            'system_health': data['stats']['system_health']
        },
        'attack_distribution': attack_types,
        'recent_alerts': data['alerts'][-5:],  # 5 dernières alertes
        'model_status': 'active' if total_connections > 0 else 'inactive'
    }
    
    return jsonify(model_stats)

def safe_read_json(path, default):
    try:
        if not path.exists():
            return default
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Erreur lors de la lecture de {path}: {e}")
        return default

@stats_bp.route('/model-metrics', methods=['GET'])
def get_model_metrics():
    """Route pour récupérer les métriques du modèle d'IA (accuracy, precision, recall, etc.)"""
    default = {
        'accuracy': 0.0,
        'precision': 0.0,
        'recall': 0.0,
        'f1_score': 0.0,
        'last_update': None
    }
    metrics = safe_read_json(METRICS_FILE, default)
    return jsonify(metrics)

@stats_bp.route('/training-history', methods=['GET'])
def get_training_history():
    """Route pour récupérer l'historique d'entraînement du modèle d'IA"""
    default = []
    history = safe_read_json(HISTORY_FILE, default)
    return jsonify(history)

@stats_bp.route('/test-logs', methods=['GET'])
def get_test_logs():
    """Route pour récupérer les logs de tests du modèle d'IA"""
    default = []
    logs = safe_read_json(TEST_LOGS_FILE, default)
    return jsonify(logs) 