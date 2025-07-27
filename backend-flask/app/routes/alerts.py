from flask import Blueprint, jsonify, request
from ..model.ai_model import predict_intrusion
from datetime import datetime
import uuid
import json
from app.utils.network_data import get_network_data
from app.config import DATA_FILE

alerts_bp = Blueprint('alerts', __name__)

# Stockage temporaire des alertes en mémoire
alerts = []

@alerts_bp.route('/alerts', methods=['GET'])
def get_alerts():
    return jsonify(alerts)

@alerts_bp.route('/alerts/<int:alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    data = get_network_data()
    if data is None:
        return jsonify({'error': 'Erreur lors de la récupération des données'}), 500
    original_len = len(data['alerts'])
    data['alerts'] = [a for a in data['alerts'] if a['id'] != alert_id]
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    return jsonify({'deleted': original_len - len(data['alerts'])})

@alerts_bp.route('/detect', methods=['POST'])
def detect_intrusion():
    data = request.get_json()
    
    required_fields = ['source_ip', 'destination_ip', 'protocol', 'source_port', 'dest_port']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Champs requis manquants'}), 400
    
    # Prédiction avec le modèle
    is_intrusion, attack_type, confidence = predict_intrusion(data)

    # Bloquer les alertes pour trafic local
    if (data.get('source_ip') in ['127.0.0.1', 'localhost'] and data.get('destination_ip') in ['127.0.0.1', 'localhost']):
        return jsonify({'message': 'Trafic local ignoré', 'timestamp': datetime.now().isoformat()}), 200
    
    if is_intrusion:
        alert = {
            'id': str(uuid.uuid4()),
            'sourceIp': data.get('source_ip', 'unknown'),
            'destinationIp': data.get('destination_ip', 'unknown'),
            'protocol': data.get('protocol', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'attackType': attack_type,
            'severity': 'high' if attack_type in ['SQL Injection', 'Remote Code Execution'] else 'medium',
            'confidence': confidence
        }
        alerts.append(alert)
        # Garder seulement les 1000 dernières alertes
        if len(alerts) > 1000:
            alerts.pop(0)
        return jsonify(alert), 201
    
    return jsonify({
        'message': 'No intrusion detected',
        'timestamp': datetime.now().isoformat()
    }) 