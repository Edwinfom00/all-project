from flask import Blueprint, jsonify, request
from ..model.tf_model import IDSModel
import os
import json
from datetime import datetime

test_logs = Blueprint('test_logs', __name__)

def get_logs_file_path():
    logs_dir = os.path.join(os.path.dirname(__file__), '../../../data/logs')
    os.makedirs(logs_dir, exist_ok=True)
    return os.path.join(logs_dir, 'test_logs.json')

def load_logs():
    logs_path = get_logs_file_path()
    if not os.path.exists(logs_path):
        return []
    
    with open(logs_path, 'r') as f:
        return json.load(f)

def save_log(log_entry):
    logs = load_logs()
    logs.append(log_entry)
    
    # Garder seulement les 1000 derniers logs
    logs = logs[-1000:]
    
    with open(get_logs_file_path(), 'w') as f:
        json.dump(logs, f)

@test_logs.route('/api/logs/tests', methods=['GET'])
def get_test_logs():
    logs = load_logs()
    
    # Filtrage par date
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if start_date:
        start_date = datetime.fromisoformat(start_date)
        logs = [log for log in logs if datetime.fromisoformat(log['timestamp']) >= start_date]
    
    if end_date:
        end_date = datetime.fromisoformat(end_date)
        logs = [log for log in logs if datetime.fromisoformat(log['timestamp']) <= end_date]
    
    return jsonify(logs)

@test_logs.route('/api/logs/tests', methods=['POST'])
def add_test_log():
    data = request.get_json()
    
    required_fields = ['testType', 'input', 'prediction', 'confidence']
    if not all(field in data for field in required_fields):
        return jsonify({
            'error': 'Champs requis manquants'
        }), 400
    
    log_entry = {
        'id': str(len(load_logs()) + 1),
        'timestamp': datetime.now().isoformat(),
        'testType': data['testType'],
        'input': data['input'],
        'prediction': data['prediction'],
        'confidence': data['confidence'],
        'actualClass': data.get('actualClass'),
        'status': data.get('status', 'success')
    }
    
    save_log(log_entry)
    return jsonify(log_entry), 201 