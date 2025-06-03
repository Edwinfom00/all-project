from flask import Blueprint, jsonify
from ..model.tf_model import IDSModel
import psutil
import os
import json
from datetime import datetime, timedelta

model_stats = Blueprint('model_stats', __name__)

def get_latest_model_path():
    models_dir = os.path.join(os.path.dirname(__file__), '../../../data/models')
    if not os.path.exists(models_dir):
        return None
    
    model_dirs = [d for d in os.listdir(models_dir) if os.path.isdir(os.path.join(models_dir, d))]
    if not model_dirs:
        return None
    
    latest_dir = max(model_dirs, key=lambda x: os.path.getctime(os.path.join(models_dir, x)))
    return os.path.join(models_dir, latest_dir)

@model_stats.route('/api/stats/model', methods=['GET'])
def get_model_stats():
    model_path = get_latest_model_path()
    if not model_path:
        return jsonify({
            'error': 'Aucun modèle trouvé'
        }), 404
    
    # Charger l'historique d'entraînement
    history_path = os.path.join(model_path, 'training_history.json')
    training_history = []
    if os.path.exists(history_path):
        with open(history_path, 'r') as f:
            training_history = json.load(f)
    
    # Charger les métriques du modèle
    metrics_path = os.path.join(model_path, 'metrics.json')
    metrics = {}
    if os.path.exists(metrics_path):
        with open(metrics_path, 'r') as f:
            metrics = json.load(f)
    
    return jsonify({
        'metrics': metrics,
        'training_history': training_history,
        'last_updated': datetime.fromtimestamp(os.path.getctime(model_path)).isoformat()
    })

@model_stats.route('/api/stats/system', methods=['GET'])
def get_system_stats():
    # Statistiques système
    cpu_usage = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    
    # Statistiques réseau
    net_io = psutil.net_io_counters()
    
    # Uptime du processus
    process = psutil.Process(os.getpid())
    uptime = datetime.now() - datetime.fromtimestamp(process.create_time())
    
    return jsonify({
        'cpu_usage': cpu_usage,
        'memory_usage': memory.percent,
        'network_stats': {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        },
        'uptime': str(uptime),
        'active_connections': len(psutil.net_connections())
    }) 