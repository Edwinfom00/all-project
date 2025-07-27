import json
from pathlib import Path

DATA_FILE = Path(__file__).parent.parent / 'data' / 'network_data.json'

def get_network_data():
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
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {
            'connections': [],
            'alerts': [],
            'stats': {}
        } 