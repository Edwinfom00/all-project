import psutil
import time
import json
from datetime import datetime
from pathlib import Path
import logging
from ..model.ai_model import predict_intrusion, preprocess_data

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.data_file = Path(__file__).parent.parent / 'data' / 'network_data.json'
        self._initialize_data()
        
    def _initialize_data(self):
        """Initialise le fichier de données s'il n'existe pas"""
        if not self.data_file.exists():
            data = {
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
            self._save_data(data)
    
    def _save_data(self, data):
        """Sauvegarde les données dans le fichier JSON"""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des données: {e}")
    
    def _process_connection(self, conn):
        """Traite une connexion réseau"""
        try:
            # Préparer les données pour le modèle
            connection_data = {
                'source_ip': conn.laddr.ip if conn.laddr else '0.0.0.0',
                'dest_ip': conn.raddr.ip if conn.raddr else '0.0.0.0',
                'source_port': conn.laddr.port if conn.laddr else 0,
                'dest_port': conn.raddr.port if conn.raddr else 0,
                'protocol': conn.type,
                'status': conn.status if hasattr(conn, 'status') else 'NONE',
                'timestamp': datetime.now().isoformat()
            }
            
            # Prétraiter les données
            processed_data = preprocess_data(connection_data)
            
            # Analyser avec le modèle d'IA
            is_intrusion, attack_type = predict_intrusion(processed_data)
            
            # Ajouter les résultats de l'analyse
            connection_data['attackType'] = attack_type
            connection_data['severity'] = 'high' if is_intrusion else 'low'
            
            return connection_data
        except Exception as e:
            logger.error(f"Erreur lors du traitement de la connexion: {e}")
            return None
    
    def _run_scanner(self):
        """Exécute le scanner réseau"""
        try:
            # Lire les données existantes
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            
            # Obtenir les connexions réseau
            connections = psutil.net_connections()
            processed_connections = []
            new_alerts = []
            
            for conn in connections:
                processed = self._process_connection(conn)
                if processed:
                    processed_connections.append(processed)
                    
                    # Si c'est une intrusion détectée, créer une alerte
                    if processed['severity'] == 'high':
                        alert = {
                            'id': len(data['alerts']) + 1,
                            'sourceIp': processed['source_ip'],
                            'destinationIp': processed['dest_ip'],
                            'protocol': processed['protocol'],
                            'timestamp': processed['timestamp'],
                            'attackType': processed['attackType'],
                            'severity': processed['severity']
                        }
                        new_alerts.append(alert)
            
            # Mettre à jour les données
            data['connections'] = processed_connections[-100:]  # Garder les 100 dernières connexions
            data['alerts'] = new_alerts[-50:]  # Garder les 50 dernières alertes
            data['stats']['total_connections'] = len(processed_connections)
            data['stats']['total_alerts'] = len(new_alerts)
            data['stats']['active_threats'] = len([a for a in new_alerts if a['severity'] == 'high'])
            
            # Sauvegarder les données
            self._save_data(data)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution du scanner: {e}")
    
    def start(self):
        """Démarre le scanner réseau"""
        logger.info("Démarrage du scanner réseau avec analyse IA...")
        while True:
            self._run_scanner()
            time.sleep(2)  # Scanner toutes les 2 secondes

# Créer une instance globale du scanner
scanner = NetworkScanner()

if __name__ == "__main__":
    # Créer et démarrer le scanner
    scanner = NetworkScanner()
    try:
        scanner.start()
        # Garder le script en cours d'exécution
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nArrêt du scanner...")
        scanner.stop() 