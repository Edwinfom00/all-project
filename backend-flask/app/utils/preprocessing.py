from typing import Dict, Any, List
import re

def parse_snort_log(log_line: str) -> Dict[str, Any]:
    """
    Parse une ligne de log Snort en dictionnaire compatible avec le modèle.
    Exemple de log Snort :
    04/10-15:23:45.123456 [**] [1:1000001:0] Test alert [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.1.100:12345 -> 10.0.0.5:80
    """
    pattern = r'(?P<date>\d{2}/\d{2})-(?P<time>\d{2}:\d{2}:\d{2}\.\d{6}) \[\*\*\] \[.*?\] (?P<msg>.*?) \[Classification: (?P<classification>.*?)\] \[Priority: (?P<priority>\d+)\] \{(?P<protocol>\w+)\} (?P<source_ip>\d+\.\d+\.\d+\.\d+):(?P<source_port>\d+) -> (?P<dest_ip>\d+\.\d+\.\d+\.\d+):(?P<dest_port>\d+)'
    match = re.match(pattern, log_line)
    if match:
        d = match.groupdict()
        # Adapter les clés pour le modèle
        return {
            'source_ip': d['source_ip'],
            'destination_ip': d['dest_ip'],
            'protocol': d['protocol'],
            'source_port': int(d['source_port']),
            'dest_port': int(d['dest_port']),
            'classification': d['classification'],
            'priority': int(d['priority'])
        }
    return {}

def extract_features(log_data: Dict[str, Any]) -> List[float]:
    """
    Extrait les features pour le modèle ML à partir des données de log.
    Aligne les features sur le dataset d'entraînement NSL-KDD (exemple simplifié).
    Args:
        log_data: Dictionnaire contenant les données du log
    Returns:
        Liste des features extraites
    """
    features = []
    # Conversion des IPs en nombres (4 octets)
    for ip_key in ['source_ip', 'destination_ip']:
        ip = log_data.get(ip_key, '0.0.0.0')
        features.extend([int(part) for part in ip.split('.')])
    # Ports
    features.append(int(log_data.get('source_port', 0)))
    features.append(int(log_data.get('dest_port', 0)))
    # Protocole (one-hot encoding simplifié)
    proto = log_data.get('protocol', '').lower()
    proto_map = {'tcp': [1,0,0], 'udp': [0,1,0], 'icmp': [0,0,1]}
    features.extend(proto_map.get(proto, [0,0,0]))
    # Classification (optionnel, si présente)
    # features.append(int(log_data.get('priority', 0)))
    return features


def normalize_features(features: List[float]) -> List[float]:
    """
    Normalise les features pour le modèle ML.
    Utilise des bornes réalistes pour chaque feature (aligné sur l'entraînement).
    Args:
        features: Liste des features à normaliser
    Returns:
        Liste des features normalisées
    """
    # 4 octets IP source, 4 octets IP dest, 2 ports, 3 protocoles
    max_vals = [255]*8 + [65535, 65535] + [1,1,1]
    return [f / m if m != 0 else 0 for f, m in zip(features, max_vals)] 