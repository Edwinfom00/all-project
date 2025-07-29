from typing import Dict, Any, List
import re
import ast
import os
import numpy as np

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

# Charger la liste des colonnes NSL-KDD prétraitées
COLUMNS_PATH = os.path.join(os.path.dirname(__file__), 'nslkdd_columns.txt')
try:
    with open(COLUMNS_PATH, 'r', encoding='utf-8') as f:
        NSLKDD_COLUMNS = ast.literal_eval(f.read())
except FileNotFoundError:
    # Colonnes NSL-KDD standard (41 features + encodages)
    NSLKDD_COLUMNS = [
        # Features numériques de base (0-40)
        'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
        'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
        'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
        'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count',
        'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
        'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
        'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
        # Protocol encodings
        'protocol_icmp', 'protocol_tcp', 'protocol_udp',
        # Service encodings (exemples principaux)
        'service_http', 'service_ftp', 'service_ssh', 'service_telnet', 'service_smtp',
        'service_domain', 'service_pop_3', 'service_imap', 'service_other',
        # Flag encodings
        'flag_SF', 'flag_S0', 'flag_REJ', 'flag_RSTR', 'flag_RSTO', 'flag_SH', 'flag_OTH'
    ]
    # Compléter jusqu'à 145 avec des features additionnelles
    while len(NSLKDD_COLUMNS) < 145:
        NSLKDD_COLUMNS.append(f'feature_{len(NSLKDD_COLUMNS)}')

def extract_features(log_data: Dict[str, Any]) -> List[float]:
    """
    VERSION CORRIGÉE SPÉCIALISÉE - Extraction optimisée pour distinguer DoS, Probe et Port Scan
    """
    # Initialiser avec des zéros pour toutes les 145 features
    features = [0.0] * 145
    
    # Variables d'entrée avec valeurs par défaut
    connections_count = log_data.get('connections_count', 0)
    dest_port = log_data.get('dest_port', 80)
    source_ip = log_data.get('source_ip', '0.0.0.0')
    dest_ip = log_data.get('destination_ip', '0.0.0.0')
    protocol = log_data.get('protocol', 'tcp').lower()
    flag = log_data.get('flag', 'SF')
    port_count = log_data.get('port_count', 1)  # NOUVEAU: nombre de ports différents
    scan_pattern = log_data.get('scan_pattern', 'none')  # NOUVEAU: pattern de scan détecté
    
    print(f"🔧 Extraction features - Connexions: {connections_count}, Ports: {port_count}, Pattern: {scan_pattern}")
    
    # === FEATURES NUMÉRIQUES DE BASE (positions 0-18) ===
    features[0] = log_data.get('duration', 0)  # duration
    features[1] = log_data.get('bytes_sent', 0)  # src_bytes  
    features[2] = log_data.get('bytes_received', 0)  # dst_bytes
    features[3] = 1 if source_ip == dest_ip else 0  # land
    features[4] = 0  # wrong_fragment
    features[5] = 0  # urgent
    features[6] = 0  # hot
    features[7] = 0  # num_failed_logins
    features[8] = 0  # logged_in
    features[9] = 0  # num_compromised
    features[10] = 0  # root_shell
    features[11] = 0  # su_attempted
    features[12] = 0  # num_root
    features[13] = 0  # num_file_creations
    features[14] = 0  # num_shells
    features[15] = 0  # num_access_files
    features[16] = 0  # num_outbound_cmds
    features[17] = 0  # is_host_login
    features[18] = 0  # is_guest_login
    
    # === FEATURES CRITIQUES POUR DIFFÉRENCIATION (positions 19-27) ===
    
    # Count - normalisé selon le type d'attaque
    count = connections_count
    features[19] = min(count, 511)  # count (limité pour éviter overflow)
    features[20] = min(count, 511)  # srv_count
    
    # === LOGIQUE DE DIFFÉRENCIATION AMÉLIORÉE ===
    
    # 1. DoS pur : >100 connexions et <=3 ports (jamais port scan)
    if count > 100 and port_count <= 3:
        # DoS
        features[21] = 0.95
        features[22] = 0.95
        features[23] = 0.05
        features[24] = 0.05
        features[25] = 0.98
        features[26] = 0.02
        print(f"🔥 PATTERN DoS PUR: count={count}, ports={port_count}")
    # 2. Port scan pur : >10 ports différents et >10 connexions (jamais DoS)
    elif port_count > 10 and count > 10:
        features[21] = 0.70
        features[22] = 0.30
        features[23] = 0.60
        features[24] = 0.60
        features[25] = 0.15
        features[26] = 0.85
        print(f"🔍 PATTERN PORT SCAN PUR: count={count}, ports={port_count}")
        
    # 3. PROBE STEALTH (10-50 connexions, 5-15 ports)
    elif 10 <= count <= 50 and 5 <= port_count <= 15:
        features[21] = 0.50  # serror_rate modéré
        features[22] = 0.40  # srv_serror_rate modéré
        features[23] = 0.45  # rerror_rate modéré
        features[24] = 0.40  # srv_rerror_rate modéré
        features[25] = 0.30  # same_srv_rate bas (services variés)
        features[26] = 0.70  # diff_srv_rate élevé (plusieurs services)
        print(f"🔍 PATTERN PROBE STEALTH: count={count}, ports={port_count}")
        
    # 4. PROBE LENT (5-20 connexions, 2-8 ports)
    elif 5 <= count <= 20 and 2 <= port_count <= 8:
        features[21] = 0.35  # serror_rate bas-modéré
        features[22] = 0.30  # srv_serror_rate bas-modéré
        features[23] = 0.40  # rerror_rate modéré
        features[24] = 0.35  # srv_rerror_rate modéré
        features[25] = 0.40  # same_srv_rate modéré
        features[26] = 0.60  # diff_srv_rate modéré-élevé
        print(f"🔍 PATTERN PROBE LENT: count={count}, ports={port_count}")
        
    # 5. NORMAL (peu de connexions, peu de ports)
    else:
        features[21] = 0.0  # serror_rate bas
        features[22] = 0.0  # srv_serror_rate bas
        features[23] = 0.0  # rerror_rate bas
        features[24] = 0.0  # srv_rerror_rate bas
        features[25] = 1.0  # same_srv_rate élevé (trafic normal)
        features[26] = 0.0  # diff_srv_rate bas
        print(f"✅ PATTERN NORMAL: count={count}, ports={port_count}")
    
    features[27] = 0.0  # srv_diff_host_rate
    
    # === FEATURES DE TRAFIC HOST (positions 28-37) ===
    # Adapter selon le pattern détecté
    features[28] = min(count * 2, 255)  # dst_host_count
    features[29] = min(count, 255)  # dst_host_srv_count
    features[30] = features[25]  # dst_host_same_srv_rate
    features[31] = features[26]  # dst_host_diff_srv_rate
    
    # Port rate - signature importante pour distinguer scan vs DoS
    if port_count > 10:  # Port scan
        features[32] = 0.1  # dst_host_same_src_port_rate très bas
    elif count > 100:  # DoS
        features[32] = 0.8  # dst_host_same_src_port_rate élevé
    else:  # Normal
        features[32] = 0.5  # dst_host_same_src_port_rate modéré
    
    features[33] = 0.0  # dst_host_srv_diff_host_rate
    features[34] = features[21]  # dst_host_serror_rate
    features[35] = features[22]  # dst_host_srv_serror_rate
    features[36] = features[23]  # dst_host_rerror_rate
    features[37] = features[24]  # dst_host_srv_rerror_rate
    
    # === ONE-HOT ENCODING POUR PROTOCOL (positions 38-40) ===
    if protocol == 'icmp':
        features[38] = 1.0  # icmp
    elif protocol == 'tcp':
        features[39] = 1.0  # tcp
    elif protocol == 'udp':
        features[40] = 1.0  # udp
    
    # === ONE-HOT ENCODING POUR SERVICE (positions 41-49) ===
    service = port_to_service(dest_port)
    service_mapping = {
        'http': 41, 'ftp': 42, 'ssh': 43, 'telnet': 44, 'smtp': 45,
        'domain': 46, 'pop_3': 47, 'imap': 48, 'other': 49
    }
    
    if service in service_mapping:
        features[service_mapping[service]] = 1.0
    else:
        features[49] = 1.0  # other
    
    # === ONE-HOT ENCODING POUR FLAG (positions 50-56) ===
    flag_mapping = {
        'SF': 50, 'S0': 51, 'REJ': 52, 'RSTR': 53, 'RSTO': 54, 'SH': 55, 'OTH': 56
    }
    
    if flag in flag_mapping:
        features[flag_mapping[flag]] = 1.0
    else:
        features[56] = 1.0  # OTH
    
    # === FEATURES SPÉCIALISÉES POUR DIFFÉRENCIATION (positions 57-66) ===
    
    # Feature DoS massif
    features[57] = 1.0 if count > 200 else 0.0
    
    # Feature DoS modéré  
    features[58] = 1.0 if (100 <= count <= 200 and port_count <= 3) else 0.0
    
    # Feature Port Scan rapide
    features[59] = 1.0 if (50 <= count <= 150 and port_count > 10) else 0.0
    
    # Feature Probe stealth
    features[60] = 1.0 if (10 <= count <= 50 and 5 <= port_count <= 15) else 0.0
    
    # Feature Probe lent
    features[61] = 1.0 if (5 <= count <= 20 and 2 <= port_count <= 8) else 0.0
    
    # Feature ratio port/connexion (signature scan)
    port_conn_ratio = port_count / max(count, 1)
    features[62] = min(port_conn_ratio, 1.0)
    
    # Feature services critiques ciblés
    critical_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 1433, 3389]
    features[63] = 1.0 if dest_port in critical_ports else 0.0
    
    # Feature pattern temporal (basé sur la durée)
    duration = log_data.get('duration', 0)
    if count > 0:
        conn_per_sec = count / max(duration, 1)
        features[64] = min(conn_per_sec / 100.0, 1.0)  # Normaliser vitesse connexions
    else:
        features[64] = 0.0
    
    # Feature flag suspect (indicateur de scan/dos)
    suspect_flags = ['S0', 'REJ', 'RSTO', 'RSTR']
    features[65] = 1.0 if flag in suspect_flags else 0.0
    
    # Compléter avec des zéros jusqu'à 145
    while len(features) < 145:
        features.append(0.0)
    
    # S'assurer qu'on a exactement 145 features
    features = features[:145]
    
    print(f"✅ Features extraites: {len(features)} features")
    print(f"🔍 Signatures clés:")
    print(f"   Count: {features[19]}, Same_srv_rate: {features[25]:.2f}, Diff_srv_rate: {features[26]:.2f}")
    print(f"   Port_ratio: {features[62]:.3f}, DoS_flag: {features[57]}, Scan_flag: {features[59]}")
    
    return features

def normalize_features(features: List[float]) -> List[float]:
    """
    VERSION AMÉLIORÉE - Normalise les features avec préservation des signatures
    """
    if not features:
        return features
    
    features_array = np.array(features, dtype=np.float32)
    normalized = np.zeros_like(features_array)
    
    for i in range(len(features_array)):
        val = features_array[i]
        
        # Normalisation adaptée par type de feature
        if i < 19:  # Features numériques de base
            if val > 0:
                normalized[i] = min(val / 1000.0, 1.0)
            else:
                normalized[i] = 0.0
                
        elif i < 38:  # Features de trafic (count, rates...)
            if i in [19, 20]:  # count, srv_count
                normalized[i] = min(val / 511.0, 1.0)  # Normalisation count
            else:  # rates (déjà entre 0 et 1)
                normalized[i] = min(max(val, 0.0), 1.0)
                
        elif i < 57:  # Features one-hot (protocol, service, flag)
            normalized[i] = 1.0 if val > 0.5 else 0.0
            
        else:  # Features spécialisées (57+)
            if i == 62:  # port_conn_ratio
                normalized[i] = min(max(val, 0.0), 1.0)
            elif i == 64:  # conn_per_sec
                normalized[i] = min(max(val, 0.0), 1.0)
            else:  # Features binaires
                normalized[i] = 1.0 if val > 0.5 else 0.0
    
    # Remplacer les valeurs problématiques
    normalized = np.nan_to_num(normalized, nan=0.0, posinf=1.0, neginf=0.0)
    
    print(f"✅ Normalisation: {len(normalized)} features normalisées")
    return normalized.tolist()

def port_to_service(port: int) -> str:
    """Convertit un numéro de port en nom de service - VERSION ÉTENDUE"""
    service_map = {
        # Services web
        80: 'http', 443: 'http', 8080: 'http', 8443: 'http',
        # Services de transfert  
        21: 'ftp', 22: 'ssh', 23: 'telnet',
        # Services mail
        25: 'smtp', 110: 'pop_3', 143: 'imap', 993: 'imap', 995: 'pop_3',
        # Services système
        53: 'domain', 135: 'other', 139: 'other', 445: 'other',
        # Bases de données
        1433: 'other', 1521: 'other', 3306: 'other', 5432: 'other',
        # Autres services critiques
        3389: 'other', 5900: 'other', 161: 'other', 162: 'other'
    }
    return service_map.get(port, 'other')

def create_dos_test_data(connections_count: int = 250, dest_port: int = 80) -> Dict[str, Any]:
    """Crée des données de test pour DoS avec signatures distinctives"""
    return {
        'connections_count': connections_count,
        'dest_port': dest_port,
        'port_count': 1,  # DoS = même port
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.1',
        'protocol': 'tcp',
        'flag': 'S0',  # SYN flood
        'bytes_sent': connections_count * 64,
        'bytes_received': 0,
        'duration': 10,
        'scan_pattern': 'dos'
    }

def create_probe_test_data(connections_count: int = 30, dest_port: int = 22) -> Dict[str, Any]:
    """Crée des données de test pour Probe avec signatures distinctives"""
    return {
        'connections_count': connections_count,
        'dest_port': dest_port,
        'port_count': 8,  # Probe = plusieurs ports
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.1',
        'protocol': 'tcp',
        'flag': 'REJ',  # Connexions rejetées
        'bytes_sent': connections_count * 32,
        'bytes_received': 0,
        'duration': 60,  # Plus lent
        'scan_pattern': 'probe'
    }

def create_portscan_test_data(connections_count: int = 80, dest_port: int = 80) -> Dict[str, Any]:
    """NOUVEAU - Crée des données de test pour Port Scan"""
    return {
        'connections_count': connections_count,
        'dest_port': dest_port,
        'port_count': 15,  # Port scan = beaucoup de ports
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.1',
        'protocol': 'tcp',
        'flag': 'REJ',  # Ports fermés
        'bytes_sent': connections_count * 40,
        'bytes_received': 0,
        'duration': 30,
        'scan_pattern': 'portscan'
    }

def create_normal_test_data(connections_count: int = 3, dest_port: int = 80) -> Dict[str, Any]:
    """Crée des données de test pour trafic Normal"""
    return {
        'connections_count': connections_count,
        'dest_port': dest_port,
        'port_count': 1,  # Normal = peu de ports
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.1',
        'protocol': 'tcp',
        'flag': 'SF',  # Connexions réussies
        'bytes_sent': 1024,
        'bytes_received': 2048,
        'duration': 30,
        'scan_pattern': 'normal'
    }

def preprocess_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """VERSION CORRIGÉE - Prétraite les données pour le modèle"""
    try:
        print(f"🔧 Préprocessing des données: {data}")
        
        features = extract_features(data)
        if len(features) != 145:
            if len(features) < 145:
                features.extend([0.0] * (145 - len(features)))
            else:
                features = features[:145]
        
        features_normalized = normalize_features(features)
        data['features'] = features_normalized
        data['features_count'] = len(features_normalized)
        
        print(f"✅ Préprocessing réussi: {len(features_normalized)} features")
        return data
        
    except Exception as e:
        print(f"❌ Erreur lors du préprocessing: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        
        # Retourner des features par défaut en cas d'erreur
        data['features'] = [0.0] * 145
        data['features_count'] = 145
        return data

def test_feature_extraction():
    """FONCTION DE TEST AMÉLIORÉE - Teste toutes les signatures"""
    print("🧪 TEST EXTRACTION DE FEATURES - VERSION CORRIGÉE")
    print("=" * 60)
    
    # Test DoS
    dos_data = create_dos_test_data(250, 80)
    print(f"\n🔥 TEST DoS MASSIF:")
    print(f"Input: {dos_data}")
    dos_features = extract_features(dos_data)
    print(f"Signatures DoS: serror={dos_features[21]:.2f}, same_srv={dos_features[25]:.2f}, dos_flag={dos_features[57]}")
    
    # Test Port Scan
    scan_data = create_portscan_test_data(80, 80)
    print(f"\n🔍 TEST PORT SCAN:")
    print(f"Input: {scan_data}")
    scan_features = extract_features(scan_data)
    print(f"Signatures Scan: serror={scan_features[21]:.2f}, diff_srv={scan_features[26]:.2f}, scan_flag={scan_features[59]}")
    
    # Test Probe
    probe_data = create_probe_test_data(30, 22)
    print(f"\n🔍 TEST PROBE:")
    print(f"Input: {probe_data}")
    probe_features = extract_features(probe_data)
    print(f"Signatures Probe: serror={probe_features[21]:.2f}, diff_srv={probe_features[26]:.2f}, probe_flag={probe_features[60]}")
    
    # Test Normal
    normal_data = create_normal_test_data(3, 80)
    print(f"\n✅ TEST NORMAL:")
    print(f"Input: {normal_data}")
    normal_features = extract_features(normal_data)
    print(f"Signatures Normal: serror={normal_features[21]:.2f}, same_srv={normal_features[25]:.2f}")

if __name__ == "__main__":
    test_feature_extraction()