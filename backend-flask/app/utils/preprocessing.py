from typing import Dict, Any, List
import re
import ast
import os

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

# Charger la liste des colonnes NSL-KDD prétraitées
COLUMNS_PATH = os.path.join(os.path.dirname(__file__), 'nslkdd_columns.txt')
try:
    with open(COLUMNS_PATH, 'r', encoding='utf-8') as f:
        NSLKDD_COLUMNS = ast.literal_eval(f.read())
except FileNotFoundError:
    # Colonnes par défaut basées sur votre exemple
    NSLKDD_COLUMNS = ['0', '491', '0.1', '0.2', '0.3', '0.4', '0.5', '0.6', '0.7', '0.8', '0.9', '0.10', '0.11', '0.12', '0.13', '0.14', '0.15', '0.16', '0.18', '2', '2.1', '0.19', '0.20', '0.21', '0.22', '1', '0.23', '0.24', '150', '25', '0.17', '0.03', '0.17.1', '0.25', '0.26', '0.27', '0.05', '0.28', 'tcp_icmp', 'tcp_tcp', 'tcp_udp', 'ftp_data_IRC', 'ftp_data_X11', 'ftp_data_Z39_50', 'ftp_data_aol', 'ftp_data_auth', 'ftp_data_bgp', 'ftp_data_courier', 'ftp_data_csnet_ns', 'ftp_data_ctf', 'ftp_data_daytime', 'ftp_data_discard', 'ftp_data_domain', 'ftp_data_domain_u', 'ftp_data_echo', 'ftp_data_eco_i', 'ftp_data_ecr_i', 'ftp_data_efs', 'ftp_data_exec', 'ftp_data_finger', 'ftp_data_ftp', 'ftp_data_ftp_data', 'ftp_data_gopher', 'ftp_data_harvest', 'ftp_data_hostnames', 'ftp_data_http', 'ftp_data_http_2784', 'ftp_data_http_443', 'ftp_data_http_8001', 'ftp_data_imap4', 'ftp_data_iso_tsap', 'ftp_data_klogin', 'ftp_data_kshell', 'ftp_data_ldap', 'ftp_data_link', 'ftp_data_login', 'ftp_data_mtp', 'ftp_data_name', 'ftp_data_netbios_dgm', 'ftp_data_netbios_ns', 'ftp_data_netbios_ssn', 'ftp_data_netstat', 'ftp_data_nnsp', 'ftp_data_nntp', 'ftp_data_ntp_u', 'ftp_data_other', 'ftp_data_pm_dump', 'ftp_data_pop_2', 'ftp_data_pop_3', 'ftp_data_printer', 'ftp_data_private', 'ftp_data_red_i', 'ftp_data_remote_job', 'ftp_data_rje', 'ftp_data_shell', 'ftp_data_smtp', 'ftp_data_sql_net', 'ftp_data_ssh', 'ftp_data_sunrpc', 'ftp_data_supdup', 'ftp_data_systat', 'ftp_data_telnet', 'ftp_data_tftp_u', 'ftp_data_tim_i', 'ftp_data_time', 'ftp_data_urh_i', 'ftp_data_urp_i', 'ftp_data_uucp', 'ftp_data_uucp_path', 'ftp_data_vmnet', 'ftp_data_whois', 'SF_OTH', 'SF_REJ', 'SF_RSTO', 'SF_RSTOS0', 'SF_RSTR', 'SF_S0', 'SF_S1', 'SF_S2', 'SF_S3', 'SF_SF', 'SF_SH', 'normal_back', 'normal_buffer_overflow', 'normal_ftp_write', 'normal_guess_passwd', 'normal_imap', 'normal_ipsweep', 'normal_land', 'normal_loadmodule', 'normal_multihop', 'normal_neptune', 'normal_nmap', 'normal_normal', 'normal_perl', 'normal_phf', 'normal_pod', 'normal_portsweep', 'normal_rootkit', 'normal_satan', 'normal_smurf', 'normal_spy', 'normal_teardrop', 'normal_warezclient', 'normal_warezmaster']

def extract_features(log_data: Dict[str, Any]) -> List[float]:
    """
    Transforme un log réseau en un vecteur de features du même format que le NSL-KDD prétraité.
    Crée un vecteur de 145 features basé sur le format NSL-KDD standard.
    """
    # Initialiser avec des zéros pour toutes les 145 features
    features = [0.0] * 145
    
    # Créer un mapping des colonnes vers leurs indices
    col_to_idx = {col: i for i, col in enumerate(NSLKDD_COLUMNS)}
    
    # === FEATURES NUMÉRIQUES DE BASE ===
    # Duration (souvent 0 pour les logs temps réel)
    if '0' in col_to_idx:
        features[col_to_idx['0']] = 0
    
    # Protocol type (position standard dans NSL-KDD)
    protocol = log_data.get('protocol', 'tcp').lower()
    
    # Service (basé sur le port de destination)
    dest_port = log_data.get('dest_port', 80)
    service = port_to_service(dest_port)
    
    # Flags (connection state) - par défaut SF (normal)
    flag = 'SF'
    
    # Source bytes (simulé)
    if '491' in col_to_idx:
        features[col_to_idx['491']] = log_data.get('bytes_sent', 491)
    
    # Destination bytes (simulé)
    dest_bytes = log_data.get('bytes_received', 0)
    
    # Land (même IP source et destination)
    source_ip = log_data.get('source_ip', '0.0.0.0')
    dest_ip = log_data.get('destination_ip', '0.0.0.0')
    land = 1 if source_ip == dest_ip else 0
    
    # Wrong fragment, urgent (généralement 0)
    wrong_fragment = 0
    urgent = 0
    
    # Hot indicators (nombre de features "hot")
    hot = 0
    
    # Number of failed logins
    num_failed_logins = 0
    
    # Logged in
    logged_in = 0
    
    # Number of compromised conditions
    num_compromised = 0
    
    # Root shell
    root_shell = 0
    
    # Su attempted
    su_attempted = 0
    
    # Number of root accesses
    num_root = 0
    
    # Number file creations
    num_file_creations = 0
    
    # Number shells
    num_shells = 0
    
    # Number access files
    num_access_files = 0
    
    # Number outbound cmds
    num_outbound_cmds = 0
    
    # Is host login
    is_host_login = 0
    
    # Is guest login
    is_guest_login = 0
    
    # === FEATURES DE TRAFIC (dernières 2 secondes) ===
    count = log_data.get('connections_count', 2)  # Nombre de connexions
    srv_count = 2  # Connexions vers le même service
    
    # Ratios d'erreurs (simulés)
    serror_rate = 0.0
    srv_serror_rate = 0.0
    rerror_rate = 0.0
    srv_rerror_rate = 0.0
    same_srv_rate = 1.0
    diff_srv_rate = 0.0
    srv_diff_host_rate = 0.0
    
    # === FEATURES DE TRAFIC (dernières 100 connexions) ===
    dst_host_count = 150
    dst_host_srv_count = 25
    dst_host_same_srv_rate = 0.17
    dst_host_diff_srv_rate = 0.03
    dst_host_same_src_port_rate = 0.17
    dst_host_srv_diff_host_rate = 0.0
    dst_host_serror_rate = 0.0
    dst_host_srv_serror_rate = 0.0
    dst_host_rerror_rate = 0.05
    dst_host_srv_rerror_rate = 0.0
    
    # === ASSIGNATION DES VALEURS AUX POSITIONS CORRECTES ===
    numeric_features = [
        0,  # duration
        dest_bytes,  # dst_bytes
        land, wrong_fragment, urgent, hot, num_failed_logins, logged_in,
        num_compromised, root_shell, su_attempted, num_root, num_file_creations,
        num_shells, num_access_files, num_outbound_cmds, is_host_login, is_guest_login,
        count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate,
        same_srv_rate, diff_srv_rate, srv_diff_host_rate,
        dst_host_count, dst_host_srv_count, dst_host_same_srv_rate,
        dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
        dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate,
        dst_host_srv_rerror_rate
    ]
    
    # Assigner les features numériques aux premières positions
    for i, val in enumerate(numeric_features[:min(len(numeric_features), 38)]):
        if i < len(features):
            features[i] = float(val)
    
    # === ONE-HOT ENCODING POUR LES FEATURES CATÉGORIELLES ===
    
    # Protocol type
    protocol_cols = ['tcp_icmp', 'tcp_tcp', 'tcp_udp']
    for col in protocol_cols:
        if col in col_to_idx:
            proto_name = col.split('_')[1]
            features[col_to_idx[col]] = 1.0 if protocol == proto_name else 0.0
    
    # Service type (basé sur le port)
    service_prefix = 'ftp_data_'
    for col in NSLKDD_COLUMNS:
        if col.startswith(service_prefix):
            service_name = col.replace(service_prefix, '')
            if col in col_to_idx:
                features[col_to_idx[col]] = 1.0 if service == service_name else 0.0
    
    # Flag (connection state)
    flag_prefix = 'SF_'
    for col in NSLKDD_COLUMNS:
        if col.startswith(flag_prefix):
            flag_name = col.replace(flag_prefix, '')
            if col in col_to_idx:
                features[col_to_idx[col]] = 1.0 if flag == flag_name else 0.0
    
    # Attack type (toujours normal par défaut pour les nouvelles données)
    attack_prefix = 'normal_'
    for col in NSLKDD_COLUMNS:
        if col.startswith(attack_prefix):
            if col in col_to_idx:
                # Mettre 'normal' à 1, tous les autres à 0
                features[col_to_idx[col]] = 1.0 if col == 'normal_normal' else 0.0
    
    # S'assurer que nous avons exactement 145 features
    if len(features) != 145:
        features = features[:145] + [0.0] * max(0, 145 - len(features))
    
    return features

def port_to_service(port: int) -> str:
    """
    Convertit un numéro de port en nom de service pour le mapping NSL-KDD.
    """
    port_map = {
        20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'domain', 80: 'http', 110: 'pop_3', 143: 'imap4', 443: 'http_443',
        993: 'imap4', 995: 'pop_3', 8001: 'http_8001', 2784: 'http_2784'
    }
    return port_map.get(port, 'other')

def format_nslkdd_features(log_data: Dict[str, Any]) -> List[str]:
    """
    Formate les données réseau au format NSL-KDD textuel.
    Retourne une liste de strings correspondant aux 41 features de base NSL-KDD.
    """
    # Extraire les informations de base
    protocol = log_data.get('protocol', 'tcp').lower()
    dest_port = log_data.get('dest_port', 80)
    service = port_to_service(dest_port)
    flag = 'SF'  # Normal connection
    
    # Construire la ligne NSL-KDD
    nslkdd_line = [
        '0',  # duration
        protocol,  # protocol_type
        service,  # service
        flag,  # flag
        '491',  # src_bytes
        '0',   # dst_bytes
        '0',   # land
        '0',   # wrong_fragment
        '0',   # urgent
        '0',   # hot
        '0',   # num_failed_logins
        '0',   # logged_in
        '0',   # num_compromised
        '0',   # root_shell
        '0',   # su_attempted
        '0',   # num_root
        '0',   # num_file_creations
        '0',   # num_shells
        '0',   # num_access_files
        '0',   # num_outbound_cmds
        '0',   # is_host_login
        '0',   # is_guest_login
        '2',   # count
        '2',   # srv_count
        '0',   # serror_rate
        '0',   # srv_serror_rate
        '0',   # rerror_rate
        '0',   # srv_rerror_rate
        '1',   # same_srv_rate
        '0',   # diff_srv_rate
        '0',   # srv_diff_host_rate
        '150', # dst_host_count
        '25',  # dst_host_srv_count
        '0.17', # dst_host_same_srv_rate
        '0.03', # dst_host_diff_srv_rate
        '0.17', # dst_host_same_src_port_rate
        '0',    # dst_host_srv_diff_host_rate
        '0',    # dst_host_serror_rate
        '0',    # dst_host_srv_serror_rate
        '0.05', # dst_host_rerror_rate
        '0',    # dst_host_srv_rerror_rate
        'normal' # class (sera prédit par le modèle)
    ]
    
    return nslkdd_line

def normalize_features(features: List[float]) -> List[float]:
    """
    Normalise les features pour le modèle ML.
    Utilise une normalisation min-max basée sur les statistiques NSL-KDD.
    """
    # Valeurs maximales approximatives pour chaque feature NSL-KDD
    # Basées sur les statistiques du dataset NSL-KDD
    max_values = [
        58329, 1379963390, 1, 3, 14, 101, 5, 1, 884, 1, 1, 9, 28, 5, 9, 2, 1, 1,
        511, 511, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 255, 255, 1.0, 1.0, 1.0, 1.0,
        1.0, 1.0, 1.0, 1.0
    ] + [1.0] * (145 - 37)  # Le reste sont des features one-hot (0 ou 1)
    
    # Normalisation min-max
    normalized = []
    for i, (feature, max_val) in enumerate(zip(features, max_values)):
        if max_val == 0:
            normalized.append(0.0)
        else:
            # Clamp entre 0 et max_val, puis normalise
            clamped = max(0, min(feature, max_val))
            normalized.append(clamped / max_val)
    
    return normalized