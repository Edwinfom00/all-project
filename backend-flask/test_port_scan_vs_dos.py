#!/usr/bin/env python3
"""
Script de test pour vérifier la distinction entre scans de port et attaques DoS
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.model.ai_model import predict_intrusion
from app.utils.preprocessing import preprocess_data

def test_port_scan():
    """Test avec des données simulées de scan de port"""
    print("🔍 Test: Scan de port (nmap)")
    
    # Données simulées d'un scan de port
    port_scan_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '192.168.1.1',
        'source_port': 12345,
        'dest_port': 80,
        'protocol': 'tcp',
        'connections_count': 15,  # Peu de connexions mais vers plusieurs ports
        'bytes_sent': 100,
        'bytes_received': 50,
        'flag': 'S',
        'duration': 0,
        'serror_rate': 0.1,
        'srv_serror_rate': 0.1,
        'rerror_rate': 0.05,
        'srv_rerror_rate': 0.05
    }
    
    processed_data = preprocess_data(port_scan_data)
    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
    
    print(f"   Résultat: {attack_type} (confiance: {confidence:.2f})")
    print(f"   Intrusion détectée: {is_intrusion}")
    print(f"   ✅ Attendu: Probe ou Normal, pas DoS")
    print()

def test_dos_attack():
    """Test avec des données simulées d'attaque DoS"""
    print("🚨 Test: Attaque DoS (hping3 flood)")
    
    # Données simulées d'une attaque DoS
    dos_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '192.168.1.1',
        'source_port': 12345,
        'dest_port': 80,
        'protocol': 'tcp',
        'connections_count': 250,  # Beaucoup de connexions
        'bytes_sent': 15000,
        'bytes_received': 0,
        'flag': 'S0',
        'duration': 0,
        'serror_rate': 0.8,
        'srv_serror_rate': 0.8,
        'rerror_rate': 0.1,
        'srv_rerror_rate': 0.1
    }
    
    processed_data = preprocess_data(dos_data)
    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
    
    print(f"   Résultat: {attack_type} (confiance: {confidence:.2f})")
    print(f"   Intrusion détectée: {is_intrusion}")
    print(f"   ✅ Attendu: DoS")
    print()

def test_normal_traffic():
    """Test avec des données de trafic normal"""
    print("✅ Test: Trafic normal")
    
    # Données simulées de trafic normal
    normal_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '192.168.1.1',
        'source_port': 12345,
        'dest_port': 80,
        'protocol': 'tcp',
        'connections_count': 2,
        'bytes_sent': 500,
        'bytes_received': 1000,
        'flag': 'SF',
        'duration': 5,
        'serror_rate': 0.0,
        'srv_serror_rate': 0.0,
        'rerror_rate': 0.0,
        'srv_rerror_rate': 0.0
    }
    
    processed_data = preprocess_data(normal_data)
    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
    
    print(f"   Résultat: {attack_type} (confiance: {confidence:.2f})")
    print(f"   Intrusion détectée: {is_intrusion}")
    print(f"   ✅ Attendu: Normal")
    print()

def main():
    print("🧪 Test de distinction Scan de Port vs DoS")
    print("=" * 50)
    
    test_port_scan()
    test_dos_attack()
    test_normal_traffic()
    
    print("🎯 Résumé des corrections:")
    print("   - Seuil DoS augmenté: >200 connexions (au lieu de >40)")
    print("   - Seuil Port Scan: >5 ports (au lieu de >2)")
    print("   - Logique spéciale pour distinguer scans et DoS")
    print("   - Features mieux calibrées pour éviter les faux positifs")

if __name__ == "__main__":
    main() 