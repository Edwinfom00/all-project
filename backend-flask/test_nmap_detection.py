#!/usr/bin/env python3
"""
Script de test pour simuler un scan nmap et vérifier la détection
"""

import sys
import os
import time
import json
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.model.ai_model import predict_intrusion
from app.utils.preprocessing import preprocess_data

def simulate_nmap_scan():
    """Simule les données d'un scan nmap"""
    print("🔍 Simulation d'un scan nmap...")
    
    # Données typiques d'un scan nmap
    nmap_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '192.168.1.1',
        'source_port': 12345,
        'dest_port': 80,
        'protocol': 'tcp',
        'connections_count': 8,  # Peu de connexions mais vers plusieurs ports
        'bytes_sent': 200,
        'bytes_received': 100,
        'flag': 'S',  # SYN flag pour scan
        'duration': 0,
        'serror_rate': 0.2,  # Quelques erreurs de connexion
        'srv_serror_rate': 0.2,
        'rerror_rate': 0.1,
        'srv_rerror_rate': 0.1
    }
    
    print(f"   Connexions: {nmap_data['connections_count']}")
    print(f"   Flag: {nmap_data['flag']}")
    print(f"   Port: {nmap_data['dest_port']}")
    
    processed_data = preprocess_data(nmap_data)
    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
    
    print(f"   Résultat: {attack_type} (confiance: {confidence:.2f})")
    print(f"   Intrusion détectée: {is_intrusion}")
    
    if attack_type == "DoS":
        print("   ❌ PROBLÈME: Scan nmap détecté comme DoS!")
    elif attack_type == "Probe" or attack_type == "Port Scan":
        print("   ✅ CORRECT: Scan nmap détecté comme Probe/Port Scan")
    else:
        print(f"   ⚠️ Résultat inattendu: {attack_type}")
    
    return attack_type

def simulate_dos_attack():
    """Simule les données d'une vraie attaque DoS"""
    print("\n🚨 Simulation d'une attaque DoS...")
    
    # Données typiques d'une attaque DoS
    dos_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '192.168.1.1',
        'source_port': 12345,
        'dest_port': 80,
        'protocol': 'tcp',
        'connections_count': 300,  # Beaucoup de connexions
        'bytes_sent': 20000,
        'bytes_received': 0,
        'flag': 'S0',  # SYN flood
        'duration': 0,
        'serror_rate': 0.8,  # Beaucoup d'erreurs
        'srv_serror_rate': 0.8,
        'rerror_rate': 0.1,
        'srv_rerror_rate': 0.1
    }
    
    print(f"   Connexions: {dos_data['connections_count']}")
    print(f"   Flag: {dos_data['flag']}")
    print(f"   Bytes: {dos_data['bytes_sent']}")
    
    processed_data = preprocess_data(dos_data)
    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
    
    print(f"   Résultat: {attack_type} (confiance: {confidence:.2f})")
    print(f"   Intrusion détectée: {is_intrusion}")
    
    if attack_type == "DoS":
        print("   ✅ CORRECT: Attaque DoS détectée correctement")
    else:
        print(f"   ❌ PROBLÈME: Attaque DoS détectée comme {attack_type}")
    
    return attack_type

def test_network_scanner_logic():
    """Test la logique du scanner réseau"""
    print("\n🔧 Test de la logique du scanner réseau...")
    
    # Simuler des connexions réseau
    connections = [
        # Connexions normales (doivent être ignorées)
        {'source_ip': '127.0.0.1', 'dest_ip': '192.168.1.1', 'port': 80, 'status': 'ESTABLISHED'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.1', 'port': 22, 'status': 'ESTABLISHED'},
        
        # Scan de port (doit être détecté comme Port Scan)
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.1', 'port': 1000, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.1', 'port': 1001, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.1', 'port': 1002, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.1', 'port': 1003, 'status': 'SYN_SENT'},
        
        # Attaque DoS (doit être détectée comme DoS)
        {'source_ip': '192.168.1.200', 'dest_ip': '192.168.1.1', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.200', 'dest_ip': '192.168.1.1', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.200', 'dest_ip': '192.168.1.1', 'port': 80, 'status': 'SYN_SENT'},
    ]
    
    # Analyser les connexions
    ip_connections = {}
    port_scan_attempts = {}
    
    for conn in connections:
        source_ip = conn['source_ip']
        dest_ip = conn['dest_ip']
        port = conn['port']
        status = conn['status']
        
        # Ignorer les connexions normales
        if (source_ip in ['127.0.0.1', '0.0.0.0'] or
            source_ip.startswith('192.168.') or
            status == 'ESTABLISHED' or
            port in [22, 80, 443, 53]):
            continue
        
        # Compter les connexions suspectes
        key = (source_ip, dest_ip)
        if key not in ip_connections:
            ip_connections[key] = 0
        ip_connections[key] += 1
        
        # Détecter les port scans
        port_key = f"{source_ip}_{dest_ip}"
        if port_key not in port_scan_attempts:
            port_scan_attempts[port_key] = set()
        port_scan_attempts[port_key].add(port)
    
    print("   Résultats de l'analyse:")
    for key, count in ip_connections.items():
        source_ip, dest_ip = key
        print(f"   - {source_ip} -> {dest_ip}: {count} connexions")
        
        # Vérifier si c'est un port scan
        port_key = f"{source_ip}_{dest_ip}"
        if port_key in port_scan_attempts:
            ports = port_scan_attempts[port_key]
            print(f"     Ports scannés: {list(ports)}")
            
            if len(ports) > 3:
                print(f"     ✅ Détecté comme Port Scan ({len(ports)} ports)")
            else:
                print(f"     ⚠️ Pas assez de ports pour Port Scan")
        
        # Vérifier si c'est un DoS
        if count > 50:
            print(f"     ✅ Détecté comme DoS ({count} connexions)")
        else:
            print(f"     ⚠️ Pas assez de connexions pour DoS")

def main():
    print("🧪 Test de détection Scan nmap vs DoS")
    print("=" * 50)
    
    # Test 1: Simulation nmap
    nmap_result = simulate_nmap_scan()
    
    # Test 2: Simulation DoS
    dos_result = simulate_dos_attack()
    
    # Test 3: Logique du scanner
    test_network_scanner_logic()
    
    print("\n🎯 Résumé:")
    if nmap_result == "DoS":
        print("   ❌ PROBLÈME: Le scan nmap est encore détecté comme DoS")
        print("   💡 Solution: Vérifier les seuils et la logique de classification")
    else:
        print("   ✅ Le scan nmap est correctement détecté")
    
    if dos_result == "DoS":
        print("   ✅ Les attaques DoS sont correctement détectées")
    else:
        print("   ❌ PROBLÈME: Les attaques DoS ne sont pas détectées")

if __name__ == "__main__":
    main() 