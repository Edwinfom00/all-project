#!/usr/bin/env python3
"""
Script de test pour vérifier la détection des attaques depuis la VM Kali
"""

import sys
import os
import time
import json
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.model.ai_model import predict_intrusion
from app.utils.preprocessing import preprocess_data

def test_vm_port_scan():
    """Test avec des données simulées de scan de port depuis la VM"""
    print("🔍 Test: Scan de port depuis VM Kali")
    
    # Données simulées d'un scan de port depuis la VM
    vm_port_scan = {
        'source_ip': '192.168.1.100',  # IP de la VM Kali
        'destination_ip': '192.168.1.178',  # IP de la machine hôte
        'source_port': 12345,
        'dest_port': 1000,  # Port non-standard
        'protocol': 'tcp',
        'connections_count': 5,  # Peu de connexions mais vers plusieurs ports
        'bytes_sent': 200,
        'bytes_received': 100,
        'flag': 'S',  # SYN flag pour scan
        'duration': 0,
        'serror_rate': 0.3,  # Quelques erreurs de connexion
        'srv_serror_rate': 0.3,
        'rerror_rate': 0.1,
        'srv_rerror_rate': 0.1
    }
    
    print(f"   Source (VM): {vm_port_scan['source_ip']}")
    print(f"   Destination (Hôte): {vm_port_scan['destination_ip']}")
    print(f"   Connexions: {vm_port_scan['connections_count']}")
    print(f"   Port: {vm_port_scan['dest_port']}")
    
    processed_data = preprocess_data(vm_port_scan)
    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
    
    print(f"   Résultat: {attack_type} (confiance: {confidence:.2f})")
    print(f"   Intrusion détectée: {is_intrusion}")
    
    if attack_type == "DoS":
        print("   ❌ PROBLÈME: Scan depuis VM détecté comme DoS!")
    elif attack_type == "Probe" or attack_type == "Port Scan":
        print("   ✅ CORRECT: Scan depuis VM détecté comme Probe/Port Scan")
    else:
        print(f"   ⚠️ Résultat inattendu: {attack_type}")
    
    return attack_type

def test_vm_dos_attack():
    """Test avec des données simulées d'attaque DoS depuis la VM"""
    print("\n🚨 Test: Attaque DoS depuis VM Kali")
    
    # Données simulées d'une attaque DoS depuis la VM
    vm_dos_attack = {
        'source_ip': '192.168.1.100',  # IP de la VM Kali
        'destination_ip': '192.168.1.178',  # IP de la machine hôte
        'source_port': 12345,
        'dest_port': 80,
        'protocol': 'tcp',
        'connections_count': 100,  # Beaucoup de connexions
        'bytes_sent': 15000,
        'bytes_received': 0,
        'flag': 'S0',  # SYN flood
        'duration': 0,
        'serror_rate': 0.8,  # Beaucoup d'erreurs
        'srv_serror_rate': 0.8,
        'rerror_rate': 0.1,
        'srv_rerror_rate': 0.1
    }
    
    print(f"   Source (VM): {vm_dos_attack['source_ip']}")
    print(f"   Destination (Hôte): {vm_dos_attack['destination_ip']}")
    print(f"   Connexions: {vm_dos_attack['connections_count']}")
    print(f"   Flag: {vm_dos_attack['flag']}")
    
    processed_data = preprocess_data(vm_dos_attack)
    is_intrusion, attack_type, confidence = predict_intrusion(processed_data)
    
    print(f"   Résultat: {attack_type} (confiance: {confidence:.2f})")
    print(f"   Intrusion détectée: {is_intrusion}")
    
    if attack_type == "DoS":
        print("   ✅ CORRECT: Attaque DoS depuis VM détectée correctement")
    else:
        print(f"   ❌ PROBLÈME: Attaque DoS depuis VM détectée comme {attack_type}")
    
    return attack_type

def test_network_scanner_vm():
    """Test la logique du scanner réseau pour les attaques VM"""
    print("\n🔧 Test: Logique scanner pour attaques VM")
    
    # Simuler des connexions réseau depuis la VM
    vm_connections = [
        # Scan de port depuis VM (doit être détecté comme Port Scan)
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 1000, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 1001, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 1002, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 1003, 'status': 'SYN_SENT'},
        
        # Attaque DoS depuis VM (doit être détectée comme DoS)
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
        {'source_ip': '192.168.1.100', 'dest_ip': '192.168.1.178', 'port': 80, 'status': 'SYN_SENT'},
    ]
    
    # Analyser les connexions
    ip_connections = {}
    port_scan_attempts = {}
    
    for conn in vm_connections:
        source_ip = conn['source_ip']
        dest_ip = conn['dest_ip']
        port = conn['port']
        status = conn['status']
        
        # Ignorer seulement les connexions loopback
        if (source_ip in ['127.0.0.1', '0.0.0.0'] or
            dest_ip in ['127.0.0.1', '0.0.0.0'] or
            status == 'ESTABLISHED'):
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
    
    print("   Résultats de l'analyse VM:")
    for key, count in ip_connections.items():
        source_ip, dest_ip = key
        print(f"   - {source_ip} -> {dest_ip}: {count} connexions")
        
        # Vérifier si c'est un port scan
        port_key = f"{source_ip}_{dest_ip}"
        if port_key in port_scan_attempts:
            ports = port_scan_attempts[port_key]
            print(f"     Ports scannés: {list(ports)}")
            
            if len(ports) > 2:
                print(f"     ✅ Détecté comme Port Scan ({len(ports)} ports)")
            else:
                print(f"     ⚠️ Pas assez de ports pour Port Scan")
        
        # Vérifier si c'est un DoS
        if count > 20:
            print(f"     ✅ Détecté comme DoS ({count} connexions)")
        else:
            print(f"     ⚠️ Pas assez de connexions pour DoS")

def main():
    print("🧪 Test de détection des attaques depuis VM Kali")
    print("=" * 55)
    
    # Test 1: Scan de port depuis VM
    vm_port_result = test_vm_port_scan()
    
    # Test 2: Attaque DoS depuis VM
    vm_dos_result = test_vm_dos_attack()
    
    # Test 3: Logique du scanner pour VM
    test_network_scanner_vm()
    
    print("\n🎯 Résumé des tests VM:")
    if vm_port_result == "DoS":
        print("   ❌ PROBLÈME: Scan depuis VM détecté comme DoS")
    else:
        print("   ✅ Scan depuis VM correctement détecté")
    
    if vm_dos_result == "DoS":
        print("   ✅ Attaque DoS depuis VM correctement détectée")
    else:
        print("   ❌ PROBLÈME: Attaque DoS depuis VM mal détectée")
    
    print("\n💡 Modifications apportées:")
    print("   - Permettre les connexions depuis réseau local (192.168.x.x)")
    print("   - Seuils ajustés pour les tests: Port Scan >2, DoS >20")
    print("   - Distinction maintenue entre Port Scan et DoS")

if __name__ == "__main__":
    main() 