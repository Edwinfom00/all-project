#!/usr/bin/env python3
"""
Script pour tester la détection d'IP source et comprendre le problème
"""

import psutil
import socket
from datetime import datetime

def get_local_ip():
    """Obtenir l'IP locale de la machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def analyze_connections():
    """Analyser les connexions pour comprendre le problème d'IP source"""
    print("🔍 Analyse des connexions réseau...")
    print("=" * 50)
    
    local_ip = get_local_ip()
    print(f"📍 IP locale: {local_ip}")
    print()
    
    connections = psutil.net_connections()
    print(f"📊 Total connexions: {len(connections)}")
    print()
    
    # Analyser les connexions par IP
    ip_counts = {}
    connection_details = []
    
    for conn in connections:
        if conn.raddr and hasattr(conn.raddr, 'ip'):
            remote_ip = conn.raddr.ip
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
            
            # Ignorer les IPs loopback et locale
            if remote_ip in ['127.0.0.1', '0.0.0.0', '::1', local_ip]:
                continue
            
            if remote_ip not in ip_counts:
                ip_counts[remote_ip] = 0
            ip_counts[remote_ip] += 1
            
            connection_details.append({
                'local': local_addr,
                'remote': remote_addr,
                'status': conn.status,
                'pid': conn.pid
            })
    
    print("📋 Connexions par IP source:")
    print("-" * 30)
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {ip}: {count} connexions")
    
    print()
    print("🔍 Détails des connexions (top 10):")
    print("-" * 50)
    for i, conn in enumerate(connection_details[:10]):
        print(f"  {i+1}. {conn['local']} <- {conn['remote']} ({conn['status']})")
    
    print()
    print("💡 Analyse:")
    print("-" * 20)
    if ip_counts:
        most_connections = max(ip_counts.items(), key=lambda x: x[1])
        print(f"  IP avec le plus de connexions: {most_connections[0]} ({most_connections[1]} connexions)")
        print(f"  Cette IP sera détectée comme source d'attaque")
        
        if most_connections[0] == "129.0.60.57":
            print("  ⚠️  PROBLÈME: Cette IP est la cible de l'attaque, pas la source!")
            print("  💡 Solution: Installer Npcap pour utiliser Scapy et capturer les vrais paquets")
        else:
            print("  ✅ Cette IP semble être la vraie source d'attaque")
    else:
        print("  Aucune connexion externe détectée")

if __name__ == "__main__":
    print("🚀 Test de détection d'IP source")
    print("=" * 40)
    analyze_connections()
    print("=" * 40) 