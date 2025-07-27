#!/usr/bin/env python3
"""
Script pour tester Scapy et la détection de paquets
"""

import sys
import platform

def test_scapy():
    """Test si Scapy fonctionne correctement"""
    print("🔍 Test de Scapy...")
    
    try:
        from scapy.all import sniff, IP, TCP
        print("✅ Scapy importé avec succès")
        
        # Test de sniffing rapide
        print("🔍 Test de sniffing (5 secondes)...")
        from datetime import datetime
        start_time = datetime.now()
        
        def test_callback(pkt):
            if IP in pkt and TCP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                print(f"📦 Paquet détecté: {src} -> {dst}")
        
        # Sniff pendant 5 secondes
        sniff(filter="tcp", prn=test_callback, store=0, timeout=5)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        print(f"✅ Sniffing testé pendant {duration} secondes")
        
        return True
        
    except ImportError as e:
        print(f"❌ Scapy non installé: {e}")
        print("💡 Installez Scapy: pip install scapy")
        return False
    except Exception as e:
        print(f"❌ Erreur Scapy: {e}")
        if "permission" in str(e).lower():
            print("💡 Lancez en tant qu'administrateur")
        return False

def test_os():
    """Affiche les informations du système"""
    print(f"🖥️  OS: {platform.system()} {platform.release()}")
    print(f"🐍 Python: {sys.version}")
    
    os_type = platform.system().lower()
    if 'windows' in os_type:
        print("💡 Windows détecté - Npcap requis pour Scapy")
    elif 'linux' in os_type:
        print("💡 Linux détecté - Raw sockets disponibles")
    else:
        print("💡 OS non reconnu")

if __name__ == "__main__":
    print("🚀 Test de compatibilité Scapy")
    print("=" * 40)
    
    test_os()
    print()
    
    success = test_scapy()
    
    print()
    if success:
        print("🎉 Scapy fonctionne correctement !")
        print("✅ Le détecteur universel peut être utilisé")
    else:
        print("⚠️  Scapy ne fonctionne pas")
        print("🔄 Le système utilisera le fallback psutil")
    
    print("=" * 40) 