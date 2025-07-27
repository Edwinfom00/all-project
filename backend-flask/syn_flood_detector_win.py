from scapy.all import sniff, IP, TCP
from collections import defaultdict, deque
from datetime import datetime
import json
import os

DATA_FILE = os.path.join(os.path.dirname(__file__), "app", "data", "network_data.json")
SYN_THRESHOLD = 20  # nombre de SYN en 5s pour alerte
WINDOW = 5  # secondes

syn_counts = defaultdict(lambda: deque())

def save_alert(source_ip, count):
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as f:
                data = json.load(f)
        else:
            data = {"alerts": [], "connections": [], "stats": {}}
        alert = {
            "id": int(datetime.now().timestamp()),
            "sourceIp": source_ip,
            "destinationIp": "Votre machine",
            "protocol": "tcp",
            "timestamp": datetime.now().isoformat(),
            "attackType": "DoS (SYN flood)",
            "severity": "high",
            "confidence": min(count / 100.0, 0.99)
        }
        data["alerts"].append(alert)
        data["alerts"] = data["alerts"][-20:]
        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=2)
        print(f"🚨 ALERTE SYN FLOOD: {source_ip} ({count} SYN en {WINDOW}s)")
    except Exception as e:
        print(f"Erreur sauvegarde alerte: {e}")

def syn_callback(pkt):
    if IP in pkt and TCP in pkt and pkt[TCP].flags & 0x02:
        src = pkt[IP].src
        now = datetime.now().timestamp()
        syn_counts[src].append(now)
        # Nettoyer la fenêtre
        while syn_counts[src] and now - syn_counts[src][0] > WINDOW:
            syn_counts[src].popleft()
        if len(syn_counts[src]) > SYN_THRESHOLD:
            save_alert(src, len(syn_counts[src]))

if __name__ == "__main__":
    print("Sniffing sur toutes les interfaces... (Ctrl+C pour arrêter)")
    sniff(filter="tcp", prn=syn_callback, store=0)
