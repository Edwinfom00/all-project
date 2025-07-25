import requests
import json
import time
import sys

# Adresse de l'API backend
API_URL = "http://localhost:5000/detect"

def check_server_status():
    """Vérifie si le serveur Flask est en marche"""
    try:
        response = requests.get("http://localhost:5000", timeout=5)
        return True
    except requests.exceptions.ConnectionError:
        return False
    except Exception:
        return False

def simulate_attack():
    """Simule une attaque et envoie les données au serveur"""
    
    # Vérifier si le serveur est en marche
    if not check_server_status():
        print("❌ Erreur: Le serveur Flask n'est pas en marche!")
        print("📝 Pour résoudre ce problème:")
        print("   1. Ouvrez un nouveau terminal")
        print("   2. Naviguez vers le dossier racine de votre projet")
        print("   3. Exécutez: python app.py")
        print("   4. Attendez le message 'Running on http://localhost:5000'")
        print("   5. Relancez ce script dans un autre terminal")
        return False
    
    # Données simulant différents types d'attaques
    attacks = [
        {
            "name": "Attaque DoS",
            "data": {
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.5",
                "protocol": "tcp",
                "source_port": 12345,
                "dest_port": 80
            }
        },
        {
            "name": "Tentative d'intrusion SSH",
            "data": {
                "source_ip": "203.0.113.1",
                "destination_ip": "10.0.0.10",
                "protocol": "tcp",
                "source_port": 54321,
                "dest_port": 22
            }
        },
        {
            "name": "Scan de ports",
            "data": {
                "source_ip": "198.51.100.5",
                "destination_ip": "10.0.0.15",
                "protocol": "tcp",
                "source_port": 60000,
                "dest_port": 443
            }
        }
    ]
    
    headers = {"Content-Type": "application/json"}
    
    print(f"🚀 Envoi de requêtes vers: {API_URL}")
    print("-" * 50)
    
    for i, attack in enumerate(attacks, 1):
        print(f"\n📡 Test {i}: {attack['name']}")
        
        try:
            response = requests.post(
                API_URL, 
                data=json.dumps(attack['data']), 
                headers=headers,
                timeout=10
            )
            
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200 or response.status_code == 201:
                try:
                    result = response.json()
                    print(f"   ✅ Réponse: {json.dumps(result, indent=2, ensure_ascii=False)}")
                except json.JSONDecodeError:
                    print(f"   📄 Réponse brute: {response.text}")
            else:
                print(f"   ❌ Erreur HTTP: {response.status_code}")
                print(f"   📄 Réponse: {response.text}")
                
        except requests.exceptions.ConnectionError:
            print("   ❌ Erreur de connexion: Le serveur Flask n'est pas accessible")
            return False
        except requests.exceptions.Timeout:
            print("   ⏰ Timeout: Le serveur met trop de temps à répondre")
        except Exception as e:
            print(f"   ❌ Erreur inattendue: {e}")
        
        # Pause entre les requêtes
        if i < len(attacks):
            time.sleep(1)
    
    print("\n" + "="*50)
    print("🏁 Simulation terminée!")
    return True

if __name__ == "__main__":
    print("🔍 Simulateur d'attaques IDS")
    print("="*50)
    
    success = simulate_attack()
    
    if not success:
        print("\n💡 Conseil: Assurez-vous que votre serveur Flask est démarré avant de lancer ce script.")
        sys.exit(1)