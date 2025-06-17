from flask import Flask, request, jsonify, render_template
import nmap
import os
import re

# Définition du dossier des templates
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

# Vérifier si le dossier templates existe
if not os.path.exists(TEMPLATE_DIR):
    os.makedirs(TEMPLATE_DIR)

# Vérifier si index.html est bien présent
if "index.html" not in os.listdir(TEMPLATE_DIR):
    print("⚠ ERREUR : Le fichier index.html est manquant dans templates/")

# Création de l'application Flask
app = Flask(__name__, template_folder=TEMPLATE_DIR)

# Vérifier si Nmap est installé
try:
    nm = nmap.PortScanner()
except nmap.PortScannerError:
    print("❌ ERREUR : Nmap n'est pas installé ou non détecté dans le PATH.")
    exit(1)

# Vérification et validation de l'adresse IP et des ports
def is_valid_ip(ip):
    pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    return bool(pattern.match(ip))

def is_valid_ports(ports):
    return re.match(r"^(\d+(-\d+)?)(,\d+(-\d+)?)*$", ports)

# Fonction pour exécuter un scan Nmap
def run_nmap_scan(target_ip, ports):
    if not is_valid_ip(target_ip):
        return {"error": f"L'adresse IP '{target_ip}' est invalide."}

    if not is_valid_ports(ports):
        return {"error": f"Le format des ports '{ports}' est invalide."}

    try:
        # Commande Nmap avec sudo pour obtenir les privilèges nécessaires
        cmd = f"sudo nmap -sC -sV --script ssl-enum-ciphers,http-title -p {ports} {target_ip}"
        print(f"🔍 Exécution de Nmap : {cmd}")  # Debugging

        # Lancer le scan Nmap avec les privilèges sudo
        nm.scan(hosts=target_ip, arguments=cmd)

        # Vérifier si l'hôte est actif
        if target_ip not in nm.all_hosts():
            return {"error": f"L'hôte {target_ip} ne répond pas ou est inaccessible."}

        # Récupérer les résultats
        result = {
            "host": target_ip,
            "state": nm[target_ip].state(),
            "ports": []
        }

        if 'tcp' in nm[target_ip]:
            for port, info in nm[target_ip]['tcp'].items():
                result["ports"].append({
                    "port": port,
                    "state": info.get('state', 'Inconnu'),
                    "service": info.get('name', 'Inconnu'),
                    "version": f"{info.get('product', '')} {info.get('version', 'Version non détectée')}".strip(),
                    "extra_info": info.get('extrainfo', '')
                })

        return result

    except Exception as e:
        return {"error": f"Erreur inattendue : {str(e)}"}

# Route pour afficher l'interface graphique
@app.route('/')
def home():
    print("📂 Contenu du dossier templates/:", os.listdir(TEMPLATE_DIR))  # Debugging
    return render_template('index.html')

# Route API pour exécuter un scan Nmap
@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Requête invalide, JSON attendu."}), 400

    target_ip = data.get('target')
    ports = data.get('ports', '1-65535')  # Scanner tous les ports par défaut

    if not target_ip:
        return jsonify({"error": "Paramètre 'target' manquant."}), 400

    scan_result = run_nmap_scan(target_ip, ports)
    
    return jsonify(scan_result), 200

if __name__ == '__main__':
    print("🚀 Serveur lancé sur http://0.0.0.0:5001")
    app.run(debug=True, host='0.0.0.0', port=5001)
