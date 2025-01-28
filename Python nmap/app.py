from flask import Flask, request, jsonify, render_template
import nmap
import os

# Définir le chemin absolu du dossier "templates"
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

# Vérifier si le dossier templates existe et le créer si nécessaire
if not os.path.exists(TEMPLATE_DIR):
    os.makedirs(TEMPLATE_DIR)

# Vérifier si index.html est bien présent
if "index.html" not in os.listdir(TEMPLATE_DIR):
    print("⚠️ ERREUR : Le fichier index.html est manquant dans templates/")

# Création de l'application Flask en spécifiant le dossier des templates
app = Flask(__name__, template_folder=TEMPLATE_DIR)

# Fonction pour exécuter un scan Nmap complet
def run_nmap_scan(target_ip, ports):
    nm = nmap.PortScanner()

    try:
        # Exécute le scan avec toutes les options demandées
        scan_command = f"-p {ports} -sC -sV -A -O -T4 --script=all -Pn -v"
        nm.scan(hosts=target_ip, arguments=scan_command)

        # Vérifie si l'hôte est actif
        if target_ip not in nm.all_hosts():
            return {"error": f"L'hôte {target_ip} ne répond pas ou est inaccessible."}

        # Récupère les résultats du scan
        result = {
            "host": target_ip,
            "state": nm[target_ip].state(),
            "os": nm[target_ip].get("osmatch", []),
            "ports": []
        }

        if 'tcp' in nm[target_ip]:
            for port, info in nm[target_ip]['tcp'].items():
                result["ports"].append({
                    "port": port,
                    "state": info['state'],
                    "service": info.get('name', 'Inconnu'),
                    "version": f"{info.get('product', '')} {info.get('version', 'Version non détectée')}".strip(),
                    "extra_info": info.get('extrainfo', '')
                })

        return result

    except nmap.PortScannerError:
        return {"error": "Nmap n'est pas installé ou n'est pas dans le PATH."}
    except Exception as e:
        return {"error": f"Erreur inattendue : {e}"}

# Route pour afficher l'interface graphique
@app.route('/')
def home():
    print("📂 Contenu du dossier templates/:", os.listdir(TEMPLATE_DIR))  # Debugging pour voir les fichiers
    return render_template('index.html')  # Vérifier que index.html est bien dans "templates/"

# Route API pour exécuter un scan Nmap
@app.route('/scan', methods=['POST'])
def scan():
    data = request.json

    target_ip = data.get('target')
    ports = data.get('ports', '1-100')

    if not target_ip:
        return jsonify({"error": "Paramètre 'target' manquant."}), 400

    # Exécute le scan
    scan_result = run_nmap_scan(target_ip, ports)
    
    return jsonify(scan_result), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
