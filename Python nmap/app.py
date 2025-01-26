from flask import Flask, request, jsonify, render_template
import nmap

app = Flask(__name__)

# Fonction pour exécuter un scan Nmap
def run_nmap_scan(target_ip, ports):
    nm = nmap.PortScanner()

    try:
        # Exécute le scan avec détection de version
        nm.scan(target_ip, ports, arguments="-sV")

        # Vérifie si l'hôte est actif
        if target_ip not in nm.all_hosts():
            return {"error": f"L'hôte {target_ip} ne répond pas ou est inaccessible."}

        # Récupère les résultats du scan
        result = {
            "host": target_ip,
            "state": nm[target_ip].state(),
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
    return render_template('index.html')

# Route API pour exécuter un scan Nmap
@app.route('/scan', methods=['POST'])
def scan():
    data = request.json

    target_ip = data.get('target')
    ports = data.get('ports', '1-1000')

    if not target_ip:
        return jsonify({"error": "Paramètre 'target' manquant."}), 400

    # Exécute le scan
    scan_result = run_nmap_scan(target_ip, ports)
    
    return jsonify(scan_result), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
