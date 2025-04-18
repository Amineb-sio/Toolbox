#!/usr/bin/env python3

from flask import Flask, request, jsonify, render_template, redirect, url_for
# Suppression de l'import problématique
# import nmap
import os
import re
import requests
import time
import subprocess
import json
from threading import Thread

# Définition du dossier des templates
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

# Vérifier si le dossier templates existe
if not os.path.exists(TEMPLATE_DIR):
    os.makedirs(TEMPLATE_DIR)
    print(f"✅ Dossier templates créé : {TEMPLATE_DIR}")

# Création de l'application Flask
app = Flask(__name__, template_folder=TEMPLATE_DIR)

# Configuration pour OWASP ZAP
ZAP_API_URL = "http://127.0.0.1:8080"
API_KEY = "monapikey"

# Variables globales pour stocker les résultats
scan_results = {
    "nmap": {},
    "zap": {},
    "wireshark": {}
}

# Vérification et validation de l'adresse IP et des ports
def is_valid_ip(ip):
    pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    return bool(pattern.match(ip))

def is_valid_ports(ports):
    return re.match(r"^(\d+(-\d+)?)(,\d+(-\d+)?)*$", ports)

# Fonction pour exécuter un scan Nmap sans utiliser le module nmap
def run_nmap_scan(target_ip, ports):
    if not is_valid_ip(target_ip):
        return {"error": f"L'adresse IP '{target_ip}' est invalide."}

    if not is_valid_ports(ports):
        return {"error": f"Le format des ports '{ports}' est invalide."}

    try:
        # Exécuter nmap directement via subprocess
        cmd = f"nmap -sC -sV -p {ports} {target_ip} -oN {os.path.join(BASE_DIR, 'nmap_results.txt')}"
        print(f"🔍 Exécution de la commande: {cmd}")
        
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if stderr:
            print(f"⚠️ Avertissement Nmap: {stderr.decode('utf-8')}")
        
        # Lire les résultats du fichier de sortie
        try:
            with open(os.path.join(BASE_DIR, 'nmap_results.txt'), 'r') as f:
                output = f.read()
            
            # Analyser les résultats de nmap
            result = {
                "host": target_ip,
                "state": "unknown",
                "ports": []
            }
            
            # Extraire l'état de l'hôte
            for line in output.splitlines():
                if "Host is" in line:
                    result["state"] = line.split("Host is")[1].strip()
            
            # Extraire les informations des ports
            current_port = None
            for line in output.splitlines():
                if "/tcp" in line or "/udp" in line:
                    parts = line.split()
                    port_str = parts[0].split('/')[0]
                    protocol = parts[0].split('/')[1]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    
                    current_port = {
                        "port": port_str,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "version": "",
                        "extra_info": ""
                    }
                    
                    # Collecter les informations supplémentaires
                    if len(parts) > 3:
                        current_port["version"] = " ".join(parts[3:])
                    
                    result["ports"].append(current_port)
                    
                # Ajouter des informations supplémentaires au port actuel
                elif current_port and "|" in line:
                    info = line.strip().split("|")[1].strip()
                    current_port["extra_info"] += info + " "
            
            scan_results["nmap"] = result
            return result
            
        except Exception as e:
            print(f"❌ Erreur lors de l'analyse des résultats Nmap: {str(e)}")
            return {"error": f"Erreur lors de l'analyse des résultats: {str(e)}"}
            
    except Exception as e:
        print(f"❌ Erreur lors de l'exécution de Nmap: {str(e)}")
        return {"error": f"Erreur inattendue: {str(e)}"}

# Le reste du code reste identique
# Fonction pour exécuter un scan ZAP
def run_zap_scan(target_url):
    try:
        print(f"DEBUG - Lancement du scan sur {target_url} via OWASP ZAP")

        # Vérifier si ZAP est accessible
        try:
            check_zap = requests.get(f"{ZAP_API_URL}/JSON/core/view/version/?apikey={API_KEY}", timeout=5)
            if check_zap.status_code != 200:
                return {"error": "OWASP ZAP n'est pas accessible"}
        except requests.exceptions.RequestException:
            return {"error": "OWASP ZAP n'est pas accessible. Assurez-vous qu'il est démarré et accessible."}

        # Accéder à l'URL
        requests.get(f"{ZAP_API_URL}/JSON/core/action/accessUrl/?apikey={API_KEY}&url={target_url}")

        # Lancer un Spider
        spider_url = f"{ZAP_API_URL}/JSON/spider/action/scan/?apikey={API_KEY}&url={target_url}"
        spider_response = requests.get(spider_url)

        if spider_response.status_code != 200:
            return {"error": "Échec du lancement du Spider", "details": spider_response.text}

        spider_id = spider_response.json().get("scan")

        # Attendre la fin du Spider (avec timeout)
        max_wait_time = 300  # 5 minutes max
        start_time = time.time()
        
        while time.time() - start_time < max_wait_time:
            status_response = requests.get(f"{ZAP_API_URL}/JSON/spider/view/status/?apikey={API_KEY}&scanId={spider_id}")
            status = status_response.json().get("status")
            if status == "100":
                break
            time.sleep(2)
        
        if time.time() - start_time >= max_wait_time:
            return {"warning": "Le Spider a dépassé le temps d'attente, passage au scan actif"}

        # Lancer le scan actif
        scan_url = f"{ZAP_API_URL}/JSON/ascan/action/scan/?apikey={API_KEY}&url={target_url}&recurse=true"
        scan_response = requests.get(scan_url)

        if scan_response.status_code != 200:
            return {"error": "Échec du lancement du scan actif", "details": scan_response.text}

        scan_id = scan_response.json().get("scan")

        # Attendre la fin du scan actif (avec timeout)
        start_time = time.time()
        
        while time.time() - start_time < max_wait_time:
            status_response = requests.get(f"{ZAP_API_URL}/JSON/ascan/view/status/?apikey={API_KEY}&scanId={scan_id}")
            status = status_response.json().get("status")
            if status == "100":
                break
            time.sleep(5)
        
        # Récupérer les alertes même si le scan n'est pas terminé
        alerts_url = f"{ZAP_API_URL}/JSON/alert/view/alerts/?apikey={API_KEY}"
        response = requests.get(alerts_url)

        if response.status_code != 200:
            return {"error": "Impossible de récupérer les résultats", "details": response.text}

        alerts = response.json().get("alerts", [])

        for alert in alerts:
            vuln_name = alert.get("name", "Inconnue").replace(" ", "+")
            alert["link"] = f"https://www.cvedetails.com/google-search-results.php?q={vuln_name}"
            alert["location"] = alert.get("url", "Non spécifié")

        scan_results["zap"] = {"alerts": alerts}
        return {"message": "Scan terminé", "alerts": alerts}

    except Exception as e:
        return {"error": f"Erreur lors du scan ZAP : {str(e)}"}

# Fonction pour démarrer une analyse réseau simplifiée
def start_wireshark(interface="eth0", duration=30):
    try:
        print(f"🔍 Simulation d'analyse du trafic réseau sur l'interface {interface}")
        
        # Attendre pour simuler l'exécution
        time.sleep(5)
        
        # Générer des données factices pour démonstration
        stats = {
            "total_packets": 150,
            "protocols": {
                "TCP": 85,
                "UDP": 45,
                "HTTP": 20,
                "DNS": 15,
                "HTTPS": 30
            },
            "suspicious_traffic": [
                {
                    "type": "HTTP Request",
                    "method": "POST",
                    "uri": "/login.php"
                },
                {
                    "type": "Multiple Failed Auth",
                    "method": "POST",
                    "uri": "/admin"
                }
            ]
        }
        
        scan_results["wireshark"] = stats
        return stats
    except Exception as e:
        error_msg = str(e)
        return {"error": f"Erreur lors de l'analyse du trafic réseau : {error_msg}", "suspicious_traffic": [], "protocols": {}, "total_packets": 0}

# Fonction pour lancer tous les scans en parallèle
def run_security_scan(target_ip, target_url, ports="1-1000", interface="eth0"):
    threads = []
    
    # Thread pour Nmap
    nmap_thread = Thread(target=run_nmap_scan, args=(target_ip, ports))
    threads.append(nmap_thread)
    
    # Thread pour ZAP
    zap_thread = Thread(target=run_zap_scan, args=(target_url,))
    threads.append(zap_thread)
    
    # Thread pour Wireshark
    wireshark_thread = Thread(target=start_wireshark, args=(interface, 30))
    threads.append(wireshark_thread)
    
    # Démarrer tous les threads
    for thread in threads:
        thread.start()
    
    # Attendre que tous les threads soient terminés
    for thread in threads:
        thread.join()
    
    # Retourner les résultats combinés
    return scan_results

@app.route('/')
def index():
    # Utiliser directement render_template avec une chaîne HTML simple
    return '''
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Toolbox Automatisée pour Tests d'Intrusion</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f9;
                margin: 0;
                padding: 0;
                display: flex;
                flex-direction: column;
                align-items: center;
            }
            .container {
                width: 80%;
                max-width: 1200px;
                margin: 20px auto;
                padding: 20px;
                background-color: #fff;
                border-radius: 10px;
                box-shadow: 0 0 15px rgba(0, 0, 0, 0.1);
            }
            h1 {
                color: #007bff;
                text-align: center;
                margin-bottom: 30px;
            }
            .button {
                background-color: #007bff;
                color: white;
                padding: 12px 25px;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                margin: 10px;
            }
            .button:hover {
                background-color: #0056b3;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Toolbox Automatisée pour Tests d'Intrusion</h1>
            <div style="text-align: center;">
                <a href="/auto_security" class="button">Accéder à l'automatisation du pôle sécurité</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/auto_security')
def auto_security():
    return render_template('auto_security.html')

@app.route('/run_security_scan', methods=['POST'])
def start_security_scan():
    data = request.form
    target_ip = data.get('target_ip')
    target_url = data.get('target_url')
    ports = data.get('ports', '1-1000')
    interface = data.get('interface', 'eth0')
    
    # Lancer la fonction asynchrone qui va exécuter tous les scans
    print(f"DEBUG - Lancement du scan sur {target_url} via OWASP ZAP")
    Thread(target=run_security_scan, args=(target_ip, target_url, ports, interface)).start()
    
    return redirect(url_for('scan_status'))

@app.route('/scan_status')
def scan_status():
    return render_template('scan_status.html', results=scan_results)

@app.route('/get_results')
def get_results():
    return jsonify(scan_results)

if __name__ == '__main__':
    print("🚀 Serveur lancé sur http://0.0.0.0:5021")
    app.run(debug=True, host='0.0.0.0', port=5021)
