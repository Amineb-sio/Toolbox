from flask import Flask, render_template, request, jsonify
import requests
import time

app = Flask(__name__)
ZAP_API_URL = "http://127.0.0.1:8080"
API_KEY = "monapikey"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    target_url = request.form.get('url')

    if not target_url:
        return jsonify({"error": "URL non spécifiée"})

    print(f"DEBUG - Lancement du scan sur {target_url} via OWASP ZAP")

    # Vérifier si l'URL est bien ajoutée
    requests.get(f"{ZAP_API_URL}/JSON/core/action/accessUrl/?apikey={API_KEY}&url={target_url}")

    # Lancer un Spider
    spider_url = f"{ZAP_API_URL}/JSON/spider/action/scan/?apikey={API_KEY}&url={target_url}"
    spider_response = requests.get(spider_url)

    if spider_response.status_code != 200:
        return jsonify({"error": "Échec du lancement du Spider", "details": spider_response.text})

    spider_id = spider_response.json().get("scan")

    # Attendre la fin du Spider
    while True:
        status = requests.get(f"{ZAP_API_URL}/JSON/spider/view/status/?apikey={API_KEY}&scanId={spider_id}").json().get("status")
        if status == "100":
            break
        time.sleep(2)

    # Lancer le scan actif
    scan_url = f"{ZAP_API_URL}/JSON/ascan/action/scan/?apikey={API_KEY}&url={target_url}&recurse=true"
    scan_response = requests.get(scan_url)

    if scan_response.status_code != 200:
        return jsonify({"error": "Échec du lancement du scan actif", "details": scan_response.text})

    scan_id = scan_response.json().get("scan")

    # Attendre la fin du scan actif
    while True:
        status = requests.get(f"{ZAP_API_URL}/JSON/ascan/view/status/?apikey={API_KEY}&scanId={scan_id}").json().get("status")
        if status == "100":
            break
        time.sleep(2)

    return jsonify({"message": "Scan terminé", "scan_id": scan_id})

@app.route('/get_results', methods=['GET'])
def get_results():
    alerts_url = f"{ZAP_API_URL}/JSON/alert/view/alerts/?apikey={API_KEY}"
    response = requests.get(alerts_url)

    if response.status_code != 200:
        return jsonify({"error": "Impossible de récupérer les résultats", "details": response.text})

    alerts = response.json().get("alerts", [])

    for alert in alerts:
        vuln_name = alert.get("name", "Inconnue").replace(" ", "+")
        alert["link"] = f"https://www.cvedetails.com/google-search-results.php?q={vuln_name}"
        alert["location"] = alert.get("url", "Non spécifié")

    return jsonify({"alerts": alerts})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5004)
