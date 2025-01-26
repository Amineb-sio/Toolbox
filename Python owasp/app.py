from flask import Flask, render_template, request, jsonify
import requests
import time

app = Flask(__name__)
ZAP_API_KEY = "tonapikey"
ZAP_URL = "http://127.0.0.1:8080"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_scan', methods=['GET'])
def start_scan():
    target_url = request.args.get('url')
    scan_type = request.args.get('type')
    
    if not target_url:
        return jsonify({"error": "URL non spécifiée"})
    
    # Lancer le scan selon le type
    if scan_type == "passif":
        scan_url = f"{ZAP_URL}/JSON/spider/action/scan/?apikey={ZAP_API_KEY}&url={target_url}&recurse=True"
    else:
        scan_url = f"{ZAP_URL}/JSON/ascan/action/scan/?apikey={ZAP_API_KEY}&url={target_url}"
    
    response = requests.get(scan_url)
    scan_id = response.json().get("scan")
    
    if not scan_id:
        return jsonify({"error": "Impossible de lancer le scan"})
    
    # Vérifier l'avancement du scan
    status_url = f"{ZAP_URL}/JSON/spider/view/status/?apikey={ZAP_API_KEY}&scanId={scan_id}"
    while True:
        status = requests.get(status_url).json().get("status")
        if status == "100":
            break
        time.sleep(5)
    
    return jsonify({"message": "Scan terminé", "scan_id": scan_id})

@app.route('/get_results', methods=['GET'])
def get_results():
    alerts_url = f"{ZAP_URL}/JSON/alert/view/alerts/?apikey={ZAP_API_KEY}"
    alerts = requests.get(alerts_url).json().get("alerts", [])
    return jsonify({"alerts": alerts})

@app.route('/download_report', methods=['GET'])
def download_report():
    report_type = request.args.get('type')
    report_url = f"{ZAP_URL}/OTHER/core/other/report/?apikey={ZAP_API_KEY}&format={report_type}"
    response = requests.get(report_url)
    return response.text

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5004)
