from flask import Flask, render_template, request, send_file
import subprocess
import os
import csv
import datetime

app = Flask(__name__)

# Dossier des rapports
REPORTS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rapports")
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# Fonction pour exécuter Subfinder
def run_subfinder(domain):
    try:
        result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        return [str(e)]

@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")

@app.route("/find_subdomains", methods=["POST"])
def find_subdomains():
    domain = request.form["domain"]
    output_format = request.form.get("output_format", "display")

    subdomains = run_subfinder(domain)

    if output_format == "display":
        return render_template("index.html", domain=domain, subdomains=subdomains)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"subfinder_{domain}_{timestamp}"
    filepath = os.path.join(REPORTS_FOLDER, filename)

    if output_format == "html":
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Subfinder Results - {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        ul {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; border: 1px solid #ddd; }}
        h1, h2 {{ color: #333; }}
    </style>
</head>
<body>
    <h1>Subfinder Results</h1>
    <h2>Domain: {domain}</h2>
    <h3>Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</h3>
    <ul>
        {''.join(f"<li>{sd}</li>" for sd in subdomains)}
    </ul>
</body>
</html>"""
        with open(f"{filepath}.html", "w") as f:
            f.write(html_content)
        return send_file(f"{filepath}.html", as_attachment=True)

    elif output_format == "csv":
        with open(f"{filepath}.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Domain", "Date", "Subdomains"])
            for sd in subdomains:
                writer.writerow([domain, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), sd])
        return send_file(f"{filepath}.csv", as_attachment=True)

    elif output_format == "txt":
        txt_content = f"""Subfinder Results
Domain: {domain}
Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

{os.linesep.join(subdomains)}"""
        with open(f"{filepath}.txt", "w") as f:
            f.write(txt_content)
        return send_file(f"{filepath}.txt", as_attachment=True)

    return "Format non supporté."

if __name__ == '__main__':
    print(f"🚀 Serveur lancé sur http://0.0.0.0:5020")
    print(f"📁 Les rapports seront sauvegardés dans: {REPORTS_FOLDER}")
    app.run(debug=True, host='0.0.0.0', port=5020)
