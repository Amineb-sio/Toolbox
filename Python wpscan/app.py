from flask import Flask, render_template, request, send_file
import subprocess
import os
import datetime
import csv
from fpdf import FPDF

app = Flask(__name__)

API_TOKEN = "3asTApXDCZDdosB76SCqOm1PiGfLYJNNNUf8nfAiHis"
REPORTS_DIR = "rapports"

# Assurez-vous que le dossier des rapports existe
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_filename():
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"wpscan_rapport_{now}"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    filename = None

    if request.method == 'POST':
        url = request.form.get('url')
        enum_option = request.form.get('enum_option')

        if url and enum_option:
            cmd = ["wpscan", "--url", url, "-e", enum_option, "--api-token", API_TOKEN]
            try:
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                result = process.stdout
                filename = generate_filename()

                # Sauvegarde en fichiers
                with open(f"{REPORTS_DIR}/{filename}.txt", "w", encoding="utf-8") as f:
                    f.write(result)
            except Exception as e:
                result = f"Erreur lors de l'exécution de WPScan : {str(e)}"

    return render_template('index.html', result=result, filename=filename)

@app.route('/export/<format>/<filename>')
def export_report(format, filename):
    filepath = f"{REPORTS_DIR}/{filename}.txt"
    if not os.path.exists(filepath):
        return "Fichier introuvable", 404

    export_path = f"{REPORTS_DIR}/{filename}.{format}"

    if format == "pdf":
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                pdf.cell(0, 10, line, ln=True)

        pdf.output(export_path)
    elif format == "html":
        with open(filepath, "r", encoding="utf-8") as f:
            content = f"<html><body><pre>{f.read()}</pre></body></html>"
        with open(export_path, "w", encoding="utf-8") as f:
            f.write(content)
    elif format == "csv":
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
        with open(export_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for line in lines:
                writer.writerow([line.strip()])

    return send_file(export_path, as_attachment=True)

if __name__ == '__main__':
    print("🚀 Serveur lancé sur http://0.0.0.0:5006")
    app.run(debug=True, host='0.0.0.0', port=5006)
