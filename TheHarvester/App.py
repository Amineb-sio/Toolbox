
from flask import Flask, render_template, request, send_file, Response
import subprocess
import os
import csv
import io
import datetime

app = Flask(__name__)

# Créer le dossier rapports s'il n'existe pas
REPORTS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rapports")
if not os.path.exists(REPORTS_FOLDER):
    os.makedirs(REPORTS_FOLDER)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form["domain"]
        output_format = request.form.get("output_format", "display")
        
        # Utilisation de l'option "-b all" pour rechercher dans toutes les sources
        try:
            result = subprocess.check_output(["theHarvester", "-d", domain, "-b", "all"], universal_newlines=True)
            
            # Si on veut juste afficher le résultat
            if output_format == "display":
                return render_template("index.html", domain=domain, result=result)
            
            # Sinon, on exporte dans le format demandé
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"theHarvester_{domain}_{timestamp}"
            filepath = os.path.join(REPORTS_FOLDER, filename)
            
            if output_format == "html":
                # Création d'un fichier HTML autonome avec les résultats
                html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>TheHarvester Results - {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        pre {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; border: 1px solid #ddd; }}
        h1, h2 {{ color: #333; }}
    </style>
</head>
<body>
    <h1>TheHarvester Results</h1>
    <h2>Domain: {domain}</h2>
    <h3>Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</h3>
    <pre>{result}</pre>
</body>
</html>"""
                with open(f"{filepath}.html", "w") as f:
                    f.write(html_content)
                return send_file(f"{filepath}.html", as_attachment=True)
                
            elif output_format == "csv":
                # Créer un CSV avec les données
                with open(f"{filepath}.csv", "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Domain", "Date", "Results"])
                    writer.writerow([domain, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result])
                return send_file(f"{filepath}.csv", as_attachment=True)
                
            elif output_format == "txt":
                # Simple fichier texte
                txt_content = f"""TheHarvester Results
Domain: {domain}
Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

{result}"""
                with open(f"{filepath}.txt", "w") as f:
                    f.write(txt_content)
                return send_file(f"{filepath}.txt", as_attachment=True)
                
        except subprocess.CalledProcessError as e:
            return render_template("index.html", domain=domain, error=f"Error: {e.output}")
    return render_template("index.html", domain=None, result=None)

if __name__ == '__main__':
    print(f"🚀 Serveur lancé sur http://0.0.0.0:5018")
    print(f"📁 Les rapports seront sauvegardés dans: {REPORTS_FOLDER}")
    app.run(debug=True, host='0.0.0.0', port=5018)
