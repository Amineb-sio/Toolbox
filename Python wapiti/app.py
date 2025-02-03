import os
from flask import Flask, render_template, request, jsonify
from wapitiCore import wapiti
import subprocess

app = Flask(__name__)

# Route principale pour afficher la page d'index
@app.route('/')
def index():
    return render_template('index.html')

# Route pour lancer un scan avec Wapiti et afficher le rapport
@app.route('/scan', methods=['POST'])
def scan():
    # Récupère l'URL du formulaire (à scanner)
    target_url = request.form['url']

    # Lancer le scan avec Wapiti
    try:
        # Lancer la commande wapiti en mode ligne de commande
        result = subprocess.run(
            ['wapiti', '--url', target_url, '--output', 'report.html'],
            capture_output=True, text=True, check=True
        )
        
        # Lire le rapport généré (report.html)
        report_file = os.path.join(os.getcwd(), 'report.html')
        
        with open(report_file, 'r') as file:
            report_content = file.read()

        return render_template('index.html', report=report_content)

    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Une erreur est survenue lors du scan : " + str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=True)
