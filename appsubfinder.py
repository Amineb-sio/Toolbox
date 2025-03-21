from flask import Flask, render_template, request, jsonify
import subprocess

app = Flask(__name__)

# Fonction pour exécuter Subfinder
def run_subfinder(domain):
    try:
        # Exécuter la commande subfinder
        result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True)
        # Retourner les résultats sous forme de liste
        return result.stdout.splitlines()
    except Exception as e:
        return str(e)

@app.route('/')
def index():
    return render_template('indexsubfinder.html')

@app.route('/find_subdomains', methods=['POST'])
def find_subdomains():
    domain = request.form['domain']
    subdomains = run_subfinder(domain)
    return render_template('indexsubfinder.html', domain=domain, subdomains=subdomains)

if __name__ == "__main__":
    app.run(debug=True)
