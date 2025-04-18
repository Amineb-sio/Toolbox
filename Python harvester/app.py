from flask import Flask, render_template, request
import subprocess

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain = request.form["domain"]
        # Utilisation de l'option "-b all" pour rechercher dans toutes les sources
        try:
            result = subprocess.check_output(["theHarvester", "-d", domain, "-b", "all"], universal_newlines=True)
            return render_template("index.html", domain=domain, result=result)  # Correction ici
        except subprocess.CalledProcessError as e:
            return f"Error: {e.output}"
    return render_template("index.html", domain=None, result=None)  # Correction ici

if __name__ == '__main__':
    print("🚀 Serveur lancé sur http://0.0.0.0:5018")
    app.run(debug=True, host='0.0.0.0', port=5018)
