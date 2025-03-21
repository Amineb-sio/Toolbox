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
            return render_template("indexharvester.html", domain=domain, result=result)
        except subprocess.CalledProcessError as e:
            return f"Error: {e.output}"
    return render_template("indexharvester.html", domain=None, result=None)

if __name__ == "__main__":
    app.run(debug=True)
