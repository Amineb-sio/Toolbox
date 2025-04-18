from flask import Flask, render_template, request
import subprocess
import threading

app = Flask(__name__)

# Variable pour stocker le résultat
result = None

# Fonction pour exécuter Hydra
def run_hydra():
    global result
    ftp_address = "127.0.0.1"  # Adresse FTP par défaut
    username = "admin"         # Nom d'utilisateur par défaut
    wordlist = "/usr/share/wordlists/rockyou.txt"  # Wordlist par défaut
    
    command = f"hydra -l {username} -P {wordlist} -f {ftp_address} ftp"

    # Exécuter Hydra et capturer la sortie
    process = subprocess.Popen(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Capturer la sortie de Hydra
    output, error = process.communicate()

    # Vérifier si un mot de passe valide a été trouvé
    if "valid password found" in output:
        # Chercher la ligne contenant le login et le password
        for line in output.splitlines():
            if "login:" in line and "password:" in line:
                try:
                    # Recherche et extraction du login et du mot de passe
                    login_part = line.split("login:")[1].split()[0].strip()  # Extrait le login
                    password_part = line.split("password:")[1].strip()  # Extrait le mot de passe
                    result = f"Login: {login_part}, Password: {password_part}"
                except Exception as e:
                    result = f"Erreur lors de l'extraction du mot de passe: {str(e)}"
    else:
        result = "Aucun mot de passe trouvé"

@app.route('/', methods=['GET', 'POST'])
def index():
    global result
    if request.method == 'POST':
        # Lancer Hydra dans un thread séparé pour ne pas bloquer l'interface
        thread = threading.Thread(target=run_hydra)
        thread.start()

        # Attendre que le thread finisse pour afficher le résultat
        thread.join()

        return render_template('index.html', result=result)

    return render_template('index.html', result=result)

if __name__ == '__main__':
    print("🚀 Serveur lancé sur http://0.0.0.0:5010")
    app.run(debug=True, host='0.0.0.0', port=5010)
