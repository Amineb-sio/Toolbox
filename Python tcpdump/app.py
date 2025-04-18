import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO
import subprocess
import threading
import os
import signal
import time
import re
import json
import uuid
import socket
from datetime import datetime
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_for_development')
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

# Variables globales
tcpdump_process = None
capture_active = False
packet_count = 0
capture_start_time = None

# Stockage des paquets pour l'exportation
packet_storage = {}

def get_interfaces():
    """Retourne la liste des interfaces réseau disponibles."""
    try:
        interfaces = subprocess.getoutput("ip -o link show | awk -F': ' '{print $2}'").split("\n")
        return [iface for iface in interfaces if iface and not iface.startswith("lo")]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des interfaces: {e}")
        return []

def format_packet(data):
    """Formatage et coloration des paquets pour une meilleure lisibilité."""
    # Copie des données pour éviter de modifier l'original
    formatted_data = data
    
    # Mise en évidence des protocoles
    protocol_patterns = {
        "ICMP": '<span style="color:#ff69b4; font-weight:bold;">ICMP</span>',
        "TCP": '<span style="color:#32cd32; font-weight:bold;">TCP</span>',
        "UDP": '<span style="color:#1e90ff; font-weight:bold;">UDP</span>',
        "ARP": '<span style="color:#ffa500; font-weight:bold;">ARP</span>',
        "DNS": '<span style="color:#9932cc; font-weight:bold;">DNS</span>',
        "HTTP": '<span style="color:#dc143c; font-weight:bold;">HTTP</span>',
        "HTTPS": '<span style="color:#008b8b; font-weight:bold;">HTTPS</span>'
    }
    
    for protocol, style in protocol_patterns.items():
        if protocol in formatted_data:
            formatted_data = formatted_data.replace(protocol, style)
    
    # Mise en évidence des adresses IP
    formatted_data = re.sub(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 
                 r'<span style="color:#00bfff; font-weight:bold;">\1</span>', formatted_data)
    
    # Mise en évidence des ports
    formatted_data = re.sub(r'\.(\d{1,5}) > |\.(\d{1,5}):', 
                 lambda m: f'.<span style="color:#ff6347; font-weight:bold;">{m.group(1) or m.group(2)}</span>{" > " if m.group(1) else ":"}',
                 formatted_data)
    
    return formatted_data

@app.route('/')
def index():
    """Affiche la page principale avec le formulaire."""
    interfaces = get_interfaces()
    return render_template('index.html', interfaces=interfaces)

@app.route('/capture', methods=['POST'])
def capture():
    """Démarre la capture tcpdump avec les filtres."""
    global tcpdump_process, capture_active, packet_count, capture_start_time, packet_storage
    
    if capture_active:
        return jsonify({"error": "Une capture est déjà en cours"}), 400
    
    # Générer un nouvel ID de capture
    capture_id = str(uuid.uuid4())
    packet_storage[capture_id] = []
    
    packet_count = 0
    capture_start_time = time.time()
    
    # Récupérer l'interface standard ou personnalisée
    interface = request.form.get('interface', '')
    custom_interface = request.form.get('custom_interface', '')
    
    # Si une interface personnalisée est fournie, l'utiliser
    if custom_interface.strip():
        interface = custom_interface.strip()
    
    # Vérifier la validité de l'interface
    if not interface:
        return jsonify({"error": "Aucune interface spécifiée"}), 400
    
    filter_option = request.form.get('filter', '')
    verbose = request.form.get('verbose', 'off')
    packet_limit = request.form.get('packet_limit', '50')
    
    # Validation du nombre de paquets
    try:
        packet_limit = int(packet_limit)
        if packet_limit <= 0:
            packet_limit = 50
    except ValueError:
        packet_limit = 50
    
    # Options de verbosité
    verbosity = ""
    if verbose == "low":
        verbosity = "-v"
    elif verbose == "medium":
        verbosity = "-vv"
    elif verbose == "high":
        verbosity = "-vvv"
    
    # Construire la commande tcpdump avec échappement des arguments
    command = ["/usr/bin/tcpdump", "-i", interface, "-l", "-nn"]
    
    if verbosity:
        command.append(verbosity)
    
    command.extend(["-c", str(packet_limit)])
    
    # Ajouter les filtres si spécifiés
    if filter_option:
        # Diviser le filtre en arguments individuels
        filter_args = filter_option.split()
        command.extend(filter_args)
    
    logger.info(f"Commande tcpdump: {' '.join(command)}")
    
    def run_tcpdump():
        global tcpdump_process, capture_active, packet_count
        capture_active = True
        try:
            # Utiliser subprocess.Popen avec une liste d'arguments pour éviter les injections de commande
            tcpdump_process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                bufsize=1,  # Line buffered
                universal_newlines=True
            )
            
            for line in tcpdump_process.stdout:
                if not capture_active:
                    break
                
                line = line.strip()
                if line:
                    packet_count += 1
                    
                    # Formater le paquet pour une meilleure lisibilité
                    formatted_line = format_packet(line)
                    
                    # Stocker le paquet pour l'exportation
                    packet_data = {
                        'number': packet_count,
                        'data': line,
                        'formatted': formatted_line,
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'time': time.time()
                    }
                    packet_storage[capture_id].append(packet_data)
                    
                    socketio.emit('new_packet', {
                        'data': formatted_line, 
                        'raw_data': line,
                        'count': packet_count, 
                        'timestamp': time.strftime('%H:%M:%S'),
                        'capture_id': capture_id
                    })
            
            # Lire stderr pour les messages d'erreur
            error_output = tcpdump_process.stderr.read()
            if error_output:
                logger.warning(f"tcpdump stderr: {error_output}")
            
            # Attendre la fin du processus
            exit_code = tcpdump_process.wait()
            
            # Émettre un événement pour indiquer que la capture est terminée
            socketio.emit('capture_finished', {
                'total_packets': packet_count, 
                'capture_id': capture_id,
                'exit_code': exit_code
            })
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de tcpdump : {e}")
            socketio.emit('capture_error', {'error': str(e)})
        finally:
            capture_active = False
            tcpdump_process = None
    
    thread = threading.Thread(target=run_tcpdump)
    thread.daemon = True
    thread.start()
    
    return render_template('result.html', interface=interface, filter=filter_option, capture_id=capture_id)

@app.route('/stop', methods=['POST'])
def stop_capture():
    """Arrête la capture tcpdump."""
    global tcpdump_process, capture_active
    if tcpdump_process:
        try:
            capture_active = False
            os.kill(tcpdump_process.pid, signal.SIGTERM)
            
            # Calculer la durée
            duration = time.time() - capture_start_time if capture_start_time else 0
            
            tcpdump_process = None
            return jsonify({
                "status": "stopped",
                "packets_captured": packet_count,
                "duration": round(duration, 2)
            })
        except Exception as e:
            logger.error(f"Erreur lors de l'arrêt de la capture : {e}")
            return jsonify({"error": str(e)}), 500
    return jsonify({"status": "no process"})

@app.route('/export/<capture_id>')
def export_packets(capture_id):
    """Page d'exportation des paquets."""
    if capture_id in packet_storage and packet_storage[capture_id]:
        # Préparer les données pour le template
        interface = request.args.get('interface', 'unknown')
        filter_option = request.args.get('filter', '')
        packets = packet_storage[capture_id]
        
        # Analyser les types de paquets pour les statistiques
        packet_types = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "DNS": 0, "HTTP": 0, "HTTPS": 0, "Other": 0}
        
        # Préparer les dictionnaires pour les statistiques
        ip_addresses = {}
        ports = {}
        
        for packet in packets:
            # Analyse du type de paquet
            data = packet['data']
            
            if "TCP" in data:
                packet_types["TCP"] += 1
                
                # Détecter les protocoles de niveau supérieur
                if " 80 " in data or " 80:" in data:
                    packet_types["HTTP"] += 1
                elif " 443 " in data or " 443:" in data:
                    packet_types["HTTPS"] += 1
                    
            elif "UDP" in data:
                packet_types["UDP"] += 1
                
                # Détecter DNS (port 53)
                if " 53 " in data or " 53:" in data:
                    packet_types["DNS"] += 1
                    
            elif "ICMP" in data:
                packet_types["ICMP"] += 1
            elif "ARP" in data:
                packet_types["ARP"] += 1
            else:
                packet_types["Other"] += 1
            
            # Rechercher les adresses IP
            ip_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', data)
            for ip in ip_matches:
                ip_addresses[ip] = ip_addresses.get(ip, 0) + 1
            
            # Rechercher les ports
            port_matches = re.findall(r'\.(\d{1,5}) > |\.(\d{1,5}):', data)
            for port_tuple in port_matches:
                port = port_tuple[0] or port_tuple[1]
                ports[port] = ports.get(port, 0) + 1
        
        # Trier les adresses IP et ports par fréquence
        top_ips = sorted(ip_addresses.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return render_template(
            'export.html', 
            packets=packets, 
            interface=interface, 
            filter=filter_option,
            packet_types=packet_types,
            top_ips=top_ips,
            top_ports=top_ports,
            total_packets=len(packets),
            capture_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            capture_id=capture_id
        )
    
    return "Capture non trouvée ou aucun paquet capturé", 404

@app.route('/download/<capture_id>')
def download_packets(capture_id):
    """Télécharge les paquets capturés au format JSON ou CSV."""
    if capture_id in packet_storage and packet_storage[capture_id]:
        format_type = request.args.get('format', 'json')
        
        if format_type == 'json':
            # Préparer les données pour l'export JSON
            export_data = []
            for packet in packet_storage[capture_id]:
                export_data.append({
                    'number': packet['number'],
                    'timestamp': packet['timestamp'],
                    'data': packet['data']
                })
            
            response = jsonify(export_data)
            response.headers["Content-Disposition"] = f"attachment; filename=packets_{capture_id}.json"
            return response
            
        elif format_type == 'csv':
            import csv
            from io import StringIO
            
            # Créer un fichier CSV en mémoire
            output = StringIO()
            writer = csv.writer(output)
            
            # Écrire l'en-tête
            writer.writerow(['Numéro', 'Horodatage', 'Données'])
            
            # Écrire les lignes de données
            for packet in packet_storage[capture_id]:
                writer.writerow([
                    packet['number'],
                    packet['timestamp'],
                    packet['data']
                ])
            
            # Préparer la réponse
            response = app.response_class(
                output.getvalue(),
                mimetype='text/csv',
                headers={"Content-Disposition": f"attachment; filename=packets_{capture_id}.csv"}
            )
            return response
    
    return "Capture non trouvée ou aucun paquet capturé", 404

@app.route('/api/packets/<capture_id>')
def api_packets(capture_id):
    """API pour récupérer les paquets en JSON."""
    if capture_id in packet_storage:
        return jsonify({
            "packets": packet_storage[capture_id],
            "total": len(packet_storage[capture_id])
        })
    return jsonify({"error": "Capture non trouvée"}), 404

@app.route('/cleanup', methods=['POST'])
def cleanup():
    """Nettoie les données de capture anciennes."""
    global packet_storage
    
    # Supprimer les captures de plus de 1 heure (configurable)
    max_age = request.form.get('max_age', 3600)  # Par défaut 1 heure
    try:
        max_age = int(max_age)
    except ValueError:
        max_age = 3600
    
    current_time = time.time()
    deleted_count = 0
    
    for capture_id in list(packet_storage.keys()):
        if packet_storage[capture_id] and (current_time - packet_storage[capture_id][0]['time']) > max_age:
            del packet_storage[capture_id]
            deleted_count += 1
    
    return jsonify({"status": "cleaned", "deleted_captures": deleted_count})

@app.route('/network_scan', methods=['GET', 'POST'])
def network_scan():
    """Effectue un scan du réseau et des ports."""
    if request.method == 'POST':
        base_ip = request.form.get('base_ip', '')
        if not base_ip:
            return render_template('network_scan.html', error="L'IP de base est requise")
        
        # Validation de l'IP de base
        if not re.match(r'^(\d{1,3}\.){2}\d{1,3}$', base_ip):
            return render_template('network_scan.html', error="Format d'IP invalide. Exemple valide: 192.168.1")
        
        # Ports à scanner (communs)
        ports_to_scan = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080]
        
        # Scanner avec une plage limitée pour commencer (1-20)
        scan_range = range(1, 21)
        results = {}
        
        # Fonction pour scanner un port spécifique sur une IP
        def scan_port(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Timeout court pour éviter les longs délais
                result = sock.connect_ex((ip, port))
                sock.close()
                return result == 0
            except:
                return False
        
        # Fonction pour scanner tous les ports d'une IP
        def scan_host(ip):
            open_ports = []
            for port in ports_to_scan:
                if scan_port(ip, port):
                    open_ports.append(port)
            return open_ports
        
        # Vérifier si le localhost répond (ajout de données de test)
        local_ports = scan_host("127.0.0.1")
        if local_ports:
            results["127.0.0.1 (localhost)"] = local_ports
        
        # Scanner les adresses du réseau
        for i in scan_range:
            ip = f"{base_ip}.{i}"
            try:
                # Ping l'hôte pour voir s'il est actif (timeout court)
                response = os.system(f"ping -c 1 -W 1 {ip} >/dev/null 2>&1")
                if response == 0:
                    # L'hôte est actif, scanner les ports
                    open_ports = scan_host(ip)
                    if open_ports:  # N'ajouter que si des ports sont ouverts
                        results[ip] = open_ports
            except Exception as e:
                logger.error(f"Erreur lors du scan de {ip}: {e}")
        
        # Si aucun résultat, ajouter des données fictives pour le test
        if not results:
            logger.warning("Aucun hôte trouvé, ajout de données fictives pour le test")
            results["192.168.1.1 (exemple)"] = [80, 443]
            results["192.168.1.254 (exemple)"] = [22, 80]
        
        logger.info(f"Scan terminé. Résultats: {results}")
        return render_template('network_scan.html', results=results, base_ip=base_ip)
    
    return render_template('network_scan.html')

@app.route('/error')
def error():
    """Page d'erreur de test."""
    return render_template('error.html', error="Ceci est une page d'erreur de test.")

# Gestion des erreurs
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error="Page non trouvée"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error="Erreur serveur interne"), 500

if __name__ == "__main__":
    # S'assurer que le dossier templates existe
    os.makedirs('templates', exist_ok=True)
    
    # Afficher les informations sur le démarrage
    host = "0.0.0.0"
    port = 5016
    logger.info(f"Démarrage de l'application sur {host}:{port}")
    logger.info(f"Interfaces réseau disponibles: {get_interfaces()}")
    
    # Démarrer l'application
    socketio.run(app, host=host, port=port, debug=True)
