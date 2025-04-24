import os
import pyshark
import csv
import time
import subprocess
from fpdf import FPDF
from flask import Flask, render_template, request, send_file, session, jsonify
from datetime import datetime
import logging

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Chemin du dossier rapports
REPORT_DIR = "rapports"
os.makedirs(REPORT_DIR, exist_ok=True)

# Vérifier si tshark est disponible avec un timeout
def check_tshark_availability(timeout=5):
    try:
        process = subprocess.run(["tshark", "--version"], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                timeout=timeout)
        return True
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        logger.error("Tshark n'est pas disponible ou ne répond pas")
        return False

# Obtenir les interfaces réseau disponibles avec gestion d'erreur et timeout
def get_interfaces():
    if not check_tshark_availability():
        return []
    
    try:
        # Appel direct à tshark pour éviter les blocages
        process = subprocess.run(["tshark", "-D"], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                timeout=3,
                                text=True)
        
        if process.returncode == 0:
            interfaces = []
            for line in process.stdout.splitlines():
                if line.strip():
                    parts = line.split('.', 1)
                    if len(parts) > 1:
                        interfaces.append(parts[1].strip())
            return interfaces
        return []
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des interfaces: {e}")
        return []

# Initialiser la liste des interfaces au démarrage
AVAILABLE_INTERFACES = get_interfaces()
logger.info(f"Interfaces disponibles au démarrage: {AVAILABLE_INTERFACES}")

def generate_filename(extension):
    """ Génère un nom de fichier basé sur la date et l'heure """
    return os.path.join(REPORT_DIR, f"wireshark_rapport_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.{extension}")

# Fonction pour sécuriser les chaînes pour l'export PDF
def safe_str(text):
    # Remplacer les caractères problématiques (comme № - U+2116)
    if isinstance(text, str):
        return text.replace('\u2116', 'No.')
    return str(text)

@app.route('/', methods=['GET', 'POST'])
def index():
    packet_summary = []
    error = None
    
    # Obtenir les interfaces disponibles à chaque requête GET
    if request.method == 'GET':
        try:
            interfaces = get_interfaces()
            if not interfaces:
                error = "Impossible de récupérer les interfaces réseau. Vérifiez que tshark est installé et fonctionne correctement."
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des interfaces: {e}")
            interfaces = []
            error = f"Erreur: {str(e)}"
    else:
        interfaces = AVAILABLE_INTERFACES
    
    if request.method == 'POST':
        interface = request.form.get('interface')
        duration = int(request.form.get('duration', 0))
        
        if not interface or duration <= 0:
            error = "Entrée invalide. Veuillez sélectionner une interface et spécifier une durée valide."
            return render_template('index.html', interfaces=interfaces, packets=packet_summary, error=error)

        capture_file = os.path.join(REPORT_DIR, f"capture_{interface}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pcap")
        
        try:
            logger.info(f"Début de capture sur l'interface {interface} pour {duration} secondes")
            
            # Utiliser un timeout pour la capture
            capture_process = subprocess.run(
                ["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", capture_file],
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=duration + 5  # Ajouter une marge
            )
            
            if capture_process.returncode != 0:
                error = f"Erreur lors de la capture: {capture_process.stderr.decode('utf-8')}"
                logger.error(error)
                return render_template('index.html', interfaces=interfaces, packets=packet_summary, error=error)
            
            logger.info(f"Capture terminée, lecture des paquets depuis {capture_file}")
            
            # Vérifier si le fichier existe et n'est pas vide
            if not os.path.exists(capture_file) or os.path.getsize(capture_file) == 0:
                error = "Aucun paquet n'a été capturé. Essayez une durée plus longue ou une autre interface."
                logger.warning(error)
                return render_template('index.html', interfaces=interfaces, packets=packet_summary, error=error)
            
            # Lecture des paquets capturés avec un timeout
            try:
                packets = pyshark.FileCapture(capture_file)
                packet_count = 0
                
                # Limiter le temps d'analyse
                start_time = time.time()
                timeout_seconds = 10  # 10 secondes max pour l'analyse
                
                for i, pkt in enumerate(packets):
                    # Vérifier le timeout
                    if time.time() - start_time > timeout_seconds:
                        logger.warning("Timeout atteint lors de l'analyse des paquets")
                        break
                        
                    if i >= 20:  # Limite à 20 paquets
                        break
                        
                    packet_count += 1
                    packet_data = {'no': i + 1}
                    
                    # Timestamp
                    try:
                        packet_data['time'] = pkt.frame_info.time_relative if hasattr(pkt.frame_info, 'time_relative') else 'N/A'
                    except:
                        packet_data['time'] = 'N/A'
                    
                    # IP source et destination
                    try:
                        packet_data['src'] = pkt.ip.src if hasattr(pkt, 'ip') else 'N/A'
                        packet_data['dst'] = pkt.ip.dst if hasattr(pkt, 'ip') else 'N/A'
                    except:
                        packet_data['src'] = 'N/A'
                        packet_data['dst'] = 'N/A'
                    
                    # Protocole
                    packet_data['protocol'] = pkt.highest_layer if hasattr(pkt, 'highest_layer') else 'Unknown'
                    
                    # Info
                    info = 'N/A'
                    try:
                        if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
                            info = pkt.dns.qry_name
                        elif hasattr(pkt, 'http') and hasattr(pkt.http, 'request_method') and hasattr(pkt.http, 'host'):
                            info = f"{pkt.http.request_method} {pkt.http.host}"
                        elif hasattr(pkt, 'tls') and hasattr(pkt.tls, 'handshake_extensions_server_name'):
                            info = f"HTTPS (SNI: {pkt.tls.handshake_extensions_server_name})"
                    except:
                        pass
                    
                    packet_data['info'] = info
                    packet_summary.append(packet_data)
                
                # Fermer le fichier
                packets.close()
                
                logger.info(f"Traitement terminé: {packet_count} paquets analysés")
                
                # Stocker en session
                session['packets'] = packet_summary
                
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse des paquets: {str(e)}")
                error = f"Erreur lors de l'analyse des paquets: {str(e)}"
                
        except subprocess.TimeoutExpired:
            logger.error("Timeout lors de la capture")
            error = "La capture a pris trop de temps et a été interrompue."
        except Exception as e:
            logger.error(f"Erreur lors de la capture: {str(e)}")
            error = f"Erreur lors de la capture: {str(e)}"
    
    return render_template('index.html', interfaces=interfaces, packets=packet_summary, error=error)

@app.route('/status', methods=['GET'])
def status():
    """Endpoint pour vérifier l'état de tshark"""
    try:
        tshark_available = check_tshark_availability()
        interfaces = get_interfaces() if tshark_available else []
        
        return jsonify({
            'status': 'ok' if tshark_available else 'error',
            'interfaces': interfaces,
            'message': 'Tshark est disponible' if tshark_available else 'Tshark n\'est pas disponible'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/export/pdf')
def export_pdf():
    packets = session.get('packets', [])
    if not packets:
        return "Aucune donnée à exporter."

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Rapport de Capture Réseau", ln=True, align='C')
    pdf.ln(10)

    # Entêtes de table
    col_width = 30
    line_height = 10
    pdf.set_font("Arial", 'B', size=10)
    # Utiliser "No." au lieu de "№"
    pdf.cell(10, line_height, "No.", 1, 0, 'C')
    pdf.cell(25, line_height, "Temps", 1, 0, 'C')
    pdf.cell(35, line_height, "Source", 1, 0, 'C')
    pdf.cell(35, line_height, "Destination", 1, 0, 'C')
    pdf.cell(25, line_height, "Protocole", 1, 0, 'C')
    pdf.cell(60, line_height, "Info", 1, 1, 'C')
    
    # Données de la table
    pdf.set_font("Arial", size=8)
    for packet in packets:
        pdf.cell(10, line_height, safe_str(packet['no']), 1, 0, 'C')
        # Limiter la longueur du temps et sécuriser le texte
        time_str = safe_str(packet['time'])
        if len(time_str) > 10:
            time_str = time_str[:10]
        pdf.cell(25, line_height, time_str, 1, 0, 'C')
        
        pdf.cell(35, line_height, safe_str(packet['src']), 1, 0, 'C')
        pdf.cell(35, line_height, safe_str(packet['dst']), 1, 0, 'C')
        pdf.cell(25, line_height, safe_str(packet['protocol']), 1, 0, 'C')
        
        # Limiter la longueur des infos et sécuriser le texte
        info = safe_str(packet['info'])
        if len(info) > 35:
            info = info[:32] + '...'
        pdf.cell(60, line_height, info, 1, 1, 'L')

    filename = generate_filename("pdf")
    pdf.output(filename)
    return send_file(filename, as_attachment=True)

@app.route('/export/csv')
def export_csv():
    packets = session.get('packets', [])
    if not packets:
        return "Aucune donnée à exporter."

    filename = generate_filename("csv")
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=['no', 'time', 'src', 'dst', 'protocol', 'info'])
        writer.writeheader()
        writer.writerows(packets)

    return send_file(filename, as_attachment=True)

@app.route('/export/html')
def export_html():
    packets = session.get('packets', [])
    if not packets:
        return "Aucune donnée à exporter."

    filename = generate_filename("html")
    with open(filename, mode="w", encoding="utf-8") as file:
        file.write("""<!DOCTYPE html>
<html>
<head>
    <title>Rapport de Capture</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>Rapport de Capture Réseau</h1>
    <p>Date: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
    <table>
        <tr>
            <th>#</th>
            <th>Temps</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocole</th>
            <th>Info</th>
        </tr>""")
        
        for packet in packets:
            file.write(f"""
        <tr>
            <td>{packet['no']}</td>
            <td>{packet['time']}</td>
            <td>{packet['src']}</td>
            <td>{packet['dst']}</td>
            <td>{packet['protocol']}</td>
            <td>{packet['info']}</td>
        </tr>""")
            
        file.write("""
    </table>
</body>
</html>""")

    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5003)
