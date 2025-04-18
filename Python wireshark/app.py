import os
import pyshark
import csv
from fpdf import FPDF
from flask import Flask, render_template, request, send_file, session
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Obtenir les interfaces réseau disponibles
AVAILABLE_INTERFACES = pyshark.tshark.tshark.get_tshark_interfaces()

# Chemin du dossier rapports
REPORT_DIR = "rapports"
os.makedirs(REPORT_DIR, exist_ok=True)

def generate_filename(extension):
    """ Génère un nom de fichier basé sur la date et l'heure """
    return os.path.join(REPORT_DIR, f"wireshark_rapport_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.{extension}")

@app.route('/', methods=['GET', 'POST'])
def index():
    packet_summary = []
    
    if request.method == 'POST':
        interface = request.form.get('interface')
        duration = int(request.form.get('duration'))
        
        if not interface or duration <= 0:
            return "Invalid input. Please select an interface and specify a valid duration."

        capture_file = f"capture_{interface}.pcap"
        
        try:
            # Capture du trafic réseau
            capture = pyshark.LiveCapture(interface=interface, output_file=capture_file)
            capture.sniff(timeout=duration)
            capture.close()

            # Lecture des paquets capturés
            packets = pyshark.FileCapture(capture_file)
            for i, pkt in enumerate(packets):
                if i >= 20:  # Limite à 20 paquets
                    break
                if pkt.highest_layer == 'ARP':
                    continue

                timestamp_str = pkt.frame_info.time_relative if hasattr(pkt.frame_info, 'time_relative') else 'N/A'
                info = (
                    pkt.dns.qry_name if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name') else
                    f"{pkt.http.request_method} {pkt.http.host}" if hasattr(pkt, 'http') and hasattr(pkt, 'http.host') else
                    f"HTTPS (SNI: {pkt.tls.handshake_extensions_server_name})" if hasattr(pkt, 'tls') and hasattr(pkt, 'tls.handshake_extensions_server_name') else
                    'N/A'
                )

                packet_summary.append({
                    'no': i + 1,
                    'time': timestamp_str,
                    'src': pkt.ip.src if hasattr(pkt, 'ip') else 'N/A',
                    'dst': pkt.ip.dst if hasattr(pkt, 'ip') else 'N/A',
                    'protocol': pkt.highest_layer,
                    'info': info,
                })
            packets.close()
            session['packets'] = packet_summary  # Stockage des paquets en session

        except Exception as e:
            packet_summary.append({'error': f"Erreur lors de la capture : {e}"})

    return render_template('index.html', interfaces=AVAILABLE_INTERFACES, packets=packet_summary)

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

    for packet in packets:
        pdf.cell(0, 10, f"#{packet['no']} - {packet['time']} - {packet['src']} -> {packet['dst']} - {packet['protocol']} - {packet['info']}", ln=True)

    filename = generate_filename("pdf")
    pdf.output(filename)
    return send_file(filename, as_attachment=True)

@app.route('/export/csv')
def export_csv():
    packets = session.get('packets', [])
    if not packets:
        return "Aucune donnée à exporter."

    filename = generate_filename("csv")
    with open(filename, mode="w", newline="") as file:
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
    with open(filename, mode="w") as file:
        file.write("<html><head><title>Rapport de Capture</title></head><body><h1>Rapport de Capture Réseau</h1><table border='1'><tr><th>#</th><th>Temps</th><th>Source</th><th>Destination</th><th>Protocole</th><th>Info</th></tr>")
        for packet in packets:
            file.write(f"<tr><td>{packet['no']}</td><td>{packet['time']}</td><td>{packet['src']}</td><td>{packet['dst']}</td><td>{packet['protocol']}</td><td>{packet['info']}</td></tr>")
        file.write("</table></body></html>")

    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5003)
