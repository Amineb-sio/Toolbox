import os
import pyshark
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Obtenir les interfaces réseau disponibles
AVAILABLE_INTERFACES = pyshark.tshark.tshark.get_tshark_interfaces()

@app.route('/')
def index():
    return render_template('index.html', interfaces=AVAILABLE_INTERFACES)

@app.route('/capture', methods=['POST'])
def capture():
    # Récupérer les paramètres du formulaire
    interface = request.form.get('interface')
    duration = int(request.form.get('duration'))

    if not interface or duration <= 0:
        return "Invalid input. Please select an interface and specify a valid duration."

    # Démarrer la capture de trafic
    capture_file = f"capture_{interface}.pcap"
    try:
        capture = pyshark.LiveCapture(interface=interface, output_file=capture_file)
        capture.sniff(timeout=duration)
        capture.close()

        return redirect(url_for('view_capture', capture_file=capture_file))
    except Exception as e:
        return f"Error during capture: {e}"

@app.route('/view_capture')
def view_capture():
    capture_file = request.args.get('capture_file')

    if not capture_file or not os.path.exists(capture_file):
        return "Capture file not found."

    # Lire le fichier de capture et afficher les paquets
    try:
        packets = pyshark.FileCapture(capture_file)
        packet_summary = []
        for i, pkt in enumerate(packets):
            if i >= 20:  # Limiter à 20 paquets
                break

            # Extraction de l'heure brute (pas de conversion)
            if hasattr(pkt, 'frame_info') and hasattr(pkt.frame_info, 'time'):
                timestamp_str = pkt.frame_info.time
            else:
                timestamp_str = 'N/A'

            # Extraction des informations DNS, HTTP ou HTTPS
            if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
                info = pkt.dns.qry_name  # Domaine résolu via DNS
            elif hasattr(pkt, 'http') and hasattr(pkt.http, 'host'):
                info = f"{pkt.http.request_method} {pkt.http.host}"  # Détails HTTP
            elif hasattr(pkt, 'tls') and hasattr(pkt.tls, 'handshake_extensions_server_name'):
                info = f"HTTPS (SNI: {pkt.tls.handshake_extensions_server_name})"  # SNI pour HTTPS
            else:
                info = 'N/A'

            packet_summary.append({
                'no': i + 1,
                'time': timestamp_str,
                'src': pkt.ip.src if hasattr(pkt, 'ip') else 'N/A',
                'dst': pkt.ip.dst if hasattr(pkt, 'ip') else 'N/A',
                'protocol': pkt.highest_layer,
                'info': info,
            })
        packets.close()
        return render_template('capture.html', packets=packet_summary)
    except Exception as e:
        return f"Error viewing capture: {e}"

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5003)
