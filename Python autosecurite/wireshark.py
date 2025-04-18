import os
import pyshark
from flask import Flask, render_template, request

app = Flask(__name__)

# Obtenir les interfaces réseau disponibles
AVAILABLE_INTERFACES = pyshark.tshark.tshark.get_tshark_interfaces()

@app.route('/', methods=['GET', 'POST'])
def index():
    packet_summary = []
    if request.method == 'POST':
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

            # Lire le fichier de capture et afficher les paquets
            packets = pyshark.FileCapture(capture_file)
            packet_summary = []
            for i, pkt in enumerate(packets):
                if i >= 20:  # Limiter à 20 paquets
                    break

                # Ignorer les paquets ARP
                if pkt.highest_layer == 'ARP':
                    continue

                # Extraire uniquement les secondes écoulées comme Wireshark (deuxième colonne)
                timestamp_str = pkt.frame_info.time_relative if hasattr(pkt.frame_info, 'time_relative') else 'N/A'

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

        except Exception as e:
            packet_summary.append({'error': f"Erreur lors de la capture : {e}"})

    return render_template('index.html', interfaces=AVAILABLE_INTERFACES, packets=packet_summary)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5003)
