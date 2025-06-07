
#!/usr/bin/env python3
from flask import Flask, render_template_string, request, jsonify, redirect, url_for
import os
from pathlib import Path
from network_analyzer import NetworkTrafficAnalyzer

app = Flask(__name__)
analyzer = NetworkTrafficAnalyzer()

# Template HTML simple
SIMPLE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Analyseur de Trafic Réseau</title>
    <style>
        body { font-family: Arial; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #0056b3; }
        .result { background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 5px; border-left: 4px solid #007bff; }
        .file-item { background: #fff; border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .success { background: #d4edda; border-color: #c3e6cb; color: #155724; }
        .alert-item { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 5px 0; border-radius: 3px; }
        h1 { color: #333; }
        h2 { color: #555; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }
        .stat-box { background: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 1.5em; font-weight: bold; color: #007bff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Analyseur de Trafic Réseau</h1>
        <p>Interface simplifiée pour analyser vos fichiers PCAP</p>
        
        <h2>📁 Fichiers PCAP Disponibles</h2>
        {% if pcap_files %}
            {% for file in pcap_files %}
                <div class="file-item">
                    <h3>📄 {{ file.name }}</h3>
                    <p><strong>Taille:</strong> {{ file.size }} | <strong>Chemin:</strong> {{ file.path }}</p>
                    <form method="POST" action="/analyze" style="display: inline;">
                        <input type="hidden" name="file_path" value="{{ file.path }}">
                        <button type="submit" class="btn">🔍 Analyser ce fichier</button>
                    </form>
                </div>
            {% endfor %}
        {% else %}
            <div class="result">
                <p>❌ Aucun fichier PCAP trouvé.</p>
                <p>Vérifiez que vous avez des fichiers .pcap dans le répertoire Python_wireshark/</p>
            </div>
        {% endif %}
        
        {% if result %}
            <h2>📊 Résultats de l'analyse</h2>
            <div class="result success">
                <h3>✅ {{ result.session_name }}</h3>
                
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-number">{{ "{:,}".format(result.summary.total_packets) }}</div>
                        <div>Paquets analysés</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{{ result.summary.unique_src_ips }}</div>
                        <div>IPs sources uniques</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{{ result.summary.unique_dst_ips }}</div>
                        <div>IPs destinations uniques</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{{ result.summary.protocols_count }}</div>
                        <div>Protocoles détectés</div>
                    </div>
                </div>
                
                {% if result.summary.alerts_count > 0 %}
                    <h4>🚨 Alertes de Sécurité ({{ result.summary.alerts_count }})</h4>
                    {% for alert in result.alerts[:5] %}
                        <div class="alert-item">
                            <strong>{{ alert.type }}:</strong> {{ alert.description }}
                            {% if alert.src_ip %} (Source: {{ alert.src_ip }}){% endif %}
                        </div>
                    {% endfor %}
                {% endif %}
                
                {% if result.top_src_ips %}
                    <h4>🔝 Top 5 Sources de Trafic:</h4>
                    <ul>
                    {% for item in result.top_src_ips %}
                        <li>{{ item[0] }}: {{ "{:,}".format(item[1]) }} paquets</li>
                    {% endfor %}
                    </ul>
                {% endif %}
                
                {% if result.top_ports %}
                    <h4>🎯 Top 5 Ports de Destination:</h4>
                    <ul>
                    {% for item in result.top_ports %}
                        <li>Port {{ item[0] }}: {{ "{:,}".format(item[1]) }} connexions</li>
                    {% endfor %}
                    </ul>
                {% endif %}
                
                <p><strong>📄 Rapports détaillés générés dans:</strong> Python_network_analyzer/rapports/</p>
            </div>
        {% endif %}
        
        <div style="margin-top: 30px; text-align: center;">
            <a href="http://localhost:5000" class="btn">← Retour à la Toolbox</a>
            <a href="/" class="btn" style="background: #28a745;">🔄 Actualiser</a>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    # Chercher les fichiers PCAP
    pcap_files = []
    base_dir = Path('..')
    
    # Chercher dans Python_wireshark
    wireshark_dir = base_dir / 'Python_wireshark'
    if wireshark_dir.exists():
        for ext in ['*.pcap', '*.pcapng', '*.cap']:
            for file_path in wireshark_dir.glob(ext):
                stat = file_path.stat()
                pcap_files.append({
                    'name': file_path.name,
                    'path': str(file_path),
                    'size': f"{stat.st_size / (1024*1024):.1f} MB" if stat.st_size > 1024*1024 else f"{stat.st_size / 1024:.1f} KB"
                })
    
    # Chercher aussi dans le répertoire courant
    current_dir = Path('.')
    for ext in ['*.pcap', '*.pcapng', '*.cap']:
        for file_path in current_dir.glob(ext):
            stat = file_path.stat()
            pcap_files.append({
                'name': file_path.name,
                'path': str(file_path),
                'size': f"{stat.st_size / (1024*1024):.1f} MB" if stat.st_size > 1024*1024 else f"{stat.st_size / 1024:.1f} KB"
            })
    
    return render_template_string(SIMPLE_TEMPLATE, pcap_files=pcap_files)

@app.route('/analyze', methods=['POST'])
def analyze():
    file_path = request.form.get('file_path')
    print(f"🔍 Tentative d'analyse: {file_path}")
    
    if file_path and os.path.exists(file_path):
        try:
            result = analyzer.analyze_pcap_file(file_path)
            if result:
                print(f"✅ Analyse réussie: {result['summary']['total_packets']} paquets")
                
                # Préparer les données pour l'affichage
                # Convertir les top talkers en listes triées
                top_src_ips = sorted(result['top_talkers']['src'].items(), 
                                   key=lambda x: x[1], reverse=True)[:5]
                result['top_src_ips'] = top_src_ips
                
                # Ajouter les top ports si disponibles
                if 'ports' in result:
                    top_ports = sorted(result['ports'].items(), 
                                     key=lambda x: x[1], reverse=True)[:5]
                    result['top_ports'] = top_ports
                
                # Chercher les fichiers PCAP à nouveau pour l'affichage
                pcap_files = []
                base_dir = Path('..')
                wireshark_dir = base_dir / 'Python_wireshark'
                if wireshark_dir.exists():
                    for ext in ['*.pcap', '*.pcapng', '*.cap']:
                        for file_path_iter in wireshark_dir.glob(ext):
                            stat = file_path_iter.stat()
                            pcap_files.append({
                                'name': file_path_iter.name,
                                'path': str(file_path_iter),
                                'size': f"{stat.st_size / (1024*1024):.1f} MB" if stat.st_size > 1024*1024 else f"{stat.st_size / 1024:.1f} KB"
                            })
                
                return render_template_string(SIMPLE_TEMPLATE, pcap_files=pcap_files, result=result)
            else:
                print("❌ Échec de l'analyse")
        except Exception as e:
            print(f"❌ Erreur lors de l'analyse: {e}")
            import traceback
            traceback.print_exc()
    
    return redirect(url_for('index'))

@app.route('/api/status')
def status():
    """API pour vérifier le statut"""
    return jsonify({
        'status': 'running',
        'analyzer': 'network_traffic_analyzer',
        'port': 5022
    })

@app.route('/reports')
def reports():
    """Liste des rapports générés"""
    reports_dir = Path('rapports')
    reports = []
    
    if reports_dir.exists():
        for file_path in reports_dir.glob('*.txt'):
            stat = file_path.stat()
            reports.append({
                'name': file_path.name,
                'size': f"{stat.st_size / 1024:.1f} KB",
                'modified': stat.st_mtime
            })
        
        # Trier par date de modification (plus récent en premier)
        reports.sort(key=lambda x: x['modified'], reverse=True)
    
    reports_html = '''
    <html>
    <head><title>Rapports d'Analyse</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h1>📄 Rapports d'Analyse Générés</h1>
        <p><a href="/">&larr; Retour à l'accueil</a></p>
    '''
    
    if reports:
        reports_html += '<ul>'
        for report in reports:
            reports_html += f'<li>{report["name"]} ({report["size"]})</li>'
        reports_html += '</ul>'
    else:
        reports_html += '<p>Aucun rapport généré pour le moment.</p>'
    
    reports_html += '</body></html>'
    
    return reports_html

if __name__ == '__main__':
    print("🌐 Démarrage de l'Analyseur de Trafic Réseau")
    print("📊 Interface disponible sur: http://localhost:5022")
    print("📁 Recherche de fichiers PCAP dans Python_wireshark/")
    app.run(debug=True, host='0.0.0.0', port=5022)
