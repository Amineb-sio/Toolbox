#!/usr/bin/env python3
"""
Interface Flask pour l'analyseur de trafic réseau
Port: 5022
"""

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
import json
import subprocess
import threading
import time
from pathlib import Path
import sqlite3
from network_analyzer import NetworkTrafficAnalyzer
import datetime

app = Flask(__name__)
app.secret_key = 'network_analyzer_secret_key'

# Configuration
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'rapports'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max

# Créer les dossiers nécessaires
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# Instance globale de l'analyseur
analyzer = NetworkTrafficAnalyzer(output_dir=REPORTS_FOLDER)

# Variables pour la capture en temps réel
live_capture_thread = None
live_capture_active = False
live_stats = {}

def allowed_file(filename):
    """Vérifie si le fichier a une extension autorisée"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Page d'accueil de l'analyseur réseau"""
    # Récupérer les dernières analyses
    recent_analyses = get_recent_analyses(limit=5)
    
    # Statistiques globales
    stats = get_global_stats()
    
    return render_template('network_analyzer/index.html', 
                         recent_analyses=recent_analyses,
                         stats=stats,
                         live_capture_active=live_capture_active)

@app.route('/upload', methods=['GET', 'POST'])
def upload_pcap():
    """Upload et analyse d'un fichier PCAP"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Aucun fichier sélectionné', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('Aucun fichier sélectionné', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Récupérer le nom de session optionnel
            session_name = request.form.get('session_name', '')
            if not session_name:
                session_name = f"upload_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Lancer l'analyse en arrière-plan
            def analyze_in_background():
                try:
                    results = analyzer.analyze_pcap_file(filepath, session_name)
                    if results:
                        flash(f'Analyse terminée: {results["summary"]["total_packets"]} paquets analysés', 'success')
                    else:
                        flash('Erreur lors de l\'analyse du fichier', 'error')
                except Exception as e:
                    flash(f'Erreur: {str(e)}', 'error')
            
            # Démarrer l'analyse
            analysis_thread = threading.Thread(target=analyze_in_background)
            analysis_thread.start()
            
            flash(f'Fichier {filename} uploadé. Analyse en cours...', 'info')
            return redirect(url_for('analyses'))
        else:
            flash('Type de fichier non autorisé. Utilisez .pcap, .pcapng ou .cap', 'error')
    
    return render_template('network_analyzer/upload.html')

@app.route('/live_capture', methods=['GET', 'POST'])
def live_capture():
    """Interface pour la capture en temps réel"""
    global live_capture_thread, live_capture_active
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'start' and not live_capture_active:
            interface = request.form.get('interface', 'any')
            duration = int(request.form.get('duration', 60))
            
            def capture_in_background():
                global live_capture_active, live_stats
                live_capture_active = True
                try:
                    live_stats = analyzer.live_capture(interface, duration)
                    flash(f'Capture terminée: {live_stats["total_packets"]} paquets capturés', 'success')
                except Exception as e:
                    flash(f'Erreur lors de la capture: {str(e)}', 'error')
                finally:
                    live_capture_active = False
            
            live_capture_thread = threading.Thread(target=capture_in_background)
            live_capture_thread.start()
            flash('Capture en temps réel démarrée', 'info')
        
        elif action == 'stop' and live_capture_active:
            live_capture_active = False
            flash('Arrêt de la capture demandé', 'info')
    
    # Obtenir la liste des interfaces réseau
    interfaces = get_network_interfaces()
    
    return render_template('network_analyzer/live_capture.html', 
                         interfaces=interfaces,
                         live_capture_active=live_capture_active,
                         live_stats=live_stats)

@app.route('/analyses')
def analyses():
    """Liste des analyses effectuées"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    analyses = get_analyses_paginated(page, per_page)
    
    return render_template('network_analyzer/analyses.html', 
                         analyses=analyses,
                         page=page,
                         per_page=per_page)

@app.route('/analysis/<int:session_id>')
def analysis_detail(session_id):
    """Détails d'une analyse spécifique"""
    analysis = get_analysis_by_id(session_id)
    if not analysis:
        flash('Analyse non trouvée', 'error')
        return redirect(url_for('analyses'))
    
    # Récupérer les statistiques détaillées
    stats = get_analysis_stats(session_id)
    alerts = get_analysis_alerts(session_id)
    
    return render_template('network_analyzer/analysis_detail.html',
                         analysis=analysis,
                         stats=stats,
                         alerts=alerts)

@app.route('/api/live_stats')
def api_live_stats():
    """API pour récupérer les statistiques en temps réel"""
    global live_stats, live_capture_active
    
    return jsonify({
        'active': live_capture_active,
        'stats': live_stats
    })

@app.route('/api/analysis/<int:session_id>/data')
def api_analysis_data(session_id):
    """API pour récupérer les données d'analyse en JSON"""
    conn = sqlite3.connect(analyzer.db_path)
    cursor = conn.cursor()
    
    # Récupérer les informations de session
    cursor.execute("SELECT * FROM analysis_sessions WHERE id = ?", (session_id,))
    session = cursor.fetchone()
    
    if not session:
        return jsonify({'error': 'Session non trouvée'}), 404
    
    # Récupérer les statistiques de paquets
    cursor.execute("""
        SELECT protocol, COUNT(*) as count
        FROM packet_analysis 
        WHERE session_id = ?
        GROUP BY protocol
        ORDER BY count DESC
    """, (session_id,))
    protocols = cursor.fetchall()
    
    # Top IPs sources
    cursor.execute("""
        SELECT src_ip, COUNT(*) as count
        FROM packet_analysis 
        WHERE session_id = ?
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT 10
    """, (session_id,))
    top_src_ips = cursor.fetchall()
    
    # Top ports
    cursor.execute("""
        SELECT dst_port, COUNT(*) as count
        FROM packet_analysis 
        WHERE session_id = ? AND dst_port IS NOT NULL
        GROUP BY dst_port
        ORDER BY count DESC
        LIMIT 10
    """, (session_id,))
    top_ports = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        'session': session,
        'protocols': protocols,
        'top_src_ips': top_src_ips,
        'top_ports': top_ports
    })

@app.route('/download/<int:session_id>/<report_type>')
def download_report(session_id, report_type):
    """Télécharger un rapport d'analyse"""
    analysis = get_analysis_by_id(session_id)
    if not analysis:
        flash('Analyse non trouvée', 'error')
        return redirect(url_for('analyses'))
    
    # Construire le nom du fichier de rapport
    session_name = analysis[2]  # session_name est le 3ème champ
    timestamp = analysis[1].strftime('%Y%m%d_%H%M%S')
    
    if report_type == 'json':
        filename = f"{session_name}_{timestamp}_detailed.json"
        mimetype = 'application/json'
    elif report_type == 'csv':
        filename = f"{session_name}_{timestamp}_summary.csv"
        mimetype = 'text/csv'
    elif report_type == 'html':
        filename = f"{session_name}_{timestamp}_report.html"
        mimetype = 'text/html'
    else:
        flash('Type de rapport non valide', 'error')
        return redirect(url_for('analysis_detail', session_id=session_id))
    
    filepath = os.path.join(REPORTS_FOLDER, filename)
    
    if not os.path.exists(filepath):
        flash('Fichier de rapport non trouvé', 'error')
        return redirect(url_for('analysis_detail', session_id=session_id))
    
    return send_file(filepath, mimetype=mimetype, as_attachment=True, download_name=filename)

@app.route('/pcap_files')
def pcap_files():
    """Liste des fichiers PCAP disponibles dans le répertoire"""
    pcap_directory = Path('.')  # Répertoire courant, peut être modifié
    
    pcap_files = []
    for ext in ['*.pcap', '*.pcapng', '*.cap']:
        pcap_files.extend(pcap_directory.glob(ext))
    
    # Ajouter les fichiers du répertoire Python_wireshark s'il existe
    wireshark_dir = Path('Python_wireshark')
    if wireshark_dir.exists():
        for ext in ['*.pcap', '*.pcapng', '*.cap']:
            pcap_files.extend(wireshark_dir.glob(ext))
    
    file_info = []
    for file_path in pcap_files:
        stat = file_path.stat()
        file_info.append({
            'name': file_path.name,
            'path': str(file_path),
            'size': format_file_size(stat.st_size),
            'modified': datetime.datetime.fromtimestamp(stat.st_mtime)
        })
    
    # Trier par date de modification (plus récent en premier)
    file_info.sort(key=lambda x: x['modified'], reverse=True)
    
    return render_template('network_analyzer/pcap_files.html', files=file_info)

@app.route('/analyze_existing', methods=['POST'])
def analyze_existing():
    """Analyser un fichier PCAP existant"""
    file_path = request.form.get('file_path')
    session_name = request.form.get('session_name', '')
    
    if not file_path or not os.path.exists(file_path):
        flash('Fichier non trouvé', 'error')
        return redirect(url_for('pcap_files'))
    
    if not session_name:
        filename = os.path.basename(file_path)
        session_name = f"existing_{filename}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Lancer l'analyse en arrière-plan
    def analyze_in_background():
        try:
            results = analyzer.analyze_pcap_file(file_path, session_name)
            if results:
                flash(f'Analyse terminée: {results["summary"]["total_packets"]} paquets analysés', 'success')
            else:
                flash('Erreur lors de l\'analyse du fichier', 'error')
        except Exception as e:
            flash(f'Erreur: {str(e)}', 'error')
    
    analysis_thread = threading.Thread(target=analyze_in_background)
    analysis_thread.start()
    
    flash(f'Analyse de {os.path.basename(file_path)} démarrée', 'info')
    return redirect(url_for('analyses'))

# Fonctions utilitaires

def get_recent_analyses(limit=5):
    """Récupère les analyses récentes"""
    conn = sqlite3.connect(analyzer.db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, timestamp, session_name, total_packets, suspicious_events
        FROM analysis_sessions 
        ORDER BY timestamp DESC 
        LIMIT ?
    """, (limit,))
    
    analyses = cursor.fetchall()
    conn.close()
    
    return analyses

def get_global_stats():
    """Récupère les statistiques globales"""
    conn = sqlite3.connect(analyzer.db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM analysis_sessions")
    total_sessions = cursor.fetchone()[0]
    
    cursor.execute("SELECT SUM(total_packets) FROM analysis_sessions")
    total_packets = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT SUM(suspicious_events) FROM analysis_sessions")
    total_alerts = cursor.fetchone()[0] or 0
    
    conn.close()
    
    return {
        'total_sessions': total_sessions,
        'total_packets': total_packets,
        'total_alerts': total_alerts
    }

def get_analyses_paginated(page, per_page):
    """Récupère les analyses avec pagination"""
    conn = sqlite3.connect(analyzer.db_path)
    cursor = conn.cursor()
    
    offset = (page - 1) * per_page
    
    cursor.execute("""
        SELECT id, timestamp, session_name, file_path, total_packets, 
               duration_seconds, suspicious_events
        FROM analysis_sessions 
        ORDER BY timestamp DESC 
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    
    analyses = cursor.fetchall()
    conn.close()
    
    return analyses

def get_analysis_by_id(session_id):
    """Récupère une analyse par son ID"""
    conn = sqlite3.connect(analyzer.db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM analysis_sessions WHERE id = ?", (session_id,))
    analysis = cursor.fetchone()
    
    conn.close()
    return analysis

def get_analysis_stats(session_id):
    """Récupère les statistiques détaillées d'une analyse"""
    conn = sqlite3.connect(analyzer.db_path)
    cursor = conn.cursor()
    
    # Protocoles
    cursor.execute("""
        SELECT protocol, COUNT(*) as count
        FROM packet_analysis 
        WHERE session_id = ?
        GROUP BY protocol
        ORDER BY count DESC
    """, (session_id,))
    protocols = cursor.fetchall()
    
    # Top IPs
    cursor.execute("""
        SELECT src_ip, COUNT(*) as count
        FROM packet_analysis 
        WHERE session_id = ?
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT 10
    """, (session_id,))
    top_ips = cursor.fetchall()
    
    conn.close()
    
    return {
        'protocols': protocols,
        'top_ips': top_ips
    }

def get_analysis_alerts(session_id):
    """Récupère les alertes d'une analyse"""
    conn = sqlite3.connect(analyzer.db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT timestamp, alert_type, severity, description, src_ip, dst_ip
        FROM security_alerts 
        WHERE session_id = ?
        ORDER BY timestamp DESC
    """, (session_id,))
    
    alerts = cursor.fetchall()
    conn.close()
    
    return alerts

def get_network_interfaces():
    """Récupère la liste des interfaces réseau disponibles"""
    try:
        # Utiliser ip link show sur Linux
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        if result.returncode == 0:
            interfaces = []
            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith(' '):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        interface_name = parts[1].strip()
                        if interface_name and not interface_name.startswith('lo'):
                            interfaces.append(interface_name)
            return interfaces
    except:
        pass
    
    # Fallback pour d'autres systèmes
    return ['any', 'eth0', 'wlan0', 'en0', 'en1']

def format_file_size(size_bytes):
    """Formate la taille de fichier en format lisible"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

if __name__ == '__main__':
    print("🌐 Démarrage de l'Analyseur de Trafic Réseau")
    print("📊 Interface disponible sur: http://localhost:5022")
    print("📁 Fichiers PCAP supportés: .pcap, .pcapng, .cap")
    print("🔍 Fonctionnalités: Analyse PCAP, Capture temps réel, Détection d'anomalies")
    
    app.run(debug=True, host='0.0.0.0', port=5022)
