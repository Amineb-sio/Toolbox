#!/usr/bin/env python3
"""
Module d'analyse de trafic réseau pour la Toolbox
Analyse des fichiers PCAP et surveillance en temps réel
"""

import os
import sys
import json
import datetime
import subprocess
import logging
from pathlib import Path
import pandas as pd
import sqlite3
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from collections import defaultdict, Counter
import geoip2.database
import argparse
import threading
import time

class NetworkTrafficAnalyzer:
    """Analyseur de trafic réseau avec capacités PCAP et temps réel"""
    
    def __init__(self, output_dir="rapports", db_path="traffic_analysis.db"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.db_path = db_path
        self.logger = self._setup_logging()
        
        # Statistiques en temps réel
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'ports': defaultdict(int),
            'suspicious_activity': [],
            'connections': defaultdict(lambda: {'packets': 0, 'bytes': 0})
        }
        
        # Configuration des seuils de détection
        self.thresholds = {
            'port_scan_threshold': 20,  # Plus de 20 ports différents
            'ddos_threshold': 1000,     # Plus de 1000 paquets par minute
            'suspicious_ports': [22, 23, 135, 139, 445, 1433, 3389, 5900],
            'time_window': 60  # Fenêtre d'analyse en secondes
        }
        
        self._init_database()
    
    def _setup_logging(self):
        """Configuration du système de logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'network_analysis.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def _init_database(self):
        """Initialise la base de données SQLite pour stocker les analyses"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table des sessions d'analyse
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                session_name TEXT,
                file_path TEXT,
                total_packets INTEGER,
                duration_seconds REAL,
                suspicious_events INTEGER
            )
        """)
        
        # Table des paquets analysés
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packet_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                timestamp DATETIME,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                packet_size INTEGER,
                flags TEXT,
                is_suspicious BOOLEAN DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES analysis_sessions (id)
            )
        """)
        
        # Table des alertes de sécurité
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT,
                severity TEXT,
                description TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                FOREIGN KEY (session_id) REFERENCES analysis_sessions (id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def analyze_pcap_file(self, pcap_path, session_name=None):
        """Analyse complète d'un fichier PCAP"""
        if not os.path.exists(pcap_path):
            self.logger.error(f"Fichier PCAP introuvable: {pcap_path}")
            return None
        
        self.logger.info(f"Début de l'analyse du fichier: {pcap_path}")
        
        if not session_name:
            session_name = f"analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        start_time = time.time()
        
        # Créer une nouvelle session d'analyse
        session_id = self._create_analysis_session(session_name, pcap_path)
        
        try:
            # Charger et analyser les paquets
            packets = rdpcap(pcap_path)
            self.logger.info(f"Fichier chargé: {len(packets)} paquets")
            
            analysis_results = self._analyze_packets(packets, session_id)
            
            # Calculer la durée d'analyse
            duration = time.time() - start_time
            
            # Mettre à jour la session avec les résultats
            self._update_analysis_session(session_id, len(packets), duration, 
                                        len(analysis_results.get('alerts', [])))
            
            # Générer les rapports
            self._generate_reports(analysis_results, session_name)
            
            self.logger.info(f"Analyse terminée en {duration:.2f} secondes")
            return analysis_results
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse: {str(e)}")
            return None
    
    def _analyze_packets(self, packets, session_id):
        """Analyse détaillée des paquets"""
        results = {
            'summary': {},
            'protocols': defaultdict(int),
            'top_talkers': {'src': defaultdict(int), 'dst': defaultdict(int)},
            'port_analysis': defaultdict(int),
            'suspicious_ips': set(),
            'dns_queries': [],
            'http_requests': [],
            'alerts': [],
            'connections': defaultdict(lambda: {'packets': 0, 'bytes': 0, 'flags': set()}),
            'timeline': []
        }
        
        packet_times = []
        
        for i, packet in enumerate(packets):
            try:
                # Analyse temporelle
                if hasattr(packet, 'time'):
                    packet_time = datetime.datetime.fromtimestamp(packet.time)
                    packet_times.append(packet_time)
                else:
                    packet_time = datetime.datetime.now()
                
                # Analyse de la couche IP
                if IP in packet:
                    ip_layer = packet[IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    protocol = ip_layer.proto
                    
                    # Statistiques générales
                    results['protocols'][ip_layer.proto] += 1
                    results['top_talkers']['src'][src_ip] += 1
                    results['top_talkers']['dst'][dst_ip] += 1
                    
                    # Analyse des ports et protocoles
                    src_port = dst_port = None
                    flags = []
                    
                    if TCP in packet:
                        tcp_layer = packet[TCP]
                        src_port = tcp_layer.sport
                        dst_port = tcp_layer.dport
                        flags = self._get_tcp_flags(tcp_layer.flags)
                        
                        results['port_analysis'][dst_port] += 1
                        
                        # Analyse des connexions TCP
                        conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                        results['connections'][conn_key]['packets'] += 1
                        results['connections'][conn_key]['bytes'] += len(packet)
                        results['connections'][conn_key]['flags'].update(flags)
                        
                    elif UDP in packet:
                        udp_layer = packet[UDP]
                        src_port = udp_layer.sport
                        dst_port = udp_layer.dport
                        results['port_analysis'][dst_port] += 1
                    
                    # Détection d'activités suspectes
                    self._detect_suspicious_activity(packet, src_ip, dst_ip, 
                                                   src_port, dst_port, results)
                    
                    # Analyse DNS
                    if DNS in packet:
                        self._analyze_dns(packet, results)
                    
                    # Analyse HTTP
                    if HTTPRequest in packet or HTTPResponse in packet:
                        self._analyze_http(packet, results)
                    
                    # Enregistrer en base de données
                    self._save_packet_to_db(session_id, packet_time, src_ip, dst_ip,
                                          protocol, src_port, dst_port, len(packet), 
                                          ','.join(flags))
                
                # Affichage du progrès
                if (i + 1) % 1000 == 0:
                    self.logger.info(f"Analysé {i + 1}/{len(packets)} paquets")
                    
            except Exception as e:
                self.logger.warning(f"Erreur lors de l'analyse du paquet {i}: {str(e)}")
                continue
        
        # Analyse temporelle
        if packet_times:
            results['timeline'] = self._analyze_timeline(packet_times)
        
        # Résumé général
        results['summary'] = {
            'total_packets': len(packets),
            'unique_src_ips': len(results['top_talkers']['src']),
            'unique_dst_ips': len(results['top_talkers']['dst']),
            'protocols_count': len(results['protocols']),
            'suspicious_ips_count': len(results['suspicious_ips']),
            'alerts_count': len(results['alerts']),
            'duration': (max(packet_times) - min(packet_times)).total_seconds() if packet_times else 0
        }
        
        return results
    
    def _detect_suspicious_activity(self, packet, src_ip, dst_ip, src_port, dst_port, results):
        """Détection d'activités suspectes"""
        alerts = []
        
        # Détection de scan de ports
        if dst_port in self.thresholds['suspicious_ports']:
            alert = {
                'type': 'suspicious_port',
                'severity': 'medium',
                'description': f"Connexion vers un port sensible: {dst_port}",
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'port': dst_port
            }
            alerts.append(alert)
            results['suspicious_ips'].add(src_ip)
        
        # Détection de trafic anormal
        if TCP in packet:
            tcp_flags = packet[TCP].flags
            
            # SYN flood detection
            if tcp_flags == 2:  # SYN flag
                syn_key = f"syn_{src_ip}_{dst_ip}"
                if syn_key not in results:
                    results[syn_key] = 0
                results[syn_key] += 1
                
                if results[syn_key] > 100:  # Plus de 100 SYN vers la même destination
                    alert = {
                        'type': 'possible_syn_flood',
                        'severity': 'high',
                        'description': f"Possible attaque SYN flood détectée",
                        'src_ip': src_ip,
                        'dst_ip': dst_ip
                    }
                    alerts.append(alert)
        
        # Ajouter les alertes aux résultats
        results['alerts'].extend(alerts)
    
    def _analyze_dns(self, packet, results):
        """Analyse des requêtes DNS"""
        if DNSQR in packet:
            query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            results['dns_queries'].append({
                'query': query,
                'type': packet[DNSQR].qtype,
                'timestamp': datetime.datetime.fromtimestamp(packet.time) if hasattr(packet, 'time') else datetime.datetime.now()
            })
    
    def _analyze_http(self, packet, results):
        """Analyse des requêtes HTTP"""
        if HTTPRequest in packet:
            http_req = packet[HTTPRequest]
            results['http_requests'].append({
                'method': http_req.Method.decode('utf-8', errors='ignore') if hasattr(http_req, 'Method') else 'Unknown',
                'host': http_req.Host.decode('utf-8', errors='ignore') if hasattr(http_req, 'Host') else 'Unknown',
                'path': http_req.Path.decode('utf-8', errors='ignore') if hasattr(http_req, 'Path') else 'Unknown',
                'timestamp': datetime.datetime.fromtimestamp(packet.time) if hasattr(packet, 'time') else datetime.datetime.now()
            })
    
    def _get_tcp_flags(self, flags):
        """Convertit les flags TCP en liste lisible"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return flag_names
    
    def _analyze_timeline(self, packet_times):
        """Analyse temporelle du trafic"""
        if not packet_times:
            return {}
        
        timeline = {
            'start_time': min(packet_times),
            'end_time': max(packet_times),
            'duration': (max(packet_times) - min(packet_times)).total_seconds(),
            'packets_per_second': {}
        }
        
        # Calculer le trafic par seconde
        for packet_time in packet_times:
            second_key = packet_time.strftime('%Y-%m-%d %H:%M:%S')
            if second_key not in timeline['packets_per_second']:
                timeline['packets_per_second'][second_key] = 0
            timeline['packets_per_second'][second_key] += 1
        
        return timeline
    
    def _create_analysis_session(self, session_name, file_path):
        """Crée une nouvelle session d'analyse en base"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO analysis_sessions (session_name, file_path)
            VALUES (?, ?)
        """, (session_name, file_path))
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return session_id
    
    def _update_analysis_session(self, session_id, total_packets, duration, suspicious_events):
        """Met à jour les informations de session d'analyse"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE analysis_sessions 
            SET total_packets = ?, duration_seconds = ?, suspicious_events = ?
            WHERE id = ?
        """, (total_packets, duration, suspicious_events, session_id))
        
        conn.commit()
        conn.close()
    
    def _save_packet_to_db(self, session_id, timestamp, src_ip, dst_ip, protocol, 
                          src_port, dst_port, packet_size, flags):
        """Sauvegarde les informations de paquet en base"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO packet_analysis 
            (session_id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size, flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size, flags))
        
        conn.commit()
        conn.close()
    
    def _generate_reports(self, analysis_results, session_name):
        """Génère les rapports d'analyse"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Rapport JSON détaillé
        json_report = self.output_dir / f"{session_name}_{timestamp}_detailed.json"
        self._generate_json_report(analysis_results, json_report)
        
        # Rapport CSV pour Excel
        csv_report = self.output_dir / f"{session_name}_{timestamp}_summary.csv"
        self._generate_csv_report(analysis_results, csv_report)
        
        # Rapport HTML
        html_report = self.output_dir / f"{session_name}_{timestamp}_report.html"
        self._generate_html_report(analysis_results, html_report)
        
        self.logger.info(f"Rapports générés:")
        self.logger.info(f"  - JSON: {json_report}")
        self.logger.info(f"  - CSV: {csv_report}")
        self.logger.info(f"  - HTML: {html_report}")
    
    def _generate_json_report(self, results, output_path):
        """Génère un rapport JSON détaillé"""
        # Convertir les objets non sérialisables
        serializable_results = self._make_serializable(results)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(serializable_results, f, indent=2, ensure_ascii=False, default=str)
    
    def _generate_csv_report(self, results, output_path):
        """Génère un rapport CSV pour analyse Excel"""
        data = []
        
        # Top talkers source
        for ip, count in sorted(results['top_talkers']['src'].items(), 
                               key=lambda x: x[1], reverse=True)[:20]:
            data.append({
                'Type': 'Source IP',
                'Value': ip,
                'Count': count,
                'Percentage': f"{(count/results['summary']['total_packets']*100):.2f}%"
            })
        
        # Top ports
        for port, count in sorted(results['port_analysis'].items(), 
                                 key=lambda x: x[1], reverse=True)[:20]:
            data.append({
                'Type': 'Destination Port',
                'Value': port,
                'Count': count,
                'Percentage': f"{(count/results['summary']['total_packets']*100):.2f}%"
            })
        
        df = pd.DataFrame(data)
        df.to_csv(output_path, index=False)
    
    def _generate_html_report(self, results, output_path):
        """Génère un rapport HTML visuel"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rapport d'Analyse de Trafic Réseau</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .alert {{ background-color: #ffebee; border-left: 4px solid #f44336; }}
                .info {{ background-color: #e3f2fd; border-left: 4px solid #2196F3; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Rapport d'Analyse de Trafic Réseau</h1>
                <p>Généré le: {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</p>
            </div>
            
            <div class="section info">
                <h2>Résumé Exécutif</h2>
                <ul>
                    <li>Total de paquets analysés: {results['summary']['total_packets']:,}</li>
                    <li>Adresses IP sources uniques: {results['summary']['unique_src_ips']}</li>
                    <li>Adresses IP destinations uniques: {results['summary']['unique_dst_ips']}</li>
                    <li>Protocoles détectés: {results['summary']['protocols_count']}</li>
                    <li>Alertes de sécurité: {results['summary']['alerts_count']}</li>
                </ul>
            </div>
            
            <div class="section">
                <h2>Top 10 des Sources de Trafic</h2>
                <table>
                    <tr><th>Adresse IP</th><th>Nombre de Paquets</th><th>Pourcentage</th></tr>
        """
        
        # Top sources
        for ip, count in sorted(results['top_talkers']['src'].items(), 
                               key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count/results['summary']['total_packets']*100)
            html_content += f"<tr><td>{ip}</td><td>{count:,}</td><td>{percentage:.2f}%</td></tr>"
        
        html_content += """
                </table>
            </div>
            
            <div class="section alert">
                <h2>Alertes de Sécurité</h2>
        """
        
        if results['alerts']:
            html_content += "<ul>"
            for alert in results['alerts'][:10]:  # Limiter à 10 alertes
                html_content += f"<li><strong>{alert['type']}</strong>: {alert['description']} (Source: {alert['src_ip']})</li>"
            html_content += "</ul>"
        else:
            html_content += "<p>Aucune alerte de sécurité détectée.</p>"
        
        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _make_serializable(self, obj):
        """Convertit les objets non sérialisables en JSON"""
        if isinstance(obj, defaultdict):
            return dict(obj)
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        else:
            return obj
    
    def live_capture(self, interface='any', duration=60, packet_count=None):
        """Capture et analyse en temps réel"""
        self.logger.info(f"Début de la capture en temps réel sur {interface}")
        
        def packet_handler(packet):
            self.stats['total_packets'] += 1
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                self.stats['src_ips'][src_ip] += 1
                self.stats['dst_ips'][dst_ip] += 1
                self.stats['protocols'][packet[IP].proto] += 1
                
                if TCP in packet:
                    self.stats['ports'][packet[TCP].dport] += 1
                elif UDP in packet:
                    self.stats['ports'][packet[UDP].dport] += 1
            
            # Affichage périodique des statistiques
            if self.stats['total_packets'] % 100 == 0:
                self.logger.info(f"Paquets capturés: {self.stats['total_packets']}")
        
        try:
            sniff(iface=interface, prn=packet_handler, timeout=duration, count=packet_count)
        except Exception as e:
            self.logger.error(f"Erreur lors de la capture: {str(e)}")
        
        return self.stats
    
    def get_analysis_history(self):
        """Récupère l'historique des analyses"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM analysis_sessions 
            ORDER BY timestamp DESC
        """)
        
        sessions = cursor.fetchall()
        conn.close()
        
        return sessions


def main():
    """Fonction principale pour l'utilisation en ligne de commande"""
    parser = argparse.ArgumentParser(description='Analyseur de Trafic Réseau')
    parser.add_argument('--pcap', help='Fichier PCAP à analyser')
    parser.add_argument('--live', help='Interface pour capture en temps réel')
    parser.add_argument('--duration', type=int, default=60, help='Durée de capture (secondes)')
    parser.add_argument('--output', default='rapports', help='Répertoire de sortie')
    parser.add_argument('--session-name', help='Nom de la session d\'analyse')
    
    args = parser.parse_args()
    
    analyzer = NetworkTrafficAnalyzer(output_dir=args.output)
    
    if args.pcap:
        # Analyse de fichier PCAP
        results = analyzer.analyze_pcap_file(args.pcap, args.session_name)
        if results:
            print(f"Analyse terminée. {results['summary']['total_packets']} paquets analysés.")
            print(f"Alertes détectées: {results['summary']['alerts_count']}")
    
    elif args.live:
        # Capture en temps réel
        print(f"Début de la capture en temps réel sur {args.live} pendant {args.duration} secondes...")
        stats = analyzer.live_capture(args.live, args.duration)
        print(f"Capture terminée. {stats['total_packets']} paquets capturés.")
    
    else:
        print("Veuillez spécifier --pcap ou --live")
        parser.print_help()


if __name__ == "__main__":
    main()
