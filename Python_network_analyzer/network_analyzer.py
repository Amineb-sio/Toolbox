#!/usr/bin/env python3
"""
Module d'analyse de trafic réseau simplifié pour démarrage rapide
"""

import os
import sys
import json
import datetime as dt
import sqlite3
from pathlib import Path
from collections import defaultdict
import logging

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    print("⚠️ Scapy non disponible - fonctionnalités limitées")
    SCAPY_AVAILABLE = False

class NetworkTrafficAnalyzer:
    """Analyseur de trafic réseau simplifié"""
    
    def __init__(self, output_dir="rapports", db_path="traffic_analysis.db"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.db_path = db_path
        self.logger = self._setup_logging()
        self._init_database()
    
    def _setup_logging(self):
        """Configuration du système de logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'network_analysis.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def _init_database(self):
        """Initialise la base de données SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
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
                FOREIGN KEY (session_id) REFERENCES analysis_sessions (id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def analyze_pcap_file(self, pcap_path, session_name=None):
        """Analyse un fichier PCAP"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy non disponible - impossible d'analyser le PCAP")
            return None
            
        if not os.path.exists(pcap_path):
            self.logger.error(f"Fichier PCAP introuvable: {pcap_path}")
            return None
        
        self.logger.info(f"Début de l'analyse du fichier: {pcap_path}")
        
        if not session_name:
            session_name = f"analysis_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Charger les paquets
            packets = rdpcap(pcap_path)
            self.logger.info(f"Fichier chargé: {len(packets)} paquets")
            
            # Analyse basique
            results = self._analyze_packets_basic(packets)
            results['session_name'] = session_name
            results['file_path'] = pcap_path
            
            # Sauvegarder en base
            session_id = self._save_to_database(session_name, pcap_path, results)
            
            # Générer un rapport simple
            self._generate_simple_report(results, session_name)
            
            self.logger.info(f"Analyse terminée: {results['summary']['total_packets']} paquets")
            return results
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
    
    def _analyze_packets_basic(self, packets):
        """Analyse basique des paquets"""
        results = {
            'summary': {
                'total_packets': len(packets),
                'unique_src_ips': set(),
                'unique_dst_ips': set(),
                'protocols': defaultdict(int),
                'alerts_count': 0
            },
            'top_talkers': {'src': defaultdict(int), 'dst': defaultdict(int)},
            'alerts': [],
            'ports': defaultdict(int)
        }
        
        suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900]
        
        for packet in packets:
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                results['summary']['unique_src_ips'].add(src_ip)
                results['summary']['unique_dst_ips'].add(dst_ip)
                results['summary']['protocols'][ip_layer.proto] += 1
                results['top_talkers']['src'][src_ip] += 1
                results['top_talkers']['dst'][dst_ip] += 1
                
                # Analyser les ports
                if TCP in packet:
                    dst_port = packet[TCP].dport
                    results['ports'][dst_port] += 1
                    
                    # Détecter des ports suspects
                    if dst_port in suspicious_ports:
                        results['alerts'].append({
                            'type': 'suspicious_port',
                            'description': f"Connexion vers port sensible: {dst_port}",
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'port': dst_port
                        })
                
                elif UDP in packet:
                    dst_port = packet[UDP].dport
                    results['ports'][dst_port] += 1
        
        # Convertir les sets en compteurs
        results['summary']['unique_src_ips'] = len(results['summary']['unique_src_ips'])
        results['summary']['unique_dst_ips'] = len(results['summary']['unique_dst_ips'])
        results['summary']['protocols_count'] = len(results['summary']['protocols'])
        results['summary']['alerts_count'] = len(results['alerts'])
        results['summary']['duration'] = 0  # Simplifié
        
        return results
    
    def _save_to_database(self, session_name, file_path, results):
        """Sauvegarde les résultats en base"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO analysis_sessions (session_name, file_path, total_packets, suspicious_events)
            VALUES (?, ?, ?, ?)
        """, (session_name, file_path, results['summary']['total_packets'], len(results['alerts'])))
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return session_id
    
    def _generate_simple_report(self, results, session_name):
        """Génère un rapport simple"""
        timestamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Rapport JSON
        json_file = self.output_dir / f"{session_name}_{timestamp}_report.json"
        
        # Convertir defaultdict en dict pour JSON
        json_results = {}
        for key, value in results.items():
            if isinstance(value, defaultdict):
                json_results[key] = dict(value)
            elif isinstance(value, dict):
                json_results[key] = {}
                for k, v in value.items():
                    if isinstance(v, defaultdict):
                        json_results[key][k] = dict(v)
                    else:
                        json_results[key][k] = v
            else:
                json_results[key] = value
        
        with open(json_file, 'w') as f:
            json.dump(json_results, f, indent=2, default=str)
        
        # Rapport texte simple
        txt_file = self.output_dir / f"{session_name}_{timestamp}_summary.txt"
        with open(txt_file, 'w') as f:
            f.write(f"Rapport d'analyse - {session_name}\n")
            f.write(f"Généré le: {dt.datetime.now()}\n")
            f.write(f"=" * 50 + "\n\n")
            f.write(f"Paquets analysés: {results['summary']['total_packets']:,}\n")
            f.write(f"IPs sources uniques: {results['summary']['unique_src_ips']}\n")
            f.write(f"IPs destinations uniques: {results['summary']['unique_dst_ips']}\n")
            f.write(f"Protocoles détectés: {results['summary']['protocols_count']}\n")
            f.write(f"Alertes détectées: {results['summary']['alerts_count']}\n\n")
            
            if results['top_talkers']['src']:
                f.write(f"Top 5 sources:\n")
                for ip, count in sorted(results['top_talkers']['src'].items(), 
                                      key=lambda x: x[1], reverse=True)[:5]:
                    f.write(f"  {ip}: {count:,} paquets\n")
            
            if results['alerts']:
                f.write(f"\nAlertes de sécurité:\n")
                for alert in results['alerts'][:10]:  # Limiter à 10
                    f.write(f"  - {alert['type']}: {alert['description']}\n")
        
        self.logger.info(f"Rapports générés: {json_file}, {txt_file}")

if __name__ == "__main__":
    analyzer = NetworkTrafficAnalyzer()
    print("✅ Module network_analyzer chargé avec succès")
