#!/usr/bin/env python3
"""
Script pour analyser les fichiers PCAP existants de votre Toolbox
Analyse automatiquement tous les fichiers PCAP trouvés et génère des rapports
"""

import os
import sys
import glob
from pathlib import Path
import datetime
import json

# Ajouter le répertoire de l'analyseur réseau au path
sys.path.append(str(Path(__file__).parent / "Python_network_analyzer"))

try:
    from network_analyzer import NetworkTrafficAnalyzer
except ImportError:
    print("❌ Module network_analyzer non trouvé.")
    print("Assurez-vous d'avoir installé l'analyseur réseau dans Python_network_analyzer/")
    sys.exit(1)

class ExistingPcapAnalyzer:
    """Analyseur pour les fichiers PCAP existants de la Toolbox"""
    
    def __init__(self):
        self.base_dir = Path.cwd()
        self.results_dir = self.base_dir / "network_analysis_results"
        self.results_dir.mkdir(exist_ok=True)
        
        # Initialiser l'analyseur réseau
        self.analyzer = NetworkTrafficAnalyzer(output_dir=str(self.results_dir))
        
        print(f"🔍 Analyseur initialisé")
        print(f"📁 Répertoire de base: {self.base_dir}")
        print(f"📊 Résultats dans: {self.results_dir}")
    
    def find_pcap_files(self):
        """Trouve tous les fichiers PCAP dans la Toolbox"""
        print("🔎 Recherche des fichiers PCAP...")
        
        pcap_files = []
        
        # Patterns de recherche pour différents emplacements
        search_patterns = [
            "*.pcap",
            "*.pcapng", 
            "*.cap",
            "Python_wireshark/*.pcap",
            "Python_wireshark/*.pcapng",
            "Python_wireshark/*.cap",
            "**/rapports/*.pcap",
            "**/rapports/*.pcapng",
            "**/*.pcap",
            "**/*.pcapng"
        ]
        
        for pattern in search_patterns:
            found_files = list(self.base_dir.glob(pattern))
            for file_path in found_files:
                if file_path.is_file() and file_path not in pcap_files:
                    pcap_files.append(file_path)
        
        # Filtrer les doublons et trier par taille
        unique_files = list(set(pcap_files))
        unique_files.sort(key=lambda x: x.stat().st_size)
        
        print(f"📁 Fichiers PCAP trouvés: {len(unique_files)}")
        for file_path in unique_files:
            size_mb = file_path.stat().st_size / (1024 * 1024)
            print(f"   📄 {file_path.name} ({size_mb:.1f} MB) - {file_path}")
        
        return unique_files
    
    def analyze_file(self, pcap_path, session_name=None):
        """Analyse un fichier PCAP spécifique"""
        if not session_name:
            # Générer un nom de session basé sur le fichier
            filename = pcap_path.stem
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            session_name = f"existing_{filename}_{timestamp}"
        
        print(f"\n🔍 Analyse de: {pcap_path.name}")
        print(f"📝 Session: {session_name}")
        
        try:
            # Lancer l'analyse
            results = self.analyzer.analyze_pcap_file(str(pcap_path), session_name)
            
            if results:
                summary = results['summary']
                print(f"✅ Analyse terminée:")
                print(f"   📦 Paquets analysés: {summary['total_packets']:,}")
                print(f"   🌐 IPs sources uniques: {summary['unique_src_ips']}")
                print(f"   🎯 IPs destinations uniques: {summary['unique_dst_ips']}")
                print(f"   🚨 Alertes détectées: {summary['alerts_count']}")
                print(f"   ⏱️  Durée du trafic: {summary['duration']:.1f} secondes")
                
                # Afficher les principales alertes
                if results['alerts']:
                    print(f"   🚨 Principales alertes:")
                    for alert in results['alerts'][:3]:  # Top 3 alertes
                        print(f"      • {alert['type']}: {alert['description']}")
                
                # Afficher les top talkers
                if results['top_talkers']['src']:
                    top_src = sorted(results['top_talkers']['src'].items(), 
                                   key=lambda x: x[1], reverse=True)[:3]
                    print(f"   📈 Top sources:")
                    for ip, count in top_src:
                        print(f"      • {ip}: {count:,} paquets")
                
                return results
            else:
                print(f"❌ Échec de l'analyse")
                return None
                
        except Exception as e:
            print(f"❌ Erreur lors de l'analyse: {str(e)}")
            return None
    
    def analyze_all_files(self):
        """Analyse tous les fichiers PCAP trouvés"""
        pcap_files = self.find_pcap_files()
        
        if not pcap_files:
            print("❌ Aucun fichier PCAP trouvé")
            return
        
        print(f"\n🚀 Démarrage de l'analyse de {len(pcap_files)} fichier(s)")
        
        results_summary = []
        
        for i, pcap_path in enumerate(pcap_files, 1):
            print(f"\n{'='*60}")
            print(f"📁 Fichier {i}/{len(pcap_files)}: {pcap_path.name}")
            print(f"{'='*60}")
            
            # Analyser le fichier
            results = self.analyze_file(pcap_path)
            
            if results:
                results_summary.append({
                    'file': str(pcap_path),
                    'session_name': results.get('session_name', 'unknown'),
                    'summary': results['summary'],
                    'alerts_count': len(results.get('alerts', [])),
                    'analysis_time': datetime.datetime.now().isoformat()
                })
            
            # Petite pause entre les analyses
            if i < len(pcap_files):
                print("⏸️  Pause de 2 secondes...")
                import time
                time.sleep(2)
        
        # Générer un rapport de synthèse
        self.generate_summary_report(results_summary)
        
        print(f"\n🎉 Analyse terminée!")
        print(f"📊 Résultats dans: {self.results_dir}")
    
    def generate_summary_report(self, results_summary):
        """Génère un rapport de synthèse de toutes les analyses"""
        print(f"\n📄 Génération du rapport de synthèse...")
        
        # Rapport JSON
        summary_file = self.results_dir / f"toolbox_pcap_analysis_summary_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(results_summary, f, indent=2, ensure_ascii=False, default=str)
        
        # Rapport HTML
        html_file = self.results_dir / f"toolbox_pcap_analysis_summary_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = self.generate_html_summary(results_summary)
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Rapport JSON: {summary_file}")
        print(f"✅ Rapport HTML: {html_file}")
        
        # Afficher un résumé dans la console
        self.print_console_summary(results_summary)
    
    def generate_html_summary(self, results_summary):
        """Génère un rapport HTML de synthèse"""
        total_packets = sum(r['summary']['total_packets'] for r in results_summary)
        total_alerts = sum(r['alerts_count'] for r in results_summary)
        
        html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport d'Analyse PCAP - Toolbox</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #e3f2fd; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .file-analysis {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .alerts {{ background: #ffebee; border-left: 4px solid #f44336; padding: 10px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
        .metric {{ display: inline-block; margin: 10px; padding: 10px; background: #f5f5f5; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📊 Rapport d'Analyse PCAP - Toolbox</h1>
        <p>Généré le: {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>📈 Résumé Global</h2>
        <div class="metric">
            <strong>Fichiers analysés:</strong> {len(results_summary)}
        </div>
        <div class="metric">
            <strong>Total paquets:</strong> {total_packets:,}
        </div>
        <div class="metric">
            <strong>Total alertes:</strong> {total_alerts}
        </div>
    </div>
    
    <h2>📁 Détails par Fichier</h2>
"""
        
        for result in results_summary:
            file_name = Path(result['file']).name
            summary = result['summary']
            
            html += f"""
    <div class="file-analysis">
        <h3>📄 {file_name}</h3>
        <table>
            <tr><th>Métrique</th><th>Valeur</th></tr>
            <tr><td>Paquets analysés</td><td>{summary['total_packets']:,}</td></tr>
            <tr><td>IPs sources uniques</td><td>{summary['unique_src_ips']}</td></tr>
            <tr><td>IPs destinations uniques</td><td>{summary['unique_dst_ips']}</td></tr>
            <tr><td>Protocoles détectés</td><td>{summary['protocols_count']}</td></tr>
            <tr><td>Durée du trafic</td><td>{summary['duration']:.1f} secondes</td></tr>
            <tr><td>Alertes de sécurité</td><td>{result['alerts_count']}</td></tr>
        </table>
        
        {f'<div class="alerts">🚨 <strong>{result["alerts_count"]} alertes détectées</strong></div>' if result['alerts_count'] > 0 else ''}
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
    
    def print_console_summary(self, results_summary):
        """Affiche un résumé dans la console"""
        print(f"\n📊 RÉSUMÉ GLOBAL")
        print(f"=" * 40)
        
        total_packets = sum(r['summary']['total_packets'] for r in results_summary)
        total_alerts = sum(r['alerts_count'] for r in results_summary)
        
        print(f"📁 Fichiers analysés: {len(results_summary)}")
        print(f"📦 Total paquets: {total_packets:,}")
        print(f"🚨 Total alertes: {total_alerts}")
        
        if total_alerts > 0:
            print(f"\n⚠️  ATTENTION: {total_alerts} alertes de sécurité détectées!")
            print("Consultez les rapports détaillés pour plus d'informations.")
        
        print(f"\n📂 Tous les rapports sont disponibles dans: {self.results_dir}")

def main():
    """Fonction principale"""
    print("🌐 ANALYSEUR DE TRAFIC RÉSEAU - FICHIERS PCAP EXISTANTS")
    print("=" * 60)
    print()
    
    try:
        analyzer = ExistingPcapAnalyzer()
        
        # Vérifier si on veut analyser un fichier spécifique
        if len(sys.argv) > 1:
            pcap_file = Path(sys.argv[1])
            if pcap_file.exists():
                print(f"🎯 Analyse du fichier spécifique: {pcap_file}")
                analyzer.analyze_file(pcap_file)
            else:
                print(f"❌ Fichier non trouvé: {pcap_file}")
                sys.exit(1)
        else:
            # Analyser tous les fichiers trouvés
            print("🔍 Recherche et analyse de tous les fichiers PCAP...")
            analyzer.analyze_all_files()
        
    except KeyboardInterrupt:
        print("\n⏹️  Analyse interrompue par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
