#!/usr/bin/env python3
from zapv2 import ZAPv2

def zap_scan(target):
    api_key = 'your_api_key'  # Remplacez par votre clé API ZAP
    zap = ZAPv2(apikey=api_key)

    print(f"[*] Lancement du scan OWASP ZAP sur : {target}")
    try:
        zap.urlopen(target)
        print("[*] Crawling terminé, lancement de l'analyse active...")
        zap.ascan.scan(target)

        while int(zap.ascan.status()) < 100:
            print(f"[*] Progression : {zap.ascan.status()}%")
        
        print("[*] Analyse terminée.")
        report = zap.core.htmlreport()
        with open("zap_report.html", "w") as file:
            file.write(report)
        print("[*] Rapport enregistré dans zap_report.html")
    except Exception as e:
        print(f"[!] Erreur lors de l'exécution du scan OWASP ZAP : {e}")

if __name__ == "__main__":
    target = input("Entrez l'URL cible (ex : http://example.com) : ")
    zap_scan(target)
