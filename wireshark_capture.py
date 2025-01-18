#!/usr/bin/env python3
import pyshark

def capture_traffic(interface, output_file):
    print(f"[*] Capture du trafic réseau sur l'interface : {interface}")
    try:
        capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
        print("[*] Capture en cours... Appuyez sur Ctrl+C pour arrêter.")
        capture.sniff(timeout=60)  # Capture pendant 60 secondes
        print(f"[*] Capture terminée. Résultats enregistrés dans {output_file}.")
    except Exception as e:
        print(f"[!] Erreur lors de la capture réseau : {e}")

if __name__ == "__main__":
    interface = input("Entrez l'interface réseau (ex : eth0, wlan0) : ")
    output_file = input("Entrez le nom du fichier de sortie (ex : capture.pcap) : ")
    capture_traffic(interface, output_file)
