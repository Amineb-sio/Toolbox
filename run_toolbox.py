#!/usr/bin/env python3
import os

def main():
    print("====================================")
    print("  Toolbox Automatisée - Le Partenaire")
    print("====================================")
    print("1. Analyse réseau avec Nmap")
    print("2. Test d'exploitation avec Metasploit")
    print("3. Capture réseau avec Wireshark")
    print("4. Scan web avec OWASP ZAP")
    print("====================================")
    
    option = input("Choisissez une option : ")

    if option == "1":
        os.system("python3 scripts/nmap_scan.py")
    elif option == "2":
        os.system("python3 scripts/metasploit_runner.py")
    elif option == "3":
        os.system("python3 scripts/wireshark_capture.py")
    elif option == "4":
        os.system("python3 scripts/owasp_zap_scan.py")
    else:
        print("[!] Option invalide.")

if __name__ == "__main__":
    main()
