#!/usr/bin/env python3
import os
import subprocess

def nmap_scan(target):
    print(f"[*] Lancement de l'analyse Nmap sur la cible : {target}")
    try:
        result = subprocess.run(
            ["nmap", "-sS", "-sV", "-O", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(result.stdout)
        with open("nmap_scan_results.txt", "w") as file:
            file.write(result.stdout)
    except Exception as e:
        print(f"[!] Erreur lors de l'exécution de Nmap : {e}")

if __name__ == "__main__":
    target = input("Entrez la cible à analyser (ex : 192.168.1.1) : ")
    nmap_scan(target)
