from flask import Flask, render_template, request
import subprocess
import time
import re
from urllib.parse import urljoin, urlparse  # Pour mieux gérer les redirections

app = Flask(__name__)

# Signification des codes HTTP
http_status_meanings = {
    "200": "OK (Accessible)",
    "301": "Redirection Permanente",
    "302": "Redirection Temporaire",
    "403": "Interdit",
    "404": "Non Trouvé",
    "500": "Erreur Serveur"
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run_gobuster', methods=['GET'])
def run_gobuster():
    url = request.args.get('url')  # URL de base entrée par l'utilisateur
    wordlist = request.args.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
    
    if not url:
        return "<pre style='color:red;'>❌ Erreur : Veuillez spécifier une URL.</pre>"
    
    # Assurer que l'URL fournie commence bien par http:// ou https://
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    command = [
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist
    ]
    
    try:
        start_time = time.time()
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        execution_time = round(time.time() - start_time, 2)
        
        formatted_results = []
        for line in result.stdout.split("\n"):
            # Correction de l'expression régulière pour capturer correctement les résultats de gobuster
            match = re.search(r"/(\S+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\](?:\s+\[-->\s+(http://[^\]]+))?", line)
            if match:
                path_raw = match.group(1)
                status = match.group(2)
                size = match.group(3)
                redirect_url = match.group(4) if len(match.groups()) > 3 else None
                
                path = "/" + path_raw
                
                # Créer le lien clickable
                if redirect_url:
                    # Si une redirection existe, on prend l'URL de base (pas localhost)
                    # Assure que l'URL complète est formée avec l'URL de base fournie par l'utilisateur
                    full_redirect_url = urljoin(url, redirect_url)  # Utilisation de l'IP de l'utilisateur ici
                    
                    # Corriger la redondance du "http://"
                    parsed_url = urlparse(full_redirect_url)
                    if parsed_url.scheme == 'http' or parsed_url.scheme == 'https':
                        full_redirect_url = parsed_url.geturl()  # Utiliser l'URL correctement formatée
                else:
                    # Sinon, on ajoute le chemin relatif à l'URL de base fournie
                    full_redirect_url = url.rstrip('/') + path
                
                # Force l'utilisation de l'IP/URL de base (évite "localhost")
                if 'localhost' in full_redirect_url:
                    full_redirect_url = full_redirect_url.replace('localhost', url)
                
                formatted_results.append({
                    "path": path,
                    "full_url": full_redirect_url,  # Utilisation de l'URL correcte
                    "status": status,
                    "meaning": http_status_meanings.get(status, "Inconnu"),
                    "size": size,
                    "has_redirect": redirect_url is not None
                })
        
        return render_template('result.html', results=formatted_results, execution_time=execution_time, url=url)
    
    except subprocess.CalledProcessError as e:
        return f"<pre style='color:red;'>❌ Erreur lors de l'exécution de Gobuster : {e}</pre>"

if __name__ == '__main__':
    print("🚀 Serveur lancé sur http://0.0.0.0:5005")
    app.run(debug=True, host='0.0.0.0', port=5005)
