from flask import Flask, render_template, redirect, url_for

app = Flask(__name__)

# Remplacer localhost par l'adresse IP ou l'URL complète
base_url = "http://192.168.47.128"  # Remplacez par l'IP ou le nom de domaine si nécessaire

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/nmap')
def nmap():
    return redirect(f"{base_url}:5001")  # Utilisation de l'IP et du port

@app.route('/webmin')
def webmin():
    return redirect(f"{base_url}:5002")  # Utilisation de l'IP et du port

@app.route('/wireshark')
def wireshark():
    return redirect(f"{base_url}:5003")  # Utilisation de l'IP et du port

@app.route('/owasp')
def owasp():
    return redirect(f"{base_url}:5004")  # Utilisation de l'IP et du port

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
