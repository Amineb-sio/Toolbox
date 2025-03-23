from flask import Flask, render_template, redirect, url_for

app = Flask(__name__)

# Remplacer localhost par l'adresse IP ou l'URL complète
base_url = "http://192.168.47.139"  # Remplacez par l'IP ou le nom de domaine si nécessaire

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/nmap')
def nmap():
    return redirect(f"{base_url}:5001/")  # Redirection vers le bon port

@app.route('/webmin')
def webmin():
    return redirect(f"{base_url}:5002/")  # Redirection vers le bon port

@app.route('/wireshark')
def wireshark():
    return redirect(f"{base_url}:5003/")  # Redirection vers le bon port

@app.route('/owasp')
def owasp():
    return redirect(f"{base_url}:5004/")  # Redirection vers le bon port

@app.route('/gobuster')
def gobuster():
    return redirect(f"{base_url}:5005/")  # Redirection vers le bon port

@app.route('/wpscan')
def wpscan():
    return redirect(f"{base_url}:5006/")  # Redirection vers le bon port

@app.route('/sqlmap')
def sqlmap():
    return redirect(f"{base_url}:5007/")  # Redirection vers le bon port

@app.route('/owaspdependencycheck')
def owaspdependencycheck():
    return redirect(f"{base_url}:5008/")  # Redirection vers le bon port

@app.route('/openvas')
def openvas():
    return redirect(f"{base_url}:5009/")  # Redirection vers le bon port

@app.route('/hydra')
def hydra():
    return redirect(f"{base_url}:5010/")  # Redirection vers le bon port

@app.route('/airodump-ng')
def airodump():
    return redirect(f"{base_url}:5011/")  # Redirection vers le bon port

@app.route('/aircrack-ng')
def aircrack():
    return redirect(f"{base_url}:5012/")  # Redirection vers le bon port

@app.route('/nikto')
def nikto():
    return redirect(f"{base_url}:5013/")  # Redirection vers le bon port

@app.route('/sslyze')
def sslyze():
    return redirect(f"{base_url}:5014/")  # Redirection vers le bon port

@app.route('/johntheripper')
def johntheripper():
    return redirect(f"{base_url}:5015/")  # Redirection vers le bon port

@app.route('/tcpdump')
def tcpdump():
    return redirect(f"{base_url}:5016/")

@app.route('/sherlock')
def sherlock():
    return redirect(f"{base_url}:5017/")  # Redirection vers le bon port

@app.route('/harvester')
def harvester():
    return redirect(f"{base_url}:5018/")

@app.route('/metagoofil')
def metagoofil():
    return redirect(f"{base_url}:5019/")

@app.route('/subfinder')
def subfinder():
    return redirect(f"{base_url}:5020/")

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
