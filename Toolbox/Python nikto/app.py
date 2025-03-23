from flask import Flask, render_template, request
import subprocess
import time
import os

app = Flask(__name__)

def run_nikto(target_url):
    try:
        start_time = time.time()
        # Exécution de la commande Nikto
        command = ["nikto", "-h", target_url]
        result = subprocess.run(command, capture_output=True, text=True)
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        return result.stdout, scan_time
    except Exception as e:
        return str(e), 0

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    scan_result, scan_time = run_nikto(target)
    return render_template('index.html', result=scan_result, scan_time=scan_time)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5013, debug=True)
