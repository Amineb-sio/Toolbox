from flask import Flask, render_template, request, jsonify
import subprocess

app = Flask(__name__)

def run_john(target):
    try:
        command = f"john --wordlist=/usr/share/wordlists/rockyou.txt {target}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

def create_user(password, filename):
    try:
        command = ["mkpasswd", "-m", "md5crypt", password]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, error = process.communicate()
        if process.returncode == 0:
            with open(filename, 'w') as file:
                file.write(output)
            return f"User hash saved in {filename}: {output.strip()}"
        else:
            return f"Error: {error}"
    except Exception as e:
        return str(e)

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>John the Ripper Toolbox</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #222; color: #ddd; }
            input, button { margin: 10px; padding: 10px; background-color: #444; color: white; border: none; }
            button { cursor: pointer; }
            #result, #createResult { margin-top: 20px; padding: 10px; border: 1px solid #555; background-color: #333; }
        </style>
    </head>
    <body>
        <h1>John the Ripper Toolbox</h1>
        <h2>Crack a Hash</h2>
        <form id="crackForm">
            <label for="target">Hash File:</label>
            <input type="text" id="target" name="target" required>
            <button type="submit">Crack</button>
        </form>
        <div id="result"></div>
       
        <h2>Create a User Hash</h2>
        <form id="createForm">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
            <label for="filename">Filename:</label>
            <input type="text" id="filename" name="filename" required>
            <button type="submit">Create</button>
        </form>
        <div id="createResult"></div>
       
        <script>
            document.querySelector('#crackForm').addEventListener('submit', function(event) {
                event.preventDefault();
                let target = document.getElementById('target').value;
                document.getElementById('result').innerHTML = 'Cracking...';
                fetch('/crack', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'target=' + encodeURIComponent(target)
                })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('result').innerHTML = '<pre>' + data.result + '</pre>';
                })
                .catch(error => {
                    document.getElementById('result').innerHTML = 'Error: ' + error;
                });
            });
           
            document.querySelector('#createForm').addEventListener('submit', function(event) {
                event.preventDefault();
                let password = document.getElementById('password').value;
                let filename = document.getElementById('filename').value;
                document.getElementById('createResult').innerHTML = 'Creating hash...';
                fetch('/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'password=' + encodeURIComponent(password) + '&filename=' + encodeURIComponent(filename)
                })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('createResult').innerHTML = '<pre>' + data.result + '</pre>';
                })
                .catch(error => {
                    document.getElementById('createResult').innerHTML = 'Error: ' + error;
                });
            });
        </script>
    </body>
    </html>
    '''

@app.route('/crack', methods=['POST'])
def crack():
    target = request.form.get('target')
    if not target:
        return jsonify({"error": "No hash file specified"}), 400
   
    result = run_john(target)
    return jsonify({"result": result})

@app.route('/create', methods=['POST'])
def create():
    password = request.form.get('password')
    filename = request.form.get('filename')
    if not password or not filename:
        return jsonify({"error": "Password and filename are required"}), 400
   
    result = create_user(password, filename)
    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5015, debug=True)
