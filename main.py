from flask import Flask, render_template, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/webmin')
def webmin():
    return redirect("http://localhost:5001")

@app.route('/wireshark')
def wireshark():
    return redirect("http://localhost:5002")

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
