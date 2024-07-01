from flask import Flask, render_template, request, redirect, url_for, flash
import requests
import os

app = Flask(__name__)
app.secret_key = '10'

API_KEY = 'b7d66f5e5363d62a30d3c828e01dfb70cb22aafdbf5912114fd795d40e31503a'

def analyze_file(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': API_KEY}
    files = {'file': (file_path, open(file_path, 'rb'))}
    response = requests.post(url, files=files, params=params)
    result = response.json()
    return result

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file:
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)
        result = analyze_file(file_path)
        os.remove(file_path)
        if result['response_code'] == 1:
            flash(f"File is safe. Scan ID: {result['scan_id']}")
        else:
            flash("File is not safe or analysis failed.")
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
