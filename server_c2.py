from flask import Flask, request, jsonify
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Konfigurasi folder untuk menyimpan file yang diupload
UPLOAD_FOLDER = '/home/cape/c2_server/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return 'File uploaded successfully', 200

if __name__ == '__main__':
    print(f"[*] Server C2 berjalan di http://0.0.0.0:8888")
    print(f"[*] File akan disimpan di: {UPLOAD_FOLDER}")
    # Gunakan 0.0.0.0 agar bisa diakses dari luar
    app.run(host='0.0.0.0', port=8888, debug=True)