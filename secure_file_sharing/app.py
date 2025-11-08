import os
from flask import Flask, render_template, request, send_file, abort
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from werkzeug.utils import secure_filename
import io
import base64

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

KEY_BASE64 = os.getenv('FILE_KEY_BASE64')
if not KEY_BASE64:
    raise RuntimeError("Set FILE_KEY_BASE64 environment variable (base64-encoded key).")
KEY = base64.b64decode(KEY_BASE64)  

BLOCK_SIZE = 16

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padding")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def encrypt_and_mac(plaintext: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext))
    
    h = HMAC.new(KEY, digestmod=SHA256)
    h.update(iv + ct)
    tag = h.digest()
    
    return iv + tag + ct

def verify_and_decrypt(stored: bytes) -> bytes:
    if len(stored) < 16 + 32:
        raise ValueError("Stored blob too short")
    iv = stored[:16]
    tag = stored[16:48]
    ct = stored[48:]
    h = HMAC.new(KEY, digestmod=SHA256)
    h.update(iv + ct)
    try:
        h.verify(tag)
    except ValueError:
        raise ValueError("HMAC verification failed — file may be tampered")
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    return pkcs7_unpad(pt_padded)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    filename = secure_filename(file.filename)
    data = file.read()
    encrypted_blob = encrypt_and_mac(data)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
    with open(save_path, 'wb') as f:
        f.write(encrypted_blob)
    return f"File '{filename}' uploaded and encrypted successfully!", 200

@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename', '')
    if not filename:
        return "No filename specified", 400
    filename = secure_filename(filename)
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
    if not os.path.exists(enc_path):
        return f"File '{filename}' not found", 404
    with open(enc_path, 'rb') as f:
        stored = f.read()
    try:
        plaintext = verify_and_decrypt(stored)
    except ValueError as e:
        return str(e), 400
    
    buf = io.BytesIO(plaintext)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(debug=True)
