from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class EncryptedText(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    encrypted_text = db.Column(db.Text, nullable=False)
    algorithm = db.Column(db.String(50), nullable=False)
    user = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# Generate keys for encryption algorithms
fernet_key = Fernet.generate_key()
fernet_cipher = Fernet(fernet_key)

aes_key = get_random_bytes(16)
des_key = get_random_bytes(8)

rsa_key = RSA.generate(2048)
rsa_cipher = PKCS1_OAEP.new(rsa_key)

def encrypt_fernet(text):
    return fernet_cipher.encrypt(text.encode()).decode()

def encrypt_aes(text):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def encrypt_des(text):
    cipher = DES.new(des_key, DES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def encrypt_rsa(text):
    ciphertext = rsa_cipher.encrypt(text.encode())
    return base64.b64encode(ciphertext).decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_text():
    data = request.json
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data received"}), 400
    text = data.get('text')
    algorithm = data.get('algorithm')
    user = data.get('user')
    if not text or not algorithm or not user:
        return jsonify({"error": "Missing text, algorithm, or user"}), 400

    if algorithm == "fernet":
        encrypted_text = encrypt_fernet(text)
    elif algorithm == "aes":
        encrypted_text = encrypt_aes(text)
    elif algorithm == "des":
        encrypted_text = encrypt_des(text)
    elif algorithm == "rsa":
        encrypted_text = encrypt_rsa(text)
    else:
        return jsonify({"error": "Unsupported algorithm"}), 400

    # Store encrypted text in the database
    encrypted_data = EncryptedText(text=text, encrypted_text=encrypted_text, algorithm=algorithm, user=user)
    db.session.add(encrypted_data)
    db.session.commit()

    return jsonify({"encrypted_text": encrypted_text, "user": user, "timestamp": encrypted_data.timestamp})

# Custom error handler for 400 Bad Request
@app.errorhandler(400)
def bad_request_error(error):
    return jsonify({"error": "Bad request. Please check your input."}), 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
