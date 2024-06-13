from flask import Flask, request, jsonify, render_template
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)

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
    text = data.get('text')
    algorithm = data.get('algorithm')
    
    if not text or not algorithm:
        return jsonify({"error": "Missing text or algorithm"}), 400

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

    return jsonify({"encrypted_text": encrypted_text})

# Custom error handler for 400 Bad Request
@app.errorhandler(400)
def bad_request_error(error):
    return jsonify({"error": "Bad request. Please check your input."}), 400

if __name__ == '__main__':
    app.run(debug=True)
