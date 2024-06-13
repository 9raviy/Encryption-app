from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Encryption keys
key = Fernet.generate_key()
cipher = Fernet(key)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Encryption functions
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

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'error')
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('Logout successful', 'success')
    return redirect(url_for('login'))  # Redirect to login page

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        text = request.form.get('text')
        algorithm = request.form.get('algorithm')
        user = current_user.username  # Assuming username is used for encryption
        if algorithm == 'fernet':
            encrypted_text = cipher.encrypt(text.encode()).decode()
        elif algorithm == 'aes':
            encrypted_text = encrypt_aes(text)
        elif algorithm == 'des':
            encrypted_text = encrypt_des(text)
        elif algorithm == 'rsa':
            encrypted_text = encrypt_rsa(text)
        else:
            encrypted_text = f"Encryption not implemented for {algorithm}"
        flash('Encryption successful', 'success')
        return render_template('dashboard.html', encrypted_text=encrypted_text)
    return render_template('dashboard.html')

@app.errorhandler(400)
def bad_request_error(error):
    return jsonify({"error": "Bad request. Please check your input."}), 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
