Encryption Web Application
This is a web application built with Flask that allows users to encrypt text using various encryption algorithms such as Fernet, AES, DES, and RSA. It provides user authentication, CSRF protection, and a simple UI for encryption operations.

Features
User registration and login
Dashboard for text encryption
Encryption algorithms: Fernet, AES, DES, RSA
CSRF protection
Bootstrap-based UI
User-friendly and secure
Setup
Clone the repository:

bash
Copy code
git clone https://github.com/username/encryption-web-app.git
Install dependencies:

Copy code
pip install -r requirements.txt
Set up environment variables:

Create a .env file in the project root and add the following:

makefile
Copy code
SECRET_KEY=your_secret_key
DATABASE_URL=sqlite:///data.db
Initialize the database:

Copy code
python app.py
Run the application:

arduino
Copy code
flask run
Access the application at http://localhost:5000 in your web browser.

Technologies Used
Flask
SQLAlchemy
Flask-Login
Flask-WTF
Bootstrap
Jinja2
Cryptography (Fernet, AES, DES, RSA)
Contributing
Fork the repository.
Create a new branch (git checkout -b feature-name).
Make your changes.
Commit your changes (git commit -am 'Add new feature').
Push to the branch (git push origin feature-name).
Create a new Pull Request.
License
This project is licensed under the MIT License - see the LICENSE file for details.
