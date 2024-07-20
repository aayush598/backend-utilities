from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necessary for flashing messages

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login if user is not authenticated

DATABASE = 'database.db'

# Function to connect to the database
def connect_db():
    return sqlite3.connect(DATABASE)

# Function to create a table if it doesn't exist
def create_table():
    with connect_db() as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
        ''')

# Hashing function using hashlib
def hash_password(password):
    salt = os.urandom(16)
    pwd_salt = salt + password.encode('utf-8')
    pwd_hash = hashlib.pbkdf2_hmac('sha256', pwd_salt, salt, 100000)
    return salt.hex() + pwd_hash.hex()

# Function to verify password
def verify_password(stored_password, input_password):
    salt = bytes.fromhex(stored_password[:32])
    stored_hash = bytes.fromhex(stored_password[32:])
    pwd_salt = salt + input_password.encode('utf-8')
    input_hash = hashlib.pbkdf2_hmac('sha256', pwd_salt, salt, 100000)
    return stored_hash == input_hash

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

# Function to load a user
@login_manager.user_loader
def load_user(user_id):
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            return User(user[0], user[1])
        return None

# Route for login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            if user and verify_password(user[2], password):
                user_obj = User(user[0], user[1])
                login_user(user_obj)
                return redirect(url_for('profile'))
            flash('Invalid username or password')

    return render_template('login.html')

# Route for profile page (requires login)
@app.route('/profile')
@login_required
def profile():
    return render_template('success.html', username=current_user.username)

# Route for logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_table()  # Create table if it doesn't exist
    app.run(debug=True)
