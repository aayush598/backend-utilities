"""
Flask application for user authentication and profile management.
"""


#  create seperate folder for init
# cd <folder>
# sphinx-quickstart
# change docs\source\conf.py
# change app.py
# change index.rst
# sphinx-build -b html source build
# output == index.html

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

def connect_db():
    """Connects to the database."""
    return sqlite3.connect(DATABASE)

def create_table():
    """Creates a table if it doesn't exist."""
    with connect_db() as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
        ''')

def hash_password(password):
    """Hashes the given password with a salt."""
    salt = os.urandom(16)
    pwd_salt = salt + password.encode('utf-8')
    pwd_hash = hashlib.pbkdf2_hmac('sha256', pwd_salt, salt, 100000)
    return salt.hex() + pwd_hash.hex()

def verify_password(stored_password, input_password):
    """Verifies the given password against the stored hash."""
    salt = bytes.fromhex(stored_password[:32])
    stored_hash = bytes.fromhex(stored_password[32:])
    pwd_salt = salt + input_password.encode('utf-8')
    input_hash = hashlib.pbkdf2_hmac('sha256', pwd_salt, salt, 100000)
    return stored_hash == input_hash

class User(UserMixin):
    """User class for Flask-Login."""
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database by ID."""
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            return User(user[0], user[1])
        return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
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

@app.route('/profile')
@login_required
def profile():
    """Displays the user's profile page."""
    return render_template('profile.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_table()  # Create table if it doesn't exist
    app.run(debug=True)
