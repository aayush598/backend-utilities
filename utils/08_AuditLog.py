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
    """Connects to the SQLite database specified by DATABASE."""
    return sqlite3.connect(DATABASE)

def create_tables():
    """Creates the necessary tables if they don't exist."""
    with connect_db() as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
        ''')
        conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        ''')

def hash_password(password):
    """Hashes the given password with a salt for secure storage."""
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

def log_audit_action(user_id, action):
    """Logs an action performed by a user."""
    with connect_db() as conn:
        conn.execute('''
        INSERT INTO audit_log (user_id, action)
        VALUES (?, ?)
        ''', (user_id, action))

class User(UserMixin):
    """User class for Flask-Login integration."""
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database by their ID."""
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            return User(user[0], user[1])
        return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = hash_password(password)

        with connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                           (username, email, hashed_password))
            conn.commit()
        flash('Registration successful. You can now log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login. Displays the login form or processes login submissions."""
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
                log_audit_action(user[0], 'Logged in')
                return redirect(url_for('profile'))
            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    """Displays the user's profile page. Requires user to be logged in."""
    return render_template('profile.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user and redirects to the login page."""
    user_id = current_user.id
    logout_user()
    log_audit_action(user_id, 'Logged out')
    return redirect(url_for('login'))

@app.route('/admin/audit-log')
@login_required
def view_audit_log():
    """Displays the audit log to admins."""
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM audit_log ORDER BY timestamp DESC')
        logs = cursor.fetchall()

    return render_template('audit_log.html', logs=logs)

if __name__ == '__main__':
    create_tables()  # Create necessary tables if they don't exist
    app.run(debug=True)
