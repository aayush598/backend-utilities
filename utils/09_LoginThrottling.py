from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hashlib
import sqlite3
import os

# require schema.sql

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necessary for flashing messages

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login if user is not authenticated

# Configure Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Database setup using sqlite3
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

@app.before_request
def initialize_db():
    """Ensure the database is initialized before each request."""
    with app.app_context():
        init_db()

class User(UserMixin):
    def __init__(self, id, username, email, password):
        self.id = id
        self.username = username
        self.email = email
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
    if user:
        return User(user['id'], user['username'], user['email'], user['password'])
    return None

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
    db = get_db()
    db.execute('INSERT INTO audit_log (user_id, action) VALUES (?, ?)', (user_id, action))
    db.commit()

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = hash_password(password)

        db = get_db()
        db.execute('INSERT INTO user (username, email, password) VALUES (?, ?, ?)',
                   (username, email, hashed_password))
        db.commit()

        flash('Registration successful. You can now log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per 15 minutes", override_defaults=False)
def login():
    """Handles user login. Displays the login form or processes login submissions."""
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()
        if user and verify_password(user['password'], password):
            login_user(User(user['id'], user['username'], user['email'], user['password']))
            log_audit_action(user['id'], 'Logged in')
            return redirect(url_for('profile'))
        else:
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
    db = get_db()
    logs = db.execute('SELECT * FROM audit_log ORDER BY timestamp DESC').fetchall()
    return render_template('audit_log.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)
