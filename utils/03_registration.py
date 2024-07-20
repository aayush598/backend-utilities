from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Necessary for flashing messages

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
    salt = os.urandom(16)  # Generate a random salt
    pwd_salt = salt + password.encode('utf-8')
    pwd_hash = hashlib.pbkdf2_hmac('sha256', pwd_salt, salt, 100000)
    return salt.hex() + pwd_hash.hex()  # Store both salt and hash

# Function to verify password
def verify_password(stored_password, input_password):
    salt = bytes.fromhex(stored_password[:32])  # Extract the salt
    stored_hash = bytes.fromhex(stored_password[32:])  # Extract the hash
    pwd_salt = salt + input_password.encode('utf-8')
    input_hash = hashlib.pbkdf2_hmac('sha256', pwd_salt, salt, 100000)
    return stored_hash == input_hash

# Route for registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not username or not email or not password:
            flash('All fields are required!')
            return redirect(url_for('register'))

        hashed_password = hash_password(password)

        with connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                           (username, email, hashed_password))
            conn.commit()

        flash('You have successfully registered!')
        return redirect(url_for('success'))

    return render_template('register.html')

# Route for success page
@app.route('/success')
def success():
    return render_template('success.html')

if __name__ == '__main__':
    create_table()  # Create table if it doesn't exist
    app.run(debug=True)