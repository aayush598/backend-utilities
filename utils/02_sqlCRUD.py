import sqlite3

# Function to connect to the database
def connect_to_db(db_name):
    return sqlite3.connect(db_name)

# Create a table
def create_table(conn):
    with conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL
        )
        ''')

# Create a new user
def create_user(conn, username, email):
    with conn:
        conn.execute('INSERT INTO users (username, email) VALUES (?, ?)', (username, email))

# Read users from the database
def read_users(conn):
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    return cursor.fetchall()

# Update a user's email
def update_user_email(conn, user_id, new_email):
    with conn:
        conn.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, user_id))

# Delete a user
def delete_user(conn, user_id):
    with conn:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))

# Main function to demonstrate CRUD operations
def main():
    db_name = 'example.db'
    
    # Connect to the database
    conn = connect_to_db(db_name)
    
    # Create table
    create_table(conn)
    
    # Create users
    create_user(conn, 'john_doe', 'john@example.com')
    create_user(conn, 'jane_smith', 'jane@example.com')
    
    # Read users
    print("Users before update:")
    users = read_users(conn)
    for user in users:
        print(user)
    
    # Update a user's email
    update_user_email(conn, 1, 'john.doe@newdomain.com')
    
    # Read users again
    print("\nUsers after update:")
    users = read_users(conn)
    for user in users:
        print(user)
    
    # Delete a user
    delete_user(conn, 2)
    
    # Read users again
    print("\nUsers after deletion:")
    users = read_users(conn)
    for user in users:
        print(user)
    
    # Close the connection
    conn.close()

if __name__ == '__main__':
    main()
