# Account Credentials Management System Database Backend
# Stores email, host website, password, and date information

import sqlite3
import datetime
import base64
from cryptography.fernet import Fernet
import os

def create_table():
    """Create the credentials table if it doesn't exist"""
    con = sqlite3.connect("credentials.db")
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS credentials(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    host_website TEXT NOT NULL,
                    password TEXT NOT NULL,
                    date_created TEXT NOT NULL,
                    date_modified TEXT NOT NULL
                )""")
    con.commit()
    con.close()

# Account Credentials Management System Database Backend
# Stores email, host website, password, and date information

import sqlite3
import datetime
import base64
from cryptography.fernet import Fernet
import os

# Global encryption key - in production, this should be derived from a master password
ENCRYPTION_KEY_FILE = "encryption.key"

def get_or_create_key():
    """Get existing encryption key or create a new one"""
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    return key

def encrypt_password(password):
    """Encrypt password for secure storage"""
    key = get_or_create_key()
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return base64.urlsafe_b64encode(encrypted_password).decode()

def decrypt_password(encrypted_password):
    """Decrypt password for viewing"""
    try:
        key = get_or_create_key()
        fernet = Fernet(key)
        decoded_password = base64.urlsafe_b64decode(encrypted_password.encode())
        decrypted_password = fernet.decrypt(decoded_password)
        return decrypted_password.decode()
    except Exception as e:
        return f"Error decrypting password: {str(e)}"

def add_credential(email, host_website, password):
    """Add a new credential entry"""
    con = sqlite3.connect("credentials.db")
    cur = con.cursor()
    
    encrypted_password = encrypt_password(password)
    current_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cur.execute("INSERT INTO credentials (email, host_website, password, date_created, date_modified) VALUES (?, ?, ?, ?, ?)",
                (email, host_website, encrypted_password, current_date, current_date))
    con.commit()
    con.close()
    return True

def view_all_credentials():
    """View all stored credentials (passwords will be masked)"""
    con = sqlite3.connect("credentials.db")
    cur = con.cursor()
    cur.execute("SELECT id, email, host_website, date_created, date_modified FROM credentials")
    rows = cur.fetchall()
    con.close()
    return rows

def search_credentials(email="", host_website=""):
    """Search for credentials by email or website"""
    con = sqlite3.connect("credentials.db")
    cur = con.cursor()
    
    if email and host_website:
        cur.execute("SELECT id, email, host_website, date_created, date_modified FROM credentials WHERE email LIKE ? AND host_website LIKE ?",
                   (f"%{email}%", f"%{host_website}%"))
    elif email:
        cur.execute("SELECT id, email, host_website, date_created, date_modified FROM credentials WHERE email LIKE ?",
                   (f"%{email}%",))
    elif host_website:
        cur.execute("SELECT id, email, host_website, date_created, date_modified FROM credentials WHERE host_website LIKE ?",
                   (f"%{host_website}%",))
    else:
        cur.execute("SELECT id, email, host_website, date_created, date_modified FROM credentials")
    
    rows = cur.fetchall()
    con.close()
    return rows

def get_password(credential_id, master_password=""):
    """Get the actual decrypted password for a credential"""
    con = sqlite3.connect("credentials.db")
    cur = con.cursor()
    cur.execute("SELECT password FROM credentials WHERE id = ?", (credential_id,))
    result = cur.fetchone()
    con.close()
    
    if result:
        encrypted_password = result[0]
        return decrypt_password(encrypted_password)
    return None

def update_credential(credential_id, email=None, host_website=None, password=None):
    """Update an existing credential"""
    con = sqlite3.connect("credentials.db")
    cur = con.cursor()
    
    current_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if email:
        cur.execute("UPDATE credentials SET email = ?, date_modified = ? WHERE id = ?",
                   (email, current_date, credential_id))
    if host_website:
        cur.execute("UPDATE credentials SET host_website = ?, date_modified = ? WHERE id = ?",
                   (host_website, current_date, credential_id))
    if password:
        encrypted_password = encrypt_password(password)
        cur.execute("UPDATE credentials SET password = ?, date_modified = ? WHERE id = ?",
                   (encrypted_password, current_date, credential_id))
    
    con.commit()
    con.close()

def delete_credential(credential_id):
    """Delete a credential by ID"""
    con = sqlite3.connect("credentials.db")
    cur = con.cursor()
    cur.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
    con.commit()
    con.close()

def get_credential_by_id(credential_id):
    """Get full credential details by ID"""
    con = sqlite3.connect("credentials.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,))
    result = cur.fetchone()
    con.close()
    return result

# Initialize the database
create_table()