import streamlit as st
import hashlib
import time
import os
import base64
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
DB_FILE = "secure_data.db"
FAILED_ATTEMPTS_LIMIT = 3
LOCKOUT_TIME = 60
SALT_LENGTH = 16

# --- SQLite Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS secure_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            data_id TEXT,
            encrypted_text TEXT,
            passkey TEXT,
            FOREIGN KEY(user_email) REFERENCES users(email)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Helper Functions ---
def hash_passkey(passkey, salt=None):
    if salt is None:
        return hashlib.sha256(passkey.encode()).hexdigest()
    else:
        passkey = passkey.encode()
        salt = salt.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(passkey).hex()

def get_fernet_key(passkey, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

def encrypt_data(text, passkey, salt):
    key = get_fernet_key(passkey, salt)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, salt):
    try:
        key = get_fernet_key(passkey, salt)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

def get_user(email):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    conn.close()
    return user

def register_user(email, password, salt):
    hashed_password = hash_passkey(password, salt)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (email, password, salt) VALUES (?, ?, ?)", (email, hashed_password, salt))
    conn.commit()
    conn.close()

def store_data(user_email, data_id, encrypted_text, hashed_passkey):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO secure_data (user_email, data_id, encrypted_text, passkey)
        VALUES (?, ?, ?, ?)
    ''', (user_email, data_id, encrypted_text, hashed_passkey))
    conn.commit()
    conn.close()

def is_locked_out(user_email):
    if user_email in st.session_state['failed_attempts'] and st.session_state['failed_attempts'][user_email]['count'] >= FAILED_ATTEMPTS_LIMIT:
        if time.time() < st.session_state['failed_attempts'][user_email]['lockout_end']:
            return True
    return False

def reset_failed_attempts(user_email):
    if user_email in st.session_state['failed_attempts']:
        del st.session_state['failed_attempts'][user_email]

# --- Initialization ---
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'user_email' not in st.session_state:
    st.session_state['user_email'] = None
if 'failed_attempts' not in st.session_state:
    st.session_state['failed_attempts'] = {}

# --- Streamlit UI ---
st.title("\U0001F512 Secure Data Encryption System")

menu = ["Home", "Login", "Register", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("\U0001F3E0 Welcome to the Secure Data System")
    st.write("Use this app to securely store and retrieve data using unique passkeys.")

elif choice == "Login":
    if not st.session_state['logged_in']:
        st.subheader("\U0001F511 User Login")
        login_email = st.text_input("Email")
        login_password = st.text_input("Password", type="password")
        if st.button("Submit Login"):
            user = get_user(login_email)
            if is_locked_out(login_email):
                st.error(f"\U0001F512 Too many failed attempts. Try again in {int(st.session_state['failed_attempts'][login_email]['lockout_end'] - time.time())} seconds.")
            elif user and user["password"] == hash_passkey(login_password, user["salt"]):
                st.session_state['logged_in'] = True
                st.session_state['user_email'] = login_email
                reset_failed_attempts(login_email)
                st.success(f"✅ Logged in as {login_email}")
            else:
                st.error("❌ Incorrect email or password")
                if login_email not in st.session_state['failed_attempts']:
                    st.session_state['failed_attempts'][login_email] = {'count': 0, 'lockout_end': 0}
                st.session_state['failed_attempts'][login_email]['count'] += 1
                if st.session_state['failed_attempts'][login_email]['count'] >= FAILED_ATTEMPTS_LIMIT:
                    st.session_state['failed_attempts'][login_email]['lockout_end'] = time.time() + LOCKOUT_TIME
                    st.warning(f"\U0001F512 Too many failed attempts. User {login_email} is locked out for {LOCKOUT_TIME} seconds.")
                else:
                    st.warning(f"❌ Incorrect credentials. Attempts: {st.session_state['failed_attempts'][login_email]['count']}/{FAILED_ATTEMPTS_LIMIT}")
    else:
        st.subheader("\U0001F44B Welcome!")
        st.write(f"Logged in as: {st.session_state['user_email']}")
        if st.button("Logout"):
            st.session_state['logged_in'] = False
            st.session_state['user_email'] = None
            st.success("\U0001F6AA Logged out")

elif choice == "Register":
    if not st.session_state['logged_in']:
        st.subheader("Register New User")
        new_email = st.text_input("New Email")
        new_password = st.text_input("New Password", type="password")
        if st.button("Register"):
            if new_email and new_password:
                if not get_user(new_email):
                    salt = os.urandom(SALT_LENGTH).hex()
                    register_user(new_email, new_password, salt)
                    st.success("✅ User registered successfully! Please log in.")
                else:
                    st.error("❌ Email already exists.")
            else:
                st.error("⚠️ Both fields are required.")
    else:
        st.warning("You are already logged in. Logout to register a new user.")

elif choice == "Store Data":
    if st.session_state['logged_in']:
        st.subheader("\U0001F4C2 Store Data Securely")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")
        if st.button("Encrypt & Save"):
            if user_data and passkey:
                user = get_user(st.session_state['user_email'])
                salt = user['salt']
                data_id = f"data_{int(time.time())}"
                hashed_passkey = hash_passkey(passkey, salt)
                encrypted = encrypt_data(user_data, passkey, salt)
                store_data(st.session_state['user_email'], data_id, encrypted, hashed_passkey)
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ Both fields are required!")
    else:
        st.warning("\U0001F512 Please log in to store data.")

elif choice == "Retrieve Data":
    if st.session_state['logged_in']:
        st.subheader("\U0001F50D Retrieve Your Data")
        encrypted_text = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password")
        if st.button("Decrypt"):
            if encrypted_text and passkey:
                user = get_user(st.session_state['user_email'])
                salt = user['salt']
                decrypted_text = decrypt_data(encrypted_text, passkey, salt)
                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data!")
            else:
                st.error("⚠️ Both fields are required!")
    else:
        st.warning("\U0001F512 Please log in to retrieve data.")
