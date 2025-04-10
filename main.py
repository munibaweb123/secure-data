import streamlit as st
import hashlib
import json
import time
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
DATA_FILE = "data.json"
USERS_FILE = "users.json"
FAILED_ATTEMPTS_LIMIT = 3
LOCKOUT_TIME = 60
SALT_LENGTH = 16

# --- Helper Functions ---
def load_data(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return json.load(f)
    return {}

def save_data(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

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

users = load_data(USERS_FILE)
stored_data = load_data(DATA_FILE)

# --- Streamlit UI ---
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Login", "Register", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# Page content
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to securely store and retrieve data using unique passkeys.")

elif choice == "Login":
    if not st.session_state['logged_in']:
        st.subheader("🔑 User Login")
        login_email = st.text_input("Email")
        login_password = st.text_input("Password", type="password")
        if st.button("Submit Login"):
            if is_locked_out(login_email):
                st.error(f"🔒 Too many failed attempts. Try again in {int(st.session_state['failed_attempts'][login_email]['lockout_end'] - time.time())} seconds.")
            elif login_email in users and users[login_email]["password"] == hash_passkey(login_password, users[login_email]["salt"]):
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
                    st.warning(f"🔒 Too many failed attempts. User {login_email} is locked out for {LOCKOUT_TIME} seconds.")
                else:
                    st.warning(f"❌ Incorrect credentials. Attempts: {st.session_state['failed_attempts'][login_email]['count']}/{FAILED_ATTEMPTS_LIMIT}")
    else:
        st.subheader("👋 Welcome!")
        st.write(f"Logged in as: {st.session_state['user_email']}")
        if st.button("Logout"):
            st.session_state['logged_in'] = False
            st.session_state['user_email'] = None
            st.success("🚪 Logged out")

elif choice == "Register":
    if not st.session_state['logged_in']:
        st.subheader("Register New User")
        new_email = st.text_input("New Email")
        new_password = st.text_input("New Password", type="password")
        if st.button("Register"):
            if new_email and new_password:
                if new_email not in users:
                    salt = os.urandom(SALT_LENGTH).hex()
                    hashed_password = hash_passkey(new_password, salt)
                    users[new_email] = {"password": hashed_password, "salt": salt}
                    save_data(USERS_FILE, users)
                    st.success("✅ User registered successfully! Please log in.")
                else:
                    st.error("❌ Email already exists.")
            else:
                st.error("⚠️ Both fields are required.")
    else:
        st.warning("You are already logged in. Logout to register a new user.")

elif choice == "Store Data":
    if st.session_state['logged_in']:
        st.subheader("📂 Store Data Securely")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")
        if st.button("Encrypt & Save"):
            if user_data and passkey:
                data_id = f"data_{len(stored_data.get(st.session_state['user_email'], {}))}"
                user_salt = users[st.session_state['user_email']]["salt"]
                hashed_passkey = hash_passkey(passkey, user_salt)
                encrypted_text = encrypt_data(user_data, passkey, user_salt)
                if st.session_state['user_email'] not in stored_data:
                    stored_data[st.session_state['user_email']] = {}
                stored_data[st.session_state['user_email']][data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                save_data(DATA_FILE, stored_data)
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ Both fields are required!")
    else:
        st.warning("🔒 Please log in to store data.")

elif choice == "Retrieve Data":
    if st.session_state['logged_in']:
        st.subheader("🔍 Retrieve Your Data")
        encrypted_text = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password")
        if st.button("Decrypt"):
            if encrypted_text and passkey:
                user_salt = users[st.session_state['user_email']]["salt"]
                decrypted_text = decrypt_data(encrypted_text, passkey, user_salt)
                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data!")
            else:
                st.error("⚠️ Both fields are required!")
    else:
        st.warning("🔒 Please log in to retrieve data.")
