import streamlit as st
import hashlib
from datetime import datetime

# In-memory storage
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = {}
if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = True
if 'current_user' not in st.session_state:
    st.session_state.current_user = None

# Caesar Cipher functions
def caesar_encrypt(text, shift=3):
    encrypted = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            encrypted += chr((ord(char) + shift - shift_base) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

# Hash passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Check authentication status
def check_authentication():
    if not st.session_state.is_authenticated:
        st.warning("Please log in to continue.")
        login_page()
        return False
    return True

# Home Page
def home_page():
    st.title("Secure Data Storage")
    st.write("Welcome to the secure data storage system.")
    option = st.selectbox("Choose an action:", ["Insert Data", "Retrieve Data"])
    if option == "Insert Data":
        insert_data_page()
    elif option == "Retrieve Data":
        retrieve_data_page()

# Insert Data Page
def insert_data_page():
    st.header("Insert Data")
    user_id = st.text_input("User ID")
    text = st.text_area("Text to encrypt")
    passkey = st.text_input("Passkey", type="password")
    
    if st.button("Store Data"):
        if user_id and text and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = caesar_encrypt(text)
            st.session_state.stored_data[user_id] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.session_state.failed_attempts[user_id] = 0
            st.success("Data stored successfully!")
        else:
            st.error("Please fill in all fields.")

# Retrieve Data Page
def retrieve_data_page():
    st.header("Retrieve Data")
    user_id = st.text_input("User ID")
    passkey = st.text_input("Passkey", type="password")
    
    if st.button("Retrieve Data"):
        if user_id in st.session_state.stored_data:
            user_data = st.session_state.stored_data[user_id]
            hashed_passkey = hash_passkey(passkey)
            
            if user_data["passkey"] == hashed_passkey:
                decrypted_text = caesar_decrypt(user_data["encrypted_text"])
                st.success("Data retrieved successfully!")
                st.write("Decrypted Text:", decrypted_text)
                st.session_state.failed_attempts[user_id] = 0
            else:
                st.session_state.failed_attempts[user_id] = st.session_state.failed_attempts.get(user_id, 0) + 1
                attempts_left = 3 - st.session_state.failed_attempts[user_id]
                st.error(f"Incorrect passkey. {attempts_left} attempts remaining.")
                
                if st.session_state.failed_attempts[user_id] >= 3:
                    st.session_state.is_authenticated = False
                    st.session_state.current_user = user_id
                    st.error("Too many failed attempts. Please reauthorize.")
                    login_page()
        else:
            st.error("User ID not found.")

# Login Page
def login_page():
    st.header("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        # Simple login check (in real-world, use proper authentication)
        if username and password:
            st.session_state.is_authenticated = True
            if st.session_state.current_user:
                st.session_state.failed_attempts[st.session_state.current_user] = 0
            st.success("Logged in successfully!")
            home_page()
        else:
            st.error("Please enter valid credentials.")

# Main app logic
def main():
    if check_authentication():
        home_page()

if __name__ == "__main__":
    main()