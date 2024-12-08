import streamlit as st
import re
from cryptography.fernet import Fernet
import hashlib

# Global key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Streamlit App
st.title("Cybersecurity Toolkit")
st.markdown("A multifunction app for encryption, decryption, password strength checking, and hash generation/verification.")

# Sidebar menu
feature = st.sidebar.selectbox("Choose a feature:", ["Password Strength Checker", "Encryption and Decryption", "Hash Generator and Verifier"])

# Password Strength Checker
if feature == "Password Strength Checker":
    st.header("Password Strength Checker")
    password = st.text_input("Enter your password:", type="password")
    
    def check_password_strength(password):
        score = 0
        if len(password) >= 8: score += 1
        if re.search(r"[A-Z]", password): score += 1
        if re.search(r"[a-z]", password): score += 1
        if re.search(r"[0-9]", password): score += 1
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1
        return "Weak" if score < 3 else "Moderate" if score == 3 else "Strong"
    
    if password:
        strength = check_password_strength(password)
        if strength == "Weak":
            st.error(f"Password Strength: {strength}")
        elif strength == "Moderate":
            st.warning(f"Password Strength: {strength}")
        else:
            st.success(f"Password Strength: {strength}")
    else:
        st.info("Enter a password to evaluate its strength.")

# Encryption and Decryption
elif feature == "Encryption and Decryption":
    st.header("Text Encryption and Decryption")
    mode = st.selectbox("Choose an action:", ["Encrypt", "Decrypt"])
    text = st.text_area("Enter the text:")
    
    st.markdown("### Encryption Key")
    st.code(key.decode())
    
    if mode == "Encrypt":
        if st.button("Encrypt"):
            if text:
                encrypted_text = cipher_suite.encrypt(text.encode())
                st.success("Encrypted Text:")
                st.code(encrypted_text.decode())
            else:
                st.error("Please enter text to encrypt.")
    elif mode == "Decrypt":
        decryption_key = st.text_input("Enter the encryption key:", key.decode())
        if st.button("Decrypt"):
            if text and decryption_key:
                try:
                    decryption_cipher = Fernet(decryption_key.encode())
                    decrypted_text = decryption_cipher.decrypt(text.encode()).decode()
                    st.success("Decrypted Text:")
                    st.code(decrypted_text)
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
            else:
                st.error("Please provide both text and a valid encryption key.")

# Hash Generator and Verifier
elif feature == "Hash Generator and Verifier":
    st.header("Hash Generator and Verifier")
    mode = st.selectbox("Choose an action:", ["Generate Hash", "Verify Hash"])
    
    if mode == "Generate Hash":
        input_text = st.text_area("Enter the text to hash:")
        if st.button("Generate"):
            if input_text:
                hash_object = hashlib.sha256(input_text.encode())
                hash_value = hash_object.hexdigest()
                st.success("Generated Hash:")
                st.code(hash_value)
            else:
                st.error("Please enter some text to hash.")
    
    elif mode == "Verify Hash":
        input_text = st.text_area("Enter the text to hash:")
        provided_hash = st.text_input("Enter the hash to verify:")
        if st.button("Verify"):
            if input_text and provided_hash:
                hash_object = hashlib.sha256(input_text.encode())
                calculated_hash = hash_object.hexdigest()
                if calculated_hash == provided_hash:
                    st.success("The hash matches! Integrity verified.")
                else:
                    st.error("The hash does not match. Data integrity compromised.")
            else:
                st.error("Please provide both text and a hash to verify.")
