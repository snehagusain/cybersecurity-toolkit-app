# Cybersecurity Toolkit

## Overview
A multipurpose cybersecurity app with the following features:
1. **Password Strength Checker**: Evaluates the strength of a password based on common security criteria.
2. **Encryption and Decryption**: Provides text encryption and decryption using the Fernet symmetric encryption algorithm.
3. **Hash Generator and Verifier**: Allows users to generate SHA-256 hashes and verify them for data integrity.

## Features
### 1. Password Strength Checker
- Checks password length, use of uppercase, lowercase, numbers, and special characters.
- Classifies passwords as Weak, Moderate, or Strong.

### 2. Encryption and Decryption
- **Encryption**: Secures text using a randomly generated symmetric key.
- **Decryption**: Recovers encrypted text using the correct key.

### 3. Hash Generator and Verifier
- **Generate Hash**: Creates a SHA-256 hash for any input text.
- **Verify Hash**: Confirms whether a given hash matches the input text.

## Installation
Follow these steps to set up and run the project:

1. Clone the repository:
   ```bash
   git clone https://github.com/snehagusain/cybersecurity-toolkit-app
   ```
2. Navigate to the project directory:
   ```bash
   cd cybersecurity-toolkit-app
   ```
3. Create a virtual environment:
   ```bash
   python -m venv venv
   ```
4. Activate the virtual environment:
   - **Windows**:
     ```bash
     venv\Scripts\activate
     ```
   - **macOS/Linux**:
     ```bash
     source venv/bin/activate
     ```
5. Install system dependencies for Pillow (if required):
   - **Ubuntu/Debian**:
     ```bash
     sudo apt update
     sudo apt install libjpeg-dev zlib1g-dev
     ```
   - **Fedora/RHEL**:
     ```bash
     sudo dnf install libjpeg-devel zlib-devel
     ```
   - **macOS**:
     ```bash
     brew install jpeg zlib
     ```
   - **Windows**: Ensure the latest version of Python is installed and run:
     ```bash
     pip install --upgrade pip
     pip install Pillow
     ```

6. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

7. Run the Streamlit app:
   ```bash
   streamlit run app.py
   ```

## Usage
1. Open the app in your browser (the terminal will display a link).
2. Choose a feature from the sidebar:
   - Password Strength Checker
   - Encryption and Decryption
   - Hash Generator and Verifier
3. Follow the instructions for the selected feature.

## Troubleshooting
- If Pillow installation fails, ensure system dependencies for JPEG and zlib are installed. Follow the steps under **Install system dependencies for Pillow**.
- Verify Pillow installation with:
  ```bash
  python -c "from PIL import Image; print('Pillow installed successfully')"
  ```

## Use Cases
- Evaluate password security.
- Encrypt and decrypt sensitive text data.
- Verify file or data integrity.

## License
This project is licensed under the MIT License.
