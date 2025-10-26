import os
from cryptography.fernet import Fernet

# This block will attempt to load the key when the file is imported by app.py.
# It will fail with an error if the key isn't set, which is the desired behavior.
try:
    ENCRYPTION_KEY = os.environ["ENCRYPTION_KEY"].encode()
    fernet = Fernet(ENCRYPTION_KEY)
except KeyError:
    # This error is expected if you run this file directly to generate a key.
    # We set fernet to None and the main app will fail if it tries to use it.
    fernet = None

def encrypt_data(data: str) -> str:
    """Encrypts a string and returns it as a string."""
    if fernet is None:
        raise RuntimeError("Encryption key not loaded. Ensure ENCRYPTION_KEY environment variable is set.")
    if not data:
        return ""
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypts an encrypted string and returns it."""
    if fernet is None:
        raise RuntimeError("Encryption key not loaded. Ensure ENCRYPTION_KEY environment variable is set.")
    if not encrypted_data:
        return ""
    try:
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return "[Decryption Error]"

# This block only runs when you execute `python encryption_utils.py` directly.
# Its only purpose is to generate and display a new key.
if __name__ == '__main__':
    new_key = Fernet.generate_key()
    print("--- Generated Encryption Key ---")
    print("Copy the key and the command below to set it in your terminal.")
    print("\nFor PowerShell (run this in your current terminal):")
    print(f'$env:ENCRYPTION_KEY="{new_key.decode()}"')
    print("\nFor Command Prompt (for the current session):")
    print(f'set ENCRYPTION_KEY={new_key.decode()}')
    print("\n---")
    print("You must set this variable before running 'python setup_admin.py' or 'python app.py'")