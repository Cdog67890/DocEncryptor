import os
import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import time

# ===============
# ENCRYPTING FILE
# ===============
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32, 
        salt = salt, 
        iterations = 600_000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(input_filename, output_filename, password):
    
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    
    with open(input_filename, 'rb') as f:
        data = f.read()      
    encrypted_data = fernet.encrypt(data)
    with open(output_filename, 'wb') as f:
        f.write(salt + encrypted_data)
        
    print(f"File successfully encrypted to {output_filename}")

# ===============
# DECRYPTING FILE
# ===============
def decrypt_file(encrypted_filename, output_filename, password):
    
    with open(encrypted_filename, 'rb') as f:
        salt = f.read(16)
        encrypted_data = f.read()

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(output_filename, 'wb') as f:
            f.write(decrypted_data)
        print(f"File successfully decoded to {output_filename}")
    except InvalidToken:
        print(f"Decryption failed: Incorrect password or file corrupted")

