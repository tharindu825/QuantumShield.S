import os
import sys
import re
import json
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from getpass import getpass
import argon2
import hmac
import hashlib

# Constants
SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 12
ITERATIONS = 2  # Reduced for better performance
MEMORY_COST = 512 * 1024  # Reduced to 512MB for better performance
PARALLELISM = 4  # Reduced for less CPU strain
MIN_PASSWORD_LENGTH = 12
LICENSE_FILE_NAME = "YOUR LICENSE KEY.lic"
NONCE_LOG_FILE = "nonce_log.dat"  # File to log used nonces

# Update with your actual public key
LICENSE_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
PUBLIC KEY OF USER
-----END PUBLIC KEY-----"""

class LicenseError(Exception):
    """Custom exception for license-related errors"""
    pass

def get_base_path():
    """Get the base path for the application"""
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))

def validate_license() -> bool:
    """Validate the license file's signature and expiration date."""
    try:
        possible_paths = [
            os.path.join(get_base_path(), LICENSE_FILE_NAME),
            os.path.join(os.path.dirname(sys.executable), LICENSE_FILE_NAME),
            os.path.join(os.getcwd(), LICENSE_FILE_NAME),
            os.path.join(os.path.expanduser("~"), LICENSE_FILE_NAME)
        ]
        
        license_path = None
        for path in possible_paths:
            if os.path.exists(path):
                license_path = path
                break
                
        if not license_path:
            raise LicenseError(
                f"License file not found. Please ensure {LICENSE_FILE_NAME} "
                f"exists in one of these locations:\n" + 
                "\n".join(possible_paths)
            )

        with open(license_path, 'rb') as f:
            license_data = f.read()

        if len(license_data) < 64:
            raise LicenseError("License file is corrupted (too short)")

        signature = license_data[:64]
        content = license_data[64:]

        public_key = serialization.load_pem_public_key(
            LICENSE_PUBLIC_KEY,
            backend=default_backend()
        )
        public_key.verify(signature, content)

        license_info = json.loads(content.decode())
        
        # Validate required fields
        required_fields = ['issued_to', 'expiry', 'features']
        for field in required_fields:
            if field not in license_info:
                raise LicenseError(f"Missing required field: {field}")

        # Parse and validate dates
        expiry_date = datetime.fromisoformat(license_info['expiry']).astimezone(timezone.utc)
        current_date = datetime.now(timezone.utc)
        
        if expiry_date < current_date:
            raise LicenseError(f"License expired on {expiry_date.strftime('%Y-%m-%d %H:%M UTC')}")

        # Validate features
        required_features = {"encryption", "decryption", "quantum_resistant"}
        if not required_features.issubset(set(license_info.get('features', []))):
            missing = required_features - set(license_info['features'])
            raise LicenseError(f"Missing required features: {', '.join(missing)}")

        print(f"\nValid license for: {license_info['issued_to']}")
        print(f"Expiration: {expiry_date.strftime('%Y-%m-%d %H:%M UTC')}")
        return True

    except LicenseError as e:
        print(f"\nLICENSE ERROR: {str(e)}")
        return False
    except Exception as e:
        print(f"\nVALIDATION ERROR: {str(e)}")
        return False

def validate_password(password: str) -> bool:
    """Validate password strength requirements"""
    if len(password) < MIN_PASSWORD_LENGTH:
        print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long")
        return False
    
    checks = [
        (r'[A-Z]', "uppercase letter"),
        (r'[a-z]', "lowercase letter"),
        (r'\d', "number"),
        (r'[!@#$%^&*(),.?":{}|<>]', "special character")
    ]
    
    for pattern, message in checks:
        if not re.search(pattern, password):
            print(f"Password must contain at least one {message}")
            return False
    
    return True

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive key using Argon2id with enhanced parameters"""
    return argon2.low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=ITERATIONS,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len=KEY_SIZE,
        type=argon2.low_level.Type.ID
    )

def secure_delete(file_path: str):
    """Securely delete a file with 7-pass overwrite (enhanced from 3-pass)"""
    if os.path.isfile(file_path):
        file_size = os.path.getsize(file_path)
        
        with open(file_path, 'wb') as f:
            for _ in range(7):  # Increased to 7 passes for better security
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        os.remove(file_path)
        print(f"Securely deleted {file_path} with 7-pass overwrite.")
    else:
        print(f"Warning: {file_path} not found for secure deletion.")

def log_nonce(nonce: bytes, log_file: str):
    """Log used nonces to prevent reuse"""
    with open(log_file, 'ab') as f:
        f.write(nonce + b'\n')

def check_nonce(nonce: bytes, log_file: str) -> bool:
    """Check if nonce has been used before"""
    if not os.path.exists(log_file):
        return False
    with open(log_file, 'rb') as f:
        content = f.read()
        return nonce in content.split(b'\n')

def generate_unique_nonce(log_file: str) -> bytes:
    """Generate a unique nonce, checking against log"""
    max_attempts = 10
    for _ in range(max_attempts):
        nonce = os.urandom(NONCE_SIZE)
        if not check_nonce(nonce, log_file):
            log_nonce(nonce, log_file)
            return nonce
    raise ValueError("Unable to generate unique nonce after multiple attempts. Possible log file issue.")

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute HMAC for integrity check"""
    return hmac.new(key, data, hashlib.sha256).digest()

def encrypt_file(key: bytes, salt: bytes, input_path: str):
    """Encrypt a file with ChaCha20-Poly1305 and integrity check"""
    nonce_log_path = os.path.join(get_base_path(), NONCE_LOG_FILE)
    nonce = generate_unique_nonce(nonce_log_path)
    chacha = ChaCha20Poly1305(key)
    
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    hmac_value = compute_hmac(key, ciphertext)
    encrypted_path = input_path + '.qs'
    
    with open(encrypted_path, 'wb') as f:
        f.write(salt + nonce + hmac_value + ciphertext)
    
    secure_delete(input_path)
    return encrypted_path

def decrypt_file(key: bytes, input_path: str):
    """Decrypt a file with ChaCha20-Poly1305 and verify integrity"""
    with open(input_path, 'rb') as f:
        data = f.read()
    
    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    hmac_value = data[SALT_SIZE+NONCE_SIZE:SALT_SIZE+NONCE_SIZE+32]  # SHA256 HMAC is 32 bytes
    ciphertext = data[SALT_SIZE+NONCE_SIZE+32:]
    
    # Verify integrity
    computed_hmac = compute_hmac(key, ciphertext)
    if not hmac.compare_digest(hmac_value, computed_hmac):
        raise ValueError("Integrity check failed - file may have been tampered with")
    
    chacha = ChaCha20Poly1305(key)
    try:
        plaintext = chacha.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError("Decryption failed - possible tampering or wrong key")
    
    original_path = input_path.replace('.qs', '')
    with open(original_path, 'wb') as f:
        f.write(plaintext)
    
    secure_delete(input_path)
    return original_path

def process_folder(action: str, password: bytes, folder_path: str):
    """Process all files in a folder"""
    error_count = 0
    total_files = 0
    for root, _, files in os.walk(folder_path):
        for file in files:
            if (action == 'encrypt' and not file.endswith('.qs')) or (action == 'decrypt' and file.endswith('.qs')):
                total_files += 1
                file_path = os.path.join(root, file)
                
                try:
                    if action == 'encrypt':
                        salt = os.urandom(SALT_SIZE)
                        key = derive_key(password, salt)
                        encrypt_file(key, salt, file_path)
                        print(f"Encrypted: {file_path}")
                        
                    elif action == 'decrypt':
                        with open(file_path, 'rb') as f:
                            salt = f.read(SALT_SIZE)
                        
                        key = derive_key(password, salt)
                        decrypt_file(key, file_path)
                        print(f"Decrypted: {file_path}")
                        
                except Exception as e:
                    print(f"Error processing {file_path}: {str(e)}")
                    error_count += 1
                    continue
    return total_files, error_count

def main():
    """Simplified CLI interface with enhanced user feedback"""
    try:
        print("\nQuantumShield Encryption Module (Enhanced Version)")
        print("------------------------------------------------")
        print("Checking license...")
        
        if not validate_license():
            print("Valid license required to use this software.")
            input("Press Enter to exit...")
            return

        # Simplified action selection
        while True:
            action = input("\nChoose action [E]ncrypt/[D]ecrypt: ").strip().lower()
            if action in ['e', 'd']:
                action = 'encrypt' if action == 'e' else 'decrypt'
                break
            print("Invalid choice. Please press E for Encrypt or D for Decrypt.")

        folder_path = input("\nFolder path: ").strip()
        if not os.path.exists(folder_path):
            print(f"Error: Path '{folder_path}' does not exist.")
            input("Press Enter to exit...")
            return

        # Password handling with additional guidance
        print("\nNote: Strong passwords are critical for security. Use a mix of characters.")
        while True:
            password = getpass("\nEnter password: ")
            if action == "encrypt" and not validate_password(password):
                continue
            password_confirm = getpass("Confirm password: ")
            if password != password_confirm:
                print("Passwords do not match. Please try again.")
                continue
            break

        password_bytes = password.encode()
        
        try:
            print(f"\nProcessing {action}ion for folder: {folder_path}")
            total_files, error_count = process_folder(action, password_bytes, folder_path)
            
            if error_count == 0:
                print(f"\n{'Encryption' if action == 'encrypt' else 'Decryption'} completed successfully for all {total_files} files!")
            else:
                print(f"\n{'Encryption' if action == 'encrypt' else 'Decryption'} completed with errors: {error_count} out of {total_files} files failed.")
            print("Original files were securely deleted with enhanced 7-pass overwrite.")
            print("Note: Secure deletion effectiveness may vary based on storage type (HDD vs SSD).")

        except Exception as e:
            print(f"\nOperation failed: {str(e)}")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
    
    finally:
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
