from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac

import Message

import os
import json
import secrets
import time
import hashlib

SALT_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
MIN_PASSWORD_LENGTH = 8
MAX_FILE_SIZE = 50 * 1024 * 1024

def secure_random_salt():
    return secrets.token_bytes(SALT_SIZE)

def derive_storage_key(password=None, salt=None):
    if password is None:
        if salt is None:
            salt = secure_random_salt()
        return salt, HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            info=b'davell_anonymous_storage_v2',
            backend=default_backend()
        ).derive(secrets.token_bytes(32))
    else:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
        
        if salt is None:
            salt = secure_random_salt()

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            info=b'davell_storage_key_v2',
            backend=default_backend()
        ).derive(password.encode('utf-8'))
        
        return salt, derived_key

def verify_file_integrity(filepath, expected_min_size=61):
    try:
        if not os.path.exists(filepath):
            return False, "File does not exist"
        
        stat = os.stat(filepath)
        
        if stat.st_size < expected_min_size:
            return False, f"File too small (minimum {expected_min_size} bytes)"
        
        if stat.st_size > MAX_FILE_SIZE:
            return False, f"File too large (maximum {MAX_FILE_SIZE} bytes)"

        if stat.st_mode & 0o077:
            Message.warning(f"File {filepath} has insecure permissions")
        
        return True, "File integrity OK"
        
    except Exception as e:
        return False, f"Integrity check failed: {e}"

def load_persistent_cert(USER_PASSWORD):
    filepath = "/usr/share/davell/storage/certs/persistent_cert.pem"

    integrity_ok, integrity_msg = verify_file_integrity(filepath, 60)
    if not integrity_ok:
        Message.warning(f"Certificate file integrity: {integrity_msg}")
        return None
    
    try:
        with open(filepath, "rb") as f:
            encrypted_data = f.read()

        if len(encrypted_data) < 60:
            Message.warning("Certificate file structure invalid")
            return None

        salt = encrypted_data[:SALT_SIZE]
        nonce = encrypted_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]
        tag = encrypted_data[-TAG_SIZE:]

        if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE:
            Message.warning("Certificate file format corrupted")
            return None

        try:
            _, storage_key = derive_storage_key(password=USER_PASSWORD, salt=salt)
        except ValueError as e:
            Message.error(f"Password validation failed: {e}")
            return None

        cipher = Cipher(
            algorithms.AES(storage_key), 
            modes.GCM(nonce, tag), 
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        try:
            cert_data = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            Message.warning("Certificate decryption failed - wrong password or corrupted file")
            return None

        try:
            persistent_cert = serialization.load_pem_private_key(
                cert_data, 
                password=None, 
                backend=default_backend()
            )
        except Exception as e:
            Message.warning("Invalid certificate format after decryption")
            return None

        if not isinstance(persistent_cert, ec.EllipticCurvePrivateKey):
            Message.warning("Certificate is not an elliptic curve key")
            return None
        
        Message.info("OK: Persistent certificate loaded successfully")
        return persistent_cert
        
    except PermissionError:
        Message.error("Permission denied accessing certificate file")
        return None
    except Exception as e:
        Message.warning(f"Failed to load certificate: {e}")
        return None

def save_persistent_cert(USER_PASSWORD, persistent_cert):
    if not USER_PASSWORD:
        raise ValueError("Password is required for certificate encryption")
    
    if not isinstance(persistent_cert, ec.EllipticCurvePrivateKey):
        raise ValueError("Invalid certificate type - must be EC private key")
    
    try:
        salt = secure_random_salt()
        _, storage_key = derive_storage_key(USER_PASSWORD, salt)

        cert_data = persistent_cert.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        if len(cert_data) > 10000:
            raise ValueError("Certificate data unexpectedly large")

        nonce = secrets.token_bytes(NONCE_SIZE)
        cipher = Cipher(
            algorithms.AES(storage_key), 
            modes.GCM(nonce), 
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(cert_data) + encryptor.finalize()

        encrypted_result = salt + nonce + ciphertext + encryptor.tag

        temp_file = "/usr/share/davell/storage/certs/persistent_cert.pem.tmp"
        try:
            with open(temp_file, "wb") as f:
                f.write(encrypted_result)
                f.flush()
                os.fsync(f.fileno())

            os.chmod(temp_file, 0o600)

            os.replace(temp_file, "/usr/share/davell/storage/certs/persistent_cert.pem")
            
        except Exception as e:
            if os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass
            raise e
        
        Message.info("OK: Persistent certificate saved successfully")
        
    except Exception as e:
        Message.error(f"Failed to save persistent cert: {e}")
        raise e

def get_or_create_persistent_cert(USER_PASSWORD):
    if not USER_PASSWORD:
        raise ValueError("Password is required")

    persistent_cert = load_persistent_cert(USER_PASSWORD)
    
    if persistent_cert is None:
        Message.info("Generating new persistent certificate...")
        persistent_cert = ec.generate_private_key(ec.SECP384R1(), default_backend())

        save_persistent_cert(USER_PASSWORD, persistent_cert)
        Message.info("OK: New certificate generated and saved")
    
    return persistent_cert

def load_encrypted_data(filename, USER_PASSWORD):
    integrity_ok, integrity_msg = verify_file_integrity(filename, 61)
    if not integrity_ok:
        if "does not exist" in integrity_msg:
            return {} 
        Message.warning(f"Data file integrity: {integrity_msg}")
        return {}
    
    try:
        with open(filename, "rb") as f:
            encrypted_data = f.read()

        if len(encrypted_data) < 61:
            Message.warning(f"File {filename} is too small")
            return {}

        password_flag = encrypted_data[-1:]
        encrypted_data = encrypted_data[:-1]

        salt = encrypted_data[:SALT_SIZE]
        nonce = encrypted_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]
        tag = encrypted_data[-TAG_SIZE:]

        if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE:
            Message.warning(f"File {filename} has invalid structure")
            return {}

        if password_flag == b'\x01':
            if not USER_PASSWORD:
                Message.warning(f"Password required to decrypt {filename}")
                return {}
            try:
                _, key = derive_storage_key(password=USER_PASSWORD, salt=salt)
            except ValueError as e:
                Message.error(f"Password validation failed for {filename}: {e}")
                return {}
        else:
            _, key = derive_storage_key(salt=salt)

        cipher = Cipher(
            algorithms.AES(key), 
            modes.GCM(nonce, tag), 
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        try:
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            Message.warning(f"Decryption failed for {filename} - wrong password or corrupted file")
            return {}

        try:
            result = json.loads(decrypted_data.decode('utf-8'))
        except json.JSONDecodeError as e:
            Message.warning(f"JSON parsing failed for {filename}: {e}")
            return {}
        except UnicodeDecodeError as e:
            Message.warning(f"Unicode decoding failed for {filename}: {e}")
            return {}

        if not isinstance(result, dict):
            Message.warning(f"File {filename} does not contain valid dictionary data")
            return {}
        
        return result
        
    except PermissionError:
        Message.error(f"Permission denied accessing {filename}")
        return {}
    except Exception as e:
        Message.error(f"Failed to load {filename}: {e}")
        return {}

def save_encrypted_data(USER_PASSWORD, data, filename, use_password=True):
    if data is None:
        data = {}
    
    if not isinstance(data, dict):
        raise ValueError("Data must be a dictionary")
    
    try:
        json_data = json.dumps(data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

        if len(json_data) > MAX_FILE_SIZE:
            raise ValueError(f"Data too large (maximum {MAX_FILE_SIZE} bytes)")

        if use_password and USER_PASSWORD:
            salt = secure_random_salt()
            _, key = derive_storage_key(password=USER_PASSWORD, salt=salt)
            password_flag = b'\x01'
        else:
            salt = secure_random_salt()
            _, key = derive_storage_key(salt=salt)
            password_flag = b'\x00'

        nonce = secrets.token_bytes(NONCE_SIZE)
        cipher = Cipher(
            algorithms.AES(key), 
            modes.GCM(nonce), 
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(json_data) + encryptor.finalize()

        encrypted_result = salt + nonce + ciphertext + encryptor.tag + password_flag

        temp_file = f"{filename}.tmp"
        try:
            with open(temp_file, "wb") as f:
                f.write(encrypted_result)
                f.flush()
                os.fsync(f.fileno())

            os.chmod(temp_file, 0o600)

            os.replace(temp_file, filename)
            
        except Exception as e:
            if os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass
            raise e
        
        Message.info(f"OK: Data saved to {filename}")
        
    except Exception as e:
        Message.error(f"Failed to save {filename}: {e}")
        raise e

def secure_delete_file(filename):
    try:
        if not os.path.exists(filename):
            return True

        file_size = os.path.getsize(filename)

        with open(filename, "r+b") as f:
            for _ in range(3):
                f.seek(0)
                random_data = secrets.token_bytes(file_size)
                f.write(random_data)
                f.flush()
                os.fsync(f.fileno())

        os.unlink(filename)
        return True
        
    except Exception as e:
        Message.warning(f"Secure delete of {filename} failed: {e}")
        return False

def backup_encrypted_data(USER_PASSWORD, backup_dir="backup"):
    if not USER_PASSWORD:
        raise ValueError("Password required for backup")
    
    try:
        os.makedirs(backup_dir, mode=0o700, exist_ok=True)

        files_to_backup = [
            "/usr/share/davell/storage/certs/persistent_cert.pem",
            "/usr/share/davell/storage/friends.enc",
            "/usr/share/davell/storage/pending_requests.enc", 
            "/usr/share/davell/storage/PersonalInfo.enc"
        ]
        
        timestamp = int(time.time())
        
        for filename in files_to_backup:
            if os.path.exists(filename):
                backup_filename = f"{backup_dir}/{filename}.backup.{timestamp}"
                try:
                    with open(filename, "rb") as src, open(backup_filename, "wb") as dst:
                        dst.write(src.read())
                    
                    os.chmod(backup_filename, 0o600)
                    Message.info(f"OK: Backed up {filename}")
                    
                except Exception as e:
                    Message.warning(f"Failed to backup {filename}: {e}")
        
        Message.info(f"Backup completed in {backup_dir}")
        return True
        
    except Exception as e:
        Message.error(f"Backup failed: {e}")
        return False

def verify_data_consistency(USER_PASSWORD):
    Message.info("Verifying data consistency...")
    
    issues = []

    try:
        cert = load_persistent_cert(USER_PASSWORD)
        if cert is None:
            issues.append("Certificate could not be loaded")
        else:
            test_data = b"test"
            signature = cert.sign(test_data, ec.ECDSA(hashes.SHA256()))
            cert.public_key().verify(signature, test_data, ec.ECDSA(hashes.SHA256()))
    except Exception as e:
        issues.append(f"Certificate verification failed: {e}")

    data_files = ["/usr/share/davell/storage/friends.enc", "/usr/share/davell/storage/pending_requests.enc", "/usr/share/davell/storage/PersonalInfo.enc"]
    for filename in data_files:
        try:
            data = load_encrypted_data(filename, USER_PASSWORD)
            if not isinstance(data, dict):
                issues.append(f"{filename} does not contain valid dictionary data")
        except Exception as e:
            issues.append(f"{filename} verification failed: {e}")
    
    if issues:
        Message.warning("Data consistency issues found:")
        for issue in issues:
            Message.warning(f"  - {issue}")
        return False
    else:
        Message.info("OK: All data files are consistent")
        return True