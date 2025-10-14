from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
import secrets
import hashlib
import os

def derive_shared_key(private_key, peer_public_key):
    try:
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'davell_session_salt_v2',
            info=b'davell_session_key',
            backend=default_backend()
        ).derive(shared_key)
        
        return derived_key
        
    except Exception as e:
        raise ValueError(f"Key derivation failed: {e}")

def generate_secure_random(length):
    return secrets.token_bytes(length)

def secure_hash(data, salt=None):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    if salt is None:
        salt = generate_secure_random(32)
    elif isinstance(salt, str):
        salt = salt.encode('utf-8')
    
    hasher = hashlib.sha256()
    hasher.update(salt)
    hasher.update(data)
    
    return salt, hasher.digest()

def constant_time_compare(a, b):
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0

def encrypt_data(data, key, associated_data=None):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes long")

    nonce = generate_secure_random(12)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    if associated_data:
        if isinstance(associated_data, str):
            associated_data = associated_data.encode('utf-8')
        encryptor.authenticate_additional_data(associated_data)
    
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    return {
        'nonce': nonce,
        'ciphertext': ciphertext,
        'tag': encryptor.tag
    }

def decrypt_data(encrypted_data, key, associated_data=None):
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes long")
    
    nonce = encrypted_data['nonce']
    ciphertext = encrypted_data['ciphertext']
    tag = encrypted_data['tag']

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    if associated_data:
        if isinstance(associated_data, str):
            associated_data = associated_data.encode('utf-8')
        decryptor.authenticate_additional_data(associated_data)
    
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    if isinstance(pem_data, str):
        pem_data = pem_data.encode('utf-8')
    
    return serialization.load_pem_public_key(pem_data, backend=default_backend())

def sign_data(private_key, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature

def verify_signature(public_key, signature, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def derive_key_from_password(password, salt=None, iterations=100000):
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    if salt is None:
        salt = generate_secure_random(32)
    
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    
    key = kdf.derive(password)
    return salt, key

def secure_wipe(data):
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = secrets.randbelow(256)
    elif isinstance(data, bytes):
        pass
    
    del data

def compute_file_hash(filepath, algorithm='sha256'):
    if algorithm.lower() == 'sha256':
        hasher = hashlib.sha256()
    elif algorithm.lower() == 'sha512':
        hasher = hashlib.sha512()
    else:
        raise ValueError("Unsupported hash algorithm")
    
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    
    return hasher.hexdigest()

def validate_key_strength(private_key):
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        return False, "Not an EC private key"

    curve = private_key.curve
    if not isinstance(curve, ec.SECP384R1):
        return False, "Unsupported curve"
    
    try:
        test_data = b"key_strength_test"
        signature = private_key.sign(test_data, ec.ECDSA(hashes.SHA256()))
        public_key = private_key.public_key()
        public_key.verify(signature, test_data, ec.ECDSA(hashes.SHA256()))
    except Exception as e:
        return False, f"Key validation failed: {e}"
    
    return True, "Key is valid and strong"

def create_message_hmac(message, key):
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    return h.finalize()

def verify_message_hmac(message, key, expected_hmac):
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    
    try:
        h.verify(expected_hmac)
        return True
    except Exception:
        return False

def generate_session_id():
    return secrets.token_hex(16)

def constant_time_string_compare(a, b):
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    return constant_time_compare(a, b)

class SecureRandom:
    
    @staticmethod
    def bytes(length):
        return secrets.token_bytes(length)
    
    @staticmethod
    def hex(length):
        return secrets.token_hex(length)
    
    @staticmethod
    def int(min_val=0, max_val=2**31-1):
        return secrets.randbelow(max_val - min_val + 1) + min_val
    
    @staticmethod
    def choice(sequence):
        return secrets.choice(sequence)

def key_derivation_function(input_key_material, salt=None, info=b'', length=32):
    if salt is None:
        salt = b'\x00' * 32
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    
    return hkdf.derive(input_key_material)

def secure_compare_digest(a, b):
    try:
        import hmac
        return hmac.compare_digest(a, b)
    except AttributeError:
        return constant_time_compare(a, b)

AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
SALT_SIZE = 32