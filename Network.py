import MyID
import Message
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
import base64
import secrets
import time
from CryptoUtils import *
from Storage import *
import socket
import socks
import EncodeID
import hashlib
import gc
import threading
import json
import struct
import re
from collections import defaultdict

# Signal Protocol Constants
SIGNAL_VERSION = "1.0"
MAX_SKIP = 1000  # Max number of message keys to skip
MAX_CHAIN_KEY_LENGTH = 32
ROOT_KEY_LENGTH = 32
CHAIN_KEY_LENGTH = 32
MESSAGE_KEY_LENGTH = 80  # 32 for encryption + 32 for authentication + 16 for IV

CONNECTION_TIMEOUT = 60
NONCE_TIMEOUT = 300
MAX_MESSAGE_SIZE = 8192
MAX_HANDSHAKE_TIME = 30
PROTOCOL_VERSION = "2.0"
MIN_PEER_ID_LENGTH = 16

_network_lock = threading.RLock()
_nonce_lock = threading.RLock()
_signal_lock = threading.RLock()

used_nonces = {}
pending_requests = {}
friends = {}
signal_sessions = {}
connection_stats = {"total": 0, "successful": 0, "failed": 0}

TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050

class SecurityError(Exception):
    pass

class NetworkError(Exception):
    pass

class SignalProtocolError(Exception):
    pass

# Signal Protocol Implementation
class MessageKeys:
    def __init__(self, cipher_key, mac_key, iv):
        self.cipher_key = cipher_key
        self.mac_key = mac_key
        self.iv = iv

class ChainKey:
    def __init__(self, key, index=0):
        self.key = key
        self.index = index
    
    def next_chain_key(self):
        h = hmac.HMAC(self.key, hashes.SHA256(), backend=default_backend())
        h.update(b'\x02')  # Chain key constant
        new_key = h.finalize()
        return ChainKey(new_key, self.index + 1)
    
    def derive_message_keys(self):
        h = hmac.HMAC(self.key, hashes.SHA256(), backend=default_backend())
        h.update(b'\x01')  # Message key constant
        message_key_material = h.finalize()
        
        # Expand the key material using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=MESSAGE_KEY_LENGTH,
            salt=None,
            info=b'Signal_MessageKeys',
            backend=default_backend()
        )
        expanded_keys = hkdf.derive(message_key_material)
        
        cipher_key = expanded_keys[:32]
        mac_key = expanded_keys[32:64]
        iv = expanded_keys[64:80]
        
        return MessageKeys(cipher_key, mac_key, iv)

class DoubleRatchetSession:
    def __init__(self, root_key, our_ratchet_key=None, their_ratchet_key=None, sending=True):
        self.root_key = root_key
        self.sending_chain_key = None
        self.receiving_chain_key = None
        self.our_ratchet_key = our_ratchet_key or ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.their_ratchet_key = their_ratchet_key
        self.pn = 0  # Number of messages in previous sending chain
        self.ns = 0  # Message number for sending
        self.nr = 0  # Message number for receiving
        self.skipped_keys = {}  # Dictionary to store skipped message keys
        
        if sending and their_ratchet_key:
            self._ratchet_encrypt()
    
    def _kdf_rk(self, root_key, dh_output):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for root key + 32 bytes for chain key
            salt=root_key,
            info=b'Signal_RootKey',
            backend=default_backend()
        )
        output = hkdf.derive(dh_output)
        return output[:32], output[32:64]  # root_key, chain_key
    
    def _ratchet_encrypt(self):
        if not self.their_ratchet_key:
            return
            
        # Perform DH
        shared_key = self.our_ratchet_key.exchange(ec.ECDH(), self.their_ratchet_key)
        
        # Derive new root key and sending chain key
        self.root_key, chain_key_bytes = self._kdf_rk(self.root_key, shared_key)
        self.sending_chain_key = ChainKey(chain_key_bytes)
        
        # Generate new DH key pair
        self.our_ratchet_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.pn = self.ns
        self.ns = 0
    
    def _ratchet_decrypt(self, their_new_ratchet_key):
        # Store current receiving chain length
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        
        # Update their ratchet key
        self.their_ratchet_key = their_new_ratchet_key
        
        # Perform DH with their new key
        shared_key = self.our_ratchet_key.exchange(ec.ECDH(), their_new_ratchet_key)
        
        # Derive new root key and receiving chain key
        self.root_key, chain_key_bytes = self._kdf_rk(self.root_key, shared_key)
        self.receiving_chain_key = ChainKey(chain_key_bytes)
        
        # Generate new key pair and perform encryption ratchet
        self.our_ratchet_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self._ratchet_encrypt()
    
    def encrypt_message(self, plaintext):
        if not self.sending_chain_key:
            raise SignalProtocolError("No sending chain key available")
        
        # Get message keys
        message_keys = self.sending_chain_key.derive_message_keys()
        
        # Advance chain key
        self.sending_chain_key = self.sending_chain_key.next_chain_key()
        
        # Encrypt the message
        cipher = Cipher(
            algorithms.AES(message_keys.cipher_key),
            modes.GCM(message_keys.iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        
        # Create message with header
        message = {
            'version': SIGNAL_VERSION,
            'dh_public': base64.b64encode(self.our_ratchet_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode(),
            'pn': self.pn,
            'n': self.ns,
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(encryptor.tag).decode()
        }
        
        # Calculate MAC
        message_bytes = json.dumps(message, sort_keys=True).encode('utf-8')
        h = hmac.HMAC(message_keys.mac_key, hashes.SHA256(), backend=default_backend())
        h.update(message_bytes)
        message['mac'] = base64.b64encode(h.finalize()).decode()
        
        self.ns += 1
        return message
    
    def decrypt_message(self, message):
        try:
            # Extract their DH public key
            their_dh_public = serialization.load_pem_public_key(
                base64.b64decode(message['dh_public']),
                backend=default_backend()
            )
            
            # Check if we need to perform a DH ratchet
            if not self.their_ratchet_key or not self._keys_equal(their_dh_public, self.their_ratchet_key):
                self._skip_message_keys(message['pn'])
                self._ratchet_decrypt(their_dh_public)

            self._skip_message_keys(message['n'])
            
            # Get receiving chain key and derive message keys
            if not self.receiving_chain_key:
                raise SignalProtocolError("No receiving chain key available")
            
            message_keys = self.receiving_chain_key.derive_message_keys()
            self.receiving_chain_key = self.receiving_chain_key.next_chain_key()
            
            # Verify MAC
            mac_message = message.copy()
            del mac_message['mac']
            message_bytes = json.dumps(mac_message, sort_keys=True).encode('utf-8')
            h = hmac.HMAC(message_keys.mac_key, hashes.SHA256(), backend=default_backend())
            h.update(message_bytes)
            calculated_mac = h.finalize()
            
            if not secrets.compare_digest(calculated_mac, base64.b64decode(message['mac'])):
                raise SignalProtocolError("MAC verification failed")

            ciphertext = base64.b64decode(message['ciphertext'])
            tag = base64.b64decode(message['tag'])
            
            cipher = Cipher(
                algorithms.AES(message_keys.cipher_key),
                modes.GCM(message_keys.iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            self.nr += 1
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise SignalProtocolError(f"Decryption failed: {e}")
    
    def _keys_equal(self, key1, key2):
        key1_bytes = key1.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key2_bytes = key2.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return secrets.compare_digest(key1_bytes, key2_bytes)
    
    def _skip_message_keys(self, until):
        if self.nr + MAX_SKIP < until:
            raise SignalProtocolError("Too many skipped messages")
        
        if not self.receiving_chain_key:
            return
        
        while self.nr < until:
            message_keys = self.receiving_chain_key.derive_message_keys()
            self.skipped_keys[self.nr] = message_keys
            self.receiving_chain_key = self.receiving_chain_key.next_chain_key()
            self.nr += 1

def create_signal_session(shared_secret, is_alice=True):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=ROOT_KEY_LENGTH,
        salt=None,
        info=b'Signal_RootKey_Init',
        backend=default_backend()
    )
    root_key = hkdf.derive(shared_secret)
    
    # Alice sends the first message, Bob receives
    if is_alice:
        session = DoubleRatchetSession(root_key, sending=True)
    else:
        session = DoubleRatchetSession(root_key, sending=False)
    
    return session

def save_signal_sessions(USER_PASSWORD):
    with _signal_lock:
        try:
            sessions_data = {}
            for peer_id, session in signal_sessions.items():
                sessions_data[peer_id] = {
                    'root_key': base64.b64encode(session.root_key).decode(),
                    'our_ratchet_key': base64.b64encode(session.our_ratchet_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )).decode(),
                    'their_ratchet_key': base64.b64encode(session.their_ratchet_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )).decode() if session.their_ratchet_key else None,
                    'pn': session.pn,
                    'ns': session.ns,
                    'nr': session.nr,
                    'sending_chain_key': base64.b64encode(session.sending_chain_key.key).decode() if session.sending_chain_key else None,
                    'receiving_chain_key': base64.b64encode(session.receiving_chain_key.key).decode() if session.receiving_chain_key else None
                }
            
            save_encrypted_data(USER_PASSWORD, sessions_data, "/usr/share/davell/storage/certs/signal_sessions.enc", use_password=True)
            return True
        except Exception as e:
            Message.error(f"Failed to save Signal sessions: {e}")
            return False

def load_signal_sessions(USER_PASSWORD):
    global signal_sessions
    
    with _signal_lock:
        try:
            sessions_data = load_encrypted_data("/usr/share/davell/storage/certs/signal_sessions.enc", USER_PASSWORD)
            if not isinstance(sessions_data, dict):
                signal_sessions = {}
                return
            
            signal_sessions = {}
            for peer_id, data in sessions_data.items():
                if not validate_peer_id(peer_id):
                    continue
                    
                # Reconstruct session
                root_key = base64.b64decode(data['root_key'])
                our_ratchet_key = serialization.load_pem_private_key(
                    base64.b64decode(data['our_ratchet_key']),
                    password=None,
                    backend=default_backend()
                )
                
                their_ratchet_key = None
                if data.get('their_ratchet_key'):
                    their_ratchet_key = serialization.load_pem_public_key(
                        base64.b64decode(data['their_ratchet_key']),
                        backend=default_backend()
                    )
                
                session = DoubleRatchetSession(root_key, our_ratchet_key, their_ratchet_key, sending=False)
                session.pn = data.get('pn', 0)
                session.ns = data.get('ns', 0)
                session.nr = data.get('nr', 0)
                
                if data.get('sending_chain_key'):
                    session.sending_chain_key = ChainKey(base64.b64decode(data['sending_chain_key']), session.ns)
                
                if data.get('receiving_chain_key'):
                    session.receiving_chain_key = ChainKey(base64.b64decode(data['receiving_chain_key']), session.nr)
                
                signal_sessions[peer_id] = session
                
        except Exception as e:
            Message.warning(f"Failed to load Signal sessions: {e}")
            signal_sessions = {}


def validate_peer_id(peer_id):
    if not peer_id or not isinstance(peer_id, str):
        return False

    pattern = r'^[A-Za-z0-9_-]{16,64}$'
    return bool(re.match(pattern, peer_id))

def safe_compare_digest(a, b):
    if a is None or b is None:
        return False
    
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    return secrets.compare_digest(a, b)

class SecureConnection:
    def __init__(self, USER_PASSWORD):
        self.USER_PASSWORD = USER_PASSWORD
        self.PERSISTENT_CERT = None
        self.PUBLIC_KEY = None
        self.connection_id = secrets.token_hex(8)
        self._load_persistent_cert()
    
    def _load_persistent_cert(self):
        try:
            self.PERSISTENT_CERT = load_persistent_cert(self.USER_PASSWORD)
            
            if not self.PERSISTENT_CERT:
                Message.warning("Creating new certificate due to load failure")
                self.PERSISTENT_CERT = ec.generate_private_key(ec.SECP384R1(), default_backend())
                save_persistent_cert(self.USER_PASSWORD, self.PERSISTENT_CERT)

        except Exception as e:
            Message.error(f"Critical certificate error: {e}")
            raise SecurityError("Certificate initialization failed")
        
        self.PUBLIC_KEY = self.PERSISTENT_CERT.public_key()

        try:
            test_data = b"integrity_test"
            signature = self.PERSISTENT_CERT.sign(test_data, ec.ECDSA(hashes.SHA256()))
            self.PUBLIC_KEY.verify(signature, test_data, ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            raise SecurityError("Certificate integrity verification failed")

def cleanup_old_nonces():
    with _nonce_lock:
        current_time = time.time()
        expired_nonces = [nonce for nonce, timestamp in used_nonces.items()
                         if current_time - timestamp > NONCE_TIMEOUT]
        
        for nonce in expired_nonces:
            del used_nonces[nonce]

def check_nonce(nonce, peer_id="unknown"):
    if not nonce or len(nonce) < 16:
        Message.info(f"Nonce too short from {peer_id}")
        return False
    
    with _nonce_lock:
        cleanup_old_nonces()
        
        if nonce in used_nonces:
            Message.info(f"Replay attack detected from {peer_id}")
            return False
        
        used_nonces[nonce] = time.time()
        return True

def load_user_data(USER_PASSWORD):
    global friends, pending_requests
    
    with _network_lock:
        try:
            friends_data = load_encrypted_data("/usr/share/davell/storage/friends.enc", USER_PASSWORD)
            pending_data = load_encrypted_data("/usr/share/davell/storage/pending_requests.enc", USER_PASSWORD)

            friends = friends_data if isinstance(friends_data, dict) else {}
            pending_requests = pending_data if isinstance(pending_data, dict) else {}

            friends = {k: v for k, v in friends.items() if validate_peer_id(k) and isinstance(v, dict)}
            pending_requests = {k: v for k, v in pending_requests.items() if validate_peer_id(k) and isinstance(v, dict)}
            
        except Exception as e:
            Message.warning(f"Failed to load user data: {e}")
            friends = {}
            pending_requests = {}

    load_signal_sessions(USER_PASSWORD)

def save_user_data(USER_PASSWORD):
    with _network_lock:
        try:
            save_encrypted_data(USER_PASSWORD, friends, "/usr/share/davell/storage/friends.enc", use_password=True)
            save_encrypted_data(USER_PASSWORD, pending_requests, "/usr/share/davell/storage/pending_requests.enc", use_password=True)
            
            # Save Signal Protocol sessions
            save_signal_sessions(USER_PASSWORD)
            return True
        except Exception as e:
            Message.error(f"Failed to save user data: {e}")
            return False

def secure_send(conn, data, encryption_key=None):
    try:
        if isinstance(data, dict):
            json_data = json.dumps(data, separators=(',', ':'))
            payload = json_data.encode('utf-8')
        else:
            payload = str(data).encode('utf-8')

        if len(payload) > MAX_MESSAGE_SIZE:
            raise NetworkError("Message too large")
        
        if encryption_key:
            nonce = secrets.token_bytes(12)
            cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(payload) + encryptor.finalize()

            encrypted_payload = nonce + ciphertext + encryptor.tag
            final_payload = encrypted_payload
        else:
            final_payload = payload

        length = len(final_payload)
        conn.sendall(struct.pack('!I', length))
        conn.sendall(final_payload)
        
    except Exception as e:
        raise NetworkError(f"Send failed: {e}")

def secure_recv(conn, encryption_key=None):
    try:
        length_data = b''
        while len(length_data) < 4:
            chunk = conn.recv(4 - len(length_data))
            if not chunk:
                return None
            length_data += chunk
        
        length = struct.unpack('!I', length_data)[0]

        if length > MAX_MESSAGE_SIZE * 2:
            raise NetworkError("Received message too large")

        payload = b''
        while len(payload) < length:
            chunk = conn.recv(min(4096, length - len(payload)))
            if not chunk:
                return None
            payload += chunk
        
        if encryption_key:
            if len(payload) < 28:
                raise NetworkError("Encrypted payload too short")
            
            nonce = payload[:12]
            ciphertext = payload[12:-16]
            tag = payload[-16:]
            
            cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            final_payload = decrypted_data
        else:
            final_payload = payload

        try:
            return json.loads(final_payload.decode('utf-8'))
        except json.JSONDecodeError:
            return final_payload.decode('utf-8')
            
    except Exception as e:
        raise NetworkError(f"Receive failed: {e}")

def perform_handshake(conn, secure_conn, is_server=True, peer_public_key=None, peer_id=None):
    handshake_start_time = time.time()
    
    try:
        if is_server:
            conn.settimeout(MAX_HANDSHAKE_TIME)
            init_data = secure_recv(conn)
            
            if not isinstance(init_data, dict) or init_data.get("type") != "handshake_init":
                raise SecurityError(f"Expected handshake_init, got {init_data.get('type') if isinstance(init_data, dict) else 'invalid'}")

            if not validate_handshake_init(init_data, peer_id or "unknown"):
                raise SecurityError("Invalid handshake init")

            try:
                peer_ephemeral_public = serialization.load_pem_public_key(
                    base64.b64decode(init_data["ephemeral_public"]), 
                    backend=default_backend()
                )
                peer_persistent_public = serialization.load_pem_public_key(
                    base64.b64decode(init_data["persistent_public"]), 
                    backend=default_backend()
                )
            except Exception as e:
                raise SecurityError(f"Invalid peer public keys: {e}")

            try:
                peer_persistent_public.verify(
                    base64.b64decode(init_data["signature"]),
                    base64.b64decode(init_data["ephemeral_public"]),
                    ec.ECDSA(hashes.SHA256())
                )
            except Exception as e:
                raise SecurityError(f"Peer signature verification failed: {e}")

            ephemeral_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            ephemeral_public = ephemeral_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            signature = secure_conn.PERSISTENT_CERT.sign(
                ephemeral_public,
                ec.ECDSA(hashes.SHA256())
            )

            response_data = {
                "type": "handshake_response",
                "ephemeral_public": base64.b64encode(ephemeral_public).decode(),
                "signature": base64.b64encode(signature).decode(),
                "persistent_public": base64.b64encode(secure_conn.PUBLIC_KEY.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode(),
                "nonce": secrets.token_hex(16),
                "timestamp": int(time.time()),
                "protocol_version": PROTOCOL_VERSION,
                "connection_id": secure_conn.connection_id,
                "signal_support": True
            }
            secure_send(conn, response_data)

            complete_msg = secure_recv(conn)
            if not complete_msg or complete_msg.get("type") != "handshake_complete":
                raise SecurityError("Handshake complete verification failed")

            session_key = derive_shared_key(ephemeral_key, peer_ephemeral_public)

            if peer_id and complete_msg.get("signal_support"):
                with _signal_lock:
                    if peer_id not in signal_sessions:
                        signal_session = create_signal_session(session_key, is_alice=False)
                        signal_sessions[peer_id] = signal_session
                        Message.info(f"Server side for {peer_id}")
            
        else:
            ephemeral_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            ephemeral_public = ephemeral_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            signature = secure_conn.PERSISTENT_CERT.sign(
                ephemeral_public,
                ec.ECDSA(hashes.SHA256())
            )

            handshake_data = {
                "type": "handshake_init",
                "ephemeral_public": base64.b64encode(ephemeral_public).decode(),
                "signature": base64.b64encode(signature).decode(),
                "persistent_public": base64.b64encode(secure_conn.PUBLIC_KEY.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode(),
                "nonce": secrets.token_hex(16),
                "timestamp": int(time.time()),
                "protocol_version": PROTOCOL_VERSION,
                "connection_id": secure_conn.connection_id,
                "signal_support": True
            }
            secure_send(conn, handshake_data)

            conn.settimeout(MAX_HANDSHAKE_TIME)
            response = secure_recv(conn)
            if not isinstance(response, dict) or response.get("type") != "handshake_response":
                raise SecurityError(f"Expected handshake_response, got {response.get('type') if isinstance(response, dict) else 'invalid'}")

            if not validate_handshake_response(response, peer_id or "unknown"):
                raise SecurityError("Invalid handshake response")

            try:
                peer_ephemeral_public = serialization.load_pem_public_key(
                    base64.b64decode(response["ephemeral_public"]), 
                    backend=default_backend()
                )
                peer_persistent_public = serialization.load_pem_public_key(
                    base64.b64decode(response["persistent_public"]), 
                    backend=default_backend()
                )
            except Exception as e:
                raise SecurityError(f"Invalid server public keys: {e}")

            try:
                peer_persistent_public.verify(
                    base64.b64decode(response["signature"]),
                    base64.b64decode(response["ephemeral_public"]),
                    ec.ECDSA(hashes.SHA256())
                )
            except Exception as e:
                raise SecurityError(f"Server signature verification failed: {e}")

            complete_data = {
                "type": "handshake_complete",
                "nonce": secrets.token_hex(16),
                "timestamp": int(time.time()),
                "signal_support": True
            }
            secure_send(conn, complete_data)

            session_key = derive_shared_key(ephemeral_key, peer_ephemeral_public)
            
            # Establish Signal Protocol session (Alice's side)
            if peer_id and response.get("signal_support"):
                with _signal_lock:
                    if peer_id not in signal_sessions:
                        signal_session = create_signal_session(session_key, is_alice=True)
                        signal_sessions[peer_id] = signal_session
                        Message.info(f"Client side for {peer_id}")

        if peer_public_key:
            stored_key_bytes = peer_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            actual_key_bytes = peer_persistent_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            if not safe_compare_digest(stored_key_bytes, actual_key_bytes):
                raise SecurityError("Certificate mismatch - possible MITM attack!")
        
        handshake_duration = time.time() - handshake_start_time
        if handshake_duration > MAX_HANDSHAKE_TIME:
            raise SecurityError("Handshake took too long")
        
        Message.info(f"Duration: {handshake_duration:.2f}s, Peer: {peer_id or 'unknown'}")
        return session_key, peer_persistent_public
        
    except Exception as e:
        Message.info(f"Error: {e}, Peer: {peer_id or 'unknown'}")

        if 'session_key' in locals():
            try:
                session_key = b'\x00' * len(session_key)
            except:
                pass
        raise e

def validate_handshake_init(data, peer_id):
    required_fields = ["type", "ephemeral_public", "signature", "persistent_public", "nonce", "timestamp"]
    for field in required_fields:
        if field not in data:
            return False
    
    if data.get("type") != "handshake_init":
        return False
    
    if not check_nonce(data.get("nonce"), peer_id):
        return False
    
    timestamp = data.get("timestamp", 0)
    if abs(int(time.time()) - timestamp) > 300:
        return False
    
    if data.get("protocol_version") != PROTOCOL_VERSION:
        return False
    
    return True

def validate_handshake_response(data, peer_id):
    required_fields = ["type", "ephemeral_public", "signature", "persistent_public", "nonce", "timestamp"]
    for field in required_fields:
        if field not in data:
            return False
    
    if data.get("type") != "handshake_response":
        return False
    
    if not check_nonce(data.get("nonce"), peer_id):
        return False
    
    timestamp = data.get("timestamp", 0)
    if abs(int(time.time()) - timestamp) > 300:
        return False
    
    if data.get("protocol_version") != PROTOCOL_VERSION:
        return False
    
    return True

def handle_client(pid, USER_PASSWORD, conn, addr):
    client_ip = addr[0] if addr else "unknown"
    connection_stats["total"] += 1
    
    Message.info(f"New connection from {client_ip}")
    Message.info(f"From {client_ip}")
    
    secure_conn = None
    session_key = None
    peer_public_key = None
    peer_id = None
    
    try:
        secure_conn = SecureConnection(USER_PASSWORD)
        load_user_data(USER_PASSWORD)

        conn.settimeout(CONNECTION_TIMEOUT)

        session_key, peer_public_key = perform_handshake(
            conn, secure_conn, is_server=True, peer_id=client_ip
        )
        
        if not session_key:
            raise SecurityError("Handshake failed")

        message_count = 0
        last_message_time = time.time()
        
        while True:
            try:
                current_time = time.time()
                if current_time - last_message_time < 0.1:
                    time.sleep(0.1)
                
                data = secure_recv(conn, encryption_key=session_key)
                if data is None:
                    break
                
                message_count += 1
                last_message_time = current_time

                if message_count > 100:
                    Message.info(f"Too many messages from {client_ip}")
                    break
                
                if not isinstance(data, dict):
                    Message.info(f"Non-dict message from {client_ip}")
                    continue
                
                message_type = data.get("type")
                message_nonce = data.get("nonce", "")
                message_timestamp = data.get("timestamp", 0)

                if not check_nonce(message_nonce, client_ip):
                    Message.info(f"From {client_ip}")
                    continue
                
                if abs(current_time - message_timestamp) > 300:
                    Message.info(f"From {client_ip}")
                    continue

                if message_type == "signal_message":
                    handle_signal_message(data, conn, session_key, USER_PASSWORD)
                elif message_type == "message":
                    handle_message(data, conn, session_key, USER_PASSWORD)
                elif message_type == "friend_request":
                    handle_friend_request(data, conn, session_key, USER_PASSWORD)
                elif message_type == "friend_request_response":
                    handle_friend_request_response(data, conn, session_key, USER_PASSWORD)
                else:
                    Message.info(f"Type: {message_type} from {client_ip}")
                    send_error_response(conn, session_key, "Unknown message type")
                    
            except NetworkError as e:
                Message.warning(f"Network error with {client_ip}: {e}")
                break
            except Exception as e:
                Message.error(f"Error processing message from {client_ip}: {e}")
                Message.error(f"Error: {e} from {client_ip}")
                break
        
        connection_stats["successful"] += 1
        
    except SecurityError as e:
        Message.error(f"Security error with {client_ip}: {e}")
        connection_stats["failed"] += 1
        
    except Exception as e:
        Message.error(f"Connection error with {client_ip}: {e}")
        connection_stats["failed"] += 1
        
    finally:
        if session_key:
            try:
                session_key = b'\x00' * len(session_key)
            except:
                pass
            del session_key

        save_signal_sessions(USER_PASSWORD)
        gc.collect()
        
        try:
            conn.close()
        except:
            pass
        Message.info(f"Connection closed from {client_ip}")

def handle_signal_message(data, conn, session_key, USER_PASSWORD):
    try:
        sender_id = data.get("sender_id", "")
        signal_message = data.get("signal_message", {})
        
        if not validate_peer_id(sender_id):
            send_error_response(conn, session_key, "Invalid sender ID")
            return
        
        with _signal_lock:
            if sender_id not in signal_sessions:
                send_error_response(conn, session_key, "No Signal session found")
                return
            
            signal_session = signal_sessions[sender_id]
            
            try:
                # Decrypt the Signal message
                plaintext = signal_session.decrypt_message(signal_message)
                
                # Parse the decrypted message
                try:
                    decrypted_data = json.loads(plaintext)
                    message_text = decrypted_data.get("message", "")
                    sender_name = decrypted_data.get("sender_name", "Unknown")
                except json.JSONDecodeError:
                    message_text = plaintext
                    sender_name = "Unknown"
                
                Message.own("SIGNAL_MESSAGE", f"From {sender_name}: {message_text}")
                
                # Send acknowledgment
                response = {
                    "type": "signal_message_ack",
                    "status": "delivered",
                    "nonce": secrets.token_hex(16),
                    "timestamp": int(time.time())
                }
                secure_send(conn, response, session_key)
                
                # Save sessions after successful decrypt
                save_signal_sessions(USER_PASSWORD)
                
            except SignalProtocolError as e:
                Message.error(f"Signal Protocol error: {e}")
                send_error_response(conn, session_key, "Decryption failed")
                
    except Exception as e:
        Message.error(f"Error handling Signal message: {e}")
        send_error_response(conn, session_key, "Internal error")

def handle_message(data, conn, session_key, USER_PASSWORD):
    message_text = data.get("message", "")
    sender_info = data.get("sender_info", {})
    
    if len(message_text) > MAX_MESSAGE_SIZE:
        send_error_response(conn, session_key, "Message too long")
        return

    sender_name = sender_info.get("name", "Unknown")
    Message.own("MESSAGE", f"From {sender_name}: {message_text}")

    response = {
        "type": "message_ack",
        "status": "delivered",
        "nonce": secrets.token_hex(16),
        "timestamp": int(time.time())
    }
    secure_send(conn, response, session_key)

def handle_friend_request(data, conn, session_key, USER_PASSWORD):
    global pending_requests
    
    requester_id = data.get("requester_id", "")
    requester_name = data.get("requester_name", "Unknown")
    public_key_str = data.get("public_key", "")

    if not validate_peer_id(requester_id):
        send_error_response(conn, session_key, "Invalid requester ID")
        return
    
    if len(requester_name) > 50:
        send_error_response(conn, session_key, "Name too long")
        return

    try:
        peer_public_key = serialization.load_pem_public_key(
            base64.b64decode(public_key_str), backend=default_backend()
        )
        if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Not an EC key")
    except Exception as e:
        send_error_response(conn, session_key, "Invalid public key")
        return

    request_added = False
    with _network_lock:
        load_user_data(USER_PASSWORD)
        
        if requester_id not in pending_requests:
            pending_requests[requester_id] = {
                "name": requester_name,
                "public_key": public_key_str,
                "timestamp": time.time(),
                "verified": True
            }
            request_added = True

            if save_user_data(USER_PASSWORD):
                Message.own("FRIEND_REQUEST", f"New friend request from {requester_name} ({requester_id})")
            else:
                Message.error("Failed to save friend request!")
                request_added = False

    status = "received" if request_added else "failed"
    response = {
        "type": "friend_request_ack",
        "status": status,
        "nonce": secrets.token_hex(16),
        "timestamp": int(time.time())
    }
    secure_send(conn, response, session_key)

def handle_friend_request_response(data, conn, session_key, USER_PASSWORD):
    global friends, pending_requests
    
    responder_id = data.get("responder_id", "")
    status = data.get("status", "")
    
    if not validate_peer_id(responder_id):
        return
    
    with _network_lock:
        load_user_data(USER_PASSWORD)
        
        if status == "accepted":
            Message.info(f"Friend request accepted by {responder_id}")

            if responder_id not in friends:
                friends[responder_id] = {
                    "name": "Friend",
                    "public_key": "",
                    "added": time.time(),
                    "verified": True
                }
                save_user_data(USER_PASSWORD)
                Message.info(f"OK: {responder_id} added to your friends")
        
        elif status == "declined":
            Message.info(f"Friend request declined by {responder_id}")

def send_error_response(conn, session_key, error_message):
    try:
        error_response = {
            "type": "error",
            "message": error_message,
            "nonce": secrets.token_hex(16),
            "timestamp": int(time.time())
        }
        secure_send(conn, error_response, session_key)
    except:
        pass

def connect_to_peer(recipient_id, USER_PASSWORD, peer_public_key=None):
    if not validate_peer_id(recipient_id):
        Message.error("Invalid recipient ID")
        return None, None
    
    secure_conn = SecureConnection(USER_PASSWORD)
    load_user_data(USER_PASSWORD)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as control_socket:
            control_socket.settimeout(10)
            control_socket.connect(("127.0.0.1", 9051))
            control_socket.sendall(b"AUTHENTICATE \"\"\r\n")
            
            response = control_socket.recv(1024)
            if b"250" in response:
                control_socket.sendall(b"signal NEWNYM\r\n")
                response = control_socket.recv(1024)
                if b"250" not in response:
                    Message.warning("Failed to get new Tor circuit")
            else:
                Message.warning("Tor authentication failed")
            
    except Exception as e:
        Message.warning(f"Tor circuit renewal failed: {e}")

    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
    
    try:
        s.settimeout(CONNECTION_TIMEOUT)

        decoded_id = EncodeID.decode_token(recipient_id)
        address = f"{decoded_id}.onion"

        s.connect((address, 6300))
        Message.info(f"Connected to {recipient_id}")
        
        session_key, verified_public_key = perform_handshake(
            s, secure_conn, 
            is_server=False,
            peer_public_key=peer_public_key, 
            peer_id=recipient_id
        )
        
        if not session_key:
            raise SecurityError("Handshake failed")

        Message.info(f"Outbound access to {recipient_id}")
        return s, session_key
        
    except SecurityError as e:
        Message.error(f"Security handshake failed with {recipient_id}: {e}")
        try:
            s.close()
        except:
            pass
        return None, None
        
    except Exception as e:
        Message.error(f"Connection to {recipient_id} failed: {e}")
        try:
            s.close()
        except:
            pass
        return None, None

def send_signal_message(pid, USER_PASSWORD, recipient_id, message):
    load_user_data(USER_PASSWORD)
    
    with _network_lock:
        if recipient_id not in friends:
            Message.error(f"Error: ID {recipient_id} is not in friends list")
            return False
        
        if len(message) > MAX_MESSAGE_SIZE:
            Message.error("Message too long")
            return False
        
        friend_info = friends[recipient_id]

    with _signal_lock:
        if recipient_id not in signal_sessions:
            Message.warning(f"No Signal session with {recipient_id}, falling back to legacy")
            return send_message(pid, USER_PASSWORD, recipient_id, message)
        
        signal_session = signal_sessions[recipient_id]

    peer_public_key = None
    if friend_info.get("public_key"):
        try:
            peer_public_key = serialization.load_pem_public_key(
                base64.b64decode(friend_info["public_key"]), backend=default_backend()
            )
        except Exception as e:
            Message.warning(f"Invalid public key for {recipient_id}: {e}")
    
    s, session_key = connect_to_peer(recipient_id, USER_PASSWORD, peer_public_key)
    if not s:
        return False
    
    try:
        personal_data = load_encrypted_data("PersonalInfo.enc", USER_PASSWORD) or {}
        sender_name = personal_data.get("name", "Unknown")

        message_content = {
            "message": message,
            "sender_name": sender_name,
            "timestamp": int(time.time())
        }
        
        with _signal_lock:
            try:
                signal_message = signal_session.encrypt_message(json.dumps(message_content))
                
                signal_data = {
                    "type": "signal_message",
                    "sender_id": MyID.id(f"/usr/share/davell/tor/hiddenService"),
                    "signal_message": signal_message,
                    "nonce": secrets.token_hex(16),
                    "timestamp": int(time.time())
                }

                secure_send(s, signal_data, session_key)

                s.settimeout(10)
                response = secure_recv(s, encryption_key=session_key)
                
                if isinstance(response, dict) and response.get("status") == "delivered":
                    Message.info("OK: Signal message delivered successfully")
                    save_signal_sessions(USER_PASSWORD)
                    return True
                else:
                    Message.warning("Signal message delivery confirmation failed")
                    return False
                    
            except SignalProtocolError as e:
                Message.error(f"Signal Protocol error: {e}")
                return False
                
    except Exception as e:
        Message.error(f"Error sending Signal message: {e}")
        return False
    finally:
        if session_key:
            try:
                session_key = b'\x00' * len(session_key)
            except:
                pass
        gc.collect()
        s.close()

def send_message(pid, USER_PASSWORD, recipient_id, message):
    load_user_data(USER_PASSWORD)
    
    with _network_lock:
        if recipient_id not in friends:
            Message.error(f"Error: ID {recipient_id} is not in friends list")
            Message.error(f"Current friends: {list(friends.keys())}")
            return False
        
        if len(message) > MAX_MESSAGE_SIZE:
            Message.error("Message too long")
            return False
        
        friend_info = friends[recipient_id]

    peer_public_key = None
    if friend_info.get("public_key"):
        try:
            peer_public_key = serialization.load_pem_public_key(
                base64.b64decode(friend_info["public_key"]), backend=default_backend()
            )
        except Exception as e:
            Message.warning(f"Invalid public key for {recipient_id}: {e}")
    
    s, session_key = connect_to_peer(recipient_id, USER_PASSWORD, peer_public_key)
    if not s:
        return False
    
    try:
        personal_data = load_encrypted_data("PersonalInfo.enc", USER_PASSWORD) or {}
        sender_name = personal_data.get("name", "Unknown")

        message_data = {
            "type": "message",
            "message": message,
            "sender_info": {
                "name": sender_name,
                "id": MyID.id(f"/usr/share/davell/tor/hiddenService")
            },
            "nonce": secrets.token_hex(16),
            "timestamp": int(time.time())
        }

        secure_send(s, message_data, session_key)

        s.settimeout(10)
        response = secure_recv(s, encryption_key=session_key)
        
        if isinstance(response, dict) and response.get("status") == "delivered":
            Message.info("OK: Message delivered successfully")
            return True
        else:
            Message.warning("Message delivery confirmation failed")
            return False
            
    except Exception as e:
        Message.error(f"Error sending message: {e}")
        return False
    finally:
        if session_key:
            try:
                session_key = b'\x00' * len(session_key)
            except:
                pass
        gc.collect()
        s.close()

def reload_user_data(USER_PASSWORD):
    global friends, pending_requests
    
    with _network_lock:
        try:
            friends_data = load_encrypted_data("/usr/share/davell/storage/friends.enc", USER_PASSWORD)
            pending_data = load_encrypted_data("/usr/share/davell/storage/pending_requests.enc", USER_PASSWORD)

            if isinstance(friends_data, dict):
                friends = {k: v for k, v in friends_data.items() 
                          if validate_peer_id(k) and isinstance(v, dict)}
            else:
                friends = {}
                
            if isinstance(pending_data, dict):
                pending_requests = {k: v for k, v in pending_data.items() 
                                  if validate_peer_id(k) and isinstance(v, dict)}
            else:
                pending_requests = {}
        except:
            pass

    load_signal_sessions(USER_PASSWORD)
    
    with _network_lock:
        Message.info(f"Data reloaded - Friends: {len(friends)}, Pending: {len(pending_requests)}")
        
    with _signal_lock:
        Message.info(f"Signal sessions: {len(signal_sessions)}")
        
    return True

def send_friend_request(pid, USER_PASSWORD, recipient_id):
    if not validate_peer_id(recipient_id):
        Message.error("Invalid recipient ID")
        return False
    
    load_user_data(USER_PASSWORD)
    secure_conn = SecureConnection(USER_PASSWORD)
    
    s, session_key = connect_to_peer(recipient_id, USER_PASSWORD)
    if not s:
        return False
    
    try:
        personal_data = load_encrypted_data("PersonalInfo.enc", USER_PASSWORD) or {}
        user_name = personal_data.get("name", "Unknown")

        friend_request_data = {
            "type": "friend_request",
            "requester_id": MyID.id(f"/usr/share/davell/tor/hiddenService"),
            "requester_name": user_name,
            "public_key": base64.b64encode(secure_conn.PUBLIC_KEY.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode(),
            "nonce": secrets.token_hex(16),
            "timestamp": int(time.time())
        }
        
        secure_send(s, friend_request_data, session_key)

        s.settimeout(15)
        ack_response = secure_recv(s, encryption_key=session_key)
        
        if isinstance(ack_response, dict) and ack_response.get("type") == "friend_request_ack":
            Message.info("OK: Friend request sent successfully")
            return True
        else:
            Message.error("Friend request acknowledgment failed")
            return False
            
    except Exception as e:
        Message.error(f"Error sending friend request: {e}")
        return False
    finally:
        if session_key:
            try:
                session_key = b'\x00' * len(session_key)
            except:
                pass
        gc.collect()
        s.close()

def respond_to_friend_request(pid, USER_PASSWORD, requester_id, accept=True):
    if not validate_peer_id(requester_id):
        Message.error("Invalid requester ID")
        return False
    
    load_user_data(USER_PASSWORD)
    
    with _network_lock:
        if requester_id not in pending_requests:
            Message.error(f"No pending friend request from {requester_id}")
            return False
        
        requester_info = pending_requests[requester_id].copy()
    
    s, session_key = connect_to_peer(requester_id, USER_PASSWORD)
    if not s:
        return False
    
    try:
        response_data = {
            "type": "friend_request_response",
            "responder_id": MyID.id(f"/usr/share/davell/tor/hiddenService"),
            "status": "accepted" if accept else "declined",
            "nonce": secrets.token_hex(16),
            "timestamp": int(time.time())
        }
        
        secure_send(s, response_data, session_key)

        with _network_lock:
            load_user_data(USER_PASSWORD)
            
            if accept:
                if requester_id in pending_requests:
                    friends[requester_id] = {
                        "name": pending_requests[requester_id]["name"],
                        "public_key": pending_requests[requester_id]["public_key"],
                        "added": time.time(),
                        "verified": True
                    }

                    del pending_requests[requester_id]

                    if save_user_data(USER_PASSWORD):
                        Message.info(f"OK: {requester_info['name']} added to friends")
                    else:
                        Message.error("Failed to save friend data!")
                        return False
                else:
                    Message.error(f"Pending request for {requester_id} not found")
                    return False
            else:
                if requester_id in pending_requests:
                    del pending_requests[requester_id]
                    save_user_data(USER_PASSWORD)
                    Message.info(f"OK: Friend request from {requester_info['name']} declined")
        
        action = "accepted" if accept else "declined"
        Message.info(f"Friend Request {action.upper()}: From {requester_id}")
        return True
        
    except Exception as e:
        Message.error(f"Error responding to friend request: {e}")
        return False
    finally:
        if session_key:
            try:
                session_key = b'\x00' * len(session_key)
            except:
                pass
        gc.collect()
        s.close()

def reset_signal_session(USER_PASSWORD, peer_id):
    if not validate_peer_id(peer_id):
        Message.error("Invalid peer ID")
        return False
    
    with _signal_lock:
        if peer_id in signal_sessions:
            del signal_sessions[peer_id]
            save_signal_sessions(USER_PASSWORD)
            Message.info(f"Signal session with {peer_id} has been reset")
            return True
        else:
            Message.warning(f"No Signal session found with {peer_id}")
            return False

def get_connection_stats():
    return connection_stats.copy()

def get_pending_requests(USER_PASSWORD):
    load_user_data(USER_PASSWORD)
    with _network_lock:
        return pending_requests.copy()

def get_friends(USER_PASSWORD):
    load_user_data(USER_PASSWORD)
    with _network_lock:
        return friends.copy()

def get_signal_sessions(USER_PASSWORD):
    load_signal_sessions(USER_PASSWORD)
    with _signal_lock:
        session_info = {}
        for peer_id, session in signal_sessions.items():
            session_info[peer_id] = {
                "ns": session.ns,
                "nr": session.nr,
                "has_sending_chain": session.sending_chain_key is not None,
                "has_receiving_chain": session.receiving_chain_key is not None,
                "skipped_keys": len(session.skipped_keys)
            }
        return session_info

def network_diagnostics():
    Message.info("=== Network Diagnostics ===")
    stats = get_connection_stats()
    Message.info(f"Connections: {stats['total']} total, {stats['successful']} successful, {stats['failed']} failed")
    
    with _nonce_lock:
        Message.info(f"Active nonces: {len(used_nonces)}")
    
    with _network_lock:
        Message.info(f"Friends: {len(friends)}")
        Message.info(f"Pending requests: {len(pending_requests)}")
    
    with _signal_lock:
        Message.info(f"Signal Protocol sessions: {len(signal_sessions)}")
        for peer_id, session in signal_sessions.items():
            Message.info(f"  {peer_id}: NS={session.ns}, NR={session.nr}, Skipped={len(session.skipped_keys)}")

    try:
        test_socket = socks.socksocket()
        test_socket.set_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
        test_socket.settimeout(5)
        test_socket.connect(("check.torproject.org", 80))
        test_socket.close()
        Message.info("Tor connectivity: OK")
    except Exception as e:
        Message.warning(f"✗ Tor connectivity: {e}")

def cleanup_network():
    global used_nonces, pending_requests, friends, signal_sessions

    with _nonce_lock:
        used_nonces.clear()
    
    with _network_lock:
        pending_requests.clear()
        friends.clear()
    
    with _signal_lock:
        for session in signal_sessions.values():
            try:
                if hasattr(session, 'root_key'):
                    session.root_key = b'\x00' * len(session.root_key)
                if hasattr(session, 'sending_chain_key') and session.sending_chain_key:
                    session.sending_chain_key.key = b'\x00' * len(session.sending_chain_key.key)
                if hasattr(session, 'receiving_chain_key') and session.receiving_chain_key:
                    session.receiving_chain_key.key = b'\x00' * len(session.receiving_chain_key.key)
                for msg_key in session.skipped_keys.values():
                    msg_key.cipher_key = b'\x00' * len(msg_key.cipher_key)
                    msg_key.mac_key = b'\x00' * len(msg_key.mac_key)
                    msg_key.iv = b'\x00' * len(msg_key.iv)
                session.skipped_keys.clear()
            except:
                pass
        
        signal_sessions.clear()
    
    gc.collect()
    Message.info(f"Network module cleanup completed")


def export_signal_session(USER_PASSWORD, peer_id):
    if not validate_peer_id(peer_id):
        return None
    
    with _signal_lock:
        if peer_id not in signal_sessions:
            return None
        
        session = signal_sessions[peer_id]
        session_data = {
            'peer_id': peer_id,
            'root_key': base64.b64encode(session.root_key).decode(),
            'our_ratchet_key': base64.b64encode(session.our_ratchet_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )).decode(),
            'their_ratchet_key': base64.b64encode(session.their_ratchet_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode() if session.their_ratchet_key else None,
            'pn': session.pn,
            'ns': session.ns,
            'nr': session.nr,
            'timestamp': int(time.time())
        }

        try:
            return encrypt_data(json.dumps(session_data), USER_PASSWORD)
        except Exception as e:
            Message.error(f"Failed to export Signal session: {e}")
            return None

def import_signal_session(USER_PASSWORD, encrypted_session_data, peer_id):
    if not validate_peer_id(peer_id):
        return False
    
    try:
        decrypted_data = decrypt_data(encrypted_session_data, USER_PASSWORD)
        session_data = json.loads(decrypted_data)
        
        if session_data.get('peer_id') != peer_id:
            Message.error("Session data doesn't match peer ID")
            return False

        root_key = base64.b64decode(session_data['root_key'])
        our_ratchet_key = serialization.load_pem_private_key(
            base64.b64decode(session_data['our_ratchet_key']),
            password=None,
            backend=default_backend()
        )
        
        their_ratchet_key = None
        if session_data.get('their_ratchet_key'):
            their_ratchet_key = serialization.load_pem_public_key(
                base64.b64decode(session_data['their_ratchet_key']),
                backend=default_backend()
            )
        
        session = DoubleRatchetSession(root_key, our_ratchet_key, their_ratchet_key, sending=False)
        session.pn = session_data.get('pn', 0)
        session.ns = session_data.get('ns', 0)
        session.nr = session_data.get('nr', 0)
        
        with _signal_lock:
            signal_sessions[peer_id] = session
        
        save_signal_sessions(USER_PASSWORD)
        Message.info(f"Signal session imported for {peer_id}")
        return True
        
    except Exception as e:
        Message.error(f"Failed to import Signal session: {e}")
        return False

def verify_signal_session_integrity(peer_id):
    if not validate_peer_id(peer_id):
        return False
    
    with _signal_lock:
        if peer_id not in signal_sessions:
            return False
        
        session = signal_sessions[peer_id]

        checks = []
        checks.append(len(session.root_key) == ROOT_KEY_LENGTH)
        checks.append(isinstance(session.our_ratchet_key, ec.EllipticCurvePrivateKey))
        checks.append(session.ns >= 0)
        checks.append(session.nr >= 0)
        checks.append(session.pn >= 0)
        checks.append(len(session.skipped_keys) <= MAX_SKIP)
        
        if session.sending_chain_key:
            checks.append(len(session.sending_chain_key.key) == CHAIN_KEY_LENGTH)
            checks.append(session.sending_chain_key.index >= 0)
        
        if session.receiving_chain_key:
            checks.append(len(session.receiving_chain_key.key) == CHAIN_KEY_LENGTH)
            checks.append(session.receiving_chain_key.index >= 0)
        
        return all(checks)

def get_signal_session_info(peer_id):
    if not validate_peer_id(peer_id):
        return None
    
    with _signal_lock:
        if peer_id not in signal_sessions:
            return None
        
        session = signal_sessions[peer_id]
        
        return {
            'peer_id': peer_id,
            'message_numbers': {
                'sending': session.ns,
                'receiving': session.nr,
                'previous_chain': session.pn
            },
            'chain_keys': {
                'has_sending': session.sending_chain_key is not None,
                'has_receiving': session.receiving_chain_key is not None,
                'sending_index': session.sending_chain_key.index if session.sending_chain_key else None,
                'receiving_index': session.receiving_chain_key.index if session.receiving_chain_key else None
            },
            'skipped_messages': len(session.skipped_keys),
            'integrity_ok': verify_signal_session_integrity(peer_id)
        }

def send_message_auto(pid, USER_PASSWORD, recipient_id, message, force_signal=False):
    load_user_data(USER_PASSWORD)
    
    with _network_lock:
        if recipient_id not in friends:
            Message.error(f"Error: ID {recipient_id} is not in friends list")
            return False
    
    with _signal_lock:
        has_signal_session = recipient_id in signal_sessions
    
    if has_signal_session:
        Message.info(f"Using Signal Protocol for {recipient_id}")
        return send_signal_message(pid, USER_PASSWORD, recipient_id, message)
    elif force_signal:
        Message.error(f"Signal Protocol required but no session exists with {recipient_id}")
        return False
    else:
        Message.warning(f"No Signal session with {recipient_id}, using legacy messaging")
        return send_message(pid, USER_PASSWORD, recipient_id, message)

def establish_signal_session_with_friend(pid, USER_PASSWORD, friend_id):
    if not validate_peer_id(friend_id):
        Message.error("Invalid friend ID")
        return False
    
    load_user_data(USER_PASSWORD)
    
    with _network_lock:
        if friend_id not in friends:
            Message.error(f"ID {friend_id} is not in friends list")
            return False
    
    with _signal_lock:
        if friend_id in signal_sessions:
            Message.info(f"Signal session with {friend_id} already exists")
            return True

    s, session_key = connect_to_peer(friend_id, USER_PASSWORD)
    if s:
        try:
            s.close()
            with _signal_lock:
                if friend_id in signal_sessions:
                    Message.info(f"Signal Protocol session established with {friend_id}")
                    return True
                else:
                    Message.warning(f"Failed to establish Signal session with {friend_id}")
                    return False
        except:
            pass
    
    return False


def list_signal_sessions(USER_PASSWORD):
    session_info = get_signal_sessions(USER_PASSWORD)
    
    if not session_info:
        Message.info("No active Signal Protocol sessions")
        return
    
    Message.info("=== Signal Protocol Sessions ===")
    for peer_id, info in session_info.items():
        status = "OK" if info["has_sending_chain"] and info["has_receiving_chain"] else "WAR"
        Message.info(f"{status} {peer_id}:")
        Message.info(f"    Sent: {info['ns']} messages")
        Message.info(f"    Received: {info['nr']} messages") 
        if info['skipped_keys'] > 0:
            Message.info(f"    Skipped keys: {info['skipped_keys']}")

def signal_session_status(USER_PASSWORD, peer_id=None):
    if peer_id:
        info = get_signal_session_info(peer_id)
        if not info:
            Message.error(f"No Signal session found with {peer_id}")
            return
        
        Message.info(f"=== Signal Session: {peer_id} ===")
        Message.info(f"Sending message number: {info['message_numbers']['sending']}")
        Message.info(f"Receiving message number: {info['message_numbers']['receiving']}")
        Message.info(f"Previous chain length: {info['message_numbers']['previous_chain']}")
        Message.info(f"Has sending chain: {'Yes' if info['chain_keys']['has_sending'] else 'No'}")
        Message.info(f"Has receiving chain: {'Yes' if info['chain_keys']['has_receiving'] else 'No'}")
        Message.info(f"Skipped messages: {info['skipped_messages']}")
        Message.info(f"Integrity check: {'✓ PASS' if info['integrity_ok'] else '✗ FAIL'}")
    else:
        list_signal_sessions(USER_PASSWORD)

def send_msg(pid, USER_PASSWORD, recipient_id, message, use_signal=True):
    if use_signal:
        return send_message_auto(pid, USER_PASSWORD, recipient_id, message, force_signal=False)
    else:
        return send_message(pid, USER_PASSWORD, recipient_id, message)