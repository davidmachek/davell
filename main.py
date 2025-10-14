import MyID as MyID
import Message as Message

from Network import save_persistent_cert, save_encrypted_data, load_encrypted_data, load_persistent_cert, handle_client, secure_send, secure_recv, derive_shared_key, send_message, respond_to_friend_request, send_friend_request

import tkinter as tk
import tkinter.font as tkFont
from tkinter import simpledialog, messagebox
import tkinter.font as tkFont
import Maskot
import cmd2
import socket, threading, shutil, os, sys, json, time, socks
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import secrets
import base64
import random
import gc
import argparse
import EncodeID
import getpass
import signal
import atexit
import re
from collections import defaultdict
import pwd
import grp
import subprocess
import shlex
import hashlib
import uuid
from pathlib import Path

print(random.choice([Maskot.firstMaskot, Maskot.secondMaskot]))

USER_PASSWORD = None
PERSISTENT_CERT = None
PUBLIC_KEY = None
NAME = None

_data_lock = threading.RLock()
_rate_limit_lock = threading.RLock()
_nonce_lock = threading.RLock()

friends = {}
pending_requests = {}
PORT = random.randint(10000, 60000)

DEBUG_MODE = False
MAX_MESSAGE_SIZE = 8192
CONNECTION_TIMEOUT = 30
MAX_CONNECTIONS = 10
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 100
CUSTOM = False

connection_attempts = defaultdict(list)
message_attempts = defaultdict(list)
used_nonces = {}

def safe_coords(widget, *args):
    try:
        if widget.winfo_exists():
            widget.coords(*args)
    except tk.TclError:
        pass

def safe_delete(widget, *args):
    try:
        if widget.winfo_exists():
            widget.delete(*args)
    except tk.TclError:
        pass

def safe_create_oval(canvas, *args, **kwargs):
    try:
        if canvas.winfo_exists():
            return canvas.create_oval(*args, **kwargs)
    except tk.TclError:
        pass
    return None


def safe_compare_strings(str1, str2):
    if str1 is None or str2 is None:
        return False
    if isinstance(str1, str):
        str1 = str1.encode('utf-8')
    if isinstance(str2, str):
        str2 = str2.encode('utf-8')
    
    return secrets.compare_digest(str1, str2)

def rate_limit_check(identifier, limit_dict, max_requests=MAX_REQUESTS_PER_WINDOW):
    with _rate_limit_lock:
        current_time = time.time()
        
        # Clean old entries
        for key in list(limit_dict.keys()):
            limit_dict[key] = [t for t in limit_dict[key] if current_time - t < RATE_LIMIT_WINDOW]
            if not limit_dict[key]:
                del limit_dict[key]

        if identifier not in limit_dict:
            limit_dict[identifier] = []
        
        if len(limit_dict[identifier]) >= max_requests:
            return False
        
        limit_dict[identifier].append(current_time)
        return True

def validate_message_size(data):
    if isinstance(data, str):
        return len(data.encode()) <= MAX_MESSAGE_SIZE
    return len(str(data).encode()) <= MAX_MESSAGE_SIZE

def validate_peer_id(peer_id):
    if not peer_id or not isinstance(peer_id, str):
        return False
    # More strict validation
    pattern = r'^[A-Za-z0-9_-]{16,64}$'
    return bool(re.match(pattern, peer_id))

def secure_memory_clear(data):
    try:
        if data is None:
            return
        
        if isinstance(data, str):
            data = None
        elif isinstance(data, bytes):
            b = bytearray(data)
            for i in range(len(b)):
                b[i] = 0
            del b
        elif isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
            del data

        gc.collect()
        
    except Exception:
        try:
            del data
        except Exception:
            pass

def debug_log(message):
    global DEBUG_MODE
    if DEBUG_MODE:
        Message.info(f"DEBUG: {message}")

def safe_compare_strings(str1, str2):
    if str1 is None or str2 is None:
        return False
    if isinstance(str1, str):
        str1 = str1.encode('utf-8')
    if isinstance(str2, str):
        str2 = str2.encode('utf-8')
    
    return secrets.compare_digest(str1, str2)

def rate_limit_check(identifier, limit_dict, max_requests=MAX_REQUESTS_PER_WINDOW):
    with _rate_limit_lock:
        current_time = time.time()
        
        # Clean old entries
        for key in list(limit_dict.keys()):
            limit_dict[key] = [t for t in limit_dict[key] if current_time - t < RATE_LIMIT_WINDOW]
            if not limit_dict[key]:
                del limit_dict[key]

        if identifier not in limit_dict:
            limit_dict[identifier] = []
        
        if len(limit_dict[identifier]) >= max_requests:
            return False
        
        limit_dict[identifier].append(current_time)
        return True

def validate_message_size(data):
    if isinstance(data, str):
        return len(data.encode()) <= MAX_MESSAGE_SIZE
    return len(str(data).encode()) <= MAX_MESSAGE_SIZE

def validate_peer_id(peer_id):
    if not peer_id or not isinstance(peer_id, str):
        return False
    # More strict validation
    pattern = r'^[A-Za-z0-9_-]{16,64}$'
    return bool(re.match(pattern, peer_id))

def secure_memory_clear(data):
    try:
        if data is None:
            return
        
        if isinstance(data, str):
            data = None
        elif isinstance(data, bytes):
            b = bytearray(data)
            for i in range(len(b)):
                b[i] = 0
            del b
        elif isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
            del data

        gc.collect()
        
    except Exception:
        try:
            del data
        except Exception:
            pass

def get_password():
    try:
        password = getpass.getpass("Enter your password: ")
        if len(password) < 8:
            Message.error("Password must be at least 8 characters long")
            secure_memory_clear(password)
            return get_password()
        return password
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

def get_new_password():
    while True:
        password1 = getpass.getpass("Enter new password (min 8 chars): ")
        if len(password1) < 8:
            Message.error("Password must be at least 8 characters long")
            secure_memory_clear(password1)
            continue
            
        password2 = getpass.getpass("Confirm password: ")
        if safe_compare_strings(password1, password2):
            secure_memory_clear(password2)
            return password1
        else:
            Message.error("Passwords do not match. Try again.")
            secure_memory_clear(password1)
            secure_memory_clear(password2)

def get_new_name():
    while True:
        name = input("Enter your display name: ").strip()
        if len(name) >= 3 and len(name) <= 50:
            if not re.match(r'^[A-Za-z0-9\s_.-]+$', name):
                Message.error("Name contains invalid characters. Use only letters, numbers, spaces, _, ., -")
                continue
            return name
        else:
            Message.error("Name must be between 3-50 characters")

def change_password():
    global USER_PASSWORD
    
    with _data_lock:
        if not USER_PASSWORD:
            Message.error("No current password set")
            return
        
        current_password = getpass.getpass("Enter current password: ")
        if not safe_compare_strings(current_password, USER_PASSWORD):
            Message.error("Incorrect current password")
            secure_memory_clear(current_password)
            return
        
        secure_memory_clear(current_password)
        new_password = get_new_password()
        old_password = USER_PASSWORD
        
        try:
            USER_PASSWORD = new_password

            if PERSISTENT_CERT:
                save_persistent_cert(USER_PASSWORD, PERSISTENT_CERT)

            save_encrypted_data(USER_PASSWORD, {"name": NAME}, "/usr/share/davell/storage/PersonalInfo.enc", use_password=True)
            save_encrypted_data(USER_PASSWORD, friends, "/usr/share/davell/storage/friends.enc", use_password=True)
            save_encrypted_data(USER_PASSWORD, pending_requests, "/usr/share/davell/storage/pending_requests.enc", use_password=True)

            secure_memory_clear(old_password)
            
            Message.info("Password changed successfully")
            
        except Exception as e:
            USER_PASSWORD = old_password
            secure_memory_clear(new_password)
            Message.error(f"Failed to change password: {e}")

def change_name():
    global NAME
    
    new_name = get_new_name()
    
    with _data_lock:
        old_name = NAME
        NAME = new_name
        
        try:
            save_encrypted_data(USER_PASSWORD, {"name": NAME}, "/usr/share/davell/storage/PersonalInfo.enc", use_password=True)
            Message.info(f"Name changed from {old_name} to {NAME}")
        except Exception as e:
            NAME = old_name
            Message.error(f"Failed to change name: {e}")

def load_user_data():
    global friends, pending_requests, NAME
    
    with _data_lock:
        try:
            # Load personal info first
            personal_data = load_encrypted_data("/usr/share/davell/storage/PersonalInfo.enc", USER_PASSWORD)
            if isinstance(personal_data, dict):
                NAME = personal_data.get("name", NAME)
                save_encrypted_data(USER_PASSWORD, {"name": NAME}, "/usr/share/davell/storage/PersonalInfo.enc", use_password=True)
            
            # Load friends
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
                
        except Exception as e:
            debug_log(f"Failed to load user data: {e}")
            friends = {}
            pending_requests = {}

def save_user_data():
    with _data_lock:
        try:
            
            save_encrypted_data(USER_PASSWORD, {"name": NAME}, "/usr/share/davell/storage/PersonalInfo.enc", use_password=True)
            save_encrypted_data(USER_PASSWORD, friends, "/usr/share/davell/storage/friends.enc", use_password=True)
            save_encrypted_data(USER_PASSWORD, pending_requests, "/usr/share/davell/storage/pending_requests.enc", use_password=True)
            return True
        except Exception as e:
            Message.error(f"Failed to save user data: {e}")
            return False

def create_secure_file(filename, mode=0o600):
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                pass

        os.chmod(filename, mode)
        return True
    except Exception as e:
        debug_log(f"Failed to create secure file {filename}: {e}")
        return False

def initialize_system(pid):
    global USER_PASSWORD, PERSISTENT_CERT, PUBLIC_KEY, NAME
    
    # Ensure storage directories exist
    storage_dirs = [
        "/usr/share/davell/storage",
        "/usr/share/davell/storage/certs",
        "/usr/share/davell/tor"
    ]
    for dir_path in storage_dirs:
        os.makedirs(dir_path, exist_ok=True)
        os.chmod(dir_path, 0o700)
    
    if os.path.exists("/usr/share/davell/storage/certs/persistent_cert.pem"):
        USER_PASSWORD = get_password()

        PERSISTENT_CERT = load_persistent_cert(USER_PASSWORD)
        if not PERSISTENT_CERT:
            Message.error("Failed to load certificate. System may be corrupted.")
            response = input("Create new system? (yes/no): ")
            if response.lower() == 'yes':
                secure_memory_clear(USER_PASSWORD)
                create_new_system()
                return
            else:
                secure_memory_clear(USER_PASSWORD)
                sys.exit(1)
        
        PUBLIC_KEY = PERSISTENT_CERT.public_key()

        try:
            personal_data = load_encrypted_data("/usr/share/davell/storage/PersonalInfo.enc", USER_PASSWORD)
            if isinstance(personal_data, dict):
                NAME = personal_data.get("name")
                
            if not NAME:
                raise ValueError("Name not found")
                
            save_encrypted_data(USER_PASSWORD, {"name": NAME}, "/usr/share/davell/storage/PersonalInfo.enc", use_password=True)
                
        except Exception as e:
            debug_log(f"Failed to load personal info: {e}")
            Message.warning("Personal info corrupted, using default name")
            NAME = f"DMSuser_{random.randint(100000, 999999)}"
            save_encrypted_data(USER_PASSWORD, {"name": NAME}, "/usr/share/davell/storage/PersonalInfo.enc", use_password=True)

        load_user_data()
        
        Message.info(f"System loaded. Welcome back, {NAME}!")
        
        # Try to get Tor ID
        myid = MyID.id('/usr/share/davell/tor/hiddenService')
        if myid == False:
            Message.warning("Could not find hostname; please check if Tor Service is running.")
        else:
            Message.info(f"Your Tor ID: {myid}")
        
    else:
        Message.info("No existing system found. Creating new system...")
        create_new_system()

def create_new_system():
    global USER_PASSWORD, PERSISTENT_CERT, PUBLIC_KEY, NAME, friends, pending_requests
    
    Message.info("=== Creating New Davell System ===")
    USER_PASSWORD = get_new_password()
    NAME = get_new_name()

    # Generate cryptographic identity
    PERSISTENT_CERT = ec.generate_private_key(ec.SECP384R1(), default_backend())
    PUBLIC_KEY = PERSISTENT_CERT.public_key()
    try:
        # Ensure directories exist
        os.makedirs("/usr/share/davell/storage/certs", exist_ok=True)
        os.chmod("/usr/share/davell/storage", 0o700)
        os.chmod("/usr/share/davell/storage/certs", 0o700)
        
        save_persistent_cert(USER_PASSWORD, PERSISTENT_CERT)
        save_encrypted_data(USER_PASSWORD, {"name": NAME}, "/usr/share/davell/storage/PersonalInfo.enc", use_password=True)

        friends = {}
        pending_requests = {}
        save_encrypted_data(USER_PASSWORD, friends, "/usr/share/davell/storage/friends.enc", use_password=True)
        save_encrypted_data(USER_PASSWORD, pending_requests, "/usr/share/davell/storage/pending_requests.enc", use_password=True)

        # Set secure file permissions
        for filename in ["/usr/share/davell/storage/certs/persistent_cert.pem", "/usr/share/davell/storage/PersonalInfo.enc", "/usr/share/davell/storage/friends.enc", "/usr/share/davell/storage/pending_requests.enc"]:
            if os.path.exists(filename):
                os.chmod(filename, 0o600)
        
        Message.info("System created successfully!")
        Message.info(f"Your name: {NAME}")        
        # Try to get Tor ID
        myid = MyID.id('/usr/share/davell/tor/hiddenService')
        if myid == False:
            Message.warning("Could not find hostname; please check if Tor Service is running.")
        else:
            Message.info(f"Your Tor ID: {myid}")
        
    except Exception as e:
        Message.error(f"Failed to create system: {e}")
        secure_memory_clear(USER_PASSWORD)
        sys.exit(1)

def create_system():
    response = input("This will delete your current identity and create a new one. Continue? (yes/no): ")
    if response.lower() != 'yes':
        Message.info("Operation cancelled")
        return

    files_to_remove = ["/usr/share/davell/storage/certs/persistent_cert.pem", "/usr/share/davell/storage/friends.enc", "/usr/share/davell/storage/pending_requests.enc", "/usr/share/davell/storage/PersonalInfo.enc"]
    for file in files_to_remove:
        try:
            if os.path.exists(file):
                # Secure file deletion
                with open(file, 'rb+') as f:
                    length = f.seek(0, 2)
                    f.seek(0)
                    f.write(secrets.token_bytes(length))
                    f.flush()
                    os.fsync(f.fileno())
                os.remove(file)
        except Exception as e:
            Message.warning(f"Could not remove {file}: {e}")
    
    create_new_system()

def check_nonce_thread_safe(nonce, peer_id="unknown"):
    if not nonce or len(nonce) < 16:
        return False
    
    with _nonce_lock:
        current_time = time.time()

        # Clean expired nonces (5 minutes)
        expired_nonces = [n for n, t in used_nonces.items() 
                         if current_time - t > 300]
        for n in expired_nonces:
            del used_nonces[n]
        
        if nonce in used_nonces:
            return False
        
        used_nonces[nonce] = current_time
        return True

def is_tor_running():
    """Check if Tor is running"""
    try:
        result = subprocess.run(["pgrep", "tor"], capture_output=True, text=True)
        return result.returncode == 0 and result.stdout.strip()
    except:
        return False

def get_available_port(start_port=9050, end_port=9060):
    """Find an available port for Tor"""
    for port in range(start_port, end_port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    return None

def setup_tor_hidden_service(custom=False):
    Message.info(f"PID: {os.getpid()}")
    
    # Check if Tor is already running
    if is_tor_running():
        Message.info("Tor is already running")
        if custom:
            Message.info("Using existing Tor configuration")
            return True
    else:
        Message.warning("Tor is not running")
    
    if custom:
        Message.info("Custom Tor mode - using system configuration")
        Message.info("Tor Configuration: Using system default")
        Message.info("Tor Data: Using system default")
        Message.info("Hidden Service: Using system configuration")
        return True
    
    try:
        # Create Tor directories
        tor_dirs = [
            "/usr/share/davell/tor",
            "/usr/share/davell/tor/data", 
            "/usr/share/davell/tor/hiddenService"
        ]
        
        for dir_path in tor_dirs:
            os.makedirs(dir_path, exist_ok=True)
            os.chmod(dir_path, 0o700)
        
        # Find available ports
        socks_port = get_available_port(9050, 9080)
        control_port = get_available_port(9051, 9090)
        
        if not socks_port or not control_port:
            Message.warning("Could not find available ports for Tor")
            return None
        
        # Update global Tor configuration
        global TOR_SOCKS_PORT
        TOR_SOCKS_PORT = socks_port
        
        torrc_content = f"""
SocksPort {socks_port}
ControlPort {control_port}
DataDirectory /usr/share/davell/tor/data
HiddenServiceDir /usr/share/davell/tor/hiddenService
HiddenServicePort 6300 127.0.0.1:{PORT}
Log notice file /dev/null
"""
        
        with open("/usr/share/davell/tor/torrc", "w") as f:
            f.write(torrc_content)

        os.chmod("/usr/share/davell/tor/torrc", 0o600)
        
        Message.info("Tor configuration prepared")
        Message.info(f"SOCKS Port: {socks_port}")
        Message.info(f"Control Port: {control_port}")
        return True
        
    except Exception as e:
        debug_log(f"Tor setup failed: {e}")
        Message.warning("Using system Tor configuration")
        return None

def cleanup_on_exit():
    try:
        global USER_PASSWORD, PERSISTENT_CERT
        secure_memory_clear(USER_PASSWORD)
        gc.collect()
    except:
        pass

def signal_handler(signum, frame):
    Message.info("\nShutting down securely...")
    cleanup_on_exit()
    sys.exit(0)

# Register cleanup handlers
atexit.register(cleanup_on_exit)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

parser = argparse.ArgumentParser(description="Davell Message System V0.4 - Privacy-Focused Secure Messenger")
parser.add_argument("-c", "--custom", type=int,
                    help="Use a custom local port for the hidden service and use system Tor config")
parser.add_argument("-gui",action="store_true",
                    help="GUI version")
args = parser.parse_args()

if args.custom:
    CUSTOM = True
    PORT = args.custom

TOR_PROCESS = setup_tor_hidden_service(custom=CUSTOM)
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
actualPrompt = " >> "

class Internet:
    @staticmethod
    def server():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", PORT))
            s.listen(MAX_CONNECTIONS)
            Message.info(f"Secure server running on port {PORT}")
            
            while True:
                try:
                    conn, addr = s.accept()

                    if not rate_limit_check(addr[0], connection_attempts, 10):
                        conn.close()
                        continue

                    conn.settimeout(CONNECTION_TIMEOUT)

                    threading.Thread(
                        target=handle_client, 
                        args=(os.getpid(), USER_PASSWORD, conn, addr), 
                        daemon=True
                    ).start()
                    
                except Exception as e:
                    debug_log(f"Server accept error: {e}")
                    
        except Exception as e:
            Message.error(f"Server startup failed: {e}")
    
    @staticmethod
    def client(ServerID):
        if not validate_peer_id(ServerID):
            Message.error("Invalid Server ID")
            return
        
        try:
            if not rate_limit_check("outgoing", message_attempts, 20):
                Message.error("Too many connection attempts. Please wait.")
                return
            
            DecodeServerID = EncodeID.decode_token(ServerID)
            ONION_ADDRESS = f"{DecodeServerID}.onion"

            # Try to renew Tor circuit
            try:
                control_port = 9051  # Default control port
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as control_socket:
                    control_socket.settimeout(5)
                    control_socket.connect(("127.0.0.1", control_port))
                    control_socket.sendall(b"AUTHENTICATE \"\"\r\n")
                    response = control_socket.recv(1024)
                    if b"250" in response:
                        control_socket.sendall(b"signal NEWNYM\r\n")
                        control_socket.recv(1024)  # Read response
                    control_socket.close()
            except Exception as e:
                debug_log(f"Tor circuit renewal failed: {e}")
            
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
            
            try:
                s.settimeout(CONNECTION_TIMEOUT)
                s.connect((ONION_ADDRESS, 6300))
                Message.info(f"Connected to {ServerID}")

                peer_public_key = None
                with _data_lock:
                    if ServerID in friends:
                        try:
                            key_data = base64.b64decode(friends[ServerID]["public_key"])
                            peer_public_key = serialization.load_pem_public_key(key_data, default_backend())
                        except Exception as e:
                            debug_log(f"Failed to load peer public key: {e}")

                from Network import connect_to_peer
                session_key = None
                try:
                    conn, session_key = connect_to_peer(ServerID, USER_PASSWORD, peer_public_key)
                    if conn and session_key:
                        Message.info("Connection established successfully")

                        with _data_lock:
                            if ServerID not in friends:
                                debug_log(f"Connected to {ServerID} but they are not a friend")
                        
                        conn.close()
                    else:
                        Message.error("Handshake failed")
                        
                except Exception as e:
                    Message.error(f"Connection failed: {e}")
                finally:
                    if session_key:
                        secure_memory_clear(session_key)
                    
            except Exception as e:
                Message.error(f"Connection failed: {e}")
            finally:
                gc.collect()
                s.close()
                
        except Exception as e:
            Message.error(f"Client error: {e}")

def reset_system():
    confirm1 = input("WARNING: This will permanently delete ALL data! Type 'DELETE' to confirm: ")
    if confirm1 != 'DELETE':
        Message.info("Reset cancelled")
        return
    
    confirm2 = input("Are you absolutely sure? This cannot be undone! (yes/no): ")
    if confirm2.lower() != 'yes':
        Message.info("Reset cancelled")
        return
    
    files_to_remove = [
        "/usr/share/davell/storage/certs/persistent_cert.pem",
        "/usr/share/davell/storage/friends.enc", 
        "/usr/share/davell/storage/pending_requests.enc",
        "/usr/share/davell/storage/PersonalInfo.enc",
    ]
    
    for file in files_to_remove:
        try:
            if os.path.exists(file):
                # Secure file deletion
                with open(file, 'rb+') as f:
                    length = f.seek(0, 2)
                    f.seek(0)
                    f.write(secrets.token_bytes(length))
                    f.flush()
                    os.fsync(f.fileno())
                os.remove(file)
                Message.info(f"Securely removed {file}")
        except Exception as e:
            Message.error(f"Error removing {file}: {e}")

    Message.info("System reset complete. Restart to create new system.")
    cleanup_on_exit()
    sys.exit(0)

def start_tor():
    if CUSTOM:
        Message.warning("Cannot start Tor automatically in custom mode.")
        return

    if is_tor_running():
        Message.info("Tor is already running")
        return

    Message.info("Starting Tor service...")
    
    TOR_FILE = "/usr/share/davell/tor/torrc"
    
    if not os.path.exists(TOR_FILE):
        Message.error("Tor configuration file not found. Run setup first.")
        return
    
    tor_started_event = threading.Event()

    def tor_run():
        try:
            Message.info("Starting Tor process...")
            with subprocess.Popen(
                ["tor", "-f", TOR_FILE],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid  # Create new process group
            ) as proc:
                tor_started_event.set()
                for line in proc.stdout:
                    line = line.rstrip()
                    if line:
                        Message.own("TOR", line)
                        # Check for successful startup
                        if "Bootstrapped 100%" in line:
                            Message.info("Tor fully initialized")
                            
        except Exception as e:
            Message.error(f"Failed to start Tor: {e}")

    t = threading.Thread(target=tor_run, daemon=True)
    t.start()

    # Wait for Tor to start
    if tor_started_event.wait(timeout=10):
        time.sleep(5)  # Give Tor time to initialize
        if is_tor_running():
            Message.info("Tor started successfully")
        else:
            Message.warning("Tor process started but may not be fully ready")
    else:
        Message.warning("Tor startup timeout")

class Console(cmd2.Cmd):
    prompt = actualPrompt
    intro = "Davell Message System V0.4. Type 'help' for commands."
    
    def __init__(self):
        super().__init__()

    def do_exit(self, args):
        """Exit Application"""
        cleanup_on_exit()
        sys.exit(0)
    
    def do_quit(self, args):
        """Exit Application (alias for exit)"""
        self.do_exit(args)
    
    def do_version(self, args):
        """Show Version"""
        Message.own("VERSION", "Davell Message System Version 0.4")
    
    def do_start_tor(self, args):
        """Automatic Tor Startup"""
        start_tor()

    def do_davell(self, args):
        """Show Short Info and Logo"""
        print(random.choice([Maskot.firstMaskot, Maskot.secondMaskot]))
    
    def do_clear(self, args):
        """Clear screen"""
        os.system("clear" if os.name == "posix" else "cls")
    
    def do_cls(self, args):
        """Clear screen (alias for clear)"""
        self.do_clear(args)

    def do_debug_enable(self, args):
        """Enable debug mode"""
        global DEBUG_MODE
        DEBUG_MODE = True
        Message.info("Debug mode enabled")
    
    def do_debug_disable(self, args):
        """Disable debug mode"""
        global DEBUG_MODE
        DEBUG_MODE = False
        Message.info("Debug mode disabled")
    
    def do_debug_data(self, args):
        """Show debug data (requires debug mode)"""
        global DEBUG_MODE
        if DEBUG_MODE:
            load_user_data()
            with _data_lock:
                Message.info("DEBUG: Data Status:")
                Message.info(f"Friends: {friends}")
                Message.info(f"Pending requests: {pending_requests}")
                Message.info(f"Friends count: {len(friends)}")
                Message.info(f"Pending count: {len(pending_requests)}")
                Message.info(f"Debug mode: {DEBUG_MODE}")
                Message.info(f"Port: {PORT}")
        else:
            Message.error("Enable debug mode first with 'debug_enable'")
    
    # Identity Management Commands
    def do_create(self, args):
        """Create new System (overwrites current)"""
        create_system()
    
    def do_change_name(self, args):
        """Change your Display Name"""
        change_name()
    
    def do_change_password(self, args):
        """Change your Password"""
        change_password()
    
    # Information Commands
    def do_info(self, args):
        """Show your ID and Display Name"""
        Message.info(f"My Name: {NAME}")
        
        myid = MyID.id('/usr/share/davell/tor/hiddenService')
        if myid == False:
            Message.warning("Could not find Tor hostname; please check if Tor Service is running.")
        else:
            Message.info(f"My Tor ID: {myid}")
    
    def do_id(self, args):
        """Show your IDs"""
        myid = MyID.id('/usr/share/davell/tor/hiddenService')
        if myid == False:
            Message.warning("Could not find Tor hostname; please check if Tor Service is running.")
        else:
            Message.info(f"My Tor ID: {myid}")
    
    def do_name(self, args):
        """Show your Display Name"""
        Message.info(f"My Name: {NAME}")
    
    def do_pid(self, args):
        """Show Process ID"""
        Message.info(f"PID: {os.getpid()}")
    
    # Friend Management Commands
    def do_friends(self, args):
        """List your Friends"""
        load_user_data()
        with _data_lock:
            Message.own("FRIENDS", "==== Friends ====")
            if not friends:
                Message.own("FRIENDS", "No friends yet")
            else:
                for friend_id, friend_info in friends.items():
                    status = "OK" if friend_info.get('verified', False) else "UN"
                    name = friend_info.get('name', 'Unknown')
                    timestamp = friend_info.get('added', 0)
                    added_date = time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp)) if timestamp else "Unknown"
                    imported = " [IMPORTED]" if friend_info.get('imported', False) else ""
                    Message.own("FRIENDS", f"{status} {friend_id}  | {name} | Added: {added_date}{imported}")
    
    def do_requests(self, args):
        """List pending friend requests"""
        load_user_data()
        with _data_lock:
            Message.own("REQUESTS", "==== Pending Friend Requests ====")
            if not pending_requests:
                Message.own("REQUESTS", "No pending requests")
            else:
                for requester_id, request_info in pending_requests.items():
                    timestamp = time.ctime(request_info.get('timestamp', 0))
                    name = request_info.get('name', 'Unknown')
                    verified = " [VERIFIED]" if request_info.get('verified', False) else " [UNVERIFIED]"
                    Message.own("REQUESTS", f"{requester_id}  | {name} | {timestamp}{verified}")
    
    def do_add(self, args):
        """Send a Friend Request to a user
        Usage: add <user_id>"""
        args = args.strip()
        if not args:
            Message.error("Usage: add <user_id>")
            return
            
        friend_id = args.strip()
        if not validate_peer_id(friend_id):
            Message.error("Invalid user ID format")
            return

        # Check if trying to add self using persistent ID
        if friend_id == MyID.id('/usr/share/davell/tor/hiddenService'):
            if DEBUG_MODE:
                Message.warning("Testing mode: Adding self as friend (debug mode only)")
                with _data_lock:
                    load_user_data()
                    if friend_id not in pending_requests:
                        pending_requests[friend_id] = {
                            "name": NAME,
                            "public_key": base64.b64encode(PUBLIC_KEY.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )).decode(),
                            "timestamp": time.time(),
                            "verified": True
                        }
                        save_user_data()
                        Message.info("Test friend request created - you can now accept it")
                        return
                    else:
                        Message.error("Self friend request already exists")
                        return
            else:
                Message.error("Cannot add yourself as a friend (enable debug mode for testing: debug_enable)")
                return
        
        # Check if trying to add self using Tor ID
        my_tor_id = MyID.id('/usr/share/davell/tor/hiddenService')
        if friend_id == my_tor_id:
            Message.error("Cannot add yourself as a friend")
            return
                        
        with _data_lock:
            load_user_data()
            if friend_id in friends:
                Message.error(f"{friend_id} is already your friend")
                return
                            
        success = send_friend_request(os.getpid(), USER_PASSWORD, friend_id)
        if success:
            Message.info(f"Friend request sent to {friend_id}")
    
    def do_accept(self, args):
        """Accept a pending friend request
        Usage: accept <user_id>"""
        args = args.strip()
        if not args:
            Message.error("Usage: accept <user_id>")
            return
            
        friend_id = args.strip()
        if not validate_peer_id(friend_id):
            Message.error("Invalid user ID format")
            return

        load_user_data()    
        with _data_lock:
            if friend_id not in pending_requests:
                Message.error(f"No pending friend request from {friend_id}")
                Message.info("Use 'requests' to see pending requests")
                return
                            
        success = respond_to_friend_request(os.getpid(), USER_PASSWORD, friend_id, accept=True)
        if success:
            Message.info(f"Friend request from {friend_id} accepted")
            load_user_data()
    
    def do_decline(self, args):
        """Decline a pending friend request
        Usage: decline <user_id>"""
        args = args.strip()
        if not args:
            Message.error("Usage: decline <user_id>")
            return
            
        friend_id = args.strip()
        if not validate_peer_id(friend_id):
            Message.error("Invalid user ID format")
            return
  
        load_user_data()
        with _data_lock:
            if friend_id not in pending_requests:
                Message.error(f"No pending friend request from {friend_id}")
                Message.info("Use 'requests' to see pending requests")
                return
                            
        success = respond_to_friend_request(os.getpid(), USER_PASSWORD, friend_id, accept=False)
        if success:
            Message.info(f"Friend request from {friend_id} declined")
            load_user_data()
    
    def do_remove(self, args):
        """Remove a friend from your friends list
        Usage: remove <user_id>"""
        args = args.strip()
        if not args:
            Message.error("Usage: remove <user_id>")
            return
            
        friend_id = args.strip()
        if not validate_peer_id(friend_id):
            Message.error("Invalid user ID format")
            return
        
        load_user_data()
        with _data_lock:
            if friend_id not in friends:
                Message.error(f"{friend_id} is not in your friends list")
                return
            
            confirm = input(f"Are you sure you want to remove {friends[friend_id].get('name', friend_id)}? (yes/no): ")
            if confirm.lower() == 'yes':
                friend_name = friends[friend_id].get('name', friend_id)
                del friends[friend_id]
                if save_user_data():
                    Message.info(f"Removed {friend_name} from friends list")
                else:
                    Message.error("Failed to save changes")
            else:
                Message.info("Operation cancelled")

    def do_message(self, args):
        """Send a message to a friend
        Usage: message <user_id> <message>"""
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            Message.error("Usage: message <user_id> <message>")
            return
            
        user_id = parts[0]
        message = parts[1]
        
        if not validate_peer_id(user_id):
            Message.error("Invalid user ID format")
            return
                    
        if not validate_message_size(message):
            Message.error("Message too long")
            return

        load_user_data()
        with _data_lock:
            if user_id not in friends:
                Message.error(f"ID {user_id} is not in friends list.")
                Message.info("Use 'friends' to see your friends list")
                return
            
            if not friends[user_id].get('public_key'):
                Message.warning(f"Missing public key for {user_id}. This might still work via handshake.")
        
        success = send_message(os.getpid(), USER_PASSWORD, user_id, message)
        if success:
            Message.info("Message sent successfully")
        else:
            Message.error("Failed to send message")
    
    def do_msg(self, args):
        """Send a message to a friend (alias for message)
        Usage: msg <user_id> <message>"""
        self.do_message(args)
    
    # Connection Commands
    def do_connect(self, args):
        """Connect to a peer for testing
        Usage: connect <user_id>"""
        args = args.strip()
        if not args:
            Message.error("Usage: connect <user_id>")
            return
            
        server_id = args.strip()
        Internet.client(server_id)
    
    # System Status Commands
    def do_security_status(self, args):
        """Show security status"""
        Message.info("=== Security Status ===")
        Message.info(f"Certificate: {'✓ Loaded' if PERSISTENT_CERT else '✗ Missing'}")
        Message.info(f"Password: {'✓ Set' if USER_PASSWORD else '✗ Not set'}")
        with _data_lock:
            Message.info(f"Friends: {len(friends)}")
            Message.info(f"Pending requests: {len(pending_requests)}")
        Message.info(f"Server port: {PORT}")
        Message.info(f"Tor SOCKS port: {TOR_SOCKS_PORT}")
        Message.info(f"Debug mode: {'On' if DEBUG_MODE else 'Off'}")
        Message.info(f"Custom Tor: {'Yes' if CUSTOM else 'No'}")
        Message.info(f"Tor running: {'Yes' if is_tor_running() else 'No'}")
    
    def do_status(self, args):
        """Show system status (alias for security_status)"""
        self.do_security_status(args)
    
    def do_configuration(self, args):
        """Show Tor Configuration"""
        if CUSTOM:
            Message.info("Tor Configuration: Using system default")
            Message.info("Tor Data: Using system default")
            Message.info("Hidden Service: Using system configuration")
        else:
            Message.info("Tor Configuration: /usr/share/davell/tor/torrc")
            Message.info("Tor Data: /usr/share/davell/tor/data")
            Message.info("Hidden Service: /usr/share/davell/tor/hiddenService")
    
    def do_config(self, args):
        """Show Tor Configuration (alias for configuration)"""
        self.do_configuration(args)
    
    # Data Management Commands
    def do_reload_data(self, args):
        """Reload user data from files"""
        load_user_data()
        Message.info("User data reloaded successfully")
        with _data_lock:
            Message.info(f"Friends: {len(friends)}, Pending: {len(pending_requests)}")
    
    def do_reload(self, args):
        """Reload user data from files (alias for reload_data)"""
        self.do_reload_data(args)
    
    def do_save_data(self, args):
        """Manually save user data to files"""
        if save_user_data():
            Message.info("User data saved successfully")
        else:
            Message.error("Failed to save user data")
    
    def do_save(self, args):
        """Manually save user data to files (alias for save_data)"""
        self.do_save_data(args)
    
    def do_backup(self, args):
        """Create a backup of your encrypted data
        Usage: backup [directory]"""
        import shutil
        backup_dir = args.strip() or f"/tmp/davell_backup_{int(time.time())}"
        
        try:
            os.makedirs(backup_dir, exist_ok=True)
            
            files_to_backup = [
                "/usr/share/davell/storage/certs/persistent_cert.pem",
                "/usr/share/davell/storage/friends.enc",
                "/usr/share/davell/storage/pending_requests.enc",
                "/usr/share/davell/storage/PersonalInfo.enc"
            ]
            
            backed_up = 0
            for file in files_to_backup:
                if os.path.exists(file):
                    shutil.copy2(file, backup_dir)
                    backed_up += 1
            
            if backed_up > 0:
                Message.info(f"Backup created in: {backup_dir}")
                Message.info(f"Files backed up: {backed_up}")
                os.chmod(backup_dir, 0o700)
            else:
                Message.warning("No files found to backup")
                
        except Exception as e:
            Message.error(f"Backup failed: {e}")
    
    # Testing Commands
    def do_test_self(self, args):
        """Add yourself as friend (testing only)"""
        if not DEBUG_MODE:
            Message.error("Enable debug mode first with 'debug_enable'")
            return
            
        Message.warning("TESTING: Creating self friend request for testing purposes")
        with _data_lock:
            load_user_data()
            if MyID.id('/usr/share/davell/tor/hiddenService') not in pending_requests:
                pending_requests[MyID.id('/usr/share/davell/tor/hiddenService')] = {
                    "name": NAME,
                    "public_key": base64.b64encode(PUBLIC_KEY.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )).decode(),
                    "timestamp": time.time(),
                    "verified": True
                }
                if save_user_data():
                    Message.info(f"Test friend request created from yourself")
                    Message.info(f"You can now use: accept {MyID.id('/usr/share/davell/tor/hiddenService')}")
                else:
                    Message.error("Failed to save test friend request")
            else:
                Message.error("Self friend request already exists")
    
    def do_test_message(self, args):
        """Send a test message to yourself (debug mode only)"""
        global DEBUG_MODE
        if not DEBUG_MODE:
            Message.error("Enable debug mode first with 'debug_enable'")
            return
        
        if MyID.id('/usr/share/davell/tor/hiddenService') not in friends:
            Message.error("You need to be friends with yourself first. Use 'test_self' then 'accept'")
            return
        
        test_message = args.strip() or "Test message from Davell system"
        self.do_message(f"{MyID.id('/usr/share/davell/tor/hiddenService')} {test_message}")
    
    # Advanced Commands
    def do_reset(self, args):
        """Reset the System completely"""
        reset_system()
    
    def do_export_friend(self, args):
        """Export friend's public information for sharing
        Usage: export_friend <user_id>"""
        args = args.strip()
        if not args:
            Message.error("Usage: export_friend <user_id>")
            return
        
        friend_id = args.strip()
        load_user_data()
        
        with _data_lock:
            if friend_id not in friends:
                Message.error(f"{friend_id} is not in your friends list")
                return
            
            friend_info = friends[friend_id]
            export_data = {
                "id": friend_id,
                "name": friend_info.get('name', 'Unknown'),
                "public_key": friend_info.get('public_key', ''),
                "verified": friend_info.get('verified', False),
                "exported_by": NAME,
                "exported_at": time.time(),
                "export_version": "0.4"
            }
            
            filename = f"/tmp/davell_friend_{friend_id[:8]}_{int(time.time())}.json"
            try:
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                os.chmod(filename, 0o600)
                Message.info(f"Friend info exported to: {filename}")
            except Exception as e:
                Message.error(f"Export failed: {e}")
    
    def do_import_friend(self, args):
        """Import friend from exported file
        Usage: import_friend <filename>"""
        args = args.strip()
        if not args:
            Message.error("Usage: import_friend <filename>")
            return
        
        filename = args.strip()
        try:
            with open(filename, 'r') as f:
                import_data = json.load(f)
            
            required_fields = ['id', 'name', 'public_key']
            if not all(field in import_data for field in required_fields):
                Message.error("Invalid friend export file format")
                return
            
            friend_id = import_data['id']
            if not validate_peer_id(friend_id):
                Message.error("Invalid friend ID in export file")
                return
            
            load_user_data()
            with _data_lock:
                if friend_id in friends:
                    Message.error(f"{friend_id} is already your friend")
                    return
                
                friends[friend_id] = {
                    'name': import_data['name'],
                    'public_key': import_data['public_key'],
                    'verified': False,  # Always false for imported friends
                    'added': time.time(),
                    'imported': True
                }
                
                if save_user_data():
                    Message.info(f"Friend {import_data['name']} ({friend_id}) imported successfully")
                    Message.warning("Friend imported but not verified - use with caution")
                else:
                    Message.error("Failed to save imported friend")
                    
        except FileNotFoundError:
            Message.error(f"File not found: {filename}")
        except json.JSONDecodeError:
            Message.error("Invalid JSON file format")
        except Exception as e:
            Message.error(f"Import failed: {e}")
    
    def do_network_status(self, args):
        """Show network and connection status"""
        Message.info("=== Network Status ===")
        Message.info(f"Local port: {PORT}")
        Message.info(f"Tor SOCKS: {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}")
        
        # Check Tor connectivity
        tor_running = is_tor_running()
        Message.info(f"Tor process: {'✓ Running' if tor_running else '✗ Not running'}")
        
        # Check if hidden service hostname exists
        my_tor_id = MyID.id('/usr/share/davell/tor/hiddenService')
        Message.info(f"Hidden service: {'✓ Available' if my_tor_id else '✗ Not available'}")
        
        # Test Tor connectivity
        if tor_running:
            try:
                test_socket = socks.socksocket()
                test_socket.set_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
                test_socket.settimeout(5)
                test_socket.connect(("check.torproject.org", 80))
                test_socket.close()
                Message.info("Tor connectivity: ✓ Working")
            except Exception as e:
                Message.info(f"Tor connectivity: ✗ Failed ({str(e)[:50]})")
        
        # Show rate limiting stats
        with _rate_limit_lock:
            Message.info(f"Active connection attempts: {len(connection_attempts)}")
            Message.info(f"Active message attempts: {len(message_attempts)}")
    
    def do_cleanup(self, args):
        """Manually cleanup temporary files and memory"""
        cleanup_on_exit()
        # Clean rate limiting data
        with _rate_limit_lock:
            connection_attempts.clear()
            message_attempts.clear()
        # Clean nonces
        with _nonce_lock:
            used_nonces.clear()
        gc.collect()
        Message.info("Cleanup completed")
    
    def do_uptime(self, args):
        """Show system uptime (since startup)"""
        Message.info("System running (uptime tracking not implemented)")
        Message.info(f"PID: {os.getpid()}")
    
    def do_whoami(self, args):
        """Show current user information"""
        Message.info(f"Name: {NAME}")
        my_tor_id = MyID.id('/usr/share/davell/tor/hiddenService')
        if my_tor_id:
            Message.info(f"Tor ID: {my_tor_id}")
        else:
            Message.warning("Tor ID not available - check Tor status")
        Message.info(f"Debug mode: {'Enabled' if DEBUG_MODE else 'Disabled'}")
    
    def do_verify_friend(self, args):
        """Manually verify a friend's identity (advanced users)
        Usage: verify_friend <user_id>"""
        args = args.strip()
        if not args:
            Message.error("Usage: verify_friend <user_id>")
            return
        
        friend_id = args.strip()
        load_user_data()
        
        with _data_lock:
            if friend_id not in friends:
                Message.error(f"{friend_id} is not in your friends list")
                return
            
            if friends[friend_id].get('verified', False):
                Message.info(f"{friends[friend_id]['name']} is already verified")
                return
            
            Message.warning("Manual verification should only be done after confirming identity through other means!")
            confirm = input(f"Are you sure you want to verify {friends[friend_id]['name']}? (yes/no): ")
            
            if confirm.lower() == 'yes':
                friends[friend_id]['verified'] = True
                friends[friend_id]['verified_at'] = time.time()
                
                if save_user_data():
                    Message.info(f"{friends[friend_id]['name']} marked as verified")
                else:
                    Message.error("Failed to save verification status")
            else:
                Message.info("Verification cancelled")

class GUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Davell Messenge System V0.4GUI")
        self.root.geometry("1000x700")
        self.root.minsize(800, 500)
        self.root.configure(bg="#0a0a0a")

        self.default_font = tkFont.Font(family="Segoe UI", size=12)
        self.profile_color = "#dc2626"
        self.username = NAME if NAME else "User"
        self.password = "********"
        
        self.animation_speed = 10
        self.menu_open = False
        self.pulse_animations = {}

        self.selected_contact = None
        self.contacts = {}
        self.message_history = {}

        self.load_real_data()
        self.setup_main_view()

    def load_real_data(self):
        """Načte skutečná data ze systému"""
        global friends, pending_requests, NAME
        
        # Načti aktuální data
        load_user_data()
        
        # Aktualizuj jméno
        self.username = NAME if NAME else "User"
        
        # Připrav kontakty z friends
        self.contacts = {}
        for friend_id, friend_data in friends.items():
            self.contacts[friend_id] = {
                "color": f"#{random.randint(100, 200):02x}4444",
                "last_seen": "online" if friend_data.get('verified', False) else "offline",
                "last_message": friend_data.get('last_message', 'No messages yet'),
                "time": time.strftime("%H:%M", time.localtime(friend_data.get('added', time.time()))),
                "name": friend_data.get('name', friend_id[:8]),
                "verified": friend_data.get('verified', False)
            }
        
        # Načti message history pokud existuje
        try:
            msg_data = load_encrypted_data("/usr/share/davell/storage/message_history.enc", USER_PASSWORD)
            if isinstance(msg_data, dict):
                self.message_history = msg_data
        except:
            self.message_history = {}

    def save_message_history(self):
        """Uloží message history"""
        try:
            save_encrypted_data(USER_PASSWORD, self.message_history, "/usr/share/davell/storage/message_history.enc", use_password=True)
        except Exception as e:
            debug_log(f"Failed to save message history: {e}")

    def stop_all_animations(self):
        """Zastaví všechny aktivní animace"""
        for canvas_id in list(self.pulse_animations.keys()):
            self.pulse_animations[canvas_id] = False

    def setup_main_view(self):
        self.stop_all_animations()
        
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.main_frame = tk.Frame(self.root, bg="#0a0a0a")
        self.main_frame.pack(fill="both", expand=True)

        # Top bar
        top_bar = tk.Canvas(self.main_frame, bg="#1a0000", height=70, highlightthickness=0)
        top_bar.pack(side="top", fill="x")
        
        for i in range(70):
            color_val = int(26 - (i * 0.2))
            color = f"#{color_val:02x}0000"
            top_bar.create_line(0, i, 1000, i, fill=color, width=1)

        # Search box
        search_frame = tk.Frame(top_bar, bg="#1a1a1a", height=40)
        search_frame.place(x=20, y=15, width=400, height=40)
        
        self.top_search_var = tk.StringVar()
        self.top_search_entry = tk.Entry(search_frame, textvariable=self.top_search_var, 
                                   font=("Segoe UI", 12), bg="#1a1a1a", fg="#666666",
                                   insertbackground="#dc2626", relief="flat", borderwidth=0)
        self.top_search_entry.pack(fill="both", expand=True, padx=15, pady=5)
        self.top_search_entry.insert(0, "🔍 Search...")
        self.top_search_entry.bind("<FocusIn>", lambda e: self.on_top_search_focus_in())
        self.top_search_entry.bind("<FocusOut>", lambda e: self.on_top_search_focus_out())
        self.top_search_entry.bind("<KeyRelease>", self.search_contacts)

        # Zakulacené rohy pro search frame
        self.create_rounded_rectangle(top_bar, 20, 15, 420, 55, 20, fill="#1a1a1a", outline="")

        # Menu button
        self.menu_button = tk.Button(top_bar, text="☰", font=("Arial", 20), 
                                   bg="#dc2626", fg="white", relief="flat",
                                   command=self.toggle_menu, cursor="hand2",
                                   activebackground="#b91c1c", activeforeground="white",
                                   borderwidth=0, highlightthickness=0)
        top_bar.create_window(950, 35, window=self.menu_button, width=40, height=40)
        self.round_button(self.menu_button)

        # Add friend button
        self.add_friend_btn = tk.Button(top_bar, text="+", font=("Arial", 20), 
                                      bg="#dc2626", fg="white", relief="flat",
                                      command=self.add_friend_dialog, cursor="hand2",
                                      activebackground="#b91c1c", activeforeground="white",
                                      borderwidth=0, highlightthickness=0)
        top_bar.create_window(900, 35, window=self.add_friend_btn, width=40, height=40)
        self.round_button(self.add_friend_btn)

        # Levý panel
        self.left_panel = tk.Frame(self.main_frame, bg="#0f0f0f", width=350)
        self.left_panel.pack(side="left", fill="y")
        self.left_panel.pack_propagate(False)

        self.contacts_canvas = tk.Canvas(self.left_panel, bg="#0f0f0f", highlightthickness=0)
        self.contacts_canvas.pack(fill="both", expand=True)
        
        self.contacts_frame = tk.Frame(self.contacts_canvas, bg="#0f0f0f")
        self.contacts_canvas.create_window((0, 0), window=self.contacts_frame, anchor="nw")
        
        self.update_contacts_list()
        self.animate_contacts_in()

        # Pravý panel
        self.right_panel = tk.Frame(self.main_frame, bg="#0a0a0a")
        self.right_panel.pack(side="right", fill="both", expand=True)

        self.show_placeholder()

    def create_rounded_rectangle(self, canvas, x1, y1, x2, y2, radius, **kwargs):
        """Vytvoří zakulacený obdélník"""
        points = [
            x1+radius, y1,
            x2-radius, y1,
            x2, y1,
            x2, y1+radius,
            x2, y2-radius,
            x2, y2,
            x2-radius, y2,
            x1+radius, y2,
            x1, y2,
            x1, y2-radius,
            x1, y1+radius,
            x1, y1
        ]
        return canvas.create_polygon(points, smooth=True, **kwargs)

    def round_button(self, button):
        def on_enter(e):
            button.config(bg="#b91c1c")
        def on_leave(e):
            button.config(bg="#dc2626")
        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)

    def on_top_search_focus_in(self):
        if self.top_search_entry.get() == "🔍 Search...":
            self.top_search_entry.delete(0, tk.END)
            self.top_search_entry.config(fg="white")

    def on_top_search_focus_out(self):
        if not self.top_search_entry.get():
            self.top_search_entry.insert(0, "🔍 Search...")
            self.top_search_entry.config(fg="#666666")

    def search_contacts(self, event):
        """Filtruje kontakty podle hledaného textu"""
        search_term = self.top_search_var.get().lower()
        if search_term == "🔍 search...":
            search_term = ""
        
        for widget in self.contacts_frame.winfo_children():
            contact_name = getattr(widget, 'contact_id', None)
            if contact_name:
                display_name = self.contacts[contact_name]["name"].lower()
                if search_term in display_name or search_term in contact_name.lower():
                    widget.pack(fill="x", pady=1)
                else:
                    widget.pack_forget()

    def animate_contacts_in(self):
        for i, widget in enumerate(self.contacts_frame.winfo_children()):
            widget.pack_forget()
            self.root.after(i * 50, lambda w=widget: self.slide_in_contact(w))

    def slide_in_contact(self, widget):
        if widget.winfo_exists():
            widget.pack(fill="x", pady=1)

    def update_contacts_list(self):
        self.stop_all_animations()
        
        for widget in self.contacts_frame.winfo_children():
            widget.destroy()

        for contact_id, data in self.contacts.items():
            self.create_contact_widget(contact_id, data)

    def create_contact_widget(self, contact_id, data):
        contact_frame = tk.Frame(self.contacts_frame, bg="#0f0f0f", cursor="hand2")
        contact_frame.pack(fill="x", pady=2)
        contact_frame.contact_id = contact_id  # Uloží ID pro vyhledávání
        
        def on_enter(e):
            if self.selected_contact != contact_id:
                contact_frame.config(bg="#1a1a1a")
                for child in contact_frame.winfo_children():
                    try:
                        child.config(bg="#1a1a1a")
                    except:
                        pass
        
        def on_leave(e):
            if self.selected_contact != contact_id:
                contact_frame.config(bg="#0f0f0f")
                for child in contact_frame.winfo_children():
                    try:
                        child.config(bg="#0f0f0f")
                    except:
                        pass
        
        contact_frame.bind("<Enter>", on_enter)
        contact_frame.bind("<Leave>", on_leave)

        # Avatar
        avatar_canvas = tk.Canvas(contact_frame, bg="#0f0f0f", width=50, height=50, 
                                 highlightthickness=0)
        avatar_canvas.pack(side="left", padx=15, pady=10)
        avatar_canvas.create_oval(5, 5, 45, 45, fill=data["color"], outline="")
        avatar_canvas.create_text(25, 25, text=data["name"][0].upper(), 
                                 font=("Segoe UI", 16, "bold"), fill="white")

        # Text část
        text_frame = tk.Frame(contact_frame, bg="#0f0f0f")
        text_frame.pack(side="left", fill="x", expand=True, padx=(0, 15), pady=10)

        top_frame = tk.Frame(text_frame, bg="#0f0f0f")
        top_frame.pack(fill="x")
        
        name_label = tk.Label(top_frame, text=data["name"], font=("Segoe UI", 14, "bold"), 
                            bg="#0f0f0f", fg="white", anchor="w")
        name_label.pack(side="left", fill="x", expand=True)
        
        time_label = tk.Label(top_frame, text=data["time"], font=("Segoe UI", 10), 
                            bg="#0f0f0f", fg="#666666")
        time_label.pack(side="right")

        bottom_frame = tk.Frame(text_frame, bg="#0f0f0f")
        bottom_frame.pack(fill="x")
        
        message_label = tk.Label(bottom_frame, text=data["last_message"], 
                               font=("Segoe UI", 11), bg="#0f0f0f", fg="#999999",
                               anchor="w")
        message_label.pack(side="left", fill="x", expand=True)
        
        # Online status a verify badge
        status_frame = tk.Frame(bottom_frame, bg="#0f0f0f")
        status_frame.pack(side="right", padx=(5, 0))
        
        if data["verified"]:
            verify_label = tk.Label(status_frame, text="✓", font=("Segoe UI", 10, "bold"),
                                  bg="#0f0f0f", fg="#22c55e")
            verify_label.pack(side="left", padx=(0, 5))

        if data["last_seen"] == "online":
            status_canvas = tk.Canvas(status_frame, bg="#0f0f0f", width=12, height=12, 
                                     highlightthickness=0)
            status_canvas.pack(side="right")
            canvas_id = id(status_canvas)
            self.pulse_animations[canvas_id] = True
            self.pulse_status(status_canvas, canvas_id)

        def select_contact(e):
            self.selected_contact = contact_id
            self.update_contacts_list()
            self.open_chat(contact_id)
        
        for widget in [contact_frame, avatar_canvas, text_frame]:
            widget.bind("<Button-1>", select_contact)

        # Context menu
        def show_context_menu(e):
            menu = tk.Menu(self.root, tearoff=0, bg="#1a1a1a", fg="white",
                          activebackground="#dc2626", activeforeground="white")
            menu.add_command(label="Send Message", command=lambda: self.open_chat(contact_id))
            menu.add_command(label="Remove Friend", command=lambda: self.remove_friend(contact_id))
            menu.add_separator()
            menu.add_command(label="View Profile", command=lambda: self.view_profile(contact_id))
            try:
                menu.tk_popup(e.x_root, e.y_root)
            finally:
                menu.grab_release()

        contact_frame.bind("<Button-3>", show_context_menu)

    def pulse_status(self, canvas, canvas_id, size=8, growing=True):
        """Bezpečná pulsující animace"""
        if canvas_id not in self.pulse_animations or not self.pulse_animations[canvas_id]:
            return
        
        try:
            if not canvas.winfo_exists():
                self.pulse_animations[canvas_id] = False
                return
        except tk.TclError:
            self.pulse_animations[canvas_id] = False
            return
        
        if growing:
            size += 0.5
            if size >= 10:
                growing = False
        else:
            size -= 0.5
            if size <= 8:
                growing = True
        
        safe_delete(canvas, "all")
        offset = (10 - size) / 2
        safe_create_oval(canvas, offset, offset, offset + size, offset + size, 
                        fill="#22c55e", outline="")
        
        self.root.after(50, lambda: self.pulse_status(canvas, canvas_id, size, growing))

    def show_placeholder(self):
        for widget in self.right_panel.winfo_children():
            widget.destroy()
        
        placeholder_frame = tk.Frame(self.right_panel, bg="#0a0a0a")
        placeholder_frame.pack(fill="both", expand=True)
        
        canvas = tk.Canvas(placeholder_frame, bg="#0a0a0a", highlightthickness=0)
        canvas.pack(expand=True)
        
        if not self.contacts:
            text = canvas.create_text(400, 300, text="No friends yet\n\nClick + to add friends", 
                                     font=("Segoe UI", 16), fill="#dc2626", justify="center")
        else:
            text = canvas.create_text(400, 350, text="Select a chat to start messaging", 
                                     font=("Segoe UI", 20), fill="#dc2626")
        
        def animate_placeholder(y=0, direction=1):
            try:
                if canvas.winfo_exists():
                    if not self.contacts:
                        safe_coords(canvas, text, 400, 300 + y)
                    else:
                        safe_coords(canvas, text, 400, 350 + y)
                    y += direction * 0.5
                    if y > 10 or y < -10:
                        direction *= -1
                    self.root.after(30, lambda: animate_placeholder(y, direction))
            except tk.TclError:
                pass
        
        animate_placeholder()

    def open_chat(self, contact_id):
        self.selected_contact = contact_id
        self.load_chat(contact_id)

    def load_chat(self, contact_id):
        for widget in self.right_panel.winfo_children():
            widget.destroy()

        # Chat header
        header_canvas = tk.Canvas(self.right_panel, bg="#1a0000", height=70, highlightthickness=0)
        header_canvas.pack(side="top", fill="x")
        
        for i in range(70):
            color_val = int(26 - (i * 0.2))
            color = f"#{color_val:02x}0000"
            header_canvas.create_line(0, i, 1000, i, fill=color, width=1)

        contact_data = self.contacts[contact_id]
        
        # Avatar
        header_canvas.create_oval(20, 15, 60, 55, fill=contact_data["color"], outline="")
        header_canvas.create_text(40, 35, text=contact_data["name"][0].upper(), 
                                 font=("Segoe UI", 16, "bold"), fill="white")

        # Jméno a status
        header_canvas.create_text(75, 27, text=contact_data["name"], anchor="w",
                                 font=("Segoe UI", 14, "bold"), fill="white")
        
        status_text = f"{contact_data['last_seen']} • {contact_id[:16]}..."
        if contact_data["verified"]:
            status_text = "✓ Verified • " + status_text
            
        header_canvas.create_text(75, 47, text=status_text, anchor="w",
                                 font=("Segoe UI", 11), fill="#22c55e" if contact_data["last_seen"] == "online" else "#666666")

        # Chat area
        chat_container = tk.Frame(self.right_panel, bg="#0a0a0a")
        chat_container.pack(fill="both", expand=True)

        self.chat_canvas = tk.Canvas(chat_container, bg="#0a0a0a", highlightthickness=0)
        scrollbar = tk.Scrollbar(chat_container, orient="vertical", 
                                command=self.chat_canvas.yview, bg="#dc2626",
                                troughcolor="#1a1a1a", activebackground="#b91c1c")
        self.scroll_frame = tk.Frame(self.chat_canvas, bg="#0a0a0a")

        self.scroll_frame.bind(
            "<Configure>",
            lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
        )

        self.chat_canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
        self.chat_canvas.configure(yscrollcommand=scrollbar.set)

        self.chat_canvas.pack(side="left", fill="both", expand=True, padx=(10, 0))
        scrollbar.pack(side="right", fill="y", padx=(0, 10))

        # Input area
        input_frame = tk.Frame(self.right_panel, bg="#0a0a0a", height=80)
        input_frame.pack(side="bottom", fill="x")
        input_frame.pack_propagate(False)

        input_container = tk.Frame(input_frame, bg="#1a1a1a", height=50)
        input_container.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.95)
        
        # Entry widget
        self.message_var = tk.StringVar()
        self.message_entry = tk.Entry(input_container, textvariable=self.message_var, 
                                    font=("Segoe UI", 14), bg="#1a1a1a", fg="white",
                                    insertbackground="#dc2626", relief="flat", 
                                    borderwidth=0, highlightthickness=0)
        self.message_entry.pack(side="left", fill="both", expand=True, padx=15, pady=10)
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.focus_set()

        # Send button
        send_btn = tk.Button(input_container, text="➤", font=("Arial", 16, "bold"),
                           bg="#dc2626", fg="white", relief="flat", cursor="hand2",
                           command=lambda: self.send_message(None),
                           activebackground="#b91c1c", width=3, height=1,
                           borderwidth=0, highlightthickness=0)
        send_btn.pack(side="right", padx=10)
        
        def hover_send(e):
            send_btn.config(bg="#b91c1c")
        def leave_send(e):
            send_btn.config(bg="#dc2626")
        
        send_btn.bind("<Enter>", hover_send)
        send_btn.bind("<Leave>", leave_send)

        self.load_message_history(contact_id)

    def load_message_history(self, contact_id):
        # Načti existující zprávy
        if contact_id in self.message_history:
            for i, msg_data in enumerate(self.message_history[contact_id]):
                self.root.after(i * 100, lambda m=msg_data: self.add_chat_message(
                    m["text"], m["sender"], m["time"]))

    def add_chat_message(self, msg, sender="me", msg_time=None):
        if not msg_time:
            msg_time = time.strftime("%H:%M")
        
        # Container pro správné zarovnání
        container = tk.Frame(self.scroll_frame, bg="#0a0a0a")
        container.pack(fill="x", pady=5)
        
        if sender == "me":
            # Moje zprávy vpravo
            bubble_color = "#dc2626"
            text_color = "white"
            bubble_frame = tk.Frame(container, bg=bubble_color, padx=15, pady=10)
            bubble_frame.pack(side="right", padx=20)
        else:
            # Zprávy ostatních vlevo
            bubble_color = "#1a1a1a"
            text_color = "white"
            bubble_frame = tk.Frame(container, bg=bubble_color, padx=15, pady=10)
            bubble_frame.pack(side="left", padx=20)
        
        msg_label = tk.Label(bubble_frame, text=msg, font=("Segoe UI", 13), 
                           bg=bubble_color, fg=text_color, wraplength=400, justify="left")
        msg_label.pack()
        
        time_label = tk.Label(bubble_frame, text=msg_time, font=("Segoe UI", 9),
                            bg=bubble_color, fg="#999999")
        time_label.pack(anchor="e")
        
        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    def send_message(self, event):
        msg = self.message_var.get().strip()
        if not msg or not self.selected_contact:
            return
        
        current_time = time.strftime("%H:%M")
        self.add_chat_message(msg, "me", current_time)
        
        # Ulož do message history
        if self.selected_contact not in self.message_history:
            self.message_history[self.selected_contact] = []
        self.message_history[self.selected_contact].append({
            "sender": "me", 
            "text": msg, 
            "time": current_time
        })
        
        # Aktualizuj poslední zprávu v kontaktech
        self.contacts[self.selected_contact]["last_message"] = msg
        self.contacts[self.selected_contact]["time"] = current_time
        
        # Odešli skutečnou zprávu přes síť
        success = send_message(os.getpid(), USER_PASSWORD, self.selected_contact, msg)
        if success:
            self.message_var.set("")
            self.save_message_history()
            self.update_contacts_list()
        else:
            self.add_chat_message("Failed to send message", "system", current_time)

    def add_friend_dialog(self):
        """Dialog pro přidání přítele"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Friend")
        dialog.geometry("400x200")
        dialog.configure(bg="#0a0a0a")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = (self.root.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (self.root.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

        tk.Label(dialog, text="Friend's ID:", font=("Segoe UI", 12), 
                bg="#0a0a0a", fg="white").pack(pady=(20, 5))
        
        friend_id_var = tk.StringVar()
        entry = tk.Entry(dialog, textvariable=friend_id_var, font=("Segoe UI", 12),
                        bg="#1a1a1a", fg="white", insertbackground="#dc2626",
                        relief="flat", width=40)
        entry.pack(pady=5, padx=20)
        entry.focus_set()

        def add_friend():
            friend_id = friend_id_var.get().strip()
            if not friend_id:
                messagebox.showerror("Error", "Please enter a friend ID", parent=dialog)
                return

            if not validate_peer_id(friend_id):
                messagebox.showerror("Error", "Invalid friend ID format", parent=dialog)
                return

            # Check if already friends
            if friend_id in self.contacts:
                messagebox.showerror("Error", "This user is already your friend", parent=dialog)
                return

            # Send friend request
            success = send_friend_request(os.getpid(), USER_PASSWORD, friend_id)
            if success:
                messagebox.showinfo("Success", f"Friend request sent to {friend_id}", parent=dialog)
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Failed to send friend request", parent=dialog)

        button_frame = tk.Frame(dialog, bg="#0a0a0a")
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Send Request", font=("Segoe UI", 12),
                 bg="#dc2626", fg="white", relief="flat", cursor="hand2",
                 command=add_friend, activebackground="#b91c1c",
                 padx=20, pady=10).pack(side="left", padx=10)

        tk.Button(button_frame, text="Cancel", font=("Segoe UI", 12),
                 bg="#666666", fg="white", relief="flat", cursor="hand2",
                 command=dialog.destroy, activebackground="#555555",
                 padx=20, pady=10).pack(side="left", padx=10)

        entry.bind("<Return>", lambda e: add_friend())

    def remove_friend(self, friend_id):
        """Odstraní přítele"""
        if messagebox.askyesno("Remove Friend", 
                              f"Are you sure you want to remove {self.contacts[friend_id]['name']}?",
                              parent=self.root):
            
            with _data_lock:
                if friend_id in friends:
                    del friends[friend_id]
                if friend_id in self.contacts:
                    del self.contacts[friend_id]
                if friend_id in self.message_history:
                    del self.message_history[friend_id]
            
            if save_user_data():
                self.save_message_history()
                self.update_contacts_list()
                if self.selected_contact == friend_id:
                    self.selected_contact = None
                    self.show_placeholder()
                messagebox.showinfo("Success", "Friend removed", parent=self.root)
            else:
                messagebox.showerror("Error", "Failed to remove friend", parent=self.root)

    def view_profile(self, contact_id):
        """Zobrazí profil kontaktu"""
        profile_data = self.contacts[contact_id]
        friend_data = friends.get(contact_id, {})
        
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Profile - {profile_data['name']}")
        dialog.geometry("400x300")
        dialog.configure(bg="#0a0a0a")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = (self.root.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (self.root.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

        # Avatar
        avatar_frame = tk.Frame(dialog, bg="#0a0a0a")
        avatar_frame.pack(pady=20)
        
        avatar_canvas = tk.Canvas(avatar_frame, bg="#0a0a0a", width=80, height=80, 
                                 highlightthickness=0)
        avatar_canvas.pack()
        avatar_canvas.create_oval(5, 5, 75, 75, fill=profile_data["color"], outline="")
        avatar_canvas.create_text(40, 40, text=profile_data["name"][0].upper(), 
                                 font=("Segoe UI", 24, "bold"), fill="white")

        # Info
        info_frame = tk.Frame(dialog, bg="#0a0a0a")
        info_frame.pack(pady=10, padx=20, fill="x")

        tk.Label(info_frame, text=profile_data["name"], font=("Segoe UI", 16, "bold"),
                bg="#0a0a0a", fg="white").pack()

        status_text = f"Status: {profile_data['last_seen']}"
        if profile_data["verified"]:
            status_text += " • ✓ Verified"
        tk.Label(info_frame, text=status_text, font=("Segoe UI", 12),
                bg="#0a0a0a", fg="#22c55e" if profile_data["last_seen"] == "online" else "#666666").pack(pady=5)

        tk.Label(info_frame, text=f"ID: {contact_id}", font=("Segoe UI", 10),
                bg="#0a0a0a", fg="#999999", wraplength=360).pack(pady=5)

        # Buttons
        button_frame = tk.Frame(dialog, bg="#0a0a0a")
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Send Message", font=("Segoe UI", 12),
                 bg="#dc2626", fg="white", relief="flat", cursor="hand2",
                 command=lambda: [self.open_chat(contact_id), dialog.destroy()],
                 activebackground="#b91c1c", padx=15, pady=8).pack(side="left", padx=5)

        tk.Button(button_frame, text="Remove", font=("Segoe UI", 12),
                 bg="#666666", fg="white", relief="flat", cursor="hand2",
                 command=lambda: [self.remove_friend(contact_id), dialog.destroy()],
                 activebackground="#555555", padx=15, pady=8).pack(side="left", padx=5)

    def toggle_menu(self):
        if not self.menu_open:
            self.show_menu()
        else:
            self.back_from_menu()

    def show_menu(self):
        self.menu_open = True
        self.menu_button.config(text="←")
        
        for widget in self.right_panel.winfo_children():
            widget.destroy()
        for widget in self.left_panel.winfo_children():
            widget.destroy()

        menu_frame = tk.Frame(self.left_panel, bg="#0f0f0f")
        menu_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # User info
        user_canvas = tk.Canvas(menu_frame, bg="#0f0f0f", height=100, highlightthickness=0)
        user_canvas.pack(fill="x", pady=10)
        
        for i in range(100):
            color_val = int(15 + (i * 0.1))
            color = f"#{color_val:02x}0000"
            user_canvas.create_rectangle(0, i, 350, i+1, fill=color, outline="")
        
        user_canvas.create_oval(15, 20, 75, 80, fill=self.profile_color, outline="")
        user_canvas.create_text(45, 50, text=self.username[0].upper(), 
                               font=("Segoe UI", 24, "bold"), fill="white")
        
        user_canvas.create_text(90, 40, text=self.username, anchor="w",
                               font=("Segoe UI", 18, "bold"), fill="white")
        user_canvas.create_text(90, 65, text="online", anchor="w",
                               font=("Segoe UI", 12), fill="#22c55e")

        # Menu items
        menu_items = [
            ("Change Name", self.change_name),
            ("Change Password", self.change_password),
            ("Friend Requests", self.show_friend_requests),
            ("Settings", self.open_settings),
            ("Privacy", self.open_privacy),
            ("Network Status", self.show_network_status)
        ]

        for text, command in menu_items:
            btn = tk.Button(menu_frame, text=text, font=("Segoe UI", 14),
                          bg="#1a1a1a", fg="white", relief="flat", cursor="hand2",
                          command=command, anchor="w", padx=20, pady=15,
                          activebackground="#dc2626", activeforeground="white",
                          borderwidth=0, highlightthickness=0)
            btn.pack(fill="x", pady=5)
            
            def on_enter(e, b=btn):
                b.config(bg="#dc2626")
            def on_leave(e, b=btn):
                b.config(bg="#1a1a1a")
            
            btn.bind("<Enter>", on_enter)
            btn.bind("<Leave>", on_leave)

        # Info panel
        my_tor_id = MyID.id('/usr/share/davell/tor/hiddenService')
        tor_status = my_tor_id if my_tor_id else "Not available"
        
        info_text = (
            f"DAVELL MESSENGER\n\n"
            f"Name: {NAME}\n"
            f"Tor ID:\n{tor_status}\n\n"
            f"Version: 0.4 GUI\n"
            f"Friends: {len(friends)}\n"
            f"Status: Connected\n"
            f"Security: End-to-end encrypted"
        )
        
        info_frame = tk.Frame(self.right_panel, bg="#0a0a0a")
        info_frame.pack(fill="both", expand=True, padx=30, pady=30)
        
        info_label = tk.Label(info_frame, text=info_text, justify="left", 
                            font=("Segoe UI", 12), bg="#0a0a0a", fg="#999999")
        info_label.pack(anchor="nw")
        
        # Action buttons
        action_frame = tk.Frame(info_frame, bg="#0a0a0a")
        action_frame.pack(side="bottom", fill="x", pady=20)

        tk.Button(action_frame, text="Reload Data", font=("Segoe UI", 12),
                 bg="#dc2626", fg="white", relief="flat", cursor="hand2",
                 command=self.reload_data, activebackground="#b91c1c",
                 padx=15, pady=8).pack(side="left", padx=5)

        tk.Button(action_frame, text="Security Status", font=("Segoe UI", 12),
                 bg="#dc2626", fg="white", relief="flat", cursor="hand2",
                 command=self.show_security_status, activebackground="#b91c1c",
                 padx=15, pady=8).pack(side="left", padx=5)

        # Reset button
        reset_btn = tk.Button(action_frame, text="Reset System", 
                            font=("Segoe UI", 14, "bold"), bg="#dc2626", fg="white",
                            relief="flat", cursor="hand2", command=self.reset_system,
                            activebackground="#b91c1c", padx=30, pady=10,
                            borderwidth=0, highlightthickness=0)
        reset_btn.pack(side="right", padx=5)
        
        def hover_reset(e):
            reset_btn.config(bg="#b91c1c")
        def leave_reset(e):
            reset_btn.config(bg="#dc2626")
        
        reset_btn.bind("<Enter>", hover_reset)
        reset_btn.bind("<Leave>", leave_reset)

    def change_name(self):
        new_name = simpledialog.askstring("Change Name", "Enter new name:", parent=self.root)
        if new_name and 3 <= len(new_name) <= 50:
            global NAME
            old_name = NAME
            NAME = new_name
            self.username = new_name
            
            try:
                save_encrypted_data(USER_PASSWORD, {"name": NAME}, 
                                  "/usr/share/davell/storage/PersonalInfo.enc", use_password=True)
                messagebox.showinfo("Success", f"Name changed from {old_name} to {NAME}", parent=self.root)
                self.show_menu()  # Refresh menu
            except Exception as e:
                NAME = old_name
                self.username = old_name
                messagebox.showerror("Error", f"Failed to change name: {e}", parent=self.root)

    def change_password(self):
        # Simple password change dialog
        from getpass import getpass
        import tkinter.simpledialog as simpledialog
        
        current = simpledialog.askstring("Change Password", "Enter current password:", 
                                       parent=self.root, show='*')
        if not current:
            return
            
        if not safe_compare_strings(current, USER_PASSWORD):
            messagebox.showerror("Error", "Incorrect current password", parent=self.root)
            return
            
        new1 = simpledialog.askstring("Change Password", "Enter new password:", 
                                    parent=self.root, show='*')
        if not new1 or len(new1) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters", parent=self.root)
            return
            
        new2 = simpledialog.askstring("Change Password", "Confirm new password:", 
                                    parent=self.root, show='*')
        if not safe_compare_strings(new1, new2):
            messagebox.showerror("Error", "Passwords do not match", parent=self.root)
            return
            
        # Change password
        old_password = USER_PASSWORD
        USER_PASSWORD = new1
        
        try:
            if PERSISTENT_CERT:
                save_persistent_cert(USER_PASSWORD, PERSISTENT_CERT)

            save_encrypted_data(USER_PASSWORD, {"name": NAME}, 
                              "/usr/share/davell/storage/PersonalInfo.enc", use_password=True)
            save_encrypted_data(USER_PASSWORD, friends, "/usr/share/davell/storage/friends.enc", use_password=True)
            save_encrypted_data(USER_PASSWORD, pending_requests, "/usr/share/davell/storage/pending_requests.enc", use_password=True)

            secure_memory_clear(old_password)
            secure_memory_clear(new1)
            secure_memory_clear(new2)
            
            messagebox.showinfo("Success", "Password changed successfully", parent=self.root)
            
        except Exception as e:
            USER_PASSWORD = old_password
            secure_memory_clear(new1)
            secure_memory_clear(new2)
            messagebox.showerror("Error", f"Failed to change password: {e}", parent=self.root)

    def show_friend_requests(self):
        """Zobrazí pending friend requests"""
        load_user_data()
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Friend Requests")
        dialog.geometry("500x400")
        dialog.configure(bg="#0a0a0a")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = (self.root.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (self.root.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

        tk.Label(dialog, text="Pending Friend Requests", font=("Segoe UI", 16, "bold"),
                bg="#0a0a0a", fg="white").pack(pady=20)

        if not pending_requests:
            tk.Label(dialog, text="No pending requests", font=("Segoe UI", 12),
                    bg="#0a0a0a", fg="#666666").pack(expand=True)
        else:
            # Scrollable frame for requests
            canvas = tk.Canvas(dialog, bg="#0a0a0a", highlightthickness=0)
            scrollbar = tk.Scrollbar(dialog, orient="vertical", command=canvas.yview,
                                   bg="#dc2626", troughcolor="#1a1a1a")
            scroll_frame = tk.Frame(canvas, bg="#0a0a0a")

            scroll_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            canvas.pack(side="left", fill="both", expand=True, padx=20, pady=10)
            scrollbar.pack(side="right", fill="y", padx=(0, 20), pady=10)

            for requester_id, request_info in pending_requests.items():
                self.create_request_widget(scroll_frame, requester_id, request_info)

    def create_request_widget(self, parent, requester_id, request_info):
        """Vytvoří widget pro friend request"""
        frame = tk.Frame(parent, bg="#1a1a1a", relief="flat", bd=1)
        frame.pack(fill="x", pady=5, padx=10)

        # Info
        info_frame = tk.Frame(frame, bg="#1a1a1a")
        info_frame.pack(fill="x", padx=15, pady=10)

        tk.Label(info_frame, text=request_info.get('name', 'Unknown'), 
                font=("Segoe UI", 14, "bold"), bg="#1a1a1a", fg="white", 
                anchor="w").pack(fill="x")
        
        tk.Label(info_frame, text=f"ID: {requester_id}", font=("Segoe UI", 10),
                bg="#1a1a1a", fg="#999999", anchor="w").pack(fill="x")
        
        timestamp = time.ctime(request_info.get('timestamp', 0))
        tk.Label(info_frame, text=f"Received: {timestamp}", font=("Segoe UI", 9),
                bg="#1a1a1a", fg="#666666", anchor="w").pack(fill="x")

        # Buttons
        button_frame = tk.Frame(frame, bg="#1a1a1a")
        button_frame.pack(fill="x", padx=15, pady=10)

        tk.Button(button_frame, text="Accept", font=("Segoe UI", 10),
                 bg="#22c55e", fg="white", relief="flat", cursor="hand2",
                 command=lambda: self.respond_to_request(requester_id, True),
                 activebackground="#16a34a", padx=15, pady=5).pack(side="left", padx=5)

        tk.Button(button_frame, text="Decline", font=("Segoe UI", 10),
                 bg="#dc2626", fg="white", relief="flat", cursor="hand2",
                 command=lambda: self.respond_to_request(requester_id, False),
                 activebackground="#b91c1c", padx=15, pady=5).pack(side="left", padx=5)

    def respond_to_request(self, requester_id, accept):
        """Zpracuje friend request"""
        success = respond_to_friend_request(os.getpid(), USER_PASSWORD, requester_id, accept)
        
        if success:
            action = "accepted" if accept else "declined"
            messagebox.showinfo("Success", f"Friend request {action}", parent=self.root)
            
            # Reload data and refresh
            self.load_real_data()
            self.show_friend_requests().destroy()  # Close requests dialog
            if accept:
                self.back_from_menu()  # Return to main view
        else:
            messagebox.showerror("Error", "Failed to process friend request", parent=self.root)

    def open_settings(self):
        messagebox.showinfo("Settings", 
                          "Settings panel - Coming soon!\n\nConfigure:\n- Theme\n- Language\n- Display options\n- Sound effects",
                          parent=self.root)

    def open_privacy(self):
        messagebox.showinfo("Privacy", 
                          "Privacy settings - Coming soon!\n\nManage:\n- Who can see your status\n- Last seen visibility\n- Profile photo privacy\n- Block contacts",
                          parent=self.root)

    def show_network_status(self):
        """Zobrazí stav sítě"""
        tor_running = is_tor_running()
        my_tor_id = MyID.id('/usr/share/davell/tor/hiddenService')
        
        status_text = (
            f"=== Network Status ===\n\n"
            f"Local port: {PORT}\n"
            f"Tor SOCKS: {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}\n"
            f"Tor process: {'✓ Running' if tor_running else '✗ Not running'}\n"
            f"Hidden service: {'✓ Available' if my_tor_id else '✗ Not available'}\n"
            f"Friends: {len(friends)}\n"
            f"Pending requests: {len(pending_requests)}\n"
            f"Debug mode: {'On' if DEBUG_MODE else 'Off'}"
        )
        
        messagebox.showinfo("Network Status", status_text, parent=self.root)

    def show_security_status(self):
        """Zobrazí bezpečnostní status"""
        status_text = (
            f"=== Security Status ===\n\n"
            f"Certificate: {'✓ Loaded' if PERSISTENT_CERT else '✗ Missing'}\n"
            f"Password: {'✓ Set' if USER_PASSWORD else '✗ Not set'}\n"
            f"Friends: {len(friends)}\n"
            f"Pending requests: {len(pending_requests)}\n"
            f"Server port: {PORT}\n"
            f"Tor SOCKS port: {TOR_SOCKS_PORT}\n"
            f"Debug mode: {'On' if DEBUG_MODE else 'Off'}\n"
            f"Custom Tor: {'Yes' if CUSTOM else 'No'}\n"
            f"Tor running: {'Yes' if is_tor_running() else 'No'}"
        )
        
        messagebox.showinfo("Security Status", status_text, parent=self.root)

    def reload_data(self):
        """Znovu načte data"""
        self.load_real_data()
        messagebox.showinfo("Success", "Data reloaded successfully", parent=self.root)
        self.back_from_menu()

    def reset_system(self):
        """Resetuje celý systém"""
        answer = messagebox.askyesno("Reset System", 
                                   "Do you really want to reset the system?\n\nThis will permanently delete ALL data!",
                                   parent=self.root)
        if answer:
            confirm = messagebox.askyesno("Confirm Reset", 
                                        "Are you absolutely sure? This cannot be undone!",
                                        parent=self.root)
            if confirm:
                reset_system()

    def back_from_menu(self):
        self.menu_open = False
        self.setup_main_view()

    def run(self):
        self.root.mainloop()

def app():
    try:
        # Initialize system first (unless custom port)
        if not args.custom:
            initialize_system(os.getpid())
        else:
            PORT = args.custom
            Message.info(f"Using custom port: {PORT}")
        
        if args.gui:
            GUI().run()
            sys.exit(1)
        console = Console()
        server_thread = threading.Thread(target=Internet.server, daemon=True)
        server_thread.start()
        
        # Start command loop
        console.cmdloop()
            
    except KeyboardInterrupt:
        Message.info("Shutting down securely...")
        cleanup_on_exit()
    except Exception as e:
        Message.error(f"System error: {e}")
        debug_log(f"Full error: {e}")
    finally:
        cleanup_on_exit()

if __name__ == "__main__":
    app()