# Davell Message System Version 0.4 (BETA)

**Davell Message System (DMS)** is a privacy-first, decentralized messaging platform that combines *end-to-end encryption* with the anonymity of the *Tor network*. Built with security as the foundation, **DMS** implements the *Signal Protocol* for *forward secrecy* and provides a *robust framework* for secure communication.

#### By downloading, installing, copying, forking, or using the Davell Message System (the “Software”), you agree to these Terms of Service (“Terms”). If you do not agree, do not use the Software.

### Key Features
 - End-to-End Encryption: Military-grade encryption using SECP384R1 elliptic curves and AES-256-GCM Signal Protocol Integration: Advanced forward secrecy with Double Ratchet Algorithm Tor Network Integration: Complete anonymity through onion routing Zero Knowledge Architecture: Your data, your keys - we never see your messages Encrypted Storage: All local data encrypted with password-derived keys Dual Interface: Command-line and modern GUI options Security Hardening: Rate limiting, nonce verification, and replay attack prevention

-----------------
## Reporting Bugs & Contributing

Davell is a **Linux-only** project. If you are using Windows or macOS, it will not work.

### Reporting Bugs
**When reporting a bug, include:**
- Linux distribution and version (e.g., Ubuntu 22.04, Arch Linux)
- Architecture (x86_64, armv7, arm64)
- Steps to reproduce the bug
- Expected behavior vs. actual behavior
- Terminal output or logs (if any)
- Davell version

### Security Issues
For **security vulnerabilities**, please do **not** open a public issue. Instead, email us at:  
**davellbugs@proton.me**

Your reports help make Davell more stable, secure, and reliable. Every bug report is one step closer to perfection.
-----------------

### Prerequisites
 - Python: Version 3.7 or higher
 - RAM: Minimum 512MB, recommended 1GB+
 - Storage: 100MB free space
 - Tor service installed and configured
 - Linux-based operating system (recommended)

### Dependecies
 - socks pycryptodome cryptography cmd2 tkinter getpass4
 - python3-pyqt5 python3-venv python3-pip python3-dev python3-tk build-essential libssl-dev libffi-dev pkg-config libbz2-dev liblzma-dev zlib1g-dev cargo

### Installation Guide:
 - [COMMING SOON.. Davell Site Installation](https://davell.org/learn.html#installation-steps)

### Run Davell
- Start Davell
 ```bash
 davell
 ```
- Check if TOR is running.
 ```python
 >> network_status
 ** <23:14:44> [inf] === Network Status ===
 ** <23:14:44> [inf] Local port: 12345
 ** <23:14:44> [inf] Tor SOCKS: 127.0.0.1:9050
 ** <23:14:44> [inf] Tor process: ✗ Not Running
 ** <23:14:44> [inf] Hidden service: ✓ Available
 ** <23:14:44> [inf] Tor connectivity: ✗ Failed (Error connecting to SOCKS5 proxy 127.0.0.1:9050: [)
 ** <23:14:44> [inf] Active connection attempts: 0
 ** <23:14:44> [inf] Active message attempts: 0
 ```
- Start TOR:
 ```python
 start_tor
 ```
OR:
 ```python
 cd /usr/local/bin/tor
 tor -f torrc
 ```
### Usage
#### First Launch
- On first launch, you'll be prompted to create a new system:

- Set a strong password (minimum 8 characters)
- Choose a display name (3-50 characters)
- System generates your cryptographic identity
- Tor hidden service is automatically configured

- Your unique Tor ID will be displayed - share this with friends to connect.
### CLI Commands:
- Identity Management
```python
info                    # Show your ID and name
change_name            # Update display name
change_password        # Change account password
```
- Friend Management
```python
add <user_id>          # Send friend request
friends                # List all friends
requests               # Show pending requests
accept <user_id>       # Accept friend request
decline <user_id>      # Decline friend request
remove <user_id>       # Remove friend
```
- Messaging
```python
message <user_id> <text>    # Send message (Signal Protocol)
msg <user_id> <text>        # Alias for message
```
- Network
```python
start_tor              # Launch Tor service
status                 # Show system status
network_status         # Network diagnostics
config                 # Show Tor configuration
```
- Advanced
```python
debug_enable           # Enable debug mode
backup [directory]     # Create encrypted backup
export_friend <id>     # Export friend data
import_friend <file>   # Import friend data
reset                  # Reset entire system
```
### GUI Interface
- The GUI provides an intuitive interface with:
- **Contact List**: Visual representation of friends with status indicators
- **Chat Window**: Real-time messaging with Signal Protocol
- **Friend Requests**: Easy management of incoming/outgoing requests
- **Settings Menu**: System configuration and security options
- **Network Status**: Live connection monitoring

- Launch with: `davell -gui`

### Security Features
#### Cryptographic Protocols
- **Key Exchange**: Elliptic Curve Diffie-Hellman (ECDH) with SECP384R1
- **Symmetric Encryption**: AES-256 in GCM mode
- **Key Derivation**: HKDF with SHA-256
- **Digital Signatures**: ECDSA with SHA-256
- **Forward Secrecy**: Signal Protocol Double Ratchet Algorithm
  
#### Security Mechanisms
- **Nonce-Based Replay Protection**: 16-byte cryptographic nonces
- **Message Authentication**: HMAC-SHA256 for integrity verification
- **Rate Limiting**: Protection against DoS attacks (100 requests/minute)
- **Secure Memory Management**: Automatic wiping of sensitive data
- **Certificate Pinning**: MITM attack prevention
- **Timestamp Validation**: 5-minute window for message acceptance
  
#### Privacy Features
- **Tor Hidden Services**: Complete IP anonymity
- **No Metadata Logging**: Zero tracking or analytics
- **Encrypted Storage**: AES-256-GCM for all local data
- **Password-Based Encryption**: HKDF with user password
- **Secure Deletion**: Multi-pass overwrite for file removal

### Architecture
#### Signal Protocol Implementation
 - DMS implements the Signal Protocol for end-to-end encryption:
```
┌─────────────────────────────────────────┐
│         Signal Protocol Layer           │
├─────────────────────────────────────────┤
│  • Double Ratchet Algorithm             │
│  • Chain Key Derivation                 │
│  • Message Key Generation               │
│  • Out-of-Order Message Handling        │
└─────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────┐
│      Cryptographic Transport Layer      │
├─────────────────────────────────────────┤
│  • ECDH Key Exchange (SECP384R1)        │
│  • AES-256-GCM Encryption               │
│  • HMAC-SHA256 Authentication           │
└─────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────┐
│         Tor Network Layer               │
├─────────────────────────────────────────┤
│  • Onion Routing                        │
│  • Hidden Service Protocol              │
│  • Circuit Management                   │
└─────────────────────────────────────────┘
```
#### File Structure
```
davell/
├── Main.py                 # Application entry point
├── Network.py              # Signal Protocol & networking
├── CryptoUtils.py          # Cryptographic primitives
├── Storage.py              # Encrypted storage management
├── Message.py              # Message formatting
├── MyID.py                 # Identity management
├── EncodeID.py             # ID encoding/decoding
├── Maskot.py               # ASCII art
└── /usr/share/davell/
    ├── storage/
    │   ├── certs/
    │   │   ├── persistent_cert.pem       # Encrypted identity
    │   │   └── signal_sessions.enc       # Signal Protocol state
    │   ├── friends.enc                   # Friend list
    │   ├── pending_requests.enc          # Pending requests
    │   └── PersonalInfo.enc              # User profile
    └── tor/
        ├── torrc                         # Tor configuration
        ├── data/                         # Tor data directory
        └── hiddenService/                # Hidden service keys
```

### Tor Configuration
```bash
davell -c 6300
```
 - Manual Tor Configuration (Edit: /usr/share/davell/tor/torrc)
```bash
SocksPort 9050
ControlPort 9051
HiddenServiceDir /usr/share/davell/tor/hiddenService
HiddenServicePort 6300 127.0.0.1:6300
```
### Security Adjust in source code (/usr/local/bin/main.py)
 - CONNECTION_TIMEOUT = 60        # Connection timeout (seconds)
 - MAX_MESSAGE_SIZE = 8192        # Maximum message size (bytes)
 - MAX_CONNECTIONS = 10           # Maximum concurrent connections
 - RATE_LIMIT_WINDOW = 60         # Rate limit window (seconds)
 - MAX_REQUESTS_PER_WINDOW = 100  # Max requests per windowSettings
### Debug Mode
 - Enable debug logging for troubleshooting:

 #### In CLI
 ```python
>> debug_enable
>> debug_data          # View internal state
```

 -  Test self-messaging (debug only)
 ```python
>> test_self           # Create self friend request
>> accept <your_id>    # Accept self request
>> test_message "Hello"  # Send message to yourself
```

### Network Diagnostic
```python
network_status      # Connection status
status              # System status
config              # Tor configuration
```

Security Disclaimer
While DMS implements robust security measures, no system is perfectly secure. Users should:

Use strong, unique passwords
Keep software updated
Verify friend identities through alternate channels
Report security vulnerabilities responsibly
Understand that Tor provides anonymity, not encryption (that's our job!)

-----------------
## Terms of Service (TOS)
#### Effective date: 10/16/2025
#### Introduction / Acceptance of Terms
  By downloading, installing, copying, forking, using or contributing to the Davell Message System (the “Software”), you agree to these Terms of Service (“Terms”). If you do not agree, do not use the Software.
#### Eligibility / Compliance with Law
  You must comply with all applicable laws when using the Software. Use the Software only for lawful purposes. The authors are not responsible for any illegal use of the Software by its users.
#### Prohibited Uses
  While the authors cannot monitor usage, you are legally responsible for your actions. Do not use the Software to:
  - commit or facilitate illegal acts (e.g., drug trade, child abuse, terrorism, fraud);
  - distribute malware, ransomware, or compromise other systems;
  - host, transmit, or distribute illegal content.
#### No Warranty — “AS IS”
  The Software is provided “AS IS”, without warranties of any kind. The authors, contributors, and maintainers disclaim all express or implied warranties, including merchantability, fitness for a particular purpose, or non-infringement.
#### Limitation of Liability
  To the maximum extent permitted by law, the authors, contributors, and maintainers are not liable for any direct, indirect, incidental, special, consequential, punitive, or exemplary damages (including lost profits, loss of data, or business interruption), even if advised of the possibility of such damages.
#### Indemnification
  You agree to indemnify and hold harmless the authors, contributors, and maintainers from any claims, damages, liabilities, losses, costs, or expenses arising from your use of the Software in a manner that violates law or these Terms.
#### Open Source Components and Licenses
  Third-party open source components included in Davell are subject to their own licenses. You must comply with these licenses when redistributing or using the components.
#### Decentralized Peer-to-Peer Architecture
  Davell is fully decentralized. There is no central server and no mechanism to block or monitor user communication. The Software is only a tool for secure, private messaging. The authors cannot control, access, or restrict user activity.
#### Governing Law
  These Terms are governed by the laws of the Czech Republic. Any disputes arising under these Terms shall be subject to the exclusive jurisdiction of Czech courts.
#### Changes to Terms
  The authors may update these Terms. Continued use of the Software after posting changes indicates acceptance.
-----------------
