# Davell Message System Version 0.4 (BETA)

**Davell Message System (DMS)** is a privacy-first, decentralized messaging platform that combines *end-to-end encryption* with the anonymity of the *Tor network*. Built with security as the foundation, **DMS** implements the *Signal Protocol* for *forward secrecy* and provides a *robust framework* for secure communication.


### Key Features
 - End-to-End Encryption: Military-grade encryption using SECP384R1 elliptic curves and AES-256-GCM Signal Protocol Integration: Advanced forward secrecy with Double Ratchet Algorithm Tor Network Integration: Complete anonymity through onion routing Zero Knowledge Architecture: Your data, your keys - we never see your messages Encrypted Storage: All local data encrypted with password-derived keys Dual Interface: Command-line and modern GUI options Security Hardening: Rate limiting, nonce verification, and replay attack prevention

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
 - [Davell Site Installation](https://davell.org/learn.html#installation-steps)

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
`info                    # Show your ID and name`
`change_name            # Update display name`
`change_password        # Change account password`

- Friend Management
`add <user_id>          # Send friend request`
`friends                # List all friends`
`requests               # Show pending requests`
`accept <user_id>       # Accept friend request`
`decline <user_id>      # Decline friend request`
`remove <user_id>       # Remove friend`

- Messaging
`message <user_id> <text>    # Send message (Signal Protocol)`
`msg <user_id> <text>        # Alias for message`

- Network
`start_tor              # Launch Tor service`
`status                 # Show system status`
`network_status         # Network diagnostics`
`config                 # Show Tor configuration`

- Advanced
`debug_enable           # Enable debug mode`
`backup [directory]     # Create encrypted backup`
`export_friend <id>     # Export friend data`
`import_friend <file>   # Import friend data`
`reset                  # Reset entire system`



