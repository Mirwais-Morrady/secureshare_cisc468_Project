# SecureShare — CISC 468 P2P Secure File Sharing

A peer-to-peer secure file sharing application built for CISC 468 (Cryptography) at Queen's University, Winter 2026.

The system consists of two interoperable clients — **Python** and **Java** — that discover each other on a local network, mutually authenticate, and exchange files with full confidentiality, integrity, and perfect forward secrecy.

---

## Protocol Overview

```
Peer A                                               Peer B
  │                                                     │
  │──── mDNS advertisement ────────────────────────────►│  (discovery)
  │◄─── mDNS advertisement ─────────────────────────────│
  │                                                     │
  │──── TCP connect ────────────────────────────────── ►│  (transport)
  │                                     v               │
  │──── CLIENT_HELLO (RSA-signed, DH pub) ─────────────►│  (handshake)
  │◄─── SERVER_HELLO (RSA-signed, DH pub) ──────────────│
  │                                                     │
  │    [Both derive AES-256-GCM session keys via HKDF]  │
  │                                                     │
  │════ All subsequent messages: AES-GCM encrypted ═════│
  │                                                     │
  │──── LIST_FILES_REQUEST ────────────────────────────►│
  │◄─── LIST_FILES_RESPONSE ────────────────────────────│
  │                                                     │
  │──── FILE_REQUEST ──────────────────────────────────►│
  │◄─── FILE_REQUEST_ACCEPT / DENY ─────────────────────│  (consent)
  │──── FILE_CHUNK × N ────────────────────────────────►│
  │──── FILE_TRANSFER_COMPLETE (SHA-256) ──────────────►│  (integrity)
```

### Cryptographic Design

| Property | Mechanism |
|---|---|
| Identity | RSA-2048, SHA-256 fingerprint, PEM storage |
| Handshake signatures | RSA-PSS-SHA-256, 32-byte salt |
| Key exchange | Ephemeral Diffie-Hellman, RFC 3526 Group 14 (2048-bit) |
| Session key derivation | HKDF-SHA-256, separate client→server and server→client keys |
| Encrypted transport | AES-256-GCM with per-message nonces and AAD |
| Secure local storage | PBKDF2-HMAC-SHA-256 (200,000 iterations) + AES-256-GCM |
| Discovery | mDNS / Zeroconf (`_cisc468share._tcp.local.`) |
| File integrity | SHA-256 attached to FILE_TRANSFER_COMPLETE |
| Redistribution integrity | RSA-PSS-signed manifest containing file SHA-256 |
| Perfect forward secrecy | Ephemeral DH private keys never stored |
| Key migration | KEY_MIGRATION message signed with old key, contacts updated |

---

## Repository Structure

```
cisc468-secure-share/
├── python_client/               # Python client (Python 3.12)
│   ├── crypto/                  # Crypto primitives
│   │   ├── identity.py          # RSA-2048 key generation, PSS signing
│   │   ├── session.py           # AES-256-GCM session encryption
│   │   ├── vault.py             # PBKDF2 + AES-GCM vault encryption
│   │   ├── manifest.py          # Signed file manifests
│   │   ├── key_migration.py     # Key compromise recovery
│   │   ├── hkdf_utils.py        # HKDF-SHA-256
│   │   ├── dh_params.py         # DH Group 14 parameters
│   │   └── hashing.py           # SHA-256 helpers
│   ├── net/                     # Networking
│   │   ├── handshake_client.py  # CLIENT_HELLO + handshake executor
│   │   ├── handshake_server.py  # SERVER_HELLO + handshake executor
│   │   ├── connection_handler.py# Per-connection handler (handshake + routing)
│   │   ├── router.py            # Message type dispatcher
│   │   ├── consent_handler.py   # User consent prompts
│   │   ├── framing.py           # 4-byte length-prefixed frames
│   │   ├── tcp_server.py        # Threaded TCP server
│   │   ├── tcp_client.py        # TCP connection helper
│   │   ├── file_sender.py       # Encrypted file send
│   │   └── file_receiver.py     # Chunk assembly
│   ├── protocol/                # Protocol definitions
│   │   ├── message_types.py     # Message type constants
│   │   ├── handshake.py         # DH key generation, session derivation, transcript hash
│   │   ├── canonical_json.py    # Sorted compact JSON
│   │   ├── serializer.py        # JSON encode/decode
│   │   └── validator.py         # Message field validation
│   ├── files/
│   │   ├── chunker.py           # Split bytes into 64 KB chunks
│   │   ├── share_manager.py     # Manage shared file directory
│   │   └── transfer_manager.py  # Consent + encrypted file send flow
│   ├── storage/
│   │   ├── vault_store.py       # Encrypted file storage
│   │   ├── contacts_store.py    # Verified peer contacts
│   │   ├── manifest_store.py    # Signed file manifests
│   │   ├── config_store.py      # Configuration
│   │   └── share_index_store.py # Shared file index
│   ├── discovery/
│   │   ├── mdns_service.py      # mDNS service advertisement
│   │   └── discovery_listener.py# mDNS peer browser
│   ├── cli/                     # Command-line interface
│   ├── tests/                   # Test suite (pytest)
│   ├── main_runtime.py          # Application entry point
│   └── run_client.py            # CLI launcher
│
├── java_client/                 # Java client (Java 17, Maven)
│   ├── src/main/java/com/cisc468share/
│   │   ├── crypto/              # AES-GCM, HKDF, RSA-PSS, DH, Vault
│   │   ├── net/                 # Framing, TCP, SecureChannel, HandshakeManager
│   │   ├── protocol/            # CanonicalJson, Serializer, MessageTypes
│   │   ├── files/               # ShareManager, Chunker, ManifestManager
│   │   ├── discovery/           # mDNS advertisement
│   │   ├── router/              # MessageRouter
│   │   └── runtime/             # RuntimeLauncher
│   └── src/test/java/com/cisc468share/
│       ├── crypto/              # Unit tests (AES-GCM, HKDF, handshake, security failures)
│       ├── protocol/            # Framing, serialization tests
│       └── interop/             # Cross-language vector tests
│
├── shared_test_vectors/         # Shared test vectors (Python + Java both verify)
│   ├── aes_gcm/                 # AES-GCM encrypt/decrypt
│   ├── hkdf/                    # HKDF-SHA-256 OKM
│   ├── hashes/                  # SHA-256
│   ├── handshake/               # CLIENT_HELLO / SERVER_HELLO samples
│   └── manifests/               # Manifest structure samples
│
├── docs/
│   └── protocol.md              # Detailed protocol specification
├── run_interop_tests.sh         # Run all tests (Python + Java)
└── README.md                    # This file
```

---

## Prerequisites

- **Python 3.12+** with pip
- **Java 17+** (OpenJDK recommended)
- **Apache Maven 3.8+**
- **Linux or WSL2** (recommended)

Install on Ubuntu/Debian:
```bash
sudo apt-get install -y python3.12 openjdk-17-jdk maven
```

---

## Environment Setup

### Python

The Python client uses a virtual environment. The `.venv` directory is included with dependencies pre-installed. If you need to recreate it:

```bash
cd python_client
python3.12 -m venv .venv
.venv/bin/pip install cryptography zeroconf pytest
```

**Note:** The venv was originally created on Windows. On Linux, use this workaround if `.venv/bin/python` appears empty:

```bash
export PYTHONPATH="$PWD/python_client/.venv/lib/python3.12/site-packages"
```

All test commands below use this export automatically.

### Java

Maven handles all dependencies on first run (Jackson, JmDNS, JUnit 5). No additional setup needed.

---

## Running the Clients

### Python Client

```bash
cd python_client
PYTHONPATH=".venv/lib/python3.12/site-packages" python3.12 run_client.py
```

**Expected output:**
```
[INFO] Identity: secureshare-peer
[INFO] Peer ID:  <64-char hex fingerprint>
[INFO] Listening on port 40468
SecureShare CLI started. Type 'help' for commands.
secure-share>
```

**CLI commands:**
```
help        Show available commands
peers       List discovered peers
list        List locally shared files
share <file>  Copy a file into the shared directory
get <file>  Request a file from a peer (prompts for consent)
exit        Quit
```

### Java Client

```bash
cd java_client
mvn compile -q
mvn exec:java -Dexec.mainClass="com.cisc468share.Main" -q
```

**Expected output:**
```
[mDNS] Advertising java-peer on port 40469
TCP server listening on port 40469
SecureShare Java Client
Commands: help, exit
>
```

---

## Running Tests

### All Tests (Python + Java)

Make the script executable (if needed):

```bash
chmod +x run_interop_tests.sh
```
Then

```bash
./run_interop_tests.sh
```

### Python Tests Only

```bash
cd python_client
PYTHONPATH=".venv/lib/python3.12/site-packages" python3.12 -m pytest tests/ -v
```

**Expected:**
```
... (tests listed) ...
XX passed in Y.YYs
```

### Java Tests Only

```bash
cd java_client
mvn test
```

**Expected:**
```
Tests run: 28, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

### Run a Specific Python Test Module

```bash
cd python_client
PYTHONPATH=".venv/lib/python3.12/site-packages" python3.12 -m pytest tests/test_handshake.py -v
```

---

## Test Coverage by Requirement

| # | Requirement | Test File(s) |
|---|---|---|
| 1 | mDNS peer discovery | `test_handshake.py` (end-to-end), `InteropVectorTest.java` |
| 2 | Mutual authentication | `test_security_failures.py::test_mutual_authentication_both_sides_verify` |
| 3 | Consent for file requests | `test_consent.py` |
| 4 | List files (no consent) | `test_consent.py::TestConsentMessages` |
| 5 | Redistribution tamper detection | `test_redistribution.py` |
| 6 | Key migration | `test_key_migration.py` |
| 7 | Confidentiality and integrity | `test_session.py`, `test_security_failures.py`, `AesGcmInteropTest.java` |
| 8 | Perfect forward secrecy | `test_pfs.py` |
| 9 | Secure local storage | `test_vault.py`, `test_vault_store.py` |
| 10 | Error messages | `test_security_failures.py` (error paths) |
| 11 | Runnable tests | All of the above |

---

## Demonstrating the Project for Grading

### 1. Run all tests

```bash
./run_interop_tests.sh
```

### 2. Start the Java server in Terminal 1

```bash
cd java_client
mvn exec:java -Dexec.mainClass="com.cisc468share.Main" -q
```

### 3. Start the Python client in Terminal 2

```bash
cd python_client
PYTHONPATH=".venv/lib/python3.12/site-packages" python3.12 run_client.py
```

### 4. Demonstrate features

In the Python client:
```
secure-share> peers           # Shows java-peer discovered via mDNS
secure-share> list            # Lists locally shared files
secure-share> share myfile.txt   # Adds a file to shared directory
```

---

## Common Errors and Fixes

### `Permission denied` on `.venv/bin/python`

The venv was created on a different OS. Use the PYTHONPATH workaround:
```bash
PYTHONPATH="python_client/.venv/lib/python3.12/site-packages" python3.12 ...
```

### `Address already in use`

Another process is using port 40468 or 40469. Find and kill it:
```bash
sudo lsof -i :40468
sudo kill <PID>
```

### mDNS discovery not working

mDNS requires being on the same LAN segment. If running both clients on the same machine, they should discover each other. On some systems, the firewall may block mDNS (UDP port 5353):
```bash
sudo ufw allow 5353/udp
```

### `mvn: command not found`

Install Maven:
```bash
sudo apt-get install -y maven
```

### Java tests fail to download dependencies

Ensure internet access for first run (Maven downloads from Maven Central). Subsequent runs use the local cache.

---

## Security Parameters

| Parameter | Value | Justification |
|---|---|---|
| RSA key size | 2048 bits | NIST recommended minimum |
| RSA-PSS salt | 32 bytes (SHA-256 digest length) | Interop with Java PSS |
| DH group | RFC 3526 Group 14 (2048-bit) | NIST recommended minimum |
| AES key size | 256 bits | Maximum AES security |
| GCM tag size | 128 bits | Maximum GCM integrity |
| HKDF hash | SHA-256 | Widely supported, 256-bit security |
| PBKDF2 iterations | 200,000 | NIST SP 800-132 recommended |
| PBKDF2 salt | 16 bytes random | Per-file random salt |
| Nonce size | 12 bytes random | GCM standard |

---

## Libraries Used

**Python:**
- `cryptography` — RSA, AES-GCM, HKDF, PBKDF2
- `zeroconf` — mDNS peer discovery

**Java:**
- `Jackson` — JSON serialization
- `JmDNS` — mDNS peer discovery
- `JUnit 5` — testing
- Standard Java cryptography (`javax.crypto`, `java.security`)
