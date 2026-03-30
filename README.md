# SecureShare

A peer-to-peer secure file sharing application built for CISC 468 (Cryptography) at Queen's University, Winter 2026. The system consists of two fully interoperable clients — written in Python and Java — that discover each other on a local network, mutually authenticate using public-key cryptography, and exchange files with confidentiality, integrity, and perfect forward secrecy guaranteed at every step.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Architecture and Cryptographic Design](#architecture-and-cryptographic-design)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Running the Clients](#running-the-clients)
- [Command Reference](#command-reference)
- [Typical Usage Walkthrough](#typical-usage-walkthrough)
- [Running the Tests](#running-the-tests)
- [Test Coverage by Requirement](#test-coverage-by-requirement)
- [Security Parameters](#security-parameters)
- [Libraries Used](#libraries-used)
- [Known Limitations](#known-limitations)

---

## What It Does

SecureShare lets two peers on the same local network:

- Discover each other automatically via mDNS — no IP addresses to configure
- Authenticate each other's identity by verifying RSA public-key fingerprints before any file exchange
- Send or request files with explicit consent from the receiving side
- Browse a peer's shared file list without triggering a consent prompt
- Fetch a file through an intermediate peer when the original owner is offline, and verify the file has not been tampered with using the owner's signed manifest
- Migrate to a new cryptographic identity if a private key is compromised, notifying all connected contacts automatically
- Store files locally in an AES-256-GCM encrypted vault protected by a user-supplied password

All network traffic after the handshake is encrypted with AES-256-GCM. Session keys are derived from an ephemeral Diffie-Hellman exchange, so capturing the long-term RSA key does not expose past sessions.

---

## Architecture and Cryptographic Design

### Handshake and Session Establishment

```
Peer A (client)                                        Peer B (server)
      │                                                       │
      │── TCP connect ────────────────────────────────────── ►│
      │                                                       │
      │── CLIENT_HELLO ───────────────────────────────────── ►│
      │   • RSA-2048 public key (DER, base64)                 │
      │   • Ephemeral DH public value (RFC 3526 Group 14)     │
      │   • 16-byte random nonce                              │
      │   • RSA-PSS-SHA-256 signature over all fields         │
      │                                                       │
      │◄─ SERVER_HELLO ──────────────────────────────────────│
      │   • RSA-2048 public key (DER, base64)                 │
      │   • Ephemeral DH public value                         │
      │   • 16-byte random nonce                              │
      │   • Echo of client nonce (replay prevention)          │
      │   • RSA-PSS-SHA-256 signature over all fields         │
      │                                                       │
      │   Both sides independently compute:                   │
      │   1. DH shared secret = g^(ab) mod p                  │
      │   2. transcript_hash = SHA-256(CLIENT_HELLO ‖ SERVER_HELLO)
      │   3. send_key  = HKDF-SHA-256(secret, transcript, "cisc468/session/client_to_server")
      │   4. recv_key  = HKDF-SHA-256(secret, transcript, "cisc468/session/server_to_client")
      │   5. session_id = HKDF-SHA-256(secret, transcript, "cisc468/session/session_id")
      │                                                       │
      │════ All subsequent messages: AES-256-GCM encrypted ══│
      │     • Per-message random 12-byte nonce                │
      │     • AAD = canonical JSON of {version, session_id,   │
      │             msg_seq, msg_type}                        │
      │     • Monotonically increasing sequence number        │
      │       (replay and reorder protection)                 │
```

### Protocol → Algorithm Mapping

| Component | Protocol / Algorithm | Purpose |
|---|---|---|
| Peer discovery | mDNS / Zeroconf (`_cisc468share._tcp.local.`) | Zero-configuration LAN peer discovery without a central server |
| Identity | RSA-2048, public key DER encoded, SHA-256 fingerprint | Long-term identity; peer_id = SHA-256(public_key_der) |
| Handshake authentication | RSA-PSS-SHA-256 (32-byte salt) | Mutual authentication — each side signs their hello message; the other side verifies before proceeding |
| Key exchange | Ephemeral Diffie-Hellman, RFC 3526 Group 14 (2048-bit prime) | Establishes a fresh shared secret per session without revealing long-term keys |
| Session key derivation | HKDF-SHA-256 with domain-separated labels | Derives directional AES keys and session ID from the DH shared secret and handshake transcript |
| Encrypted transport | AES-256-GCM, per-message random nonce, AAD | Provides confidentiality and authentication for every message after the handshake |
| Message framing | 4-byte big-endian length prefix | Allows reliable decoding of variable-length messages over TCP streams |
| Canonical serialisation | JSON with sorted keys and no whitespace | Ensures AAD and signature inputs are identical on both sides regardless of language or library |
| File integrity (in transit) | SHA-256 attached to FILE_TRANSFER_COMPLETE | Receiver independently hashes reassembled file and compares to sender's hash |
| File chunking | 64 KB fixed-size chunks with sequential index | Splits large files for streaming over an encrypted channel |
| Offline redistribution | RSA-PSS-SHA-256 signed manifest (owner peer_id, filename, file_size, SHA-256) | A third peer can verify file authenticity using only the owner's public key — owner need not be online |
| Key migration | KEY_MIGRATION message dual-signed with old and new keys | Old key proves message origin; new key proves ownership; contacts update their stored public key atomically |
| Local storage | PBKDF2-HMAC-SHA-256 (200,000 iterations) + AES-256-GCM, per-file random 16-byte salt and 12-byte nonce | Password-protected vault; offline theft of the device does not expose file contents |
| Perfect forward secrecy | Ephemeral DH private keys generated fresh per session and never persisted | Compromise of the long-term RSA key cannot decrypt any past session |

---

## Project Structure

```
secureshare_cisc468_Project/
│
├── python_client/
│   ├── crypto/
│   │   ├── identity.py          # RSA-2048 key generation and PSS signing/verification
│   │   ├── session.py           # AES-256-GCM session encrypt/decrypt with sequence numbers
│   │   ├── vault.py             # PBKDF2 key derivation + AES-GCM vault encryption
│   │   ├── manifest.py          # Build and sign file manifests for offline redistribution
│   │   ├── key_migration.py     # Build and verify KEY_MIGRATION messages
│   │   ├── hkdf_utils.py        # HKDF-SHA-256 wrapper
│   │   ├── dh_params.py         # RFC 3526 Group 14 DH parameters
│   │   └── hashing.py           # SHA-256 helpers
│   ├── net/
│   │   ├── router.py            # Dispatches incoming decrypted messages to handlers
│   │   ├── connection_handler.py# Per-connection lifecycle (handshake → routing)
│   │   ├── consent_handler.py   # Consent prompt logic
│   │   ├── consent_manager.py   # Thread-safe consent queue (background → main thread)
│   │   ├── framing.py           # 4-byte length-prefix framing
│   │   ├── tcp_server.py        # Multi-threaded TCP listener
│   │   ├── file_receiver.py     # Chunk collection and reassembly
│   │   └── discovery_listener.py# mDNS browser
│   ├── protocol/
│   │   ├── handshake.py         # DH key generation, transcript hash, session key derivation
│   │   ├── message_types.py     # Message type string constants
│   │   ├── canonical_json.py    # Deterministic JSON serialisation
│   │   ├── serializer.py        # JSON encode / decode helpers
│   │   └── validator.py         # Handshake message field validation
│   ├── files/
│   │   ├── chunker.py           # Split bytes into 64 KB chunks
│   │   ├── share_manager.py     # Manages the shared-files vault and index
│   │   └── transfer_manager.py  # Consent + chunk send flow for outbound transfers
│   ├── storage/
│   │   ├── vault_store.py       # Encrypted-at-rest file storage (personal vault)
│   │   ├── contacts_store.py    # Verified peer public keys
│   │   ├── manifest_store.py    # Signed file manifests
│   │   ├── share_index_store.py # Index of files available for sharing
│   │   └── config_store.py      # Peer name and port configuration
│   ├── cli/
│   │   ├── cli.py               # Main CLI loop with consent polling
│   │   ├── commands.py          # Command dispatcher and help text
│   │   └── commands_*.py        # One file per command group
│   ├── discovery/
│   │   └── mdns_service.py      # mDNS service advertisement via zeroconf
│   ├── data/                    # Runtime data (created on first run, gitignored)
│   ├── main_runtime.py          # Application bootstrap
│   ├── run_client.py            # Entry point
│   └── requirements.txt
│
├── java_client/
│   ├── src/main/java/com/cisc468share/
│   │   ├── crypto/
│   │   │   ├── AesGcmUtil.java      # AES-256-GCM encrypt/decrypt
│   │   │   ├── Vault.java           # PBKDF2 + AES-GCM vault crypto
│   │   │   ├── IdentityManager.java # RSA-2048 key generation and PSS signing
│   │   │   ├── HandshakeManager.java# Orchestrates CLIENT_HELLO / SERVER_HELLO
│   │   │   ├── SecureSession.java   # Per-session key material
│   │   │   ├── ManifestManager.java # Build, sign, and verify file manifests
│   │   │   ├── KeyMigrationUtil.java# Apply and verify KEY_MIGRATION messages
│   │   │   ├── HkdfUtil.java        # HKDF-SHA-256
│   │   │   ├── DhParams.java        # RFC 3526 Group 14 parameters
│   │   │   └── HashUtil.java        # SHA-256 helpers
│   │   ├── net/
│   │   │   ├── SecureChannel.java   # AES-GCM send/receive over a socket
│   │   │   ├── ConnectionHandler.java# Per-connection lifecycle
│   │   │   ├── ConsentManager.java  # Thread-safe consent queue
│   │   │   ├── Framing.java         # Length-prefix framing
│   │   │   ├── TcpServer.java       # Multi-threaded TCP listener
│   │   │   ├── TcpClient.java       # TCP connection helper
│   │   │   ├── FileTransfer.java    # Chunk send/receive
│   │   │   └── SessionManager.java  # DH shared secret + key derivation
│   │   ├── protocol/
│   │   │   ├── CanonicalJson.java   # Deterministic JSON (sorted keys)
│   │   │   ├── MessageTypes.java    # Message type string constants
│   │   │   ├── HandshakeUtil.java   # Build CLIENT_HELLO / SERVER_HELLO
│   │   │   ├── Serializer.java      # JSON encode / decode
│   │   │   └── Validator.java       # Handshake field validation
│   │   ├── files/
│   │   │   ├── ShareManager.java    # Manages the shared-files vault and index
│   │   │   └── Chunker.java         # 64 KB file chunking
│   │   ├── storage/
│   │   │   ├── VaultStore.java      # Encrypted-at-rest file storage
│   │   │   ├── ContactsStore.java   # Verified peer public keys
│   │   │   ├── ManifestStore.java   # Signed file manifests
│   │   │   ├── ShareIndexStore.java # Index of shared files
│   │   │   └── ConfigStore.java     # Configuration
│   │   ├── discovery/
│   │   │   └── MdnsService.java     # mDNS advertisement and discovery via JmDNS
│   │   ├── router/
│   │   │   └── MessageRouter.java   # Dispatches incoming messages to handlers
│   │   ├── cli/
│   │   │   └── CommandLine.java     # CLI loop and all command implementations
│   │   └── runtime/
│   │       └── RuntimeLauncher.java # Application bootstrap
│   ├── src/test/java/com/cisc468share/
│   │   ├── crypto/                  # VaultTest, ManifestManagerTest, KeyMigrationTest,
│   │   │                            # HandshakeManagerTest, SecurityFailureTest, etc.
│   │   ├── protocol/                # FramingTest, SerializerTest
│   │   └── interop/                 # Cross-language vector tests (AES-GCM, HKDF, session keys)
│   └── pom.xml
│
├── tests/
│   ├── python/                      # pytest test suite (97 tests)
│   │   ├── conftest.py
│   │   ├── test_req2_mutual_authentication.py
│   │   ├── test_req3_req4_file_transfer_protocol.py
│   │   ├── test_req5_offline_redistribution.py
│   │   ├── test_req6_key_migration.py
│   │   ├── test_req7_confidentiality_integrity.py
│   │   ├── test_req8_perfect_forward_secrecy.py
│   │   ├── test_req9_secure_storage.py
│   │   └── test_req10_error_scenarios.py
│   └── run_all_tests.sh             # Runs both Python and Java test suites
│
├── shared_test_vectors/             # Cross-language interoperability vectors
├── docs/
│   └── protocol.md                  # Detailed protocol specification
└── README.md
```

---

## Prerequisites

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.12+ | |
| Java | 17+ | OpenJDK recommended |
| Apache Maven | 3.8+ | Manages Java dependencies |
| Linux or WSL2 | — | Recommended; mDNS may require firewall adjustment |

Install on Ubuntu / Debian:

```bash
sudo apt-get install -y python3.12 python3.12-venv openjdk-17-jdk maven
```

---

## Setup

### Python client

```bash
cd python_client
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

A `.venv` directory is already included in the repository with dependencies pre-installed. If it works out of the box, skip the above.

### Java client

Maven downloads all dependencies automatically on first run. No manual step is needed beyond having Maven installed.

```bash
cd java_client
mvn package -q -DskipTests    # compile and build the JAR
```

---

## Running the Clients

Open two terminals. Run one client in each.

### Terminal 1 — Python client

```bash
cd python_client
.venv/bin/python3.12 run_client.py
```

You will be prompted for a vault password. The password encrypts all locally stored files. Use the same password every time you launch on the same machine. To obtain the vault passwords for testing or grading, contact the project owner.

```
[INFO] Identity: secureshare-peer-a1b2c3d4
[INFO] Peer ID:  3f8a2c...
Vault password: ••••••••••••
[INFO] Listening on port 52341
[INFO] Local vault unlocked.
secure-share>
```

### Terminal 2 — Java client

```bash
cd java_client
mvn exec:java -Dexec.mainClass="com.cisc468share.Main" -q
```

```
[INFO] Identity: java-peer
[INFO] Peer ID:  810a9e...
Vault password: ••••••••••••
Discovered peer: {'name': 'secureshare-peer-a1b2c3d4._cisc468share._tcp.local.', ...}
[INFO] Listening on port 48201
[INFO] Local vault unlocked.
secure-share>
```

Both clients bind to a random available port and advertise themselves via mDNS. Discovery is automatic — within a few seconds each client will print the other's name.

---

## Command Reference

All commands are identical across both clients.

### `help`

Prints all available commands.

---

### `peers`

Lists peers discovered on the local network via mDNS.

```
secure-share> peers
secureshare-peer-a1b2c3d4._cisc468share._tcp.local. - 127.0.1.1
java-peer._cisc468share._tcp.local. - 127.0.1.1
```

---

### `connect <peer-name>`

Opens a TCP connection to a peer and performs the full mutual authentication handshake. Both sides exchange RSA-signed DH hello messages. After verification, a session key is derived and the connection is kept open for subsequent commands.

```
secure-share> connect java-peer
[INFO] Connecting to java-peer at 127.0.1.1:48201
[INFO] Handshake complete with java-peer
[INFO]   Peer ID   : 810a9ee3...
[INFO]   Fingerprint: 810a9e...  ← verify this out-of-band
```

Both peers must verify the displayed fingerprint matches their contact record. This is the trust anchor.

---

### `list`

Lists the files you have shared (made available to other peers).

```
secure-share> list
report_2026.pdf
dataset_v3.csv
```

### `list downloads`

Lists files in your `data/downloads/` folder (plaintext exports from the vault).

```
secure-share> list downloads
Files in data/downloads/:
  notes.txt
```

---

### `share <file-path>`

Encrypts a file and adds it to your shared vault, signs an RSA manifest, and makes the file available for other peers to request. The original plaintext file is not modified.

```
secure-share> share /home/user/documents/report.pdf
[OK] File shared: report.pdf
     Stored encrypted at rest in the shared vault
[OK] Manifest signed and stored for 'report.pdf'
     SHA-256 : 4a7f3c...
     Owner   : java-peer (810a9ee3...)
```

The manifest binds the filename, SHA-256, and file size to the owner's identity via an RSA-PSS signature. It is used later by `fetch` to verify files received through intermediaries.

---

### `list-files <peer-name>`

Requests the list of files a peer has shared. No consent is required from the peer.

```
secure-share> list-files java-peer
report_2026.pdf
dataset_v3.csv
```

---

### `send <peer-name> <filename>`

Sends a file from your shared vault to a peer. The peer is shown the filename and size and must accept before any data is transmitted.

```
# On the sender:
secure-share> send java-peer report.pdf
[INFO] java-peer accepted 'report.pdf', sending 142,304 bytes...
[INFO] 'report.pdf' sent successfully (SHA-256: 4a7f3c...)

# On the receiver (java-peer):
[INCOMING FILE REQUEST]
  Peer: secureshare-peer
  File: report.pdf
  Size: 142,304 bytes
  Accept? [y/N]: y
[INFO] 'report.pdf' saved to encrypted vault (142,304 bytes)
[INFO] Integrity OK: SHA-256=4a7f3c...
```

---

### `request <peer-name> <filename>`

Asks a peer to send you a specific file from their shared vault. The peer must consent before the transfer begins. Equivalent to `send` but initiated from the receiver's side.

```
secure-share> request java-peer dataset_v3.csv
```

On the Java side, the consent prompt appears. If accepted, the file is streamed back and saved to your vault.

---

### `fetch <peer-name> <filename>`

Fetches a file from an **intermediary** peer — useful when the original owner is offline. SecureShare verifies the received file against the owner's signed manifest. If the file has been tampered with, the transfer is rejected with a security error.

```
secure-share> fetch java-peer report.pdf
[INFO] Fetching 'report.pdf' from java-peer...
[INFO] Manifest verified — owner: alice (3f8a2c...)
[INFO] Integrity check passed: SHA-256 matches manifest
[INFO] 'report.pdf' saved to vault
```

The intermediary peer must have the file in their vault and the owner's signed manifest. No connection to the original owner is needed.

---

### `store <file-path>`

Stores any local file into your personal encrypted vault. The file is encrypted with AES-256-GCM using your vault password.

```
secure-share> store notes.txt
[OK] Stored 'notes.txt' in the encrypted vault.
```

If the file is not found at the given path, the command also checks `data/downloads/`.

---

### `vault list`

Lists all files currently in your personal encrypted vault.

```
secure-share> vault list
Encrypted vault files:
  report.pdf
  notes.txt
```

### `vault get <filename>`

Decrypts a file from the vault and exports the plaintext copy to `data/downloads/`.

```
secure-share> vault get notes.txt
[OK] Exported 'notes.txt' from vault to data/downloads/notes.txt
```

### `vault delete <filename>`

Permanently removes a file from the vault.

```
secure-share> vault delete notes.txt
[OK] Deleted 'notes.txt' from the encrypted vault.
```

---

### `rotate-key`

Generates a new RSA-2048 key pair, signs a KEY_MIGRATION message with both the old and new private keys, and broadcasts it to all currently connected peers. Contacts update their stored public key for this peer atomically.

```
secure-share> rotate-key
[ROTATE-KEY] Generating new RSA-2048 key pair ...
[ROTATE-KEY] New peer ID : 9c1e4f...
[ROTATE-KEY] Migration message built and signed with both keys.
[ROTATE-KEY] Sent KEY_MIGRATION to 'java-peer'
[ROTATE-KEY] Identity rotated. New peer ID: 9c1e4f...
```

The old key is retired. Any peer that was not online when the migration was broadcast will receive it on their next connection.

---

### `exit` / `quit`

Closes all connections and exits.

---

## Typical Usage Walkthrough

This walkthrough demonstrates all major features between the Python and Java clients on the same machine.

**1. Start both clients** (two separate terminals, as shown in [Running the Clients](#running-the-clients)).

**2. Verify peer discovery**
```
secure-share> peers
```
Both clients should appear within a few seconds.

**3. Connect and authenticate**
```
# Python terminal:
secure-share> connect java-peer
```
Both clients print a fingerprint. In a real deployment you would compare these out-of-band (e.g., by phone) before trusting the peer.

**4. Share a file and send it**
```
# Python terminal:
secure-share> share ~/documents/report.pdf
secure-share> send java-peer report.pdf
```
The Java terminal shows the consent prompt. Accept it, then on Java:
```
secure-share> vault list     # report.pdf should appear
```

**5. Request a file from the other direction**
```
# Java terminal:
secure-share> share data/sample.txt
# Python terminal:
secure-share> list-files java-peer
secure-share> request java-peer sample.txt
```

**6. Test offline redistribution (fetch)**
```
# After Java has received report.pdf via send:
# Python terminal:
secure-share> fetch java-peer report.pdf
```
The manifest is verified automatically. If the file were modified, you would see a `[SECURITY ERROR]` and the transfer would be rejected.

**7. Vault operations**
```
secure-share> vault list
secure-share> vault get report.pdf
secure-share> list downloads
```

---

## Running the Tests

All tests run without any network connection and do not require both clients to be running. They test the cryptographic and protocol components directly.

### Run everything at once

From the project root:

```bash
bash tests/run_all_tests.sh
```

Expected output:

```
── Python Unit Tests (97 tests, Requirements 2–10) ────────
...
97 passed in 5.4s
[PASS] All Python tests passed

── Java Unit Tests (53 tests, Requirements 2–10) ──────────
Tests run: 53, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
[PASS] All Java tests passed

  RESULT: 2 suites passed — all 150 tests green
```

### Run Python tests only

```bash
cd python_client
.venv/bin/pytest ../tests/python/ -v
```

### Run Java tests only

```bash
cd java_client
mvn test
```

### Run a single Python test file

```bash
cd python_client
.venv/bin/pytest ../tests/python/test_req9_secure_storage.py -v
```

---

## Test Coverage by Requirement

### Python test suite — `tests/python/` (97 tests total)

| File | Tests | Requirement covered |
|---|---|---|
| `test_req2_mutual_authentication.py` | 11 | **REQ 2** — Mutual authentication. Verifies that peer_id = SHA-256(public_key), RSA-PSS signatures verify correctly, cross-key verification fails, DH transcript hash is deterministic, and both peers derive identical session keys. |
| `test_req3_req4_file_transfer_protocol.py` | 17 | **REQ 3 & 4** — File transfer with consent; listing files. Tests file chunking (empty, boundary, large), TCP framing encode/decode, FILE_REQUEST and FILE_TRANSFER_COMPLETE message structure, and the ConsentManager accept/deny flow. |
| `test_req5_offline_redistribution.py` | 10 | **REQ 5** — Offline redistribution with tamper verification. Tests manifest field correctness, SHA-256 match, RSA-PSS signing and verification, detection of tampered files, forged manifests, and signatures from the wrong key. |
| `test_req6_key_migration.py` | 7 | **REQ 6** — Key migration. Tests migration message construction, required fields, old-key signature verifiability, forged and tampered migration detection, missing-field validation, and usability of the returned new public key. |
| `test_req7_confidentiality_integrity.py` | 9 | **REQ 7** — Confidentiality and integrity. Tests AES-256-GCM encrypt/decrypt roundtrip, unique ciphertext per encryption, tampered ciphertext detection, modified AAD detection, wrong-key rejection, SHA-256 file integrity, and replay/reorder protection. |
| `test_req8_perfect_forward_secrecy.py` | 9 | **REQ 8** — Perfect forward secrecy. Tests that each DH keypair is unique, shared secrets match on both sides, independent sessions produce different keys, send and recv keys are distinct, HKDF labels produce separate outputs, and RSA key material does not appear in session keys. |
| `test_req9_secure_storage.py` | 15 | **REQ 9** — Secure local storage. Tests vault encrypt/decrypt roundtrip, absence of plaintext in the blob, wrong-password rejection, tamper detection, non-deterministic encryption, minimum blob size, PBKDF2 iteration count (200,000), 1 MB file roundtrip, and full VaultStore API (store, retrieve, list, delete, overwrite, wrong-password on retrieve). |
| `test_req10_error_scenarios.py` | 19 | **REQ 10** — Error detection. Covers every error scenario: SHA-256 mismatch on transit, AES-GCM tag failure, replay rejection, out-of-order rejection, wrong vault password, truncated vault blob, signature forgery, tampered manifest, truncated frame, empty stream, partial length prefix, and canonical JSON determinism. |

### Java test suite — `src/test/java/` (53 tests total)

| File | Tests | Requirement covered |
|---|---|---|
| `crypto/VaultTest.java` | 13 | **REQ 9** — Secure local storage (Java). Mirrors the Python vault tests: PBKDF2 + AES-GCM roundtrip, plaintext absent from blob, wrong password, tamper detection, non-deterministic blobs, minimum blob length, 1 MB roundtrip, and full VaultStore API. |
| `crypto/ManifestManagerTest.java` | 6 | **REQ 5** — Offline redistribution (Java). Tests manifest field correctness, SHA-256 match, signed manifest verification, tampered manifest rejection, wrong-key rejection, and tampered-file detection via SHA-256. |
| `crypto/KeyMigrationTest.java` | 6 | **REQ 6** — Key migration (Java). Tests message construction, old/new peer ID difference, old-key signature verifiability, `applyMigrationMessage` acceptance from known contacts, rejection of unknown senders, and rejection of tampered messages. |
| `crypto/HandshakeManagerTest.java` | 5 | **REQ 2 & 8** — Mutual authentication and PFS. Tests CLIENT_HELLO and SERVER_HELLO field completeness, signature verification, transcript hash determinism, and full session derivation including client/server key swap correctness. |
| `crypto/SecurityFailureTest.java` | 6 | **REQ 7 & 10** — Error scenarios. Tests cross-key signature rejection, tampered signature rejection, tampered data rejection, AES-GCM tampered ciphertext, wrong AAD, and wrong decryption key. |
| `crypto/HkdfInteropTest.java` | 3 | **REQ 8** — HKDF produces correct output against shared test vectors, matching the Python implementation. |
| `crypto/AesGcmInteropTest.java` | 4 | **REQ 7** — AES-GCM produces correct output against shared test vectors, matching the Python implementation. |
| `crypto/HashUtilTest.java` | 1 | SHA-256 implementation correctness. |
| `protocol/FramingTest.java` | 1 | **REQ 3** — Framing encodes and decodes correctly. |
| `protocol/SerializerTest.java` | 1 | Canonical JSON serialisation correctness. |
| `interop/InteropVectorTest.java` | 5 | Cross-language interoperability — Java and Python produce identical outputs for AES-GCM, HKDF, and SHA-256 given the same inputs. |
| `interop/DeriveSessionTest.java` | 2 | **REQ 2 & 8** — Session key derivation produces correct values and the Java and Python implementations agree. |

---

## Security Parameters

| Parameter | Value | Rationale |
|---|---|---|
| RSA key size | 2048 bits | NIST-recommended minimum for long-term identity keys |
| RSA-PSS salt length | 32 bytes | Equals SHA-256 digest length; matches Java PSS default for interoperability |
| DH group | RFC 3526 Group 14, 2048-bit prime | NIST-recommended minimum for Diffie-Hellman |
| AES key size | 256 bits | Maximum AES security level |
| GCM tag size | 128 bits | Maximum GCM integrity guarantee |
| GCM nonce | 12 bytes, random per message | GCM standard; random nonces eliminate nonce reuse risk |
| HKDF hash | SHA-256 | Widely supported; 256-bit security |
| PBKDF2 hash | SHA-256 | NIST-recommended for password-based key derivation |
| PBKDF2 iterations | 200,000 | Meets NIST SP 800-132 recommendation for current hardware |
| PBKDF2 salt | 16 bytes, random per file | Prevents rainbow table and pre-computation attacks |
| Sequence numbers | Per-session monotonic counter | Rejects replayed and out-of-order messages |

---

## Libraries Used

**Python**
- `cryptography` — RSA-PSS, AES-256-GCM, HKDF-SHA-256, PBKDF2-HMAC-SHA256
- `zeroconf` — mDNS service advertisement and discovery
- `pytest` — test framework

**Java**
- `javax.crypto` / `java.security` (JDK standard library) — AES-GCM, RSA-PSS, HKDF, PBKDF2
- `Jackson` — JSON serialisation and deserialisation
- `JmDNS` — mDNS service advertisement and discovery
- `JUnit 5` (Jupiter) — test framework

---

## Known Limitations

- **Same LAN only.** mDNS is a link-local protocol. Both peers must be on the same network segment. Internet-facing deployment would require a DHT or relay server.
- **No GUI.** The interface is a command-line REPL. Consent prompts require the user to be at the terminal.
- **Single concurrent consent.** The ConsentManager serialises consent requests. If two peers request files simultaneously, the second request queues until the first is answered.
- **Port assignment.** Ports are assigned randomly at startup by the OS. If a peer disconnects and reconnects, its new port may differ, though mDNS advertisements are updated automatically.
- **Key migration requires live connection.** Contacts that are offline when `rotate-key` is run will receive the migration message on their next connection. There is no guarantee of delivery if the peer never reconnects.
