
# Secure Share Protocol Specification

This document defines the shared protocol used by both the Python and Java clients.

## 1. Discovery

Service type:

```text
_cisc468share._tcp.local.
```

Advertised TXT fields:

- `peer_name`
- `peer_id`
- `fingerprint`
- `proto_ver`
- `port`

Default TCP port:

```text
40468
```

Protocol version:

```text
1.0
```

## 2. Transport

All peer-to-peer communication uses TCP.

Each payload is framed as:

- 4-byte unsigned big-endian payload length
- payload bytes of that exact length

The framed payload is either:
- a plaintext JSON handshake message, or
- an encrypted JSON secure envelope after handshake

## 3. Identity and Fingerprints

Long-term identity algorithm:
- RSA
- 2048-bit minimum
- public exponent 65537

Signature algorithm:
- RSA-PSS with SHA-256

Fingerprint:
- SHA-256 of DER-encoded public key bytes
- represented as lowercase hex

Peer ID:
- same value as fingerprint hex for simplicity and stability

## 4. Ephemeral Diffie-Hellman

Key exchange:
- finite-field Diffie-Hellman
- RFC 3526 Group 14
- generator g = 2

Each session generates a fresh private exponent and corresponding public value.

Shared secret serialization:
- big-endian fixed-length byte string equal to modulus length in bytes

## 5. HKDF

Algorithm:
- HKDF-SHA-256

Input key material:
- serialized DH shared secret

Salt:
- transcript hash = SHA-256(client_hello_raw || server_hello_raw)

Info labels:
- `cisc468/session/client_to_server`
- `cisc468/session/server_to_client`
- `cisc468/session/session_id`

Output lengths:
- 32 bytes for each AES key
- 16 bytes for session id source material before hex/base64 formatting

## 6. Handshake Messages

Handshake messages are sent in plaintext JSON before secure session establishment.

### 6.1 ClientHello

```json
{
  "type": "CLIENT_HELLO",
  "proto_ver": "1.0",
  "peer_name": "alice-python",
  "peer_id": "<fingerprint-hex>",
  "rsa_public_key_der_b64": "<base64>",
  "dh_public_b64": "<base64>",
  "nonce1_b64": "<base64>",
  "signature_b64": "<base64>"
}
```

### 6.2 ServerHello

```json
{
  "type": "SERVER_HELLO",
  "proto_ver": "1.0",
  "peer_name": "bob-java",
  "peer_id": "<fingerprint-hex>",
  "rsa_public_key_der_b64": "<base64>",
  "dh_public_b64": "<base64>",
  "nonce2_b64": "<base64>",
  "client_nonce1_b64": "<base64>",
  "signature_b64": "<base64>"
}
```

### 6.3 Transcript Hash

After both messages are received and validated:

T = SHA-256(client_hello_canonical_json_bytes || server_hello_canonical_json_bytes)

### 6.4 Handshake Finish

Encrypted secure envelope payload:

```json
{
  "type": "HANDSHAKE_FINISH",
  "role": "initiator",
  "session_id": "<session-id>",
  "transcript_hash_b64": "<base64>"
}
```

or

```json
{
  "type": "HANDSHAKE_FINISH",
  "role": "responder",
  "session_id": "<session-id>",
  "transcript_hash_b64": "<base64>"
}
```

## 7. Secure Envelope

After handshake, all protocol messages are encrypted.

```json
{
  "version": "1.0",
  "session_id": "<session-id>",
  "msg_seq": 1,
  "msg_type": "LIST_FILES_REQUEST",
  "nonce_b64": "<base64-12-byte-nonce>",
  "aad_b64": "<base64-aad-bytes>",
  "ciphertext_b64": "<base64-ciphertext-and-tag>"
}
```

## 8. Message Types

Handshake:
- CLIENT_HELLO
- SERVER_HELLO
- HANDSHAKE_FINISH

Control:
- PING
- PONG
- ERROR
- LIST_FILES_REQUEST
- LIST_FILES_RESPONSE
- GET_FILE_REQUEST
- GET_FILE_RESPONSE
- SEND_FILE_OFFER
- SEND_FILE_ACCEPT
- SEND_FILE_DENY
- KEY_UPDATE_NOTICE

Transfer:
- FILE_CHUNK
- FILE_TRANSFER_COMPLETE

## 9. Manifest Format

```json
{
  "manifest_version": "1.0",
  "manifest_id": "<hex>",
  "owner_peer_id": "<fingerprint-hex>",
  "owner_peer_name": "alice-python",
  "file_name": "example.txt",
  "file_size": 1234,
  "file_sha256_hex": "<hex>",
  "mime_type": "application/octet-stream",
  "created_at": "2026-03-06T12:00:00Z",
  "chunk_size": 65536,
  "chunks": [
    {
      "index": 0,
      "offset": 0,
      "size": 1234,
      "sha256_hex": "<hex>"
    }
  ],
  "signature_b64": "<base64>"
}
```

## 10. Vault Format

```json
{
  "version": "1.0",
  "kdf": "PBKDF2-HMAC-SHA-256",
  "iterations": 200000,
  "salt_b64": "<base64-16-bytes>",
  "nonce_b64": "<base64-12-bytes>",
  "ciphertext_b64": "<base64-ciphertext-and-tag>"
}
```
