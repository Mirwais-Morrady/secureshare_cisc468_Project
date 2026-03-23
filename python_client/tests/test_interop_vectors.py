import base64
import json
import hashlib
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "shared_test_vectors"


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_sha256_vectors():
    data = load_json(VECTORS / "hashes" / "sha256_vectors.json")
    for item in data["vectors"]:
        raw = base64.b64decode(item["input_b64"])
        expected = base64.b64decode(item["sha256_b64"])
        actual = hashlib.sha256(raw).digest()
        assert actual == expected, f"SHA-256 mismatch for input {item['input_b64']}"


def test_hkdf_extract_vector():
    """Verify HKDF-Extract output (PRK) against test vector."""
    import hmac
    data = load_json(VECTORS / "hkdf" / "hkdf_test_vectors.json")
    ikm = base64.b64decode(data["ikm_b64"])
    salt = base64.b64decode(data["salt_b64"])
    expected_prk = base64.b64decode(data["expected_prk_sha256_b64"])
    # HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
    actual_prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    assert actual_prk == expected_prk, "HKDF PRK mismatch"


def test_hkdf_okm_vector():
    """Verify HKDF full output against stored OKM."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    data = load_json(VECTORS / "hkdf" / "hkdf_test_vectors.json")
    if "okm_b64" not in data:
        import pytest
        pytest.skip("okm_b64 not yet in vector file")
    ikm = base64.b64decode(data["ikm_b64"])
    salt = base64.b64decode(data["salt_b64"])
    info = base64.b64decode(data["info_b64"])
    expected_okm = base64.b64decode(data["okm_b64"])
    length = data.get("length", 32)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    actual_okm = hkdf.derive(ikm)
    assert actual_okm == expected_okm, "HKDF OKM mismatch"


def test_aes_gcm_encrypt_vector():
    """Verify AES-GCM encryption against stored ciphertext."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    data = load_json(VECTORS / "aes_gcm" / "aes_gcm_vector.json")
    if "ciphertext_b64" not in data:
        import pytest
        pytest.skip("ciphertext_b64 not yet in vector file")
    key = base64.b64decode(data["key_b64"])
    nonce = base64.b64decode(data["nonce_b64"])
    aad = base64.b64decode(data["aad_b64"])
    plaintext = base64.b64decode(data["plaintext_b64"])
    expected_ct = base64.b64decode(data["ciphertext_b64"])
    aes = AESGCM(key)
    actual_ct = aes.encrypt(nonce, plaintext, aad)
    assert actual_ct == expected_ct, "AES-GCM ciphertext mismatch"


def test_aes_gcm_decrypt_vector():
    """Verify AES-GCM decryption against stored vector."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    data = load_json(VECTORS / "aes_gcm" / "aes_gcm_vector.json")
    if "ciphertext_b64" not in data:
        import pytest
        pytest.skip("ciphertext_b64 not yet in vector file")
    key = base64.b64decode(data["key_b64"])
    nonce = base64.b64decode(data["nonce_b64"])
    aad = base64.b64decode(data["aad_b64"])
    expected_pt = base64.b64decode(data["plaintext_b64"])
    ct = base64.b64decode(data["ciphertext_b64"])
    aes = AESGCM(key)
    actual_pt = aes.decrypt(nonce, ct, aad)
    assert actual_pt == expected_pt, "AES-GCM plaintext mismatch"


def test_handshake_vector_file_exists_and_has_fields():
    data = load_json(VECTORS / "handshake" / "handshake_vector.json")
    assert "client_nonce_b64" in data
    assert "server_nonce_b64" in data
    assert "client_dh_public_b64" in data
    assert "server_dh_public_b64" in data


def test_manifest_vector_file_exists_and_has_fields():
    data = load_json(VECTORS / "manifests" / "manifest_vector.json")
    assert "filename" in data
    assert "size" in data
    assert "sha256_b64" in data
    assert "signature_b64" in data
