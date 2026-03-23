
import base64
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from crypto.hashing import sha256_hex


PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"


@dataclass
class Identity:
    peer_name: str
    peer_id: str
    fingerprint_hex: str
    private_key: object
    public_key: object
    public_key_der: bytes


class IdentityManager:
    def __init__(self, identity_dir: Path):
        self.identity_dir = identity_dir
        self.identity_dir.mkdir(parents=True, exist_ok=True)

    def load_or_create_identity(self, peer_name: str) -> Identity:
        priv = self.identity_dir / PRIVATE_KEY_FILE
        pub = self.identity_dir / PUBLIC_KEY_FILE

        if priv.exists() and pub.exists():
            private_key = serialization.load_pem_private_key(priv.read_bytes(), password=None)
            public_key = serialization.load_pem_public_key(pub.read_bytes())
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            priv.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

            pub.write_bytes(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        fingerprint = sha256_hex(public_key_der)
        peer_id = fingerprint

        return Identity(peer_name, peer_id, fingerprint, private_key, public_key, public_key_der)

    @staticmethod
    def sign(private_key, data: bytes) -> bytes:
        return private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )

    @staticmethod
    def verify(public_key, data: bytes, sig: bytes):
        public_key.verify(
            sig,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
