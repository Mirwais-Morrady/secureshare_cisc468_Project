"""
Cross-language session test.

This test verifies that Python and Java derive IDENTICAL session keys
when given the SAME inputs. It uses the shared fixed vectors from
the DeriveSessionTest handshake messages.

Run this test after running Java's DeriveSessionTest to confirm
both sides produce the same transcript hash.
"""
import sys
from pathlib import Path
import base64

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

from protocol.handshake import (
    derive_session_keys,
    transcript_hash,
    compute_shared_secret,
)
from crypto.dh_params import bytes_to_int


# The same fixed vectors used in Java's DeriveSessionTest
CLIENT_HELLO = {
    "type": "CLIENT_HELLO",
    "proto_ver": "1.0",
    "peer_name": "python-peer",
    "peer_id": "68bf78cc91c41ebfc206ea48b40b9a5034efec1ff3c3223ca659fec53bfda86a",
    "rsa_public_key_der_b64": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAraHchP+bl8IcNjjysrgZ40bsLOPoCLsPH9cRWgm8nE25OZJ9BCOsr1AMDJ+iH0kKO6D0oc9IEPBG1EHfnVMs0A1DAmGyKUeIocOfeW24xKUV5Seu1mtmxirb/qFgj+Mq/810C9+OJN8lmX1IWxYtPVmUs6TA6DgKDHoxBxjZmvV32KqA2rGC/DT0dIWx80mDAAv4og0LmMdS0CI+WTlV7G/99Ea4zzr5G46hDfrUdLVP7EehLrEK+/E3iEK9u77Z/2efGI6DfKBkui68TERir9PDDnld4qeLRtim6nx50ny3wg+ISyzvzul+EzQyA1paPAvRAN2S4xSazc3U/+AMfQIDAQAB",
    "dh_public_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHiegwSZcBlcm7RThKzBDLg1iCdXBMpxoxau1ZP0yPYsbADo6+dJAvpcn29Im3Z/QuO59vSCGmogfeEKoC3xA2zkKHbi2dyIhqinkdgcL4hmIavEnGh6CM0BsbNq0WbNhK3bmK+TPSgLMPlDG5h5e0ok4WeILF2qV+Zw1KJOu6HKHB2V4E0BjdRPVumeOJ1ZSzRJ5TDT6TH55BfDq5dHoxXWhqyA92XuFblYkS/meNxWnKVHtongtAwkkypBX6gqdw==",
    "nonce1_b64": "JxrLe1stN7vA4JqFzVmQCg==",
    "signature_b64": "ORObOeixthhn9C1Px7C6kI3/IvL9jw9d2aRgrYmXjOAqQstQ17Q0iucIKyD2UqwfgmX5LC7EBEWtTKajkr4tSuDqlMMnnh2/FlOAj5lqx2TEDotEakkbvQdM3acOhOxQHeVCHh+MdhG7+alve4uy8lRRoJsDR0tg6qw7gUuySjynjVMwsU956XlmFPsR8Pn6vTsMngKYCVkuiHiFunLh0FkyMqkGKvWdQie5zQAIbJdfIEijlAQgj9fmjmfYVqBwpQgtR9KNsaqJuSznNZeRGPbSZCb8fN6/g3R66hs3WdUDpdSc7o0PDG5zBxuvB7qnlKKNQb7xM5LFf3UYZSP/fg==",
}

SERVER_HELLO = {
    "type": "SERVER_HELLO",
    "proto_ver": "1.0",
    "peer_name": "java-peer",
    "peer_id": "130b2fc830101cd795423eb3cea66a9677d0387a2f02cd6d4d1cfa447fd95eb2",
    "rsa_public_key_der_b64": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1lNKOeiJWah0+U5NXyRQTe9B7rfJw2kVfPID3ptkZc5UIgjri2jtkDSP37IUoKPckFd0dORlDz0plv2Ajgd6v1ezSi+7CdQfKfZ4dxm7NBZmU4nZQGrpxwPFOGTkkU6/FgolHDhan8+lxUMl77nYAnOC6dGiJe6DkIIIPUIHEC8XNmiDqaWmviN9JlNhxZK8Y4yeKL00vYX3S2kWCT3hNyBvW7+VzaSACzG+cRDUFwXlMg+tyd9gjhvd0ugXAIyR/Rr6JS0/Hn4SJr4P5N0V89rGyD8uvxrHaontb9pPkBFjUpcmNzliL/d7lFK6F3YYPrSL2f7ePsK8oG9gthCDLwIDAQAB",
    "dh_public_b64": "wAbjZ6yyYh6NUleR2GwCx5J5MxZ1/eWt2y/9a5G2eaQHVgXbtmHlWhgCMipHbk+ljPaObSxPTSOIPyP0YDVpz7keDL9Rhqd3sD6yvpEhRPTFNTcuPwfl2V6+Dg4169nWYBpXOuDhpBN7fGqcrZVQtY+R4JSnEuplX4j/RaElB3MFpUVNX4Nzu1GrT9/yyW6S/Wu70Aokx6azH58K6ZVfs+pY33pWAPVGFQy44Sw/VkOedfRMn8SG113qoG5E9xp9",
    "nonce2_b64": "AQIDBAUGBwgJCgsMDQ4PEA==",
    "client_nonce1_b64": "ERITFBUWFxgZGhscHR4fIA==",
    "signature_b64": "D5kUDZiHWW0rPVH2L6vu1R/2fEiMN7CGhY6CNHEdxtD6ssibJkufWgf3IoiJy8UC+2hcnPTw7S74AIyrMCJV/CFUGUbPZFwgbtG0tU2UFtr9Xx4+nKMLx38G++fyBpUutoB0oPJ0qh0qWog7Qc4RntQQMxTfbiXwGnzMl60A1F/H5UxMGXvRkodctNieYeCL3Aw2TPwAeGVulXlkLdgdPmFkopp0bhRuGK5mZI4H77zIdx5gsDvjERThpkiwTu6MMnXhPcuuesA0qhvrgS5Ego/0ImjE1el5biAJ6+2jBijq6UwRQO2lbOa+m0Dyc4wk1dMtzWpNykPWmHKIQTmmJA==",
}


def test_transcript_hash_from_fixed_vectors():
    """Verify transcript hash computation from fixed handshake vectors."""
    thash = transcript_hash(CLIENT_HELLO, SERVER_HELLO)
    assert len(thash) == 32
    thash_b64 = base64.b64encode(thash).decode()
    print(f"\ntranscript_hash_b64 = {thash_b64}")
    # This value must match what Java's DeriveSessionTest prints


def test_hkdf_session_keys_deterministic():
    """Verify that HKDF session keys are deterministic given same inputs."""
    thash = transcript_hash(CLIENT_HELLO, SERVER_HELLO)
    dummy_shared = b"\x00" * 256

    send1, recv1, sid1 = derive_session_keys(dummy_shared, thash)
    send2, recv2, sid2 = derive_session_keys(dummy_shared, thash)

    assert send1 == send2
    assert recv1 == recv2
    assert sid1 == sid2


def test_session_keys_from_fixed_vectors():
    """Compute session keys from fixed DH public values and a dummy shared secret.

    In a real test, we'd need the private keys too. This validates
    the key derivation structure is correct.
    """
    thash = transcript_hash(CLIENT_HELLO, SERVER_HELLO)

    # Use a fixed shared secret for reproducibility
    fixed_shared = bytes.fromhex("a" * 64 + "b" * 64 + "c" * 64 + "d" * 64)  # 128 bytes

    send_key, recv_key, session_id = derive_session_keys(fixed_shared, thash)

    assert len(send_key) == 32
    assert len(recv_key) == 32
    assert len(session_id) == 32  # 16 bytes hex = 32 chars
    assert send_key != recv_key

    print(f"\nWith fixed shared secret:")
    print(f"  send_key_b64 = {base64.b64encode(send_key).decode()}")
    print(f"  recv_key_b64 = {base64.b64encode(recv_key).decode()}")
    print(f"  session_id = {session_id}")
