"""
Consent handler for file transfer requests.

When a peer requests to send a file, the receiving peer must explicitly
consent before the transfer begins. This module provides the prompt logic.
"""


def prompt_receive_consent(peer_name: str, filename: str, filesize: int) -> bool:
    """
    Prompt the user to accept or deny an incoming file transfer request.

    Args:
        peer_name: Name of the peer requesting to send
        filename: The filename being offered
        filesize: File size in bytes

    Returns:
        bool: True if user accepted, False if denied
    """
    print(f"\n[INCOMING FILE REQUEST]")
    print(f"  Peer: {peer_name}")
    print(f"  File: {filename}")
    print(f"  Size: {filesize:,} bytes")
    try:
        response = input("  Accept? [y/N]: ").strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def prompt_send_consent(peer_name: str, filename: str) -> bool:
    """
    Prompt the user to confirm sending a file to a peer.

    Args:
        peer_name: Name of the destination peer
        filename: The filename to be sent

    Returns:
        bool: True if user confirmed, False otherwise
    """
    print(f"\n[SEND FILE]")
    print(f"  Destination: {peer_name}")
    print(f"  File: {filename}")
    try:
        response = input("  Confirm send? [y/N]: ").strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False
