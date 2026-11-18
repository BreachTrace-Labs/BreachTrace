"""Encrypt project credentials with a deployment-specific AES-256-GCM key."""
import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _key() -> bytes:
    try:
        key = bytes.fromhex(os.environ.get("WALLET_ENCRYPTION_KEY", ""))
    except ValueError as exc:
        raise RuntimeError("WALLET_ENCRYPTION_KEY must be 64 hexadecimal characters") from exc
    if len(key) != 32:
        raise RuntimeError("WALLET_ENCRYPTION_KEY must be 64 hexadecimal characters")
    return key


def encrypt_blob(plaintext: dict) -> tuple[str, str]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, json.dumps(plaintext).encode(), None)
    return base64.b64encode(ciphertext).decode(), nonce.hex()


def decrypt_blob(ciphertext_b64: str, iv_hex: str) -> dict:
    return json.loads(AESGCM(_key()).decrypt(bytes.fromhex(iv_hex), base64.b64decode(ciphertext_b64, validate=True), None))
