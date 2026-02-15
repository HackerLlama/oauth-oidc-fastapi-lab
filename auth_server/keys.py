"""
RSA key for signing JWTs. Load from file or generate and persist (no key material in code).
"""
import base64
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# 2048-bit RSA per security best practice
_KEY_BITS = 2048
_KID = "auth-server-key"


def _generate_key():
    return generate_private_key(65537, _KEY_BITS, default_backend())


def _serialize_private(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _deserialize_private(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None, backend=default_backend())


def load_or_create_signing_key(path: str | None) -> tuple[object, str]:
    """
    Load RSA private key from path, or generate and save. Returns (private_key, kid).
    Path from config; no key material in source.
    """
    if not path:
        path = ".auth_signing_key.pem"
    p = Path(path)
    if p.exists():
        try:
            pem = p.read_bytes()
            key = _deserialize_private(pem)
            return key, _KID
        except Exception as e:
            logger.warning("Failed to load signing key from %s: %s; generating new key", path, e)
    key = _generate_key()
    try:
        p.write_bytes(_serialize_private(key))
        logger.info("Generated and saved signing key to %s", path)
    except OSError as e:
        logger.warning("Could not save signing key to %s: %s", path, e)
    return key, _KID


def public_key_to_jwk(public_key) -> dict:
    """Export cryptography RSA public key to JWK (for JWKS)."""
    numbers = public_key.public_numbers()
    n_b64 = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("ascii")
    e_b64 = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("ascii")
    return {
        "kty": "RSA",
        "kid": _KID,
        "alg": "RS256",
        "use": "sig",
        "n": n_b64,
        "e": e_b64,
    }


# Module-level key (set at app startup)
_signing_key = None
_signing_kid = None


def get_signing_key() -> tuple[object, str]:
    global _signing_key, _signing_kid
    if _signing_key is None:
        from auth_server.config import SIGNING_KEY_PATH
        _signing_key, _signing_kid = load_or_create_signing_key(SIGNING_KEY_PATH)
    return _signing_key, _signing_kid


def get_jwks() -> dict:
    """Return JWKS dict with the public key for token verification."""
    private_key, _ = get_signing_key()
    public_key = private_key.public_key()
    jwk = public_key_to_jwk(public_key)
    return {"keys": [jwk]}
