"""
RSA key(s) for signing JWTs (M11: key rotation — current + optional previous).
Load from file or generate and persist; no key material in code.
New tokens use current key; JWKS exposes all keys so tokens signed with previous key still verify.
"""
import base64
import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

_KEY_BITS = 2048
_KID_CURRENT = "auth-server-key"
_KID_PREVIOUS = "auth-server-key-prev"


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


def load_or_create_signing_key(path: str | None, kid: str = _KID_CURRENT) -> tuple[object, str]:
    """
    Load RSA private key from path, or generate and save. Returns (private_key, kid).
    """
    if not path:
        path = ".auth_signing_key.pem"
    p = Path(path)
    if p.exists():
        try:
            pem = p.read_bytes()
            key = _deserialize_private(pem)
            return key, kid
        except Exception as e:
            logger.warning("Failed to load signing key from %s: %s; generating new key", path, e)
    key = _generate_key()
    try:
        p.write_bytes(_serialize_private(key))
        logger.info("Generated and saved signing key to %s", path)
    except OSError as e:
        logger.warning("Could not save signing key to %s: %s", path, e)
    return key, kid


def _load_previous_key(path: str) -> tuple[object, str] | None:
    """Load optional previous key (for rotation). Returns (private_key, kid) or None if missing/invalid."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        pem = p.read_bytes()
        key = _deserialize_private(pem)
        return key, _KID_PREVIOUS
    except Exception as e:
        logger.warning("Failed to load previous signing key from %s: %s", path, e)
        return None


def public_key_to_jwk(public_key, kid: str) -> dict:
    """Export cryptography RSA public key to JWK with given kid."""
    numbers = public_key.public_numbers()
    n_b64 = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("ascii")
    e_b64 = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("ascii")
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": n_b64,
        "e": e_b64,
    }


# Module-level state (set at app startup)
_current_key = None
_current_kid = None
_keys_by_kid: dict[str, object] = {}  # kid -> private_key (we use .public_key() for verification)


def _ensure_keys_loaded():
    global _current_key, _current_kid, _keys_by_kid
    if _current_key is not None:
        return
    from auth_server.config import SIGNING_KEY_PATH, SIGNING_KEY_PREVIOUS_PATH

    _current_key, _current_kid = load_or_create_signing_key(SIGNING_KEY_PATH, _KID_CURRENT)
    _keys_by_kid[_current_kid] = _current_key

    if SIGNING_KEY_PREVIOUS_PATH:
        prev = _load_previous_key(SIGNING_KEY_PREVIOUS_PATH)
        if prev:
            priv, kid_prev = prev
            _keys_by_kid[kid_prev] = priv
            logger.info("Loaded previous signing key (kid=%s) for rotation", kid_prev)


def get_signing_key() -> tuple[object, str]:
    """Return the current (private) key and kid for signing new tokens."""
    _ensure_keys_loaded()
    return _current_key, _current_kid


def get_public_key_for_kid(kid: str) -> object | None:
    """Return the public key for the given kid, or None if unknown. Used to verify JWTs by kid from header."""
    _ensure_keys_loaded()
    private_key = _keys_by_kid.get(kid)
    if private_key is None:
        return None
    return private_key.public_key()


def get_jwks() -> dict:
    """Return JWKS with all keys (current + previous) so tokens signed with any exposed key verify."""
    _ensure_keys_loaded()
    keys = []
    for kid, private_key in _keys_by_kid.items():
        jwk = public_key_to_jwk(private_key.public_key(), kid)
        keys.append(jwk)
    return {"keys": keys}
