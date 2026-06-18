"""
Symmetric encryption for sensitive integration credentials at rest.

The Fernet key is generated once and persisted to backend/.fernet_key
(which is mounted via the same volume as .env in docker-compose).

Encrypted values are stored in .env with the prefix `enc:` so plaintext
and ciphertext can coexist during migration.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger("zerotrustx.crypto")

ENC_PREFIX = "enc:"
_KEY_PATH = Path(__file__).resolve().parent.parent / ".fernet_key"
_fernet: Fernet | None = None


def _load_or_create_key() -> bytes:
    env_key = os.environ.get("FERNET_KEY")
    if env_key:
        return env_key.encode() if isinstance(env_key, str) else env_key
    if _KEY_PATH.exists():
        data = _KEY_PATH.read_bytes().strip()
        if data:
            return data
    new_key = Fernet.generate_key()
    try:
        _KEY_PATH.write_bytes(new_key)
        try:
            os.chmod(_KEY_PATH, 0o600)
        except Exception:
            pass
        log.info("Generated new Fernet key at %s", _KEY_PATH)
    except Exception as e:
        log.warning("Could not persist Fernet key (%s); using in-memory key", e)
    return new_key


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_or_create_key())
    return _fernet


def encrypt(value: str) -> str:
    """Return ciphertext with the `enc:` prefix. Empty/None returns unchanged."""
    if value is None or value == "":
        return value or ""
    if value.startswith(ENC_PREFIX):
        return value  # already encrypted
    token = _get_fernet().encrypt(value.encode("utf-8")).decode("ascii")
    return ENC_PREFIX + token


def decrypt(value: str) -> str:
    """Return plaintext, or the original value if it is not enc-prefixed."""
    if not value or not isinstance(value, str):
        return value or ""
    if not value.startswith(ENC_PREFIX):
        return value
    token = value[len(ENC_PREFIX):]
    try:
        return _get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        log.error("Failed to decrypt sensitive value: invalid token (key rotated?)")
        return ""


def is_encrypted(value: str) -> bool:
    return isinstance(value, str) and value.startswith(ENC_PREFIX)
