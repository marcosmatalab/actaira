"""Ed25519 signing and key handling.

Design note D-12. Ed25519 rather than RSA or ECDSA: deterministic (no
nonce to leak), fixed 64-byte signatures, no curve or padding parameters to
get wrong, and one implementation in `cryptography`, the only runtime
dependency of this project.

Key identity is the SHA-256 of the DER SubjectPublicKeyInfo, not of the raw
32 bytes, so a fingerprint computed here matches what `openssl` prints for
the same key. That interoperability is the point: an auditor must be able to
check the fingerprint without installing Actaira.
"""
from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class KeyPair:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    @property
    def public_der(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.public_der).hexdigest()

    @property
    def key_id(self) -> str:
        """Short, stable handle. Collision-resistant enough for a keyring."""
        return self.fingerprint[:16]

    @property
    def public_b64(self) -> str:
        raw = self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")

    def sign(self, payload: bytes) -> bytes:
        return self.private.sign(payload)


def generate() -> KeyPair:
    private = Ed25519PrivateKey.generate()
    return KeyPair(private=private, public=private.public_key())


def load_or_create(path: Path) -> tuple[KeyPair, bool]:
    """Load a private key, creating one on first use.

    Returns (keypair, created). The file is written with mode 0600 before any
    key material reaches it: creating it world-readable and chmod-ing after
    leaves a window where the key is exposed.
    """
    path = Path(path)
    if path.exists():
        private = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError(f"{path} does not hold an Ed25519 private key")
        return KeyPair(private=private, public=private.public_key()), False

    keypair = generate()
    pem = keypair.private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
    return keypair, True


def public_from_b64(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(value))


def fingerprint_of(public: Ed25519PublicKey) -> str:
    der = public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def verify(public: Ed25519PublicKey, signature: bytes, payload: bytes) -> bool:
    try:
        public.verify(signature, payload)
        return True
    except InvalidSignature:
        return False
