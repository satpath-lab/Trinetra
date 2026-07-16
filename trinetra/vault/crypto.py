"""
Hybrid post-quantum + classical envelope encryption for vault secrets.

ML-KEM-768 (FIPS 203) gives post-quantum confidentiality; X25519 gives a
second, independently-analyzed classical exchange. Both shared secrets
are combined via HKDF before deriving the AEAD key - defense in depth,
not a race to whichever algorithm is weaker. Breaking ML-KEM alone, or
X25519 alone, is not enough to recover a sealed secret.

  seal:   ML-KEM encapsulate + fresh X25519 exchange -> HKDF -> AES-256-GCM
  unseal: ML-KEM decapsulate + X25519 exchange       -> HKDF -> AES-256-GCM
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

AEAD_KEY_LEN = 32  # AES-256-GCM
NONCE_LEN = 12
HKDF_INFO = b"trinetra-vault-hybrid-v1"


@dataclass
class VaultKeyPair:
    """The vault's long-term hybrid keypair. In production this lives in an
    HSM/KMS; here it's held in-process for the demo."""
    mlkem_private: MLKEM768PrivateKey
    x25519_private: X25519PrivateKey

    @classmethod
    def generate(cls) -> "VaultKeyPair":
        return cls(MLKEM768PrivateKey.generate(), X25519PrivateKey.generate())

    @property
    def mlkem_public(self) -> MLKEM768PublicKey:
        return self.mlkem_private.public_key()

    @property
    def x25519_public(self) -> X25519PublicKey:
        return self.x25519_private.public_key()


@dataclass
class SealedBlob:
    mlkem_ciphertext: bytes
    ephemeral_x25519_public: bytes
    nonce: bytes
    aead_ciphertext: bytes


def _combine(kem_secret: bytes, x25519_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA384(), length=AEAD_KEY_LEN, salt=None, info=HKDF_INFO)
    return hkdf.derive(kem_secret + x25519_secret)


def seal(recipient: VaultKeyPair, plaintext: bytes, aad: bytes = b"") -> SealedBlob:
    """Hybrid-encrypt plaintext for recipient's public keys."""
    kem_secret, kem_ciphertext = recipient.mlkem_public.encapsulate()

    ephemeral_x25519 = X25519PrivateKey.generate()
    x25519_secret = ephemeral_x25519.exchange(recipient.x25519_public)
    ephemeral_pub_bytes = ephemeral_x25519.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    key = _combine(kem_secret, x25519_secret)
    nonce = os.urandom(NONCE_LEN)
    aead_ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

    return SealedBlob(kem_ciphertext, ephemeral_pub_bytes, nonce, aead_ciphertext)


def unseal(recipient: VaultKeyPair, blob: SealedBlob, aad: bytes = b"") -> bytes:
    """Reverse of seal. Only recipient (holder of both private keys)
    can recover the plaintext."""
    kem_secret = recipient.mlkem_private.decapsulate(blob.mlkem_ciphertext)
    ephemeral_pub = X25519PublicKey.from_public_bytes(blob.ephemeral_x25519_public)
    x25519_secret = recipient.x25519_private.exchange(ephemeral_pub)
    key = _combine(kem_secret, x25519_secret)
    return AESGCM(key).decrypt(blob.nonce, blob.aead_ciphertext, aad)
