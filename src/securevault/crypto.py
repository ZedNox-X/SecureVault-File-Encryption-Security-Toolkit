from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_KEY_SIZE = 32
GCM_NONCE_SIZE = 12
RSA_KEY_SIZE = 3072


@dataclass(frozen=True)
class EncryptedPayload:
    nonce: bytes
    ciphertext: bytes


def generate_rsa_keypair() -> tuple[bytes, bytes]:
    """Return (private_pem, public_pem) using a 3072-bit RSA key."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def encrypt_aes_gcm(key: bytes, plaintext: bytes, nonce: bytes, aad: bytes) -> bytes:
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes.")
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError("GCM nonce must be exactly 12 bytes.")
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_aes_gcm(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes) -> bytes:
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes.")
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError("GCM nonce must be exactly 12 bytes.")
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def wrap_key(public_pem: bytes, aes_key: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("The supplied public key is not RSA.")
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_key(private_pem: bytes, wrapped_key: bytes, password: bytes | None = None) -> bytes:
    private_key = serialization.load_pem_private_key(private_pem, password=password)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("The supplied private key is not RSA.")
    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
