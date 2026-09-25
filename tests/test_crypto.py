import os

import pytest
from cryptography.exceptions import InvalidTag

from securevault.crypto import decrypt_aes_gcm, encrypt_aes_gcm


def test_aes_gcm_round_trip():
    key = os.urandom(32)
    nonce = os.urandom(12)
    aad = b"test"
    plaintext = b"confidential data"

    ciphertext = encrypt_aes_gcm(key, plaintext, nonce, aad)
    assert decrypt_aes_gcm(key, ciphertext, nonce, aad) == plaintext


def test_aes_gcm_detects_tampering():
    key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = encrypt_aes_gcm(key, b"secret", nonce, b"aad")
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])

    with pytest.raises(InvalidTag):
        decrypt_aes_gcm(key, tampered, nonce, b"aad")
