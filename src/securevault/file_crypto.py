from __future__ import annotations

import base64
import json
import os
import struct
from pathlib import Path

from .crypto import (
    AES_KEY_SIZE,
    GCM_NONCE_SIZE,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    unwrap_key,
    wrap_key,
)

MAGIC = b"SVLT1"
AAD = b"SecureVault-v1"
HEADER_FORMAT = "!5sI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def _pack(metadata: dict, ciphertext: bytes) -> bytes:
    metadata_bytes = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    return MAGIC + struct.pack("!I", len(metadata_bytes)) + metadata_bytes + ciphertext


def _unpack(blob: bytes) -> tuple[dict, bytes]:
    if len(blob) < HEADER_SIZE:
        raise ValueError("Invalid SecureVault package.")

    magic, metadata_len = struct.unpack(HEADER_FORMAT, blob[:HEADER_SIZE])
    if magic != MAGIC:
        raise ValueError("Invalid SecureVault package header.")

    start = HEADER_SIZE
    end = start + metadata_len
    if end > len(blob):
        raise ValueError("Corrupted SecureVault metadata.")

    metadata = json.loads(blob[start:end].decode())
    return metadata, blob[end:]


def encrypt_file(input_path: Path, output_path: Path, public_key_path: Path) -> None:
    plaintext = input_path.read_bytes()
    aes_key = os.urandom(AES_KEY_SIZE)
    nonce = os.urandom(GCM_NONCE_SIZE)

    ciphertext = encrypt_aes_gcm(aes_key, plaintext, nonce, AAD)
    wrapped_key = wrap_key(public_key_path.read_bytes(), aes_key)

    metadata = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "key_wrap": "RSA-3072-OAEP-SHA-256",
        "nonce": base64.b64encode(nonce).decode(),
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "original_name": input_path.name,
    }

    output_path.write_bytes(_pack(metadata, ciphertext))


def decrypt_file(
    input_path: Path,
    output_path: Path,
    private_key_path: Path,
    password: str | None = None,
) -> None:
    metadata, ciphertext = _unpack(input_path.read_bytes())

    if metadata.get("version") != 1:
        raise ValueError("Unsupported SecureVault package version.")

    nonce = base64.b64decode(metadata["nonce"])
    wrapped_key = base64.b64decode(metadata["wrapped_key"])

    aes_key = unwrap_key(
        private_key_path.read_bytes(),
        wrapped_key,
        password=password.encode() if password else None,
    )

    plaintext = decrypt_aes_gcm(aes_key, ciphertext, nonce, AAD)
    output_path.write_bytes(plaintext)


def verify_package(path: Path) -> bool:
    metadata, ciphertext = _unpack(path.read_bytes())
    required = {"version", "algorithm", "key_wrap", "nonce", "wrapped_key"}
    if not required.issubset(metadata):
        return False
    if metadata["algorithm"] != "AES-256-GCM":
        return False
    if metadata["key_wrap"] != "RSA-3072-OAEP-SHA-256":
        return False
    if len(base64.b64decode(metadata["nonce"])) != GCM_NONCE_SIZE:
        return False
    return len(ciphertext) > 0
