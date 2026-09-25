from pathlib import Path

import pytest

from securevault.file_crypto import decrypt_file, encrypt_file, verify_package
from securevault.key_manager import generate_and_save_keys


def test_file_round_trip(tmp_path: Path):
    keys = tmp_path / "keys"
    generate_and_save_keys(keys)

    original = tmp_path / "message.txt"
    encrypted = tmp_path / "message.txt.svlt"
    restored = tmp_path / "restored.txt"

    original.write_bytes(b"SecureVault test data.")
    encrypt_file(original, encrypted, keys / "public_key.pem")

    assert verify_package(encrypted)

    decrypt_file(encrypted, restored, keys / "private_key.pem")
    assert restored.read_bytes() == original.read_bytes()


def test_tampered_package_fails(tmp_path: Path):
    keys = tmp_path / "keys"
    generate_and_save_keys(keys)

    original = tmp_path / "message.txt"
    encrypted = tmp_path / "message.txt.svlt"
    restored = tmp_path / "restored.txt"

    original.write_bytes(b"SecureVault test data.")
    encrypt_file(original, encrypted, keys / "public_key.pem")

    data = bytearray(encrypted.read_bytes())
    data[-1] ^= 1
    encrypted.write_bytes(data)

    with pytest.raises(Exception):
        decrypt_file(encrypted, restored, keys / "private_key.pem")
