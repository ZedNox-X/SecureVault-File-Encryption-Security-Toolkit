from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .crypto import generate_rsa_keypair


def generate_and_save_keys(output_dir: Path, password: str | None = None) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem = generate_rsa_keypair()

    if password:
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
        )

    private_path = output_dir / "private_key.pem"
    public_path = output_dir / "public_key.pem"

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    try:
        private_path.chmod(0o600)
    except OSError:
        pass

    return private_path, public_path
