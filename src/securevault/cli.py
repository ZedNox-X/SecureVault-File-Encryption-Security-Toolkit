from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from .file_crypto import decrypt_file, encrypt_file, verify_package
from .integrity import sha256_file
from .key_manager import generate_and_save_keys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securevault",
        description="Defensive file encryption and integrity toolkit.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="Generate an RSA-3072 key pair.")
    keygen.add_argument("--output-dir", type=Path, default=Path("keys"))
    keygen.add_argument("--password", action="store_true", help="Protect private key with a passphrase.")

    enc = sub.add_parser("encrypt", help="Encrypt a file.")
    enc.add_argument("input", type=Path)
    enc.add_argument("--public-key", type=Path, required=True)
    enc.add_argument("--output", type=Path)

    dec = sub.add_parser("decrypt", help="Decrypt a SecureVault package.")
    dec.add_argument("input", type=Path)
    dec.add_argument("--private-key", type=Path, required=True)
    dec.add_argument("--output", type=Path)
    dec.add_argument("--password", action="store_true")

    digest = sub.add_parser("hash", help="Calculate SHA-256 for a file.")
    digest.add_argument("input", type=Path)

    verify = sub.add_parser("verify", help="Validate SecureVault package structure.")
    verify.add_argument("input", type=Path)

    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "keygen":
        password = getpass.getpass("Private-key passphrase: ") if args.password else None
        private_path, public_path = generate_and_save_keys(args.output_dir, password)
        print(f"Private key: {private_path}")
        print(f"Public key:  {public_path}")

    elif args.command == "encrypt":
        output = args.output or args.input.with_suffix(args.input.suffix + ".svlt")
        encrypt_file(args.input, output, args.public_key)
        print(f"Encrypted file: {output}")

    elif args.command == "decrypt":
        output = args.output or Path(args.input.stem)
        password = getpass.getpass("Private-key passphrase: ") if args.password else None
        decrypt_file(args.input, output, args.private_key, password)
        print(f"Decrypted file: {output}")

    elif args.command == "hash":
        print(sha256_file(args.input))

    elif args.command == "verify":
        print("Valid SecureVault package." if verify_package(args.input) else "Invalid package.")
