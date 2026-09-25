# SecureVault 🔐

SecureVault is a defensive cybersecurity project that demonstrates secure file encryption, integrity verification, key management, and security-focused software engineering using Python.

<img width="1986" height="792" alt="Vault" src="https://github.com/user-attachments/assets/88adca0a-d8d3-492f-8d4f-0c830848f8bb" />


## Features

- AES-256-GCM authenticated file encryption
- RSA-3072-OAEP-SHA-256 key wrapping
- SHA-256 integrity verification
- Password-protected private key support
- Tamper detection through authenticated encryption
- Secure random nonce generation
- Command-line interface
- Unit tests
- No plaintext secrets in logs
- Local-only operation; no network service is required

## Architecture

```text
                    ┌─────────────────┐
                    │    Input File   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Random AES-256  │
                    │   Session Key   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   AES-256-GCM   │
                    │ Authenticated   │
                    │    Encryption   │
                    └────────┬────────┘
                             │
                 ┌───────────┴───────────┐
                 ▼                       ▼
          Encrypted Data          Authentication Tag
                 │
                 ▼
          ┌─────────────────┐
          │ RSA-3072-OAEP   │
          │ Wrap AES Key    │
          └─────────────────┘
```

## Requirements

- Python 3.10+
- `cryptography`
- `pytest`

## Installation

```bash
python -m venv .venv
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Windows:

```powershell
.venv\Scripts\activate
```

Then:

```bash
pip install -r requirements.txt
```

## Usage

Generate an RSA key pair:

```bash
python -m securevault keygen --output-dir keys
```

Encrypt a file:

```bash
python -m securevault encrypt report.pdf --public-key keys/public_key.pem
```

Decrypt a file:

```bash
python -m securevault decrypt report.pdf.svlt --private-key keys/private_key.pem
```

Verify a SHA-256 checksum:

```bash
python -m securevault hash report.pdf
```

Verify an encrypted package without decrypting it:

```bash
python -m securevault verify report.pdf.svlt
```

## Security notes

This project is educational and portfolio-oriented. It is not intended to replace a professionally audited encryption product.

Important design choices:

- AES-GCM provides confidentiality and authentication.
- A fresh 96-bit nonce is generated for every encryption operation.
- RSA-OAEP protects the randomly generated AES session key.
- RSA private keys can be protected with a passphrase.
- Sensitive key material is never printed by the CLI.
- Decryption fails when authenticated ciphertext has been modified.

## Testing

```bash
pytest -q
```

## Project structure

```text
SecureVault/
├── README.md
├── LICENSE
├── requirements.txt
├── pyproject.toml
├── src/
│   └── securevault/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── crypto.py
│       ├── file_crypto.py
│       ├── integrity.py
│       └── key_manager.py
├── tests/
│   ├── test_crypto.py
│   ├── test_file_crypto.py
│   └── test_integrity.py
├── docs/
│   ├── architecture.md
│   └── security.md
└── examples/
    └── example_usage.md
```

Updated on 25-09-2026 by Melbin George
