# Security Considerations

## Threat model

SecureVault is intended to protect files from unauthorized disclosure or undetected modification while stored or transferred as an encrypted package.

## Defenses

- AES-256-GCM: confidentiality plus authenticated encryption.
- RSA-OAEP with SHA-256: secure asymmetric wrapping of the session key.
- 96-bit random GCM nonce: fresh nonce per encryption.
- SHA-256: file digest utility for integrity checking outside the encrypted package.
- Optional encrypted private-key storage.
- No passwords or key contents are printed.

## Limitations

- This is an educational reference project, not a replacement for audited cryptographic software.
- Private-key backups and passphrase management remain the user's responsibility.
- File metadata such as the original filename is stored in the package header.
- The `verify` command checks package structure; cryptographic authenticity is ultimately confirmed during decryption.
