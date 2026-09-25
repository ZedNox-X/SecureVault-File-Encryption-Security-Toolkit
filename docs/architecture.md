# Architecture

SecureVault uses a hybrid cryptographic design.

1. A random 256-bit AES session key is generated for each file.
2. A random 96-bit GCM nonce is generated.
3. AES-256-GCM encrypts and authenticates the plaintext.
4. RSA-3072-OAEP-SHA-256 encrypts the AES session key.
5. The encrypted package stores metadata, nonce, wrapped key, and ciphertext.
6. During decryption, the RSA private key recovers the AES key.
7. AES-GCM verifies authenticity before returning plaintext.

The design separates bulk encryption from asymmetric key protection, avoiding the use of RSA for large file contents.
