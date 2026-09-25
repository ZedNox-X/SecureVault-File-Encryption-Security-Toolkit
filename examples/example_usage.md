# Example

```bash
python -m securevault keygen --output-dir keys

echo "Confidential project information" > secret.txt

python -m securevault encrypt secret.txt --public-key keys/public_key.pem

python -m securevault verify secret.txt.svlt

python -m securevault decrypt secret.txt.svlt \
  --private-key keys/private_key.pem \
  --output restored.txt
```

Then compare the original and restored files:

```bash
python -m securevault hash secret.txt
python -m securevault hash restored.txt
```

The SHA-256 values should match.
