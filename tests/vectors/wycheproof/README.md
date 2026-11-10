# Wycheproof test vectors

From https://github.com/C2SP/wycheproof (`testvectors_v1/`), branch `main`, fetched on
2026-10-23. Apache License 2.0, © Google LLC and the Wycheproof authors.

- `ed25519_test.json` — Ed25519 verification, including malleable and non-canonical signatures.
- `x25519_test.json` — X25519, including points of small order and on the twist.
- `aes_wrap_test.json` — AES Key Wrap (RFC 3394), including malformed ciphertexts.

Used by `tests/wycheproof.test.ts`. Never edit them to make a test pass.
