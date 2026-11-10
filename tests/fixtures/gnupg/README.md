Made once by `tools/gnupg-fixtures.sh` with the GnuPG in `VERSION`, and committed: fixed
vectors — what GnuPG (and so Kleopatra) writes — never regenerated to make a test pass.
Throwaway test keys. Passphrases: `carol passphrase`, `erin passphrase`, `frank passphrase`;
Dave and Gina have none; `symmetric.gpg` is `correct horse battery staple`.

- Carol: ed25519 + cv25519, our profile's preferences (no AEAD feature).
- Dave: ed25519 + cv25519, GnuPG's default preferences (AEAD) — so `to-dave.asc` is OCB.
- Erin: certify-only primary, ed25519 signing subkey, cv25519 encryption subkey.
- Frank: RSA, outside the profile. Gina: expired in 2020.
