Copied from html-pgp (`tests/fixtures/gnupg/`, made there by its `tools/gnupg-fixtures.sh` with
the GnuPG in `VERSION`). Fixed vectors — what GnuPG (and so Kleopatra) writes — never
regenerated to make a test pass. Throwaway test keys: `alice passphrase`, `bob passphrase`, and
`correct horse battery staple` for `symmetric.asc`.

Alice is ed25519 + cv25519 made by GnuPG with its default features (AEAD included), so what
GnuPG encrypts to her is OCB — outside our profile, which makes these files good negative
cases. Bob is RSA: also outside it. Our own fixtures are in `../gnupg/`.
