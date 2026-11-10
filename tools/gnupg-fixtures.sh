#!/usr/bin/env bash
# Writes tests/fixtures/gnupg/: keys, messages and signatures made by GnuPG — what Kleopatra
# would hand over — which the tests must read. Run once by hand; the files are committed and
# are fixed vectors from then on: never regenerate them to make a test pass.
#
# A throwaway GNUPGHOME keeps the user's own keyring out of it. Its path must be short: GnuPG
# puts its agent's sockets there, and a socket path over ~100 characters fails with "File name
# too long" — so it goes under $HSP_TMP (default /tmp), not the long macOS $TMPDIR.
set -euo pipefail
cd "$(dirname "$0")/.."
out=tests/fixtures/gnupg
rm -rf "$out"
mkdir -p "$out"
export GNUPGHOME=$(mktemp -d "${HSP_TMP:-/tmp}/hsp-gpg.XXXXXX")
trap 'gpgconf --kill all >/dev/null 2>&1; rm -rf "$GNUPGHOME"' EXIT
g() { gpg --batch --yes --pinentry-mode loopback --trust-model always "$@"; }
fpr() { gpg --list-keys --with-colons "$1" | awk -F: '/^fpr/ { print $10; exit }'; }
# Our profile's preferences: AES-256, SHA-512/SHA-256, no compression — and so no AEAD feature.
ourprefs() { printf 'setpref AES256 SHA512 SHA256 Uncompressed\ny\nsave\n' | gpg --batch --pinentry-mode loopback --passphrase "$2" --command-fd 0 --edit-key "$1" >/dev/null 2>&1; }

# Carol: ed25519 + cv25519 under a passphrase, with our profile's preferences.
g --passphrase 'carol passphrase' --quick-gen-key 'Carol Example <carol@example.org>' ed25519 sign,cert never
CAROL=$(fpr carol@example.org)
g --passphrase 'carol passphrase' --quick-add-key "$CAROL" cv25519 encr never
ourprefs "$CAROL" 'carol passphrase'

# Dave: ed25519 + cv25519 without a passphrase, GnuPG's default preferences (AEAD included).
g --passphrase '' --quick-gen-key 'Dave Example <dave@example.org>' ed25519 sign,cert never
DAVE=$(fpr dave@example.org)
g --passphrase '' --quick-add-key "$DAVE" cv25519 encr never

# Erin: a certify-only primary key, a signing subkey and an encryption subkey.
g --passphrase 'erin passphrase' --quick-gen-key 'Erin Example <erin@example.org>' ed25519 cert never
ERIN=$(fpr erin@example.org)
g --passphrase 'erin passphrase' --quick-add-key "$ERIN" ed25519 sign never
g --passphrase 'erin passphrase' --quick-add-key "$ERIN" cv25519 encr never
ourprefs "$ERIN" 'erin passphrase'

# Frank: RSA, outside the profile.
g --passphrase 'frank passphrase' --quick-gen-key 'Frank Example <frank@example.org>' rsa3072 sign,cert never
FRANK=$(fpr frank@example.org)
g --passphrase 'frank passphrase' --quick-add-key "$FRANK" rsa3072 encr never

# Gina: a key that expired in 2020, made with a faked clock.
g --faked-system-time 20200101T000000 --passphrase '' --quick-gen-key 'Gina Example <gina@example.org>' ed25519 sign,cert 1d
GINA=$(fpr gina@example.org)
g --faked-system-time 20200101T000000 --passphrase '' --quick-add-key "$GINA" cv25519 encr 1d

# Carol checked Dave's fingerprint: a local, non-exportable certification.
g --passphrase 'carol passphrase' -u "$CAROL" --quick-lsign-key "$DAVE" 'Dave Example <dave@example.org>'

for who in CAROL DAVE ERIN FRANK GINA; do
  name=$(echo "$who" | tr '[:upper:]' '[:lower:]')
  g --armor --export "${!who}" > "$out/$name-public.asc"
done
g --export "$CAROL" > "$out/carol-public.gpg"
g --armor --export --export-options export-local-sigs "$DAVE" > "$out/dave-public-lsigned-by-carol.asc"
g --passphrase 'carol passphrase' --armor --export-secret-keys "$CAROL" > "$out/carol-secret.asc"
g --passphrase '' --armor --export-secret-keys "$DAVE" > "$out/dave-secret.asc"
g --passphrase 'erin passphrase' --armor --export-secret-keys "$ERIN" > "$out/erin-secret.asc"
cp "$GNUPGHOME/openpgp-revocs.d/$CAROL.rev" "$out/carol-revocation.rev"

printf 'Привет, Carol! The meeting is at 10.\nВторая строка с пробелом в конце   \n-- \nDash line\n' > "$out/message.txt"
m="$out/message.txt"
g -r "$CAROL" --encrypt -o "$out/to-carol.gpg" "$m"
g --passphrase 'erin passphrase' -u "$ERIN" --armor -r "$CAROL" --sign --encrypt -o "$out/to-carol-signed-by-erin.asc" "$m"
g --passphrase 'carol passphrase' -u "$CAROL" --armor -r "$CAROL" --sign --encrypt -o "$out/to-carol-signed-by-carol.asc" "$m"
g --armor -r "$CAROL" -r "$DAVE" -r "$FRANK" --encrypt -o "$out/to-carol-dave-frank.asc" "$m"
g --throw-keyids -r "$CAROL" --encrypt -o "$out/to-carol-hidden.gpg" "$m"
g --armor -r "$DAVE" --encrypt -o "$out/to-dave.asc" "$m"
g --passphrase 'carol passphrase' -u "$CAROL" --sign -o "$out/signed-by-carol.gpg" "$m"
g --passphrase 'carol passphrase' -u "$CAROL" --clearsign -o "$out/clearsigned-by-carol.asc" "$m"
g --passphrase 'carol passphrase' -u "$CAROL" --detach-sign -o "$out/message.txt.carol.sig" "$m"
g --passphrase 'carol passphrase' -u "$CAROL" --armor --detach-sign -o "$out/message.txt.carol.asc" "$m"
g --passphrase 'erin passphrase' -u "$ERIN" --detach-sign -o "$out/message.txt.erin.sig" "$m"
g --passphrase 'frank passphrase' -u "$FRANK" --clearsign -o "$out/clearsigned-by-frank.asc" "$m"
g --passphrase 'correct horse battery staple' --s2k-cipher-algo AES256 --s2k-digest-algo SHA256 --cipher-algo AES256 --compress-algo none --symmetric -o "$out/symmetric.gpg" "$m"

gpg --version | head -1 > "$out/VERSION"
cat > "$out/README.md" <<'TEXT'
Made once by `tools/gnupg-fixtures.sh` with the GnuPG in `VERSION`, and committed: fixed
vectors — what GnuPG (and so Kleopatra) writes — never regenerated to make a test pass.
Throwaway test keys. Passphrases: `carol passphrase`, `erin passphrase`, `frank passphrase`;
Dave and Gina have none; `symmetric.gpg` is `correct horse battery staple`.

- Carol: ed25519 + cv25519, our profile's preferences (no AEAD feature).
- Dave: ed25519 + cv25519, GnuPG's default preferences (AEAD) — so `to-dave.asc` is OCB.
- Erin: certify-only primary, ed25519 signing subkey, cv25519 encryption subkey.
- Frank: RSA, outside the profile. Gina: expired in 2020.
TEXT
ls -l "$out"
