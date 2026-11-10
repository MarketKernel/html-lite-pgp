# Simple PGP

**[Русский](docs/README.ru.md)**

OpenPGP for GnuPG and Kleopatra in **one HTML file**, with **every line of the cryptography
in this repository**: no npm packages, no external libraries, not even the browser's WebCrypto.
It makes key pairs, encrypts, signs, decrypts and verifies text and files; what it writes,
GnuPG and Kleopatra read, and it reads theirs. It works offline — open the file from disk —
and has no network access at all.

It is the simple sibling of html-pgp: one kind of key instead of twelve,
chosen as the one where an implementation is hardest to get wrong. The reasoning, the format
profile and the plan are in [Task.md](Task.md) (in Russian).

## One algorithm: Curve25519

Every key is **Ed25519 for signatures with a Cv25519 subkey for encryption** — the key GnuPG
2.3+ and Kleopatra make by default — in the OpenPGP v4 format every GnuPG reads. Messages are
**AES-256 in CFB with an MDC** (SEIPD v1), signatures **SHA-512**.

Why this one, when the code is our own:

- **A key is 32 random bytes.** Nothing to search for or check — RSA needs primes, and every
  check in its generation is a place to go wrong.
- **No big-integer arithmetic.** The field of Curve25519 is computed in 16 limbs with no branch
  on a secret (after TweetNaCl); RSA in JavaScript means BigInt, which is not constant-time.
- **Deterministic signatures.** Ed25519 has no random nonce whose reuse or leak would reveal
  the key, unlike ECDSA and DSA.
- **X25519 takes any 32 bytes as a public key**: no invalid-curve attacks; a zero result (a
  point of small order) is refused.

The price: **recipients need Curve25519 keys.** A GnuPG user with an RSA key can add one:
`gpg --quick-add-key <fingerprint> cv25519 encr`.

## Using it

Build `build/html-simple-pgp.html` (see [Build](#build)) and open it in a browser. Three views
and the settings:

- **Keys** — make a key pair, import (files, the clipboard, pasted text, dropped files),
  export, back up, change the expiry or the passphrase, revoke, make a revocation
  certificate, **mark a key as verified** after comparing its fingerprint with its owner (a
  local, non-exportable certification, as `gpg --lsign-key`), delete.
- **Notepad** — encrypt for recipients (and yourself), sign and encrypt, clear-sign, decrypt
  and verify, in place.
- **Files** — the same for files, detached signatures (`report.pdf.sig` finds `report.pdf`),
  key files.
- **Settings** — language (English, Russian), theme, how long passphrases are remembered,
  where randomness comes from, where keys are kept.

### Where the randomness comes from

A new key is made from **one** source, chosen in the new-key dialog; sources are never mixed:

| Source | How | Can the key be made again? |
| --- | --- | --- |
| **Hardware generator** | `crypto.getRandomValues` — the system's generator, fed by the hardware — the only call to it in the program | no |
| **Mouse movements** | pointer movements (only real ones: script-made events do not count) and key timings, one bit per event at most, 256 events over at least 2 seconds | no |
| **Passphrase** | scrypt (N=2¹⁸, r=8, 256 MiB) over the phrase and the e-mail address; the key dated at midnight UTC of a chosen day | **yes**: phrase + address + date, or phrase + the public key |

The phrase needs at least five different words — any language, prepositions count. **The
public key is public, so anyone can try phrases against it without limit.** Five words a
person makes up can be guessed; take seven or more random ones. The derivation is fixed for
good (version 1, frozen in `tests/vectors/phrase/v1.json`).

Every message needs fresh random bytes too: from the hardware generator, or — a setting —
from the mouse, collected once per session. The phrase is never used for that. Either way the
bytes come out of HMAC_DRBG (SHA-512).

### Where the keys are kept

- **In this browser** (IndexedDB), secret keys under their passphrases.
- **In a container file**: the whole keyring in one OpenPGP message encrypted with a password
  (five different words or 16 characters at least). GnuPG opens it:
  `gpg -d keys.gpg | gpg --import --import-options import-local-sigs`. In container mode the
  keys live in the page only while it is open; changes are written back into the file —
  automatically in Chrome and Edge, with a Save button elsewhere. Keep the file on a USB stick
  or in an encrypted volume (VeraCrypt, BitLocker To Go, FileVault).

What a web page **cannot** do: use a key inside an OpenPGP smartcard, YubiKey or Nitrokey
(WebUSB blocks smart cards; the Web Smart Card API is for Isolated Web Apps only), or reach the
system's keychain or TPM. To keep a key on a card: back it up, import it into Kleopatra or
GnuPG, move it with `keytocard`, and use the card through GnuPG. Passkeys and security keys
serve in the installed app only — see below.

### The installed app (PWA) and passkeys

`build/pages/` is the same page as an installable app, for any https host (`.github/workflows/pages.yml`
deploys it to GitHub Pages; the domain is set in the host's settings, never in the build). It
updates by a button in the settings, works offline, and adds what WebAuthn allows — which needs an
https origin, so the single file has none of it:

- **Unlock with a touch** (key menu): a passkey (Touch ID, Face ID, Windows Hello, a phone) or a
  security key (YubiKey and other FIDO2 keys) unlocks the key instead of its passphrase. The
  device's PRF (`hmac-secret`) gives a key that wraps a second copy of the secret (SEIPD v1,
  AES-256 + MDC) kept in the browser; the copy under the passphrase stays.
- **Keep on a device** (key menu): the secret itself is written into the device's `largeBlob`,
  read back and checked against the public key; then, after an explicit "I understand", the copy
  in the browser can go. The keyring keeps GnuPG's own mark for a secret that is elsewhere
  (`gnu-dummy`, as `gpg --export-secret-subkeys` writes it), so a backup or a container still
  imports into GnuPG. Lose or reset the device and the key is lost: keep a backup.
- **Open the container with a touch** (settings, in container mode): the device wraps the key the
  container's password gave — never the password.

Every secret a device gives back is checked against the public key, as after a passphrase.
These are on only when the app is **alone on its origin**: at the root of its own (sub)domain,
not on a shared host such as `*.github.io` where other projects share the origin's storage and
passkeys. Elsewhere the settings explain why they are off. To delete a passkey itself, use the
system's settings (passwords and passkeys) or the security key's manager — a page cannot.

Support differs by browser, system and device, and changes. The browser tests use Chrome's
virtual authenticators (with and without PRF and large blobs); **real devices are not checked
yet** — the checklist:

| Device | Unlock with a touch (PRF) | Keep on the device (largeBlob) |
| --- | --- | --- |
| Mac, Touch ID (Chrome, Safari) | ☐ | ☐ |
| Windows Hello (Chrome, Edge; Windows 11) | ☐ | ☐ |
| Android, Google Password Manager | ☐ | ☐ |
| iPhone, iCloud Keychain | ☐ | ☐ |
| YubiKey 5 (firmware ≥ 5.2 for PRF; large blobs: ?) | ☐ | ☐ |

For each: connect, lock the keys ("Forget passphrases"), sign — no passphrase asked; reload and sign
again; for "keep on the device", remove the copy, clear the site's data, import the container
or the public key, and unlock by picking the passkey.

## Compatibility with GnuPG and Kleopatra

Checked against GnuPG itself (`tests/gnupg.test.ts`, in a throwaway home directory) and against
what GnuPG wrote (`tests/fixtures/gnupg/`, made once by `tools/gnupg-fixtures.sh`):

- GnuPG imports our keys with their preferences (AES-256; SHA-512, SHA-256; no compression;
  MDC — and **not AEAD**, so that GnuPG 2.4+ answers in SEIPD v1 rather than OCB), unlocks our
  protected secret keys, sees our expiry changes and revocations;
- GnuPG checks our clear-signed texts and detached signatures, decrypts our messages (to keys
  and by password) and checks the signatures inside;
- we read GnuPG's keys (secret ones too), its messages to us (also to several recipients, to a
  hidden recipient, compressed, by password), clear-signed texts, detached signatures (also by
  a signing subkey), revocation certificates, `gpg -c` containers.

What GnuPG sends in OCB (to keys that announce AEAD — not ours) and keys of other algorithms
are reported as not supported.

Kleopatra uses GnuPG; a manual check on Windows: import a key from here (public and backup),
decrypt a message and a file from here, check a signature from here, import the container
after `gpg -d`.

## Security

- **Nothing leaves the page.** Its Content-Security-Policy: `default-src 'none'`,
  `connect-src 'none'`, and the script and the style allowed **by their SHA-256 hashes**, not
  `'unsafe-inline'`; Trusted Types refuse HTML from strings. Everything is inlined.
- **No dependencies.** `package.json` has none; imports are relative or `node:`; the cryptography
  is in `src/core/crypto/`, and `crypto.subtle` appears nowhere (`tests/policy.test.ts`).
- **Constant time, as far as JavaScript allows**: AES is bitsliced (no S-box table to leak the key
  through the cache), the curve arithmetic branches on nothing secret.
- **Plaintext only after the MDC checks**; a changed or cut message gives nothing back.
- **Key Overwriting** (2022): after every unlock the public key is computed again from the
  secret and must match; the KDF parameters must be ours.
- **Passphrases are never stored.** Unlocked keys stay in memory for the minutes the settings
  say. A container keeps only the key derived from its password, in memory, for the session.
- Passphrase fields are text inputs with dots drawn over them (from html-pgp), so macOS Secure
  Input does not force a Latin layout.

The browser is the trusted base: anything that can run code in the page or read the browser's
profile can read what the page can.

## Build

Node 24, nothing to install. The short way — `./build.sh` builds both and prints the file's
SHA-256; `./build.sh --check` runs the tests too. The same by parts:

```sh
node --run build          # build/html-simple-pgp.html
node --run test           # unit tests (node:test, TypeScript run by Node itself)
node --run test:browser   # the page in headless Chrome (CHROME=/path/to/chrome)
node --run check          # all of it
node --run bench          # speeds of the primitives
```

There is no compiler or bundler from npm: Node strips the TypeScript types
(`module.stripTypeScriptTypes`), and `build.mjs` joins the modules — its rules are at its top.
Types are checked by the editor (`tsconfig.json`), not in CI: `tsc` is an npm package.

**Checking a release**: the build is reproducible — the same commit gives the same bytes. Compare
the file with the release's `SHA256SUMS.txt`, or build the tag yourself and compare.

## Where the cryptography comes from

| Module | From | License |
| --- | --- | --- |
| `sha1.ts`, `sha256.ts`, `sha512.ts`, `hmac.ts`, `pbkdf2.ts` | FIPS 180-4, RFC 2104, RFC 8018 | — |
| `scrypt.ts` | RFC 7914 | — |
| `drbg.ts` | NIST SP 800-90A (HMAC_DRBG) | — |
| `aes.ts` | FIPS 197; bitsliced after BearSSL's `aes_ct` (Thomas Pornin) | MIT |
| `cfb.ts`, `keywrap.ts` | RFC 4880 §13.9, RFC 3394 | — |
| `field25519.ts`, `x25519.ts`, `ed25519.ts` | RFC 7748, RFC 8032; after TweetNaCl and tweetnacl-js | public domain |
| `inflate.ts` | RFC 1951/1950; after Mark Adler's `puff.c` | zlib |

Checked against the standards' vectors, all of Wycheproof's for Ed25519, X25519 and AES Key Wrap
(`tests/vectors/wycheproof/`, Apache 2.0), and Node's OpenSSL on random inputs. Speeds (Node 24,
Apple M-series): AES-256-CFB 21 MiB/s encrypting, 38 MiB/s decrypting; SHA-512 90 MiB/s;
scrypt for a phrase key 1.6 s.

The interface's styles and parts of its code come from html-pgp.

## Limitations

- Curve25519 keys only; OpenPGP v4 only (no v5/v6, no OCB).
- Files are read whole into memory; the limit is 256 MiB.
- No key servers: exchange keys as files or text.
- No certifications of others' keys beyond the local "verified" mark.
- Where a key came from (hardware, mouse, phrase) is remembered in the browser only.
- Passkeys and security keys: in the installed app only, and not yet checked on real devices.

## License

MIT — see [LICENSE](LICENSE).
