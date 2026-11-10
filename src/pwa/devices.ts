// Passkeys and security keys in the interface of the PWA (Task.md §5.2–5.3, §10): unlocking our
// key with a touch, keeping it on the device alone, opening the container with a touch — and
// the settings that explain it, or why it is off here. The WebAuthn calls are in hardware.ts;
// the packing and wrapping, in src/core/device.ts.
//
// Two ways a device serves a key:
//   - "unlock with a touch" (prf): the secrets are wrapped under the key from the device's PRF
//     and kept in this browser beside the copy under the passphrase, which stays;
//   - "keep on the device" (largeBlob): the secrets are written to the device itself, read back
//     and checked; then, if the user agrees, the copy in this browser goes, and the keyring
//     keeps GnuPG's mark that the secret is elsewhere. The PRF salt of such a credential is a
//     fixed one, so the key still opens after this browser forgot everything: the user picks
//     the passkey, and the blob says which key it holds.

import { utf8, toHex } from '../core/bytes.ts';
import { containerSkesk } from '../core/container.ts';
import type { ContainerSession } from '../core/container.ts';
import { sha256 } from '../core/crypto/sha256.ts';
import { wipe } from '../core/crypto/util.ts';
import { openBlob, packSecrets, packedFingerprints, sealBlob, unpackSecrets, unwrap, wrap, wrapKey } from '../core/device.ts';
import { PgpError } from '../core/errors.ts';
import { t } from '../core/i18n.ts';
import { fingerprintHex } from '../core/keys.ts';
import { secretHere, secretsElsewhere, wipeSecret } from '../core/secret.ts';
import type { Secret } from '../core/secret.ts';
import { messageRandom } from '../app/entropy.ts';
import { label, viewOf } from '../app/model.ts';
import type { KeyView } from '../app/model.ts';
import type { PlatformContext } from '../app/platform.ts';
import { app, keyringChanged, now } from '../app/state.ts';
import { checkbox, dialog, h, inform, toast } from '../app/ui.ts';
import { DeviceCancelled, aloneOnOrigin, createCredential, deleteRecord, deviceSupport, loadRecords, putRecord, recordOf, touch, webAuthnHere } from './hardware.ts';

/** The PRF salt of credentials that keep a key on the device: fixed, so that no record here is needed to use them. */
const BLOB_SALT = sha256(utf8('html-simple-pgp/largeBlob/v1'));

let context: PlatformContext | null = null;
let loaded = false;

const keyId = (v: KeyView): string => `key:${v.fingerprint}`;
const containerId = (skesk: Uint8Array): string => `container:${toHex(sha256(skesk)).slice(0, 32)}`;

/** Devices can serve here: WebAuthn, a secure origin the app has to itself, and somewhere to keep the records. */
const usable = (): boolean => loaded && webAuthnHere() && aloneOnOrigin() === 'ok';

export async function startDevices(c: PlatformContext): Promise<void> {
  context = c;
  if (!webAuthnHere() || aloneOnOrigin() !== 'ok') return;
  loaded = await loadRecords();
  if (loaded) keyringChanged();
}

/** Random bytes from the generator the settings choose, or null when the user closed the mouse window. */
async function randomBytes(): Promise<((n: number) => Uint8Array) | null> {
  return (await messageRandom())?.bytes ?? null;
}

/** Why a device or the browser refused, in words; null when the user only closed the prompt. */
function problemText(error: unknown): string | null {
  if (error instanceof DeviceCancelled) return null;
  if (error instanceof PgpError && error.code === 'integrity') return t('devices', 'What the device gave does not open this key: it is another passkey, or the record was changed.');
  if (error instanceof DOMException && error.name === 'InvalidStateError') return t('devices', 'This device already holds a passkey for this key.');
  if (error instanceof DOMException && error.name === 'NotSupportedError') return t('devices', 'This browser or device cannot do this.');
  return error instanceof Error ? error.message : String(error);
}

async function report(title: string, error: unknown): Promise<void> {
  const text = problemText(error);
  if (text) await inform(title, text);
}

/** The PRF output of a credential: given at creation by some devices, by one more touch otherwise. */
async function prfOf(credential: Uint8Array, given: Uint8Array | null, salt: Uint8Array, random: (n: number) => Uint8Array): Promise<Uint8Array | null> {
  return given ?? (await touch({ credential, challenge: random(32), salt })).prf;
}

const rawOf = (s: Secret): Uint8Array => (s.kind === 'ed25519' ? s.seed : s.scalar);
const sameSecret = (a: Secret, b: Secret): boolean => a.kind === b.kind && toHex(rawOf(a)) === toHex(rawOf(b));

// ---- Unlock with a touch (prf) -----------------------------------------------------------------

async function connectTouch(v: KeyView): Promise<void> {
  if ((await deviceSupport()).prf === false) {
    await inform(t('devices', 'Unlock with a touch'), t('devices', 'This browser cannot get a key from a passkey (the PRF extension). Try Chrome, Edge or Safari, or a newer version.'));
    return;
  }
  const ok = await dialog({
    title: t('devices', 'Unlock with a touch'),
    body: [
      t('devices', 'A passkey (Touch ID, Face ID, Windows Hello, your phone) or a security key such as a YubiKey will unlock this key instead of its passphrase. The passphrase keeps working too.'),
      t('devices', 'The browser asks you to create a passkey for this page and to confirm it with a fingerprint, your face or a PIN.'),
    ],
    confirm: t('devices', 'Continue'),
  });
  if (!ok) return;
  const secrets = await context!.unlockWithPassphrase(v);
  if (!secrets) return;
  const random = await randomBytes();
  if (!random) return;
  try {
    const salt = random(32);
    const created = await createCredential({ label: label(v), userId: random(16), challenge: random(32), salt, blob: false });
    if (!created.prfEnabled) {
      await inform(t('devices', 'Unlock with a touch'), t('devices', 'This passkey or security key cannot give a key to the page (it has no PRF). Delete the passkey it made in your system settings, and try another device.'));
      return;
    }
    const prf = await prfOf(created.credential, created.prf, salt, random);
    if (!prf) throw new Error(t('devices', 'The device did not answer with its key.'));
    const k = wrapKey(prf);
    const wrapped = await wrap(k, packSecrets(v.entry.cert, secrets), random);
    wipe(k, prf);
    await putRecord({ kind: 'prf', id: keyId(v), credential: created.credential, salt, wrapped });
    keyringChanged();
    toast(t('devices', 'From now on a touch unlocks this key'));
  } catch (error) {
    await report(t('devices', 'Unlock with a touch'), error);
  }
}

async function forgetTouch(v: KeyView): Promise<void> {
  await deleteRecord('prf', keyId(v));
  keyringChanged();
  await inform(t('devices', 'The device is forgotten'), t('devices', 'This key opens with its passphrase only again. The passkey itself stays on the device: delete it in your system settings (passwords and passkeys) or in the security key manager.'));
}

async function unlockByTouch(v: KeyView): Promise<Map<string, Secret> | null> {
  const record = recordOf('prf', keyId(v));
  if (!record?.salt || !record.wrapped) return null;
  const random = await randomBytes();
  if (!random) return null;
  try {
    const answer = await touch({ credential: record.credential, challenge: random(32), salt: record.salt });
    if (!answer.prf) throw new Error(t('devices', 'The device did not answer with its key.'));
    const k = wrapKey(answer.prf);
    wipe(answer.prf);
    try {
      const packed = await unwrap(k, record.wrapped);
      const secrets = unpackSecrets(v.entry.cert, packed);
      wipe(packed);
      return secrets;
    } finally {
      wipe(k);
    }
  } catch (error) {
    const text = problemText(error);
    if (text) toast(text, 'error');
    return null;
  }
}

// ---- Keep on the device (largeBlob) -------------------------------------------------------------

/** The key's secrets as the device holds them, checked against the key; null when it gave none. */
async function readFromDevice(v: KeyView, credential: Uint8Array | null, random: (n: number) => Uint8Array): Promise<Map<string, Secret>> {
  const answer = await touch({ credential, challenge: random(32), salt: BLOB_SALT, read: true });
  if (!answer.blob?.length) throw new Error(t('devices', 'This passkey holds no key.'));
  const k = answer.prf ? wrapKey(answer.prf) : null;
  try {
    const packed = await openBlob(answer.blob, k);
    if (!packedFingerprints(packed).includes(v.fingerprint)) throw new PgpError('integrity', 'another key');
    const secrets = unpackSecrets(v.entry.cert, packed);
    wipe(packed);
    if (!recordOf('blob', keyId(v)) || credential === null) await putRecord({ kind: 'blob', id: keyId(v), credential: answer.credential, salt: null, wrapped: null }).catch(() => undefined);
    return secrets;
  } finally {
    if (k) wipe(k);
    if (answer.prf) wipe(answer.prf);
  }
}

async function unlockFromBlob(v: KeyView): Promise<Map<string, Secret> | null> {
  const random = await randomBytes();
  if (!random) return null;
  try {
    return await readFromDevice(v, recordOf('blob', keyId(v))?.credential ?? null, random);
  } catch (error) {
    const text = problemText(error);
    if (text) toast(text, 'error');
    return null;
  }
}

async function keepOnDevice(v: KeyView): Promise<void> {
  const title = t('devices', 'Keep the key on a device');
  if ((await deviceSupport()).largeBlob === false) {
    await inform(title, t('devices', 'This browser cannot store data on a passkey (the largeBlob extension). Unlocking with a touch may still work.'));
    return;
  }
  const ok = await dialog({
    title,
    body: [
      t('devices', 'The secret key is written onto a security key (a YubiKey or another FIDO2 key that keeps data) or a passkey, and read back to check. After that you may remove the copy from this browser: then the key opens only with that device.'),
      h('p', { class: 'dialog-warning', text: t('devices', 'A device can be lost or reset, and with it the key. Keep a backup or a container in a safe place.') }),
      t('devices', 'The browser asks you to touch the device several times.'),
    ],
    confirm: t('devices', 'Continue'),
  });
  if (!ok) return;
  const secrets = await context!.unlockWithPassphrase(v);
  if (!secrets) return;
  const random = await randomBytes();
  if (!random) return;
  try {
    const created = await createCredential({ label: label(v), userId: random(16), challenge: random(32), salt: BLOB_SALT, blob: true });
    if (!created.blobSupported) {
      await inform(title, t('devices', 'This device cannot keep data for the page (it has no large blobs). Delete the passkey it made in your system settings. Unlocking with a touch may still work with it.'));
      return;
    }
    const prf = created.prfEnabled ? await prfOf(created.credential, created.prf, BLOB_SALT, random) : null;
    const k = prf ? wrapKey(prf) : null;
    const blob = await sealBlob(packSecrets(v.entry.cert, secrets), k, random);
    if (k) wipe(k);
    if (prf) wipe(prf);
    const written = await touch({ credential: created.credential, challenge: random(32), write: blob });
    if (!written.written) throw new Error(t('devices', 'The device did not store the key.'));
    await putRecord({ kind: 'blob', id: keyId(v), credential: created.credential, salt: null, wrapped: null });
    const back = await readFromDevice(v, created.credential, random);
    const same = [...secrets].every(([fpr, s]) => back.has(fpr) && sameSecret(s, back.get(fpr)!));
    for (const s of back.values()) wipeSecret(s);
    if (!same) throw new Error(t('devices', 'What the device gave back is not what was written.'));
    keyringChanged();
    await offerRemoval(v);
  } catch (error) {
    await report(title, error);
  }
}

/** After the device was read back: removes the copy in this browser, if the user agrees in so many words. */
async function offerRemoval(v: KeyView): Promise<void> {
  const understood = checkbox(t('devices', 'I understand: without a copy the key lives only on this device.'));
  const backup = h('button', { type: 'button', class: 'button button--small', text: t('devices', 'Back up the secret key') });
  backup.addEventListener('click', () => void context!.backupSecret(v));
  const container = h('button', { type: 'button', class: 'button button--small', text: t('devices', 'Save all keys to a container') });
  container.addEventListener('click', () => void context!.backupToContainer());
  const removed = await dialog({
    title: t('devices', 'The key is on the device'),
    wide: true,
    body: [
      t('devices', 'The device holds the key and gave it back. Remove the copy from this browser? The key then opens only with the device.'),
      t('devices', 'Before you do, keep a copy somewhere safe:'),
      app.settings.storage === 'browser' ? h('div', { class: 'dialog-buttons' }, backup, container) : h('div', { class: 'dialog-buttons' }, backup),
      understood.node,
    ],
    confirm: t('devices', 'Remove the copy'),
    cancel: t('devices', 'Keep the copy'),
    danger: true,
    submit: async () => {
      if (!understood.input.checked) return t('devices', 'Tick the box first: without a copy, losing the device loses the key.');
      await removeCopyNow(v);
      return null;
    },
  });
  if (!removed) toast(t('devices', 'The key is on the device; the copy in this browser stays'));
}

async function removeCopyNow(v: KeyView): Promise<void> {
  const fresh = viewOf(app.keyring.get(v.fingerprint)!);
  await app.keyring.put(secretsElsewhere(fresh.entry.cert), fresh.entry.record.source, now());
  // A copy wrapped for unlocking with a touch is a copy too.
  await deleteRecord('prf', keyId(v));
  app.agent.forget(v.fingerprint);
  keyringChanged();
  toast(t('devices', 'The key is only on the device now'));
}

/** Later: the device read again and checked, then the same question. */
async function removeCopy(v: KeyView): Promise<void> {
  const random = await randomBytes();
  if (!random) return;
  try {
    const back = await readFromDevice(v, recordOf('blob', keyId(v))?.credential ?? null, random);
    const missing = [v.entry.cert.primary, ...v.entry.cert.subkeys.map((s) => s.key)].filter((k) => secretHere(k) && !back.has(fingerprintHex(k.fingerprint)));
    for (const s of back.values()) wipeSecret(s);
    if (missing.length) throw new Error(t('devices', 'The device does not hold every secret of this key.'));
    await offerRemoval(v);
  } catch (error) {
    await report(t('devices', 'Remove the copy from this browser'), error);
  }
}

async function forgetBlob(v: KeyView): Promise<void> {
  await deleteRecord('blob', keyId(v));
  keyringChanged();
  await inform(t('devices', 'The device is forgotten'), t('devices', 'The key stays in this browser. The passkey and the copy on it stay on the device: delete them in your system settings or in the security key manager.'));
}

// ---- The container --------------------------------------------------------------------------

async function connectContainer(): Promise<void> {
  const title = t('devices', 'Open the container with a touch');
  const session = app.container?.session;
  if (!session) return;
  const random = await randomBytes();
  if (!random) return;
  try {
    const salt = random(32);
    const created = await createCredential({ label: app.container!.name || 'container', userId: random(16), challenge: random(32), salt, blob: false });
    if (!created.prfEnabled) {
      await inform(title, t('devices', 'This passkey or security key cannot give a key to the page (it has no PRF). Delete the passkey it made in your system settings, and try another device.'));
      return;
    }
    const prf = await prfOf(created.credential, created.prf, salt, random);
    if (!prf) throw new Error(t('devices', 'The device did not answer with its key.'));
    const k = wrapKey(prf);
    const plain = Uint8Array.of(session.cipher, ...session.key);
    const wrapped = await wrap(k, plain, random);
    wipe(k, prf, plain);
    await putRecord({ kind: 'prf', id: containerId(session.skesk), credential: created.credential, salt, wrapped });
    context?.redraw();
    toast(t('devices', 'From now on a touch opens this container'));
  } catch (error) {
    await report(title, error);
  }
}

async function forgetContainer(): Promise<void> {
  const session = app.container?.session;
  if (!session) return;
  await deleteRecord('prf', containerId(session.skesk));
  context?.redraw();
  toast(t('devices', 'The container opens with its password only again'));
}

/** The container's session from the device that keeps it; null when none does, or it did not answer. */
export async function containerFromDevice(bytes: Uint8Array): Promise<ContainerSession | null> {
  if (!usable()) return null;
  const skesk = containerSkesk(bytes);
  const record = skesk && recordOf('prf', containerId(skesk));
  if (!skesk || !record?.salt || !record.wrapped) return null;
  const random = await randomBytes();
  if (!random) return null;
  try {
    const answer = await touch({ credential: record.credential, challenge: random(32), salt: record.salt });
    if (!answer.prf) return null;
    const k = wrapKey(answer.prf);
    wipe(answer.prf);
    const plain = await unwrap(k, record.wrapped);
    wipe(k);
    return { skesk, cipher: plain[0], key: plain.slice(1) };
  } catch (error) {
    const text = problemText(error);
    if (text) toast(text, 'error');
    return null;
  }
}

// ---- What the page asks ------------------------------------------------------------------------

export async function unlockWithDevice(v: KeyView): Promise<Map<string, Secret> | null> {
  if (!usable()) return null;
  // A key whose secret is only elsewhere may be on a device this browser has no record of.
  if (recordOf('blob', keyId(v)) || !v.here) return unlockFromBlob(v);
  if (recordOf('prf', keyId(v))) return unlockByTouch(v);
  return null;
}

export function deviceChips(v: KeyView): HTMLElement[] {
  if (!usable() || !v.secret) return [];
  const chips: HTMLElement[] = [];
  if (recordOf('blob', keyId(v))) chips.push(h('span', { class: 'chip chip--ok', 'data-device': 'blob', title: t('devices', 'The secret key is kept on a passkey or a security key'), text: t('devices', 'On a device') }));
  if (recordOf('prf', keyId(v))) chips.push(h('span', { class: 'chip chip--ok', 'data-device': 'prf', title: t('devices', 'A passkey or a security key unlocks this key'), text: t('devices', 'Unlocks with a touch') }));
  return chips;
}

export function deviceActions(v: KeyView): { label: string; action: () => void }[] {
  if (!usable() || !v.secret) return [];
  const items: { label: string; action: () => void }[] = [];
  const blob = recordOf('blob', keyId(v));
  if (v.here && app.settings.storage === 'browser') {
    items.push(recordOf('prf', keyId(v)) ? { label: t('devices', 'Forget the device that unlocks it'), action: () => void forgetTouch(v) } : { label: t('devices', 'Unlock with a touch…'), action: () => void connectTouch(v) });
  }
  if (v.here && !blob) items.push({ label: t('devices', 'Keep on a device…'), action: () => void keepOnDevice(v) });
  if (v.here && blob) {
    items.push({ label: t('devices', 'Remove the copy from this browser…'), action: () => void removeCopy(v) });
    items.push({ label: t('devices', 'Forget the device that keeps it'), action: () => void forgetBlob(v) });
  }
  return items;
}

export function deviceSettings(): HTMLElement[] {
  if (!webAuthnHere()) return [];
  const rows: HTMLElement[] = [h('h2', { class: 'settings-group', text: t('devices', 'Passkeys and security keys') })];
  const where = aloneOnOrigin();
  if (where !== 'ok') {
    const why = where === 'insecure' ? t('devices', 'The page is not on a secure (https) address.') : t('devices', 'Other pages on this address could see your data and use the same passkeys.');
    rows.push(h('p', { class: 'settings-hint', 'data-setting': 'devices-off', text: `${why} ${t('devices', 'Unlocking with a passkey or a security key is off here: put the app on a (sub)domain of its own, at its root.')}` }));
    return rows;
  }
  rows.push(h('p', { class: 'settings-hint', 'data-setting': 'devices', text: t('devices', "A passkey or a security key can unlock your key instead of its passphrase, or keep the key itself: see the key's menu. To delete a passkey, use your system settings (passwords and passkeys) or the security key manager.") }));
  const session = app.container?.session;
  if (app.settings.storage === 'container' && session && loaded) {
    const known = !!recordOf('prf', containerId(session.skesk));
    const go = h('button', { type: 'button', class: 'button button--small', 'data-device': 'container', text: known ? t('devices', 'Forget the device') : t('devices', 'Use a device…') });
    go.addEventListener('click', () => void (known ? forgetContainer() : connectContainer()));
    rows.push(
      h(
        'div',
        { class: 'settings-row' },
        h('div', { class: 'settings-text' }, h('div', { class: 'settings-title', text: t('devices', 'Open the container with a touch') }), h('div', { class: 'settings-hint', text: known ? t('devices', 'A passkey or a security key opens this container.') : t('devices', 'A passkey or a security key opens this container instead of its password.') })),
        go,
      ),
    );
  }
  return rows;
}

export async function keyDeleted(fingerprint: string): Promise<void> {
  if (!loaded) return;
  await deleteRecord('prf', `key:${fingerprint}`).catch(() => undefined);
  await deleteRecord('blob', `key:${fingerprint}`).catch(() => undefined);
}
