// A key as the interface shows it: names, status, trust — computed from the core's KeyState.

import { dateFormat, t } from '../core/i18n.ts';
import type { Entry } from '../core/keyring.ts';
import { fingerprintHex, formatFingerprint } from '../core/keys.ts';
import type { KeyPacket, KeyState } from '../core/keys.ts';
import { isUnprotected, secretHere } from '../core/secret.ts';
import { app, now } from './state.ts';

export type Status = 'valid' | 'expired' | 'revoked' | 'invalid';

export interface KeyView {
  entry: Entry;
  state: KeyState;
  fingerprint: string;
  keyId: string;
  name: string;
  email: string;
  status: Status;
  secret: boolean;
  /** Ours, and some secret of it is in this keyring (not only on a device, as GnuPG's sec#). */
  here: boolean;
  verified: boolean;
  canEncrypt: boolean;
  canSign: boolean;
  unprotected: boolean;
}

/** "Name <address>" as its parts; either may be missing. */
export function splitUserId(userId: string): { name: string; email: string } {
  const m = /^(.*?)\s*<([^<>]*)>\s*$/.exec(userId);
  if (m) return { name: m[1].trim(), email: m[2].trim() };
  if (/^[^\s@]+@[^\s@]+$/.test(userId.trim())) return { name: '', email: userId.trim() };
  return { name: userId.trim(), email: '' };
}

export function viewOf(entry: Entry, at = now()): KeyView {
  const state = app.keyring.state(entry, at);
  const { name, email } = splitUserId(state.primaryUserId ?? entry.cert.users[0]?.text ?? '');
  const status: Status = state.revoked ? 'revoked' : state.expired ? 'expired' : state.valid ? 'valid' : 'invalid';
  let unprotected = false;
  try {
    unprotected = entry.secret && isUnprotected(entry.cert.primary);
  } catch {
    unprotected = false;
  }
  return {
    entry,
    state,
    fingerprint: entry.record.fingerprint,
    keyId: entry.record.fingerprint.slice(-16),
    name,
    email,
    status,
    secret: entry.secret,
    here: entry.secret && [entry.cert.primary, ...entry.cert.subkeys.map((s) => s.key)].some(secretHere),
    verified: app.keyring.verified(entry, at),
    canEncrypt: status === 'valid' && !!state.encryption,
    canSign: status === 'valid' && entry.secret && state.signing.some((k) => !!k.secretBody),
    unprotected,
  };
}

export const allViews = (): KeyView[] => app.keyring.list().map((e) => viewOf(e));

export const label = (v: KeyView): string => (v.name && v.email ? `${v.name} <${v.email}>` : v.name || v.email || keyIdLabel(v.keyId));

/** A name inside a sentence, kept whole in right-to-left text. */
export const named = (v: KeyView): string => `⁨${label(v)}⁩`;

export const keyIdLabel = (hex: string): string => `0x${hex.slice(-16).toUpperCase()}`;

export const fingerprintGroups = (fpr: Uint8Array | string): string =>
  typeof fpr === 'string' ? fpr.replace(/(.{4})/g, '$1 ').trim().replace(/^((?:\S{4} ){4}\S{4}) /, '$1  ') : formatFingerprint(fpr);

export const keyPacketId = (k: KeyPacket): string => keyIdLabel(fingerprintHex(k.fingerprint));

export function formatDate(seconds: number | null): string {
  if (seconds === null) return t('details', 'never');
  return dateFormat({ year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(seconds * 1000));
}

export function formatDateTime(seconds: number): string {
  return dateFormat({ year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(seconds * 1000));
}

export interface Validity {
  label: string;
  tone: 'ok' | 'warn' | 'bad' | 'neutral';
  hint: string;
}

export function validity(v: KeyView): Validity {
  if (v.status === 'revoked') return { label: t('status', 'Revoked'), tone: 'bad', hint: t('status', 'Its owner revoked this key: do not use it.') };
  if (v.status === 'expired') return { label: t('status', 'Expired'), tone: 'bad', hint: t('status', 'The key is past its expiry date.') };
  if (v.status === 'invalid') return { label: t('status', 'Invalid'), tone: 'bad', hint: t('status', 'The key has no valid self-signature.') };
  if (v.secret) return { label: t('status', 'Your key'), tone: 'ok', hint: t('status', 'Your key pair: the secret key is here.') };
  if (v.verified) return { label: t('status', 'Verified'), tone: 'ok', hint: t('status', 'You checked its fingerprint with its owner.') };
  return { label: t('status', 'Not verified'), tone: 'warn', hint: t('status', 'Check the fingerprint with its owner before you trust it.') };
}

/** Our keys that can sign, the default one first. */
export function ownSigning(): KeyView[] {
  const own = allViews().filter((v) => v.canSign);
  const preferred = app.settings.defaultKey;
  return own.sort((a, b) => Number(b.fingerprint === preferred) - Number(a.fingerprint === preferred));
}

/** Our key to encrypt to as well: the default one, or the first that can. */
export function ownEncryption(): KeyView | null {
  const own = allViews().filter((v) => v.secret && v.canEncrypt);
  return own.find((v) => v.fingerprint === app.settings.defaultKey) ?? own[0] ?? null;
}
