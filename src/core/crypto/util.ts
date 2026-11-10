// Small byte helpers the primitives share.
//
// A note for every module: copy an input with `new Uint8Array(x)`, never `x.slice()` — a
// Node Buffer's slice() is a view on the same memory, and writing to it changes the caller's
// data.

export function concat(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** Overwrites secrets once they are no longer needed — as far as a garbage-collected language allows. */
export function wipe(...buffers: (Uint8Array | Uint32Array | Float64Array | Int32Array | undefined)[]): void {
  for (const buffer of buffers) buffer?.fill(0);
}

/**
 * Equal contents, in time that depends only on the length. Lengths are public; the bytes may
 * not be.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
