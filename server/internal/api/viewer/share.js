// SPDX-License-Identifier: AGPL-3.0-or-later

// The cryptography of a share link (PROTOCOL.md §12) on WebCrypto alone, for the viewer
// page. It derives the link's ID and key from the secret in the address's fragment and
// opens ShareUpdates. Nothing here talks to the network.

const te = new TextEncoder();
const subtle = globalThis.crypto.subtle;

// Padding buckets (PROTOCOL.md §7.4).
export const BUCKETS = [256, 512, 1024, 2048, 4096, 8192, 16384, 65536];

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

function equal(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

const vec16 = b => concat(Uint8Array.of(b.length >> 8, b.length & 0xff), b);
const label = purpose => te.encode('kinfold/v0/' + purpose);

/** H(purpose, data) = SHA-256(vec16(label) ‖ data) */
export async function H(purpose, data) {
  return new Uint8Array(await subtle.digest('SHA-256', concat(vec16(label(purpose)), data)));
}

/** KDF(ikm, purpose, n): HKDF-SHA-256, salt 32 zero bytes, info vec16(label). */
export async function KDF(ikm, purpose, length) {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: vec16(label(purpose)) }, key, length * 8);
  return new Uint8Array(bits);
}

export const linkId = async secret => (await H('share-id', secret)).slice(0, 16);
export const shareKey = secret => KDF(secret, 'share-key', 32);

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function b64uEncode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    const chars = [18, 12, 6, 0].map(s => ALPHABET[(n >> s) & 63]);
    out += chars.slice(0, Math.min(4, bytes.length - i + 1)).join('');
  }
  return out;
}

/** Strict base64url (PROTOCOL.md §2): no padding, the URL-safe alphabet only, canonical. */
export function b64uDecode(text) {
  if (text.length % 4 === 1 || /[^A-Za-z0-9_-]/.test(text)) {
    throw new Error('not base64url');
  }
  const out = [];
  let n = 0, bits = 0;
  for (const ch of text) {
    n = (n << 6) | ALPHABET.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((n >> bits) & 0xff);
    }
  }
  const bytes = Uint8Array.from(out);
  if (b64uEncode(bytes) !== text) {
    throw new Error('not canonical base64url');
  }
  return bytes;
}

/** Unpad (PROTOCOL.md §7.4): the length must be a bucket size. */
export function unpad(x) {
  if (!BUCKETS.includes(x.length)) {
    throw new Error('bad padding');
  }
  let i = x.length - 1;
  while (i >= 0 && x[i] === 0) {
    i--;
  }
  if (i < 0 || x[i] !== 0x80) {
    throw new Error('bad padding');
  }
  return x.slice(0, i);
}

/**
 * openUpdate reads a ShareUpdate for this link and opens it: {seq, expiresAt, payload}.
 * It throws on anything that isn't one, or doesn't open.
 */
export async function openUpdate(key, id, b) {
  if (b.length < 49 || b[0] !== 0 || !equal(b.subarray(1, 17), id)) {
    throw new Error('not an update for this link');
  }
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const seq = dv.getBigUint64(17);
  const expiresAt = Number(dv.getBigUint64(25));
  const nonce = b.subarray(33, 45);
  if (b.length !== 49 + dv.getUint32(45)) {
    throw new Error('malformed update');
  }
  const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: b.subarray(0, 33) }, k, b.subarray(49));
  const text = new TextDecoder('utf-8', { fatal: true }).decode(unpad(new Uint8Array(plain)));
  const payload = JSON.parse(text);
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload) || payload.t !== 'loc') {
    throw new Error('not a location');
  }
  return { seq, expiresAt, payload };
}
