// Kinfold protocol v0 (draft 0.3): an implementation written from spec/PROTOCOL.md.
//
// Only WebCrypto is used (globalThis.crypto.subtle and crypto.getRandomValues), so this
// module runs unchanged in Node 22+ and in browsers that support Ed25519 and X25519 in
// WebCrypto. No Node built-ins are imported.

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

export const VERSION = 0;
export const SUITE = 0x0001;
export const LABEL_PREFIX = 'kinfold/v0/';

// ---------------------------------------------------------------------------
// §2 Encoding
// ---------------------------------------------------------------------------

export class ParseError extends Error {
  constructor(msg) { super(msg); this.name = 'ParseError'; }
}

export function toHex(b) {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(s) {
  if (typeof s !== 'string' || s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) throw new ParseError('bad hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** Bytewise comparison (negative, zero, positive). */
export function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

export const isZero = b => b.every(x => x === 0);
export const utf8 = s => te.encode(s);

export const u8 = n => Uint8Array.of(n & 0xff);
export const u16 = n => Uint8Array.of((n >>> 8) & 0xff, n & 0xff);
export const u32 = n => Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
export function u64(n) {
  let v = BigInt(n);
  if (v < 0n || v >= 1n << 64n) throw new RangeError('u64 out of range');
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
export function vec16(b) {
  if (b.length > 0xffff) throw new RangeError('vec16 too long');
  return concat(u16(b.length), b);
}
export const vec32 = b => concat(u32(b.length), b);

/** Sequential parser; every failure is a ParseError (reason code `malformed`). u64 values are BigInt. */
export class Reader {
  constructor(buf) { this.buf = buf; this.off = 0; }
  take(n) {
    if (n > this.buf.length - this.off) throw new ParseError('input ends before a field is complete');
    const v = this.buf.slice(this.off, this.off + n);
    this.off += n;
    return v;
  }
  u8() { return this.take(1)[0]; }
  u16() { const b = this.take(2); return (b[0] << 8) | b[1]; }
  u32() { const b = this.take(4); return ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3]; }
  u64() { const b = this.take(8); let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x); return v; }
  bytes(n) { return this.take(n); }
  vec16() { return this.take(this.u16()); }
  vec32() { return this.take(this.u32()); }
  flag() {
    const v = this.u8();
    if (v > 1) throw new ParseError('flag is not 0 or 1');
    return v === 1;
  }
  ids() {
    const b = this.vec16();
    if (b.length % 16 !== 0) throw new ParseError('ids length is not a multiple of 16');
    const out = [];
    for (let i = 0; i < b.length; i += 16) {
      const id = b.slice(i, i + 16);
      if (out.length && compareBytes(out[out.length - 1], id) >= 0) throw new ParseError('ids not strictly ascending');
      out.push(id);
    }
    return out;
  }
  end() { if (this.off !== this.buf.length) throw new ParseError('bytes left over after the last field'); }
}

// Base64url without padding, strict (§2 "Text forms").
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function b64uEncode(bytes) {
  let out = '';
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63];
  }
  return out;
}

export function b64uDecode(text) {
  if (typeof text !== 'string') throw new ParseError('base64url: not a string');
  if (text.length % 4 === 1) throw new ParseError('base64url: impossible length');
  const vals = new Array(text.length);
  for (let i = 0; i < text.length; i++) {
    const v = B64.indexOf(text[i]);
    if (v < 0) throw new ParseError('base64url: character outside the alphabet (or padding)');
    vals[i] = v;
  }
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let o = 0;
  let i = 0;
  for (; i + 4 <= vals.length; i += 4) {
    const n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6) | vals[i + 3];
    out[o++] = (n >> 16) & 255; out[o++] = (n >> 8) & 255; out[o++] = n & 255;
  }
  const rem = vals.length - i;
  if (rem === 2) {
    const n = (vals[i] << 18) | (vals[i + 1] << 12);
    out[o++] = (n >> 16) & 255;
  } else if (rem === 3) {
    const n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6);
    out[o++] = (n >> 16) & 255; out[o++] = (n >> 8) & 255;
  }
  if (b64uEncode(out) !== text) throw new ParseError('base64url: non-canonical encoding');
  return out;
}

const utf8Strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
export function decodeUtf8(b) {
  try { return utf8Strict.decode(b); } catch { return null; }
}

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

// ---------------------------------------------------------------------------
// §3 Cryptography
// ---------------------------------------------------------------------------

export const label = purpose => te.encode(LABEL_PREFIX + purpose);

export async function sha256(data) { return new Uint8Array(await subtle.digest('SHA-256', data)); }
export async function sha512(data) { return new Uint8Array(await subtle.digest('SHA-512', data)); }

/** H with a full label given as bytes or string. */
export async function hashLabeled(lbl, data) {
  const l = typeof lbl === 'string' ? te.encode(lbl) : lbl;
  return sha256(concat(vec16(l), data));
}
/** H("purpose", a ‖ b ‖ …) */
export const H = (purpose, ...parts) => hashLabeled(label(purpose), concat(...parts));

/** KDF with a full label: HKDF-SHA-256, salt = 32 zero bytes, info = vec16(label). */
export async function kdfLabeled(ikm, lbl, length) {
  const l = typeof lbl === 'string' ? te.encode(lbl) : lbl;
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: vec16(l) }, key, length * 8);
  return new Uint8Array(bits);
}
export const KDF = (ikm, purpose, length) => kdfLabeled(ikm, label(purpose), length);

// --- Ed25519 ---------------------------------------------------------------

const PKCS8_ED25519 = fromHex('302e020100300506032b657004220420');
const PKCS8_X25519 = fromHex('302e020100300506032b656e04220420');
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;   // order of the base point
const P25519 = (1n << 255n) - 19n;
// y of the eight small-order points (two of the five values stand for two points each: either sign)
const ED25519_SMALL_ORDER_Y = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
]);

function littleEndian(b) {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}

/**
 * §3.3 checks 2 and 3, on a public key or on the R half of a signature: true when the encoding
 * is not canonical (y >= p) or names one of the eight small-order points.
 */
export function ed25519PointRejected(enc) {
  if (!(enc instanceof Uint8Array) || enc.length !== 32) return true;
  const y = enc.slice();
  y[31] &= 0x7f;   // clear the sign bit
  return littleEndian(y) >= P25519 || ED25519_SMALL_ORDER_Y.has(toHex(y));
}
/** An "invalid key" in the sense of §3.3. */
export const ed25519KeyInvalid = ed25519PointRejected;

/**
 * Public key for a raw 32-byte Ed25519 seed. JWK import needs `x` (and Node rejects an `x`
 * that doesn't match `d`), so the only WebCrypto route from a bare seed to its public key is
 * a PKCS#8 import of an extractable key followed by a JWK export.
 */
export async function ed25519PublicFromSeed(seed) {
  const k = await subtle.importKey('pkcs8', concat(PKCS8_ED25519, seed), { name: 'Ed25519' }, true, ['sign']);
  return b64uDecode((await subtle.exportKey('jwk', k)).x);
}

/** A signing key from a raw seed, imported through JWK (d = seed, x = public key). */
export async function importSigningKey(seed, pub) {
  if (!pub) pub = await ed25519PublicFromSeed(seed);
  const key = await subtle.importKey(
    'jwk', { kty: 'OKP', crv: 'Ed25519', d: b64uEncode(seed), x: b64uEncode(pub) },
    { name: 'Ed25519' }, false, ['sign']);
  return { key, pub };
}

export async function generateSigningKey() {
  const kp = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  return { key: kp.privateKey, pub: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)) };
}

/**
 * True when `seed` is the private half of `pub`. Works whether or not the platform checks a
 * JWK's `x` against `d` at import: a mismatch either throws or yields a signature that does
 * not verify under `pub`.
 */
export async function seedMatchesPublic(seed, pub) {
  try {
    const k = await importSigningKey(seed, pub);
    const msg = utf8('kinfold seed check');
    return verifyRaw(pub, msg, new Uint8Array(await subtle.sign({ name: 'Ed25519' }, k.key, msg)));
  } catch {
    return false;
  }
}

export async function signLabeled(signer, lbl, data) {
  const l = typeof lbl === 'string' ? te.encode(lbl) : lbl;
  return new Uint8Array(await subtle.sign({ name: 'Ed25519' }, signer.key, concat(vec16(l), data)));
}
/** Sign(sk, "purpose", data); `signer` comes from importSigningKey. */
export const sign = (signer, purpose, data) => signLabeled(signer, label(purpose), data);

const verifyKeyCache = new Map();
/**
 * Strict Ed25519 verification of a signature over `msg` as given (§3.3). The three byte checks
 * are made here, whatever the platform does, and then the platform's own single-signature
 * check runs: [S]B = R + [k]A with no cofactor. Never batch verification.
 */
export async function verifyRaw(pub, msg, sig) {
  if (!(pub instanceof Uint8Array) || pub.length !== 32 || !(sig instanceof Uint8Array) || sig.length !== 64) return false;
  if (littleEndian(sig.subarray(32)) >= ED25519_L) return false;                             // 1: S below the group order
  if (ed25519PointRejected(pub) || ed25519PointRejected(sig.subarray(0, 32))) return false;   // 2, 3: the key and R
  try {
    const h = toHex(pub);
    let k = verifyKeyCache.get(h);
    if (!k) { k = await subtle.importKey('raw', pub, { name: 'Ed25519' }, true, ['verify']); verifyKeyCache.set(h, k); }
    return await subtle.verify({ name: 'Ed25519' }, k, sig, msg);
  } catch {
    return false;
  }
}
export async function verifyLabeled(pub, lbl, data, sig) {
  const l = typeof lbl === 'string' ? te.encode(lbl) : lbl;
  return verifyRaw(pub, concat(vec16(l), data), sig);
}
/** Verify(pk, "purpose", data, sig) */
export const verify = (pub, purpose, data, sig) => verifyLabeled(pub, label(purpose), data, sig);

// --- AES-256-GCM -------------------------------------------------------------

export async function aeadSeal(key, nonce, plaintext, aad) {
  if (key.length !== 32 || nonce.length !== 12) throw new RangeError('AES-256-GCM needs a 32-byte key and a 12-byte nonce');
  const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, k, plaintext));
}
/** Returns the plaintext, or null if authentication fails. */
export async function aeadOpen(key, nonce, ciphertext, aad) {
  if (key.length !== 32 || nonce.length !== 12 || ciphertext.length < 16) return null;
  const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  try {
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, k, ciphertext));
  } catch {
    return null;
  }
}

// --- X25519 ------------------------------------------------------------------

const X25519_LOW_ORDER = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
]);
/** An "invalid key" in the sense of §3.5: top bit set, not below p, or one of the low-order values. */
export function x25519KeyInvalid(pub) {
  return !(pub instanceof Uint8Array) || pub.length !== 32 || (pub[31] & 0x80) !== 0
    || littleEndian(pub) >= P25519 || X25519_LOW_ORDER.has(toHex(pub));
}

/** X25519 public key for a raw private scalar (PKCS#8 import, then JWK export of `x`). */
export async function x25519PublicFromPrivate(sk) {
  const k = await subtle.importKey('pkcs8', concat(PKCS8_X25519, sk), { name: 'X25519' }, true, ['deriveBits']);
  return b64uDecode((await subtle.exportKey('jwk', k)).x);
}

/** An X25519 private key from raw bytes, imported through JWK (d = sk, x = public key). */
export async function importDecryptionKey(sk, pub) {
  if (!pub) pub = await x25519PublicFromPrivate(sk);
  const key = await subtle.importKey(
    'jwk', { kty: 'OKP', crv: 'X25519', d: b64uEncode(sk), x: b64uEncode(pub) },
    { name: 'X25519' }, false, ['deriveBits']);
  return { key, pub };
}

export async function generateDecryptionKey() {
  const kp = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  return { key: kp.privateKey, pub: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)) };
}

/** X25519(sk, pk). WebCrypto throws on an all-zero result, as RFC 9180 §7.1.4 requires. */
async function x25519(privateKey, peerPub) {
  const pk = await subtle.importKey('raw', peerPub, { name: 'X25519' }, true, []);
  return new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pk }, privateKey, 256));
}

// --- HPKE (RFC 9180), base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM ----

const HPKE_V1 = te.encode('HPKE-v1');
const KEM_SUITE_ID = concat(te.encode('KEM'), u16(0x0020));
const HPKE_SUITE_ID = concat(te.encode('HPKE'), u16(0x0020), u16(0x0001), u16(0x0002));
const EMPTY = new Uint8Array(0);

async function hmacSha256(key, data) {
  // WebCrypto refuses zero-length HMAC keys. RFC 5869 defines an absent salt as HashLen
  // zeros, and HMAC zero-pads keys, so 32 zero bytes give the identical result.
  const k = await subtle.importKey('raw', key.length ? key : new Uint8Array(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}
const hkdfExtract = (salt, ikm) => hmacSha256(salt, ikm);
async function hkdfExpand(prk, info, length) {
  const out = new Uint8Array(length);
  let t = EMPTY;
  for (let i = 1, o = 0; o < length; i++, o += 32) {
    t = await hmacSha256(prk, concat(t, info, u8(i)));
    out.set(t.subarray(0, Math.min(32, length - o)), o);
  }
  return out;
}
const labeledExtract = (suite, salt, lbl, ikm) => hkdfExtract(salt, concat(HPKE_V1, suite, te.encode(lbl), ikm));
const labeledExpand = (suite, prk, lbl, info, length) =>
  hkdfExpand(prk, concat(u16(length), HPKE_V1, suite, te.encode(lbl), info), length);

/** RFC 9180 DeriveKeyPair for X25519: returns raw { sk, pk }. */
export async function hpkeDeriveKeyPair(ikm) {
  const prk = await labeledExtract(KEM_SUITE_ID, EMPTY, 'dkp_prk', ikm);
  const sk = await labeledExpand(KEM_SUITE_ID, prk, 'sk', EMPTY, 32);
  return { sk, pk: await x25519PublicFromPrivate(sk) };
}

async function extractAndExpand(dh, kemContext) {
  const prk = await labeledExtract(KEM_SUITE_ID, EMPTY, 'eae_prk', dh);
  return labeledExpand(KEM_SUITE_ID, prk, 'shared_secret', kemContext, 32);
}

/** Encap. With `ikmE` the ephemeral key is DeriveKeyPair(ikmE) (test vectors only). */
export async function hpkeEncap(pkR, ikmE) {
  let eph;
  if (ikmE) {
    const { sk, pk } = await hpkeDeriveKeyPair(ikmE);
    eph = await importDecryptionKey(sk, pk);
  } else {
    eph = await generateDecryptionKey();
  }
  const dh = await x25519(eph.key, pkR);
  return { sharedSecret: await extractAndExpand(dh, concat(eph.pub, pkR)), enc: eph.pub };
}

/** Decap. `recipient` is { key, pub } from importDecryptionKey. */
export async function hpkeDecap(enc, recipient) {
  const dh = await x25519(recipient.key, enc);
  return extractAndExpand(dh, concat(enc, recipient.pub));
}

export async function hpkeKeySchedule(sharedSecret, info) {
  const pskIdHash = await labeledExtract(HPKE_SUITE_ID, EMPTY, 'psk_id_hash', EMPTY);
  const infoHash = await labeledExtract(HPKE_SUITE_ID, EMPTY, 'info_hash', info);
  const ctx = concat(u8(0), pskIdHash, infoHash);
  const secret = await labeledExtract(HPKE_SUITE_ID, sharedSecret, 'secret', EMPTY);
  return {
    key: await labeledExpand(HPKE_SUITE_ID, secret, 'key', ctx, 32),
    baseNonce: await labeledExpand(HPKE_SUITE_ID, secret, 'base_nonce', ctx, 12),
  };
}

export function hpkeNonce(baseNonce, seq) {
  const n = baseNonce.slice();
  let v = BigInt(seq);
  for (let i = 11; i >= 0 && v > 0n; i--) { n[i] ^= Number(v & 0xffn); v >>= 8n; }
  return n;
}

export async function hpkeSetupS(pkR, info, ikmE) {
  const { sharedSecret, enc } = await hpkeEncap(pkR, ikmE);
  return { enc, sharedSecret, ...(await hpkeKeySchedule(sharedSecret, info)) };
}
export async function hpkeSetupR(enc, recipient, info) {
  const sharedSecret = await hpkeDecap(enc, recipient);
  return { sharedSecret, ...(await hpkeKeySchedule(sharedSecret, info)) };
}
export const hpkeContextSeal = (ctx, seq, aad, pt) => aeadSeal(ctx.key, hpkeNonce(ctx.baseNonce, seq), pt, aad);
export const hpkeContextOpen = (ctx, seq, aad, ct) => aeadOpen(ctx.key, hpkeNonce(ctx.baseNonce, seq), ct, aad);

/** §3.5 single-shot Seal with empty aad. */
export async function hpkeSeal(pkR, info, pt, ikmE) {
  const ctx = await hpkeSetupS(pkR, info, ikmE);
  return { enc: ctx.enc, ct: await hpkeContextSeal(ctx, 0, EMPTY, pt) };
}
/** §3.5 single-shot Open with empty aad; null on failure. */
export async function hpkeOpen(enc, recipient, info, ct) {
  try {
    const ctx = await hpkeSetupR(enc, recipient, info);
    return await hpkeContextOpen(ctx, 0, EMPTY, ct);
  } catch {
    return null; // e.g. an all-zero X25519 result
  }
}

// ---------------------------------------------------------------------------
// §4 Accounts and devices
// ---------------------------------------------------------------------------

export const KIND = Object.freeze({ PHONE: 1, TABLET: 2, WEB: 3, HOME_ASSISTANT: 4, RECOVERY: 5 });
export const DEVICE_KINDS = new Set(Object.values(KIND));
/** A receiving device (§1.3) has an encryption key; a recovery device has none. */
export const isReceivingKind = k => k >= KIND.PHONE && k <= KIND.HOME_ASSISTANT;
export const isPhoneOrTablet = k => k === KIND.PHONE || k === KIND.TABLET;
/** §4.2: of the account's first identity key; it never changes afterwards. */
export const accountIdOf = async firstIkPub => (await H('account-id', firstIkPub)).slice(0, 16);
export const deviceIdOf = async dskPub => (await H('device-id', dskPub)).slice(0, 16);
export const keyIdOf = async dekPub => (await H('key-id', dekPub)).slice(0, 8);

export const CERT_LEN = 156;
export const BUNDLE_LEN = 152;
export const LINK_LEN = 192;
export const MAX_CHAIN_LINKS = 8;
export const MAX_BUNDLE_SPAN = 3024000000n; // 35 days in ms
export const BUNDLE_EARLY_MS = 600000n;     // a bundle may start up to 10 minutes after its entry

export function parseDeviceCert(bytes) {
  const r = new Reader(bytes);
  const c = {
    raw: bytes.slice(), version: r.u8(), suite: r.u16(), account_id: r.bytes(16), dsk_pub: r.bytes(32),
    device_kind: r.u8(), issued_at: r.u64(), ik_pub: r.bytes(32), sig: r.bytes(64),
  };
  r.end();
  return c;
}

/** §4.3 "well-formed". Whether account_id belongs to ik_pub is a separate question: chainProves. */
export async function deviceCertWellFormed(c) {
  if (c.version !== 0 || c.suite !== SUITE || !DEVICE_KINDS.has(c.device_kind)) return false;
  if (ed25519KeyInvalid(c.ik_pub) || ed25519KeyInvalid(c.dsk_pub)) return false;
  return verify(c.ik_pub, 'device-cert', c.raw.slice(0, 60), c.sig);
}

/** `account_id` defaults to the ID of an account whose identity key never rotated. */
export async function buildDeviceCert(ikSigner, { account_id, device_kind, issued_at, dsk_pub }) {
  const body = concat(u8(0), u16(SUITE), account_id ?? await accountIdOf(ikSigner.pub), dsk_pub, u8(device_kind), u64(issued_at));
  return concat(body, ikSigner.pub, await sign(ikSigner, 'device-cert', body));
}

// §4.3 Identity chain

export function parseIdentityLink(bytes) {
  if (bytes.length !== LINK_LEN) throw new ParseError('an identity link is 192 bytes');
  return { raw: bytes.slice(), old_ik_pub: bytes.slice(0, 32), new_ik_pub: bytes.slice(32, 64), old_sig: bytes.slice(64, 128), new_sig: bytes.slice(128, 192) };
}

/** The contents of a `vec16 chain`: 0 to 8 links. */
export function parseChain(bytes) {
  if (bytes.length % LINK_LEN !== 0 || bytes.length > LINK_LEN * MAX_CHAIN_LINKS) throw new ParseError('identity chain length');
  const links = [];
  for (let i = 0; i < bytes.length; i += LINK_LEN) links.push(parseIdentityLink(bytes.slice(i, i + LINK_LEN)));
  return links;
}
export const serializeChain = links => concat(...links.map(l => l.raw ?? l));

/** Both keys usable, and both signatures verify for this account. */
export async function identityLinkValid(accountId, link) {
  if (ed25519KeyInvalid(link.old_ik_pub) || ed25519KeyInvalid(link.new_ik_pub)) return false;
  const data = concat(accountId, link.old_ik_pub, link.new_ik_pub);
  return await verify(link.old_ik_pub, 'identity-rotate', data, link.old_sig)
    && await verify(link.new_ik_pub, 'identity-rotate', data, link.new_sig);
}

export async function buildIdentityLink(accountId, oldSigner, newSigner) {
  const data = concat(accountId, oldSigner.pub, newSigner.pub);
  return concat(oldSigner.pub, newSigner.pub, await sign(oldSigner, 'identity-rotate', data), await sign(newSigner, 'identity-rotate', data));
}

/** §4.3: does the chain prove that cert.ik_pub is the current identity key of cert.account_id? */
export async function chainProves(cert, links) {
  if (links.length === 0) return bytesEqual(cert.account_id, await accountIdOf(cert.ik_pub));
  let key = null;
  for (const l of links) {
    if (key === null) {
      if (!bytesEqual(await accountIdOf(l.old_ik_pub), cert.account_id)) return false;
    } else if (!bytesEqual(l.old_ik_pub, key)) return false;
    if (!await identityLinkValid(cert.account_id, l)) return false;
    key = l.new_ik_pub;
  }
  return bytesEqual(key, cert.ik_pub);
}

// §4.4 Key bundle

export function parseKeyBundle(bytes) {
  const r = new Reader(bytes);
  const b = {
    raw: bytes.slice(), version: r.u8(), suite: r.u16(), account_id: r.bytes(16), device_id: r.bytes(16),
    dek_pub: r.bytes(32), not_before: r.u64(), not_after: r.u64(), proto_max: r.u8(), features: r.u32(), sig: r.bytes(64),
  };
  r.end();
  return b;
}

/** §4.4: is bundle `b` valid for the device with `dskPub` in account `accountId`? proto_max and features never matter. */
export async function keyBundleValidFor(b, dskPub, accountId) {
  if (b.version !== 0 || b.suite !== SUITE) return false;
  if (!bytesEqual(b.device_id, await deviceIdOf(dskPub))) return false;
  if (!bytesEqual(b.account_id, accountId)) return false;
  if (x25519KeyInvalid(b.dek_pub)) return false;
  if (!(b.not_before < b.not_after && b.not_after <= b.not_before + MAX_BUNDLE_SPAN)) return false;
  return verify(dskPub, 'key-bundle', b.raw.slice(0, 88), b.sig);
}

/** §4.4 "current at t": what a bundle must be when it enters the log. */
export const keyBundleCurrent = (b, t) => b.not_before <= BigInt(t) + BUNDLE_EARLY_MS && BigInt(t) < b.not_after;

export async function buildKeyBundle(dskSigner, { account_id, dek_pub, not_before, not_after, proto_max = 0, features = 0 }) {
  const body = concat(u8(0), u16(SUITE), account_id, await deviceIdOf(dskSigner.pub), dek_pub, u64(not_before), u64(not_after),
    u8(proto_max), u32(features));
  return concat(body, await sign(dskSigner, 'key-bundle', body));
}

// §4.6 Wraps
export const WRAP_LEN = 104;

export function parseWraps(bytes) {
  if (bytes.length % WRAP_LEN !== 0) throw new ParseError('wrap list length is not a multiple of 104');
  const out = [];
  for (let i = 0; i < bytes.length; i += WRAP_LEN) {
    const r = new Reader(bytes.slice(i, i + WRAP_LEN));
    out.push({ recipient_device_id: r.bytes(16), key_id: r.bytes(8), enc: r.bytes(32), ct: r.bytes(48) });
  }
  return out;
}
export const serializeWraps = wraps => concat(...wraps.map(w => concat(w.recipient_device_id, w.key_id, w.enc, w.ct)));

export const wrapsAscending = wraps =>
  wraps.every((w, i) => i === 0 || compareBytes(wraps[i - 1].recipient_device_id, w.recipient_device_id) < 0);

/**
 * Seal `secret` to each recipient ({device_id, key_id, dek_pub, ikmE?}), sorted by device ID.
 * `infoFor(recipient)` returns the HPKE info for that recipient.
 */
export async function sealWraps(recipients, secret, infoFor) {
  const sorted = [...recipients].sort((a, b) => compareBytes(a.device_id, b.device_id));
  const wraps = [];
  for (const r of sorted) {
    const { enc, ct } = await hpkeSeal(r.dek_pub, await infoFor(r), secret, r.ikmE);
    wraps.push({ recipient_device_id: r.device_id, key_id: r.key_id, enc, ct });
  }
  return wraps;
}

/**
 * Open the wrap addressed to `deviceId` (§4.6). `keys` maps key-ID hex to {key, pub} from
 * importDecryptionKey. Returns { secret } or { error }.
 */
export async function openWrap(wraps, deviceId, keys, infoFor) {
  const w = wraps.find(x => bytesEqual(x.recipient_device_id, deviceId));
  if (!w) return { error: 'not_a_recipient' };
  const k = keys.get(toHex(w.key_id));
  if (!k) return { error: 'unknown_key' };
  const pt = await hpkeOpen(w.enc, k, await infoFor(w), w.ct);
  if (!pt || pt.length !== 32) return { error: 'bad_wrap' };
  return { secret: pt };
}

// ---------------------------------------------------------------------------
// §5 Member log: format
// ---------------------------------------------------------------------------

export const ENTRY = Object.freeze({
  GENESIS: 1, ADD_MEMBER: 2, REMOVE_MEMBER: 3, ADD_DEVICE: 4, REMOVE_DEVICE: 5,
  UPDATE_KEY: 6, POLICY: 7, REKEY: 8, SET_ADMIN: 9, ADD_RECOVERY: 10, SET_OPTIONS: 11, ROTATE_IDENTITY: 12,
});
export const POLICY_SUBTYPE = Object.freeze({
  SET_RULES: 1, SET_GUARDIANS: 2, GRANT_PAUSE: 3, REVOKE_PAUSE: 4, END_TEEN: 5, SET_CIRCLE_NAME: 6,
});
export const HEADER_LEN = 88;
// §16.6 limits and §16.7 options
export const MAX_ENTRY = 65536;
export const DETAILS_LEN = 540;   // nonce 12 + padded plaintext 512 + tag 16
export const DETAILS_PLAIN = 512;
export const MAX_MEMBERS = 32;
export const MAX_DEVICES = 8;
export const MAX_GUARDIANS = 8;
export const MAX_PAUSES = 16;
export const OPTION = Object.freeze({ WEB: 1, HOME_ASSISTANT: 2 });
const OPTIONS_DEFINED = OPTION.WEB | OPTION.HOME_ASSISTANT;

export function parseEntryFraming(raw) {
  const r = new Reader(raw);
  const e = { raw: raw.slice() };
  e.version = r.u8();
  e.suite = r.u16();
  e.type = r.u8();
  e.circle_id = r.bytes(16);
  e.seq = r.u64();
  e.prev_hash = r.bytes(32);
  e.created_at = r.u64();
  e.author = r.bytes(16);
  e.epoch = r.u32();
  e.header = raw.slice(0, HEADER_LEN);
  e.body = r.vec32();
  e.sig = r.bytes(64);
  r.end();
  e.signed = raw.slice(0, raw.length - 64);
  return e;
}

export function serializeEntryHeader(h) {
  return concat(u8(h.version ?? 0), u16(h.suite ?? SUITE), u8(h.type), h.circle_id, u64(h.seq), h.prev_hash,
    u64(h.created_at), h.author, u32(h.epoch));
}

export function parseEntryBody(type, body) {
  const r = new Reader(body);
  const cert = () => parseDeviceCert(r.bytes(CERT_LEN));
  const bundle = () => parseKeyBundle(r.bytes(BUNDLE_LEN));
  let b;
  switch (type) {
    case ENTRY.GENESIS:
      b = { founder_cert: cert(), chain: parseChain(r.vec16()), founder_bundle: bundle(),
        epoch_commit: r.bytes(32), details: r.bytes(DETAILS_LEN) };
      break;
    case ENTRY.ADD_MEMBER:
      b = { cert: cert(), chain: parseChain(r.vec16()), bundle: bundle(), invite_id: r.bytes(16),
        terms_commit: r.bytes(32), consent_sig: r.bytes(64), admin: r.flag(), details: r.bytes(DETAILS_LEN) };
      break;
    case ENTRY.REMOVE_MEMBER:
      b = { account_id: r.bytes(16), epoch_commit: r.bytes(32), wraps: parseWraps(r.vec32()) };
      break;
    case ENTRY.ADD_DEVICE:
      b = { cert: cert(), bundle: bundle() };
      break;
    case ENTRY.REMOVE_DEVICE:
      b = { device_id: r.bytes(16), epoch_commit: r.bytes(32), wraps: parseWraps(r.vec32()) };
      break;
    case ENTRY.UPDATE_KEY:
      b = { bundle: bundle() };
      break;
    case ENTRY.POLICY:
      b = { details: r.bytes(DETAILS_LEN) };
      break;
    case ENTRY.REKEY:
      b = { epoch_commit: r.bytes(32), wraps: parseWraps(r.vec32()) };
      break;
    case ENTRY.SET_ADMIN:
      b = { account_id: r.bytes(16), admin: r.flag() };
      break;
    case ENTRY.ADD_RECOVERY:
      b = { cert: cert() };
      break;
    case ENTRY.SET_OPTIONS:
      b = { options: r.u32() };
      break;
    case ENTRY.ROTATE_IDENTITY:
      b = { link: parseIdentityLink(r.bytes(LINK_LEN)) };
      break;
    default:
      throw new ParseError('unknown entry type');
  }
  r.end();
  return b;
}

/** Serialize a body object (as produced by parseEntryBody, or with raw cert/bundle/chain/link bytes). */
export function serializeEntryBody(type, b) {
  const rawOf = c => c.raw ?? c;
  const chainB = c => vec16(c instanceof Uint8Array ? c : serializeChain(c ?? []));
  switch (type) {
    case ENTRY.GENESIS: return concat(rawOf(b.founder_cert), chainB(b.chain), rawOf(b.founder_bundle), b.epoch_commit, b.details);
    case ENTRY.ADD_MEMBER: return concat(rawOf(b.cert), chainB(b.chain), rawOf(b.bundle), b.invite_id, b.terms_commit, b.consent_sig, u8(b.admin ? 1 : 0), b.details);
    case ENTRY.REMOVE_MEMBER: return concat(b.account_id, b.epoch_commit, vec32(serializeWraps(b.wraps)));
    case ENTRY.ADD_DEVICE: return concat(rawOf(b.cert), rawOf(b.bundle));
    case ENTRY.REMOVE_DEVICE: return concat(b.device_id, b.epoch_commit, vec32(serializeWraps(b.wraps)));
    case ENTRY.UPDATE_KEY: return rawOf(b.bundle);
    case ENTRY.POLICY: return b.details;
    case ENTRY.REKEY: return concat(b.epoch_commit, vec32(serializeWraps(b.wraps)));
    case ENTRY.SET_ADMIN: return concat(b.account_id, u8(b.admin ? 1 : 0));
    case ENTRY.ADD_RECOVERY: return rawOf(b.cert);
    case ENTRY.SET_OPTIONS: return u32(b.options);
    case ENTRY.ROTATE_IDENTITY: return rawOf(b.link);
    default: throw new RangeError('unknown entry type');
  }
}

/** header ‖ vec32(body) ‖ Sign(author DSK, "log-entry", header ‖ vec32(body)) */
export async function buildEntry(header, body, authorSigner) {
  const unsigned = concat(serializeEntryHeader(header), vec32(body));
  return concat(unsigned, await sign(authorSigner, 'log-entry', unsigned));
}

export const entryHash = raw => H('log-hash', raw);
export const epochCommit = (epoch, secret) => H('epoch-commit', u32(epoch), secret);
export const logKey = secret => KDF(secret, 'log-key', 32);
export const epochWrapInfo = (circleId, seq, prevHash, newEpoch, deviceId, keyId) =>
  H('epoch-wrap', circleId, u64(seq), prevHash, u32(newEpoch), deviceId, keyId);

/** §5.4: nonce ‖ AEAD-Seal(log_key, nonce, PadTo(plaintext, 512), header): always 540 bytes. */
export async function sealDetails(epochSecret, header, plaintext, nonce = randomBytes(12)) {
  return concat(nonce, await aeadSeal(await logKey(epochSecret), nonce, padTo(plaintext, DETAILS_PLAIN), header));
}
/** The plaintext, or null if the ciphertext or its padding is bad. */
export async function openDetailsWith(epochSecret, header, det) {
  const padded = await aeadOpen(await logKey(epochSecret), det.slice(0, 12), det.slice(12), header);
  return padded ? unpadTo(padded, DETAILS_PLAIN) : null;
}

// §5.5 Private structures

const TZ_CHARS = /^[A-Za-z0-9/_+-]*$/;
// One character per byte, so that a zone holding a byte outside ASCII still round-trips; rulesValid judges it.
const bytesToLatin1 = b => Array.from(b, x => String.fromCharCode(x)).join('');
const latin1ToBytes = s => Uint8Array.from(s, ch => ch.charCodeAt(0));

export function parseRules(r) {
  const rules = {
    pause_mode: r.u8(), approx_mode: r.u8(), speed_alert_kmh: r.u16(), phone_use_alerts: r.u8(),
    history_days: r.u8(), silence_alert_min: r.u16(), tz: bytesToLatin1(r.vec16()), schedule: [],
  };
  const sched = r.vec16();
  if (sched.length % 6 !== 0) throw new ParseError('schedule is not a whole number of 6-byte windows');
  const wr = new Reader(sched);
  while (wr.off < sched.length) rules.schedule.push({ kind: wr.u8(), days: wr.u8(), start_min: wr.u16(), end_min: wr.u16() });
  return rules;
}

export function serializeRules(x) {
  const sched = concat(...x.schedule.map(w => concat(u8(w.kind), u8(w.days), u16(w.start_min), u16(w.end_min))));
  return concat(u8(x.pause_mode), u8(x.approx_mode), u16(x.speed_alert_kmh), u8(x.phone_use_alerts),
    u8(x.history_days), u16(x.silence_alert_min), vec16(latin1ToBytes(x.tz)), vec16(sched));
}

export function rulesValid(x) {
  const inMode = v => v === 0 || v === 1 || v === 2;
  return inMode(x.pause_mode) && inMode(x.approx_mode)
    && x.speed_alert_kmh <= 300
    && (x.phone_use_alerts === 0 || x.phone_use_alerts === 1)
    && x.history_days >= 1 && x.history_days <= 30
    && (x.silence_alert_min === 0 || (x.silence_alert_min >= 15 && x.silence_alert_min <= 1440))
    && x.tz.length <= 64 && TZ_CHARS.test(x.tz)
    && x.schedule.length <= 32 && (x.tz !== '' || x.schedule.length === 0)
    && x.schedule.every(w => (w.kind === 1 || w.kind === 2) && w.days >= 1 && w.days <= 127
      && w.start_min < w.end_min && w.end_min <= 1440);
}

export function nameValid(bytes) {
  return bytes.length >= 1 && bytes.length <= 128 && decodeUtf8(bytes) !== null;
}

export function parseGenesisDetails(pt) {
  const r = new Reader(pt);
  const name = r.vec16();
  r.end();
  return { name };
}

/** MemberTerms: what a new member is asked to accept (§5.5, §9). */
export function readMemberTerms(r) {
  return { role: r.u8(), teen_until: r.u64(), guardians: r.ids(), rules: parseRules(r) };
}
export function serializeMemberTerms(d) {
  return concat(u8(d.role), u64(d.teen_until), vec16(concat(...d.guardians)), serializeRules(d.rules));
}
export const termsCommit = (termsSalt, termsBytes) => H('member-terms', termsSalt, termsBytes);

export function parseMemberDetails(pt) {
  const r = new Reader(pt);
  const terms_salt = r.bytes(16);
  const terms = readMemberTerms(r);
  r.end();
  return { terms_salt, terms, terms_bytes: pt.slice(16) };
}

/** Parse a Policy whose subtype is known (§16.2); throws ParseError otherwise. */
export function parsePolicy(pt) {
  const r = new Reader(pt);
  const p = { subtype: r.u8() };
  switch (p.subtype) {
    case POLICY_SUBTYPE.SET_RULES: p.target = r.bytes(16); p.rules = parseRules(r); break;
    case POLICY_SUBTYPE.SET_GUARDIANS: p.target = r.bytes(16); p.guardians = r.ids(); break;
    case POLICY_SUBTYPE.GRANT_PAUSE:
      p.target = r.bytes(16); p.pause_id = r.bytes(8); p.kind = r.u8(); p.start = r.u64(); p.end = r.u64(); break;
    case POLICY_SUBTYPE.REVOKE_PAUSE: p.target = r.bytes(16); p.pause_id = r.bytes(8); break;
    case POLICY_SUBTYPE.END_TEEN: p.target = r.bytes(16); break;
    case POLICY_SUBTYPE.SET_CIRCLE_NAME: p.name = r.vec16(); break;
    default: throw new ParseError('unknown policy subtype');
  }
  r.end();
  return p;
}

// ---------------------------------------------------------------------------
// §6 Member log: validation
// ---------------------------------------------------------------------------

export function emptyState() {
  return {
    empty: true, circle_id: null, seq: -1n, head: new Uint8Array(32),
    hashes: new Map(),           // entry hash (hex) -> seq
    epoch: 0, commits: new Map(), rekey_pending: false,
    options: 0,                  // public circle options (§16.7)
    usedInvites: new Set(),      // invite IDs (hex) already spent (§6.4)
    receivingChangedSeq: -1n,    // last entry that changed the set of receiving devices (§7.5)
    members: new Map(), name: '', flags: [],
    stateHash: null,             // §6.9, hex; null while private state is frozen and in public mode
    // §6.5 "Missing secrets": set while private state is frozen, as
    // { from: seq, epoch, checkpoint: client state before that entry, entries: [raw, …] }.
    locked: null,
  };
}

function cloneMember(m) {
  return {
    ...m,
    devices: new Map([...m.devices].map(([k, d]) => [k, { ...d }])),
    guardians: [...m.guardians],
    rules: m.rules ? { ...m.rules, schedule: m.rules.schedule.map(w => ({ ...w })) } : null,
    pauses: new Map([...m.pauses].map(([k, p]) => [k, { ...p }])),
  };
}
export function cloneState(s) {
  return {
    ...s, hashes: new Map(s.hashes), commits: new Map(s.commits), flags: s.flags.map(f => ({ ...f })),
    usedInvites: new Set(s.usedInvites),
    members: new Map([...s.members].map(([k, m]) => [k, cloneMember(m)])),
  };
}

function newMember(accountId, ikPub, admin) {
  return {
    account_id: accountId, ik_pub: ikPub, admin, devices: new Map(),
    role: 'adult', teen_until: 0n, guardians: [], rules: null, pauses: new Map(),
  };
}
/** bundle is null for a recovery device. added_by: the account that authored the adding entry (§8.2 `welcome`). */
async function deviceRecord(cert, bundle, addedBy) {
  return {
    device_id: await deviceIdOf(cert.dsk_pub), dsk_pub: cert.dsk_pub, kind: cert.device_kind,
    bundle, dek_pub: bundle ? bundle.dek_pub : null, key_id: bundle ? await keyIdOf(bundle.dek_pub) : null,
    added_by: toHex(addedBy),
  };
}

export function findDevice(state, deviceId) {
  const h = toHex(deviceId);
  for (const m of state.members.values()) {
    const d = m.devices.get(h);
    if (d) return { member: m, device: d };
  }
  return null;
}

/** Every active device as { account_id, device_id, key_id, dek_pub, dsk_pub, kind }, recovery devices included. */
export function activeDevices(state) {
  const out = [];
  for (const m of state.members.values()) for (const d of m.devices.values()) out.push({ account_id: m.account_id, ...d });
  return out.sort((a, b) => compareBytes(a.device_id, b.device_id));
}
/** The devices that receive envelopes and epoch wraps: kinds 1 to 4 (§6.1). */
export const receivingDevices = state => activeDevices(state).filter(d => isReceivingKind(d.kind));
const receivingSetOf = state => receivingDevices(state).map(d => toHex(d.device_id)).join(',');

const countAdmins = state => [...state.members.values()].filter(m => m.admin).length;

/** §6.4 wrap coverage: ascending, exactly the required devices, each at its current key ID. */
export function wrapsCover(wraps, required) {
  if (!wrapsAscending(wraps) || wraps.length !== required.length) return false;
  const req = [...required].sort((a, b) => compareBytes(a.device_id, b.device_id));
  return wraps.every((w, i) => bytesEqual(w.recipient_device_id, req[i].device_id) && bytesEqual(w.key_id, req[i].key_id));
}

function endTeen(m) {
  m.role = 'adult'; m.teen_until = 0n; m.guardians = []; m.rules = null; m.pauses = new Map();
}

/** §6.6: every teen is judged against the same snapshot of adults, so no teen becomes another's guardian here. */
export function guardianRepair(s) {
  const adults = [...s.members.values()].filter(m => m.role === 'adult');
  const ids = ms => ms.map(m => toHex(m.account_id)).sort();
  const adultIds = ids(adults);
  const adminIds = ids(adults.filter(m => m.admin));
  const ending = [];
  for (const t of s.members.values()) {
    if (t.role !== 'teen') continue;
    let g = t.guardians.filter(h => adultIds.includes(h));
    if (!g.length) g = adminIds.slice(0, MAX_GUARDIANS);
    if (!g.length) g = adultIds.slice(0, MAX_GUARDIANS);
    if (g.length) t.guardians = g;
    else ending.push(t);
  }
  for (const t of ending) endTeen(t);
}

/**
 * Secret for `epoch`, used only if it matches the recorded commitment (§8.5: "check each
 * secret against the log's epoch_commit values before using it").
 */
async function verifiedEpochSecret(commits, secrets, epoch) {
  const secret = secrets.get(epoch);
  const commit = commits.get(epoch);
  if (!secret || !commit) return null;
  return bytesEqual(await epochCommit(epoch, secret), commit) ? secret : null;
}

/** §6.5 ADD_MEMBER: are these terms valid for a member added at `createdAt`? */
function memberTermsValid(d, state, createdAt) {
  if (!rulesValid(d.rules)) return false;
  if (d.role === 1) return d.teen_until === 0n && d.guardians.length === 0;
  if (d.role === 2) {
    return d.teen_until > createdAt && d.guardians.length >= 1 && d.guardians.length <= MAX_GUARDIANS
      && d.guardians.every(g => { const m = state.members.get(toHex(g)); return !!m && m.role === 'adult'; });
  }
  return false;
}

/** §6.5 POLICY private rules. Returns { reject: reason } or { apply(stateClone) }. */
function policyDecision(state, e, authorMember, pt) {
  if (!pt || pt.length < 1) return { reject: 'bad_details' };
  const subtype = pt[0];
  if (!Object.values(POLICY_SUBTYPE).includes(subtype)) return { reject: 'unknown_policy' };
  let p;
  try { p = parsePolicy(pt); } catch (x) { if (x instanceof ParseError) return { reject: 'bad_details' }; throw x; }
  if (subtype === POLICY_SUBTYPE.SET_CIRCLE_NAME) {
    if (!authorMember.admin) return { reject: 'not_admin' };
    if (!nameValid(p.name)) return { reject: 'bad_details' };
    return { apply: s => { s.name = decodeUtf8(p.name); } };
  }
  const targetHex = toHex(p.target);
  const t = state.members.get(targetHex);
  if (!t) return { reject: 'not_member' };
  if (t.role !== 'teen') return { reject: 'not_teen' };
  const authorHex = toHex(authorMember.account_id);
  const isGuardian = t.guardians.includes(authorHex);
  const target = s => s.members.get(targetHex);
  if (subtype === POLICY_SUBTYPE.END_TEEN) {
    if (isGuardian) return { apply: s => endTeen(target(s)) };
    if (authorHex === targetHex) {
      if (e.created_at >= t.teen_until) return { apply: s => endTeen(target(s)) };
      return { reject: 'teen_until_not_reached' };
    }
    return { reject: 'not_guardian' };
  }
  if (!isGuardian) return { reject: 'not_guardian' };
  switch (subtype) {
    case POLICY_SUBTYPE.SET_RULES:
      if (!rulesValid(p.rules)) return { reject: 'bad_rules' };
      return { apply: s => { target(s).rules = p.rules; } };
    case POLICY_SUBTYPE.SET_GUARDIANS: {
      const ok = p.guardians.length >= 1 && p.guardians.length <= MAX_GUARDIANS
        && p.guardians.every(g => { const m = state.members.get(toHex(g)); return !!m && m.role === 'adult'; });
      if (!ok) return { reject: 'bad_guardians' };
      return { apply: s => { target(s).guardians = p.guardians.map(toHex); } };
    }
    case POLICY_SUBTYPE.GRANT_PAUSE: {
      const ok = (p.kind === 1 || p.kind === 2) && p.start < p.end && p.end <= p.start + 86400000n
        && !t.pauses.has(toHex(p.pause_id));
      if (!ok) return { reject: 'bad_pause' };
      return { apply: s => {
        const pauses = target(s).pauses;
        if (pauses.size >= MAX_PAUSES) {   // keep 16: drop the one that ends earliest (ties: the lowest ID)
          const [drop] = [...pauses].sort(([ia, a], [ib, b]) => (a.end < b.end ? -1 : a.end > b.end ? 1 : ia < ib ? -1 : 1))[0];
          pauses.delete(drop);
        }
        pauses.set(toHex(p.pause_id), { kind: p.kind, start: p.start, end: p.end });
      } };
    }
    case POLICY_SUBTYPE.REVOKE_PAUSE:
      if (!t.pauses.has(toHex(p.pause_id))) return { reject: 'unknown_pause' };
      return { apply: s => { target(s).pauses.delete(toHex(p.pause_id)); } };
  }
  throw new Error('unreachable');
}

/** The table in §6.3: what a device may write depends on its kind. */
function kindMayAuthor(state, e, b, kind, authorAccountId) {
  if (isPhoneOrTablet(kind)) return true;
  if (kind === KIND.WEB || kind === KIND.HOME_ASSISTANT) {
    return e.type === ENTRY.UPDATE_KEY || (e.type === ENTRY.REMOVE_DEVICE && bytesEqual(b.device_id, e.author));
  }
  if (kind === KIND.RECOVERY) {
    if (e.type === ENTRY.ADD_DEVICE) return true;
    if (e.type === ENTRY.REMOVE_DEVICE) {
      const f = findDevice(state, b.device_id);
      return !!f && bytesEqual(f.member.account_id, authorAccountId);
    }
  }
  return false;
}

/**
 * Process one log entry (§6.3).
 *   opts.mode    'client' (all rules, default) or 'public' (steps 1-9 and the public effects
 *                of step 11: what a server runs)
 *   opts.secrets Map epoch -> 32-byte epoch secret (client mode). A secret is used only if it
 *                matches the log's epoch_commit (§6.5 "Missing secrets").
 * Returns { result: 'accepted'|'rejected'|'deferred'|'fatal', reason, state, entry, body, hash,
 * privateUnknown }. A fatal entry returns the input state unchanged. When a client lacks the
 * secret for an entry with details (GENESIS, ADD_MEMBER, POLICY), that entry and every later
 * one are `deferred`: public effects only, private state frozen at its last known values, and
 * `state.locked` records where to resume (see resumePrivate).
 */
export async function processEntry(state, raw, opts = {}) {
  const client = (opts.mode ?? 'client') === 'client';
  const secrets = opts.secrets ?? new Map();
  const fatal = reason => ({ result: 'fatal', reason, state });
  const malformed = x => { if (x instanceof ParseError) return fatal('malformed'); throw x; };

  // 1-4: size, framing, version, type, body
  if (raw.length > MAX_ENTRY) return fatal('too_large');
  let e, b;
  try { e = parseEntryFraming(raw); } catch (x) { return malformed(x); }
  if (e.version !== 0 || e.suite !== SUITE) return fatal('bad_version');
  if (!(e.type >= 1 && e.type <= 12)) return fatal('unknown_entry_type');
  try { b = parseEntryBody(e.type, e.body); } catch (x) { return malformed(x); }

  // 5: position
  if (state.empty) {
    if (e.type !== ENTRY.GENESIS || e.seq !== 0n) return fatal('bad_seq');
    if (!isZero(e.prev_hash)) return fatal('bad_prev_hash');
    if (!isZero(e.circle_id)) return fatal('bad_circle_id');
    if (e.epoch !== 0) return fatal('bad_epoch');
  } else {
    if (e.type === ENTRY.GENESIS) return fatal('unexpected_genesis');
    if (e.seq !== state.seq + 1n) return fatal('bad_seq');
    if (!bytesEqual(e.prev_hash, state.head)) return fatal('bad_prev_hash');
    if (!bytesEqual(e.circle_id, state.circle_id)) return fatal('bad_circle_id');
    if (e.epoch !== state.epoch) return fatal('bad_epoch');
  }

  // 6: author
  let authorPub, authorKind, authorAccountId, author = null;
  if (e.type === ENTRY.GENESIS) {
    if (!bytesEqual(e.author, await deviceIdOf(b.founder_cert.dsk_pub))) return fatal('bad_author');
    authorPub = b.founder_cert.dsk_pub; authorKind = b.founder_cert.device_kind; authorAccountId = b.founder_cert.account_id;
  } else {
    author = findDevice(state, e.author);
    if (!author) return fatal('author_not_active');
    authorPub = author.device.dsk_pub; authorKind = author.device.kind; authorAccountId = author.member.account_id;
  }

  // 7: signature; 8: what this kind of device may write
  if (!await verify(authorPub, 'log-entry', e.signed, e.sig)) return fatal('bad_signature');
  if (!kindMayAuthor(state, e, b, authorKind, authorAccountId)) return fatal('kind_not_allowed');

  // §6.5 "Missing secrets": only entries with details need their epoch's secret, and only one
  // that matches the commitment counts. Without it, this entry and every later one are deferred.
  const hasDetails = e.type === ENTRY.GENESIS || e.type === ENTRY.ADD_MEMBER || e.type === ENTRY.POLICY;
  let secret = null;
  let lockHere = false;
  if (client && !state.locked && hasDetails) {
    const commits = e.type === ENTRY.GENESIS ? new Map([[0, b.epoch_commit]]) : state.commits;
    secret = await verifiedEpochSecret(commits, secrets, e.epoch);
    lockHere = !secret;
  }
  const deferred = client && (!!state.locked || lockHere);
  const priv = client && !deferred;

  // 9-11: public rules, private rules, effects
  const s = cloneState(state);
  let result = 'accepted';
  let reason = null;
  const flag = r => { reason = r; s.flags.push({ seq: e.seq, reason: r }); };
  const authorMember = author?.member;
  const authorInClone = () => s.members.get(toHex(authorMember.account_id));
  const advanceEpoch = commit => { s.epoch = e.epoch + 1; s.commits.set(s.epoch, commit); s.rekey_pending = false; };
  const noEpoch = () => isZero(b.epoch_commit) && b.wraps.length === 0;
  // §6.4: a removal by a non-admin, or of the author's own membership or device, starts no
  // epoch: it carries an all-zero commitment and no wraps, and leaves a rekey pending.
  const noEpochRemoval = () => {
    if (!noEpoch()) return false;
    s.rekey_pending = true;
    return true;
  };
  const keyTaken = ikPub => [...state.members.values()].some(m => bytesEqual(m.ik_pub, ikPub));
  // The first two checks of ADD_DEVICE and ADD_RECOVERY.
  const ownCert = async cert => {
    if (!await deviceCertWellFormed(cert)) return 'bad_cert';
    if (!bytesEqual(cert.account_id, authorMember.account_id) || !bytesEqual(cert.ik_pub, authorMember.ik_pub)) return 'wrong_account';
    return null;
  };

  switch (e.type) {
    case ENTRY.GENESIS: {
      const fc = b.founder_cert, fb = b.founder_bundle;
      if (!await deviceCertWellFormed(fc) || !await chainProves(fc, b.chain)) return fatal('bad_cert');
      if (!await keyBundleValidFor(fb, fc.dsk_pub, fc.account_id) || !keyBundleCurrent(fb, e.created_at)) return fatal('bad_bundle');
      s.empty = false;
      s.circle_id = (await H('circle-id', raw)).slice(0, 16);
      s.epoch = 0;
      s.commits.set(0, b.epoch_commit);
      const m = newMember(fc.account_id, fc.ik_pub, true);
      const d = await deviceRecord(fc, fb, fc.account_id);
      m.devices.set(toHex(d.device_id), d);
      s.members.set(toHex(m.account_id), m);
      if (priv) {
        let name = null;
        const pt = await openDetailsWith(secret, e.header, b.details);
        if (pt) {
          try { const g = parseGenesisDetails(pt); if (nameValid(g.name)) name = decodeUtf8(g.name); }
          catch (x) { if (!(x instanceof ParseError)) throw x; }
        }
        s.name = name ?? '';
        if (name === null) flag('bad_details');
      }
      break;
    }

    case ENTRY.ADD_MEMBER: {
      const { cert, bundle } = b;
      if (!authorMember.admin) return fatal('not_admin');
      if (state.rekey_pending) return fatal('rekey_pending');
      if (state.members.size >= MAX_MEMBERS) return fatal('too_many_members');
      if (!await deviceCertWellFormed(cert) || !await chainProves(cert, b.chain)) return fatal('bad_cert');
      if (!isPhoneOrTablet(cert.device_kind)) return fatal('kind_not_allowed');
      if (!await keyBundleValidFor(bundle, cert.dsk_pub, cert.account_id) || !keyBundleCurrent(bundle, e.created_at)) return fatal('bad_bundle');
      if (state.members.has(toHex(cert.account_id)) || keyTaken(cert.ik_pub)) return fatal('already_member');
      if (findDevice(state, await deviceIdOf(cert.dsk_pub))) return fatal('device_active');
      if (state.usedInvites.has(toHex(b.invite_id))) return fatal('invite_reused');
      const consentData = concat(state.circle_id, b.invite_id, cert.raw, bundle.raw, b.terms_commit);
      if (!await verify(cert.ik_pub, 'join-consent', consentData, b.consent_sig)) return fatal('bad_consent');
      const m = newMember(cert.account_id, cert.ik_pub, b.admin);
      const d = await deviceRecord(cert, bundle, authorMember.account_id);
      m.devices.set(toHex(d.device_id), d);
      s.usedInvites.add(toHex(b.invite_id));
      if (priv) {
        let terms = null;
        const pt = await openDetailsWith(secret, e.header, b.details);
        if (pt) {
          try {
            const md = parseMemberDetails(pt);
            // The terms must be the ones the new member signed (§9), and valid.
            if (bytesEqual(await termsCommit(md.terms_salt, md.terms_bytes), b.terms_commit)
              && memberTermsValid(md.terms, state, e.created_at)) terms = md.terms;
          } catch (x) { if (!(x instanceof ParseError)) throw x; }
        }
        if (terms && terms.role === 2) {
          m.role = 'teen'; m.teen_until = terms.teen_until; m.guardians = terms.guardians.map(toHex); m.rules = terms.rules;
        }
        if (!terms) flag('bad_details');
      }
      s.members.set(toHex(m.account_id), m);
      break;
    }

    case ENTRY.REMOVE_MEMBER: {
      const target = state.members.get(toHex(b.account_id));
      if (!target) return fatal('not_member');
      const selfRemoval = bytesEqual(authorMember.account_id, b.account_id);
      if (!(authorMember.admin || selfRemoval)) return fatal('not_admin');
      if (target.admin && countAdmins(state) === 1 && state.members.size !== 1) return fatal('last_admin');
      if (authorMember.admin && !selfRemoval) {
        const required = receivingDevices(state).filter(d => !bytesEqual(d.account_id, b.account_id));
        if (!wrapsCover(b.wraps, required)) return fatal('bad_wraps');
        advanceEpoch(b.epoch_commit);
      } else if (!noEpochRemoval()) {
        return fatal('bad_wraps');
      }
      s.members.delete(toHex(b.account_id));
      break;
    }

    case ENTRY.ADD_DEVICE: {
      const { cert, bundle } = b;
      const why = await ownCert(cert);
      if (why) return fatal(why);
      const allowed = isReceivingKind(cert.device_kind)
        && !(cert.device_kind === KIND.WEB && !(state.options & OPTION.WEB))
        && !(cert.device_kind === KIND.HOME_ASSISTANT && !(state.options & OPTION.HOME_ASSISTANT));
      if (!allowed) return fatal('kind_not_allowed');
      if (authorMember.devices.size >= MAX_DEVICES) return fatal('too_many_devices');
      if (!await keyBundleValidFor(bundle, cert.dsk_pub, cert.account_id) || !keyBundleCurrent(bundle, e.created_at)) return fatal('bad_bundle');
      if (findDevice(state, await deviceIdOf(cert.dsk_pub))) return fatal('device_active');
      const d = await deviceRecord(cert, bundle, authorMember.account_id);
      authorInClone().devices.set(toHex(d.device_id), d);
      break;
    }

    case ENTRY.ADD_RECOVERY: {
      const why = await ownCert(b.cert);
      if (why) return fatal(why);
      if (b.cert.device_kind !== KIND.RECOVERY) return fatal('kind_not_allowed');
      const mine = [...authorMember.devices.values()];
      if (mine.some(d => d.kind === KIND.RECOVERY) || mine.length >= MAX_DEVICES) return fatal('too_many_devices');
      if (findDevice(state, await deviceIdOf(b.cert.dsk_pub))) return fatal('device_active');
      const d = await deviceRecord(b.cert, null, authorMember.account_id);
      authorInClone().devices.set(toHex(d.device_id), d);
      break;
    }

    case ENTRY.REMOVE_DEVICE: {
      const f = findDevice(state, b.device_id);
      if (!f) return fatal('unknown_device');
      if (!(bytesEqual(f.member.account_id, authorMember.account_id) || authorMember.admin)) return fatal('not_admin');
      if (f.member.devices.size === 1) return fatal('last_device');
      if (f.device.kind === KIND.RECOVERY) {
        // It never held an epoch secret, so nothing else changes.
        if (!noEpoch()) return fatal('bad_wraps');
      } else if (authorMember.admin && !bytesEqual(b.device_id, author.device.device_id)) {
        const required = receivingDevices(state).filter(d => !bytesEqual(d.device_id, b.device_id));
        if (!wrapsCover(b.wraps, required)) return fatal('bad_wraps');
        advanceEpoch(b.epoch_commit);
      } else if (!noEpochRemoval()) {
        return fatal('bad_wraps');
      }
      s.members.get(toHex(f.member.account_id)).devices.delete(toHex(b.device_id));
      break;
    }

    case ENTRY.UPDATE_KEY: {
      const valid = await keyBundleValidFor(b.bundle, author.device.dsk_pub, authorMember.account_id)
        && keyBundleCurrent(b.bundle, e.created_at)
        && !bytesEqual(await keyIdOf(b.bundle.dek_pub), author.device.key_id);
      if (!valid) return fatal('bad_bundle');
      const d = authorInClone().devices.get(toHex(author.device.device_id));
      d.bundle = b.bundle; d.dek_pub = b.bundle.dek_pub; d.key_id = await keyIdOf(b.bundle.dek_pub);
      break;
    }

    case ENTRY.POLICY: {
      if (state.rekey_pending) return fatal('rekey_pending');
      if (priv) {
        const pt = await openDetailsWith(secret, e.header, b.details);
        const decision = policyDecision(state, e, authorMember, pt);
        if (decision.reject) { result = 'rejected'; flag(decision.reject); }
        else decision.apply(s);
      }
      break;
    }

    case ENTRY.REKEY: {
      if (!authorMember.admin) return fatal('not_admin');
      if (!wrapsCover(b.wraps, receivingDevices(state))) return fatal('bad_wraps');
      advanceEpoch(b.epoch_commit);
      break;
    }

    case ENTRY.SET_ADMIN: {
      if (!authorMember.admin) return fatal('not_admin');
      const t = state.members.get(toHex(b.account_id));
      if (!t) return fatal('not_member');
      if (!b.admin && t.admin && countAdmins(state) === 1) return fatal('last_admin');
      s.members.get(toHex(b.account_id)).admin = b.admin;
      break;
    }

    case ENTRY.SET_OPTIONS: {
      if (!authorMember.admin) return fatal('not_admin');
      if ((b.options & ~OPTIONS_DEFINED) !== 0) return fatal('bad_options');
      s.options = b.options;
      break;
    }

    case ENTRY.ROTATE_IDENTITY: {
      const l = b.link;
      const ok = bytesEqual(l.old_ik_pub, authorMember.ik_pub) && !ed25519KeyInvalid(l.new_ik_pub)
        && !bytesEqual(l.new_ik_pub, l.old_ik_pub) && !keyTaken(l.new_ik_pub)
        && await identityLinkValid(authorMember.account_id, l);
      if (!ok) return fatal('bad_rotation');
      authorInClone().ik_pub = l.new_ik_pub;
      break;
    }
  }

  const hash = await entryHash(raw);
  s.seq = e.seq;
  s.head = hash;
  s.hashes.set(toHex(hash), e.seq);
  if (e.type === ENTRY.GENESIS || receivingSetOf(s) !== receivingSetOf(state)) s.receivingChangedSeq = e.seq;
  if (client) {
    if (state.locked) s.locked = { ...state.locked, entries: [...state.locked.entries, raw.slice()] };
    else if (lockHere) s.locked = { from: e.seq, epoch: e.epoch, checkpoint: state, entries: [raw.slice()] };
  }
  if (deferred) { result = 'deferred'; reason = null; }
  if (priv) guardianRepair(s);
  s.stateHash = priv ? toHex((await H('state-hash', stateBytes(s))).slice(0, 8)) : null;
  return { result, reason, state: s, entry: e, body: b, hash, privateUnknown: deferred };
}

/**
 * §6.5: once the missing secret arrives, run the private rules again from the entry where
 * private state became unknown, in order. Returns the new state (still locked, further on,
 * if a later secret is missing too).
 */
export async function resumePrivate(state, secrets) {
  if (!state.locked) return state;
  let st = state.locked.checkpoint;
  for (const raw of state.locked.entries) {
    const r = await processEntry(st, raw, { mode: 'client', secrets });
    // Public rules don't depend on secrets, so an entry that was applied can't turn fatal.
    if (r.result === 'fatal') throw new Error(`entry turned fatal on replay: ${r.reason}`);
    st = r.state;
  }
  return st;
}

/** §6.9: the bytes whose hash lets two clients compare everything they believe about a circle. */
export function stateBytes(s) {
  const parts = [s.circle_id, u64(s.seq), s.head, u32(s.epoch), u8(s.rekey_pending ? 1 : 0), u32(s.options),
    vec16(utf8(s.name)), u16(s.members.size)];
  for (const m of [...s.members.values()].sort((a, b) => compareBytes(a.account_id, b.account_id))) {
    const teen = m.role === 'teen';
    parts.push(m.account_id, m.ik_pub, u8(m.admin ? 1 : 0), u8(teen ? 2 : 1), u64(m.teen_until),
      vec16(concat(...m.guardians.map(fromHex))), vec16(teen ? serializeRules(m.rules) : new Uint8Array(0)), u16(m.pauses.size));
    for (const [id, p] of [...m.pauses].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
      parts.push(fromHex(id), u8(p.kind), u64(p.start), u64(p.end));
    }
    parts.push(u16(m.devices.size));
    for (const d of [...m.devices.values()].sort((a, b) => compareBytes(a.device_id, b.device_id))) {
      parts.push(d.device_id, u8(d.kind), d.key_id ?? new Uint8Array(8));
    }
  }
  return concat(...parts);
}

/**
 * The state as the JSON object used by the test vectors (§6.1, vectors/README.md). While
 * private state is frozen (§6.5) the private fields keep their last known values and
 * `private_unknown_from` gives the seq where it froze; otherwise it is null.
 */
export function stateToJSON(s, { publicOnly = false } = {}) {
  const members = [...s.members.values()]
    .sort((a, b) => compareBytes(a.account_id, b.account_id))
    .map(m => {
      const devices = [...m.devices.values()]
        .sort((a, b) => compareBytes(a.device_id, b.device_id))
        .map(d => ({ device_id: toHex(d.device_id), kind: d.kind, key_id: d.key_id ? toHex(d.key_id) : null }));
      const pub = { account_id: toHex(m.account_id), ik_pub: toHex(m.ik_pub), admin: m.admin, devices };
      if (publicOnly) return pub;
      return {
        ...pub,
        role: m.role,
        teen_until: Number(m.teen_until),
        guardians: [...m.guardians],
        rules: m.role === 'teen' && m.rules ? { ...m.rules, schedule: m.rules.schedule.map(w => ({ ...w })) } : null,
        pauses: [...m.pauses.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([id, p]) => ({ id, kind: p.kind, start: Number(p.start), end: Number(p.end) })),
      };
    });
  const out = {
    circle_id: s.circle_id ? toHex(s.circle_id) : null, seq: Number(s.seq), head: toHex(s.head), epoch: s.epoch,
    rekey_pending: !!s.rekey_pending, options: s.options, used_invites: [...s.usedInvites].sort(), members,
  };
  if (!publicOnly) {
    out.name = s.name;
    out.flags = s.flags.map(f => ({ seq: Number(f.seq), reason: f.reason }));
    out.private_unknown_from = s.locked ? Number(s.locked.from) : null;
    out.state_hash = s.locked ? null : s.stateHash;
  }
  return out;
}

// ---------------------------------------------------------------------------
// §7 Envelopes
// ---------------------------------------------------------------------------

export const ENV_HEADER_LEN = 88;
export const BUCKETS = [256, 512, 1024, 2048, 4096, 8192, 16384, 65536];
export const MAX_WRAPS = 255;

/** §7.4 PadTo(p, n) = p ‖ 0x80 ‖ zero bytes, to exactly n bytes. */
export function padTo(p, n) {
  if (p.length > n - 1) throw new RangeError(`too long to pad to ${n} bytes`);
  const out = new Uint8Array(n);
  out.set(p);
  out[p.length] = 0x80;
  return out;
}

export function pad(p) {
  if (p.length > 65535) throw new RangeError('payload larger than 65,535 bytes');
  return padTo(p, BUCKETS.find(n => n >= p.length + 1));
}

function stripPadding(x) {
  let i = x.length - 1;
  while (i >= 0 && x[i] === 0) i--;
  if (i < 0 || x[i] !== 0x80) return null;
  return x.slice(0, i);
}

/** Unpad for a fixed size (512 for log details, 2,560 for pushes). Null if the padding is invalid. */
export const unpadTo = (x, n) => (x.length === n ? stripPadding(x) : null);

/** Returns the payload, or null if the padding is invalid. */
export const unpad = x => (BUCKETS.includes(x.length) ? stripPadding(x) : null);

export function serializeEnvelopeHeader(h) {
  return concat(u8(h.version ?? 0), u16(h.suite ?? SUITE), u8(h.kind), h.circle_id, h.sender_device_id,
    u64(h.seq), u64(h.sent_at), u32(h.ttl_s), h.log_head);
}

export function parseEnvelope(raw) {
  const r = new Reader(raw);
  const v = { raw: raw.slice() };
  v.version = r.u8(); v.suite = r.u16(); v.kind = r.u8(); v.circle_id = r.bytes(16);
  v.sender_device_id = r.bytes(16); v.seq = r.u64(); v.sent_at = r.u64(); v.ttl_s = r.u32(); v.log_head = r.bytes(32);
  v.header = raw.slice(0, ENV_HEADER_LEN);
  const wrapBytes = r.vec32();
  v.wraps = parseWraps(wrapBytes);
  v.throughWraps = raw.slice(0, ENV_HEADER_LEN + 4 + wrapBytes.length);
  v.ciphertext = r.vec32();
  v.sig = r.bytes(64);
  r.end();
  v.signed = raw.slice(0, raw.length - 64);
  return v;
}

export const envelopeWrapInfo = (header, deviceId, keyId) => H('wrap', header, deviceId, keyId);

async function payloadKeys(messageSecret) {
  return { key: await KDF(messageSecret, 'payload-key', 32), nonce: await KDF(messageSecret, 'payload-nonce', 12) };
}

/**
 * §7.3/§7.5 Build an envelope. `recipients`: [{device_id, key_id, dek_pub, ikmE?}].
 * `messageSecret` and per-recipient `ikmE` are only for byte-exact test vectors.
 */
export async function sealEnvelope({ header, recipients, payload, signer, messageSecret = randomBytes(32) }) {
  const hdr = serializeEnvelopeHeader(header);
  const wraps = await sealWraps(recipients, messageSecret, r => envelopeWrapInfo(hdr, r.device_id, r.key_id));
  const wrapBytes = serializeWraps(wraps);
  const aad = await H('env-aad', hdr, vec32(wrapBytes));
  const { key, nonce } = await payloadKeys(messageSecret);
  const ct = await aeadSeal(key, nonce, pad(payload), aad);
  const unsigned = concat(hdr, vec32(wrapBytes), vec32(ct));
  return concat(unsigned, await sign(signer, 'envelope', unsigned));
}

// §8.1 payload limits
export const PAYLOAD_LIMITS = Object.freeze({ depth: 8, string: 4096, avatar: 43700, array: 256 });

function withinLimits(v, depth, avatar = false) {
  if (v === null || typeof v === 'boolean') return true;
  if (typeof v === 'string') {
    if (!v.isWellFormed()) return false;   // an unpaired surrogate, which a \u escape can smuggle in
    return te.encode(v).length <= (avatar ? PAYLOAD_LIMITS.avatar : PAYLOAD_LIMITS.string);   // bytes of UTF-8
  }
  // JSON.parse reads every number as a double; §8.1 judges that value: whole, and at most 2^53 - 1 either way.
  if (typeof v === 'number') return Number.isSafeInteger(v);
  if (depth > PAYLOAD_LIMITS.depth) return false;
  if (Array.isArray(v)) return v.length <= PAYLOAD_LIMITS.array && v.every(x => withinLimits(x, depth + 1));
  return Object.entries(v).every(([k, x]) => withinLimits(k, depth + 1) && withinLimits(x, depth + 1, depth === 1 && k === 'avatar'));
}

/** §7.6 step 14: UTF-8 JSON, an object with a string "t", within the limits of §8.1. Null otherwise. */
export function parsePayloadJSON(bytes) {
  const text = decodeUtf8(bytes);
  if (text === null) return null;
  let obj;
  try { obj = JSON.parse(text); } catch { return null; }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj) || typeof obj.t !== 'string') return null;
  return withinLimits(obj, 1) ? obj : null;
}

// §8.2 who may send what
const CIRCLE_TYPES = new Set(['loc', 'hb', 'evt', 'checkin', 'sos', 'place', 'profile', 'chat', 'pause_req', 'pause_deny',
  'watch_grant', 'refresh_req', 'refresh']);
const DIRECT_TYPES = new Set(['sig', 'welcome', 'ik']);
const KIND_MAY_SEND = new Map([[KIND.WEB, new Set(['sig', 'refresh_req'])], [KIND.HOME_ASSISTANT, new Set(['refresh_req'])]]);

export const placeId = async (creator, n) => (await H('place-id', creator, n)).slice(0, 8);

/** A base64url field of exactly `size` bytes, or null. */
function b64Field(obj, name, size) {
  if (typeof obj[name] !== 'string') return null;
  try {
    const b = b64uDecode(obj[name]);
    return b.length === size ? b : null;
  } catch (x) {
    if (x instanceof ParseError) return null;
    throw x;
  }
}

// The types whose sender rule needs roles, which a client with frozen private state doesn't know (§6.5).
const ROLE_RULES = new Set(['pause_req', 'pause_deny', 'place']);

/**
 * §7.6 step 15: the Kind and Sent by columns of §8.2 and the rules under the table.
 * `sender` = { member, device } from findDevice; `me` = the receiving device's ID.
 * Returns true, false, or 'hold' when the rule needs roles and this client's private state is
 * frozen: the envelope then waits until the client has caught up (§7.6).
 */
export async function senderMaySend(payload, kind, sender, state, me) {
  const t = payload.t;
  const allowed = KIND_MAY_SEND.get(sender.device.kind);
  if (allowed && !allowed.has(t)) return false;
  if ((CIRCLE_TYPES.has(t) && kind !== 1) || (DIRECT_TYPES.has(t) && kind !== 2)) return false;
  if (ROLE_RULES.has(t) && state.locked) return 'hold';
  const senderAcc = toHex(sender.member.account_id);
  switch (t) {
    case 'pause_req':
      return sender.member.role === 'teen';
    case 'pause_deny': {
      const teen = b64Field(payload, 'teen', 16);
      const m = teen && state.members.get(toHex(teen));
      return !!m && m.role === 'teen' && m.guardians.includes(senderAcc);
    }
    case 'welcome': {
      const mine = findDevice(state, me);
      return !!mine && mine.device.added_by === senderAcc;
    }
    case 'watch_grant': {
      const grant = b64Field(payload, 'grant', WATCH_GRANT_LEN);
      return !!grant && bytesEqual(parseWatchGrant(grant).watched_device_id, sender.device.device_id);
    }
    case 'ik': {
      const mine = findDevice(state, me);
      const seed = b64Field(payload, 'ik', 32);
      return !!mine && !!seed && toHex(mine.member.account_id) === senderAcc
        && bytesEqual(await ed25519PublicFromSeed(seed), sender.member.ik_pub);
    }
    case 'place': {
      const creator = b64Field(payload, 'creator', 16), n = b64Field(payload, 'n', 8), id = b64Field(payload, 'id', 8);
      if (!creator || !n || !id || !bytesEqual(id, await placeId(creator, n))) return false;
      return sender.member.role !== 'teen' || toHex(creator) === senderAcc;
    }
    default:
      return true;
  }
}

export const MAX_ENVELOPE_AGE_MS = 2678400000n; // 31 days (§7.6 step 8, expired)
export const MAX_CLOCK_AHEAD_MS = 86400000n;     // 1 day (§7.6 step 8, bad_time)
export const TTL_MIN_S = 60;
export const TTL_MAX_S = 2592000;

/**
 * A replay record (§7.6 step 9): Map "senderHex:seq" -> { sentAt, digest }. Pairs are recorded
 * only after every check passes and must be kept for at least 31 days after sent_at. A server
 * also keeps the SHA-256 of what it stored, because posting the same bytes again succeeds (§7.5).
 */
export const newReplayRecord = () => new Map();
export function pruneReplayRecord(replay, now) {
  for (const [k, v] of replay) if (BigInt(now) - v.sentAt > MAX_ENVELOPE_AGE_MS) replay.delete(k);
}

/** §7.6 steps 1-10, shared by receivers and servers. ctx = { state, now, replay }. */
async function envelopeSteps1to10(ctx, raw) {
  let v;
  try { v = parseEnvelope(raw); } catch (x) { if (x instanceof ParseError) return { error: 'malformed' }; throw x; }   // 1
  if (v.version !== 0 || v.suite !== SUITE) return { error: 'bad_version' };                                          // 2
  if (v.kind !== 1 && v.kind !== 2) return { error: 'bad_kind' };                                                     // 3
  if (!bytesEqual(v.circle_id, ctx.state.circle_id)) return { error: 'wrong_circle' };                                // 4
  const sender = findDevice(ctx.state, v.sender_device_id);                                                           // 5
  if (!sender || !isReceivingKind(sender.device.kind)) return { error: 'sender_not_active' };
  if (!await verify(sender.device.dsk_pub, 'envelope', v.signed, v.sig)) return { error: 'bad_signature' };           // 6
  if (!ctx.state.hashes.has(toHex(v.log_head))) return { error: 'unknown_log_head' };                                 // 7
  const now = BigInt(ctx.now ?? Date.now());                                                                          // 8
  if (now - v.sent_at > MAX_ENVELOPE_AGE_MS) return { error: 'expired' };
  if (v.sent_at - now > MAX_CLOCK_AHEAD_MS) return { error: 'bad_time' };
  const replayKey = `${toHex(v.sender_device_id)}:${v.seq}`;                                                          // 9
  if (ctx.replay.has(replayKey)) return { error: 'replay', v, replayKey };
  if (v.wraps.length < 1 || v.wraps.length > MAX_WRAPS || !wrapsAscending(v.wraps)) return { error: 'bad_wraps' };    // 10
  return { v, replayKey, sender };
}

/**
 * §7.6 Receive. ctx = { state (verified log state, with its private fields), now (ms, the
 * receiver's clock), deviceId, keys: Map keyIdHex -> {key, pub}, replay: Map from newReplayRecord() }.
 * Returns { ok: true, payload, payloadBytes, padded, envelope }, { ok: false, error }, or
 * { ok: false, held: true } for a payload that must wait for this client's private state.
 * Steps 5 and 7's "fetch new log entries first" is the caller's job.
 */
export async function receiveEnvelope(ctx, raw) {
  const fail = error => ({ ok: false, error });
  const pre = await envelopeSteps1to10(ctx, raw);
  if (pre.error) return fail(pre.error);
  const { v, replayKey, sender } = pre;
  const opened = await openWrap(v.wraps, ctx.deviceId, ctx.keys, w => envelopeWrapInfo(v.header, w.recipient_device_id, w.key_id));   // 11
  if (opened.error) return fail(opened.error);
  const { key, nonce } = await payloadKeys(opened.secret);
  const padded = await aeadOpen(key, nonce, v.ciphertext, await H('env-aad', v.throughWraps));   // 12
  if (!padded) return fail('bad_ciphertext');
  const payloadBytes = unpad(padded);                                                           // 13
  if (!payloadBytes) return fail('bad_padding');
  const payload = parsePayloadJSON(payloadBytes);                                               // 14
  if (!payload) return fail('bad_payload');
  const may = await senderMaySend(payload, v.kind, sender, ctx.state, ctx.deviceId);            // 15
  if (may === 'hold') return { ok: false, held: true };   // neither accepted nor refused: keep it and try again later
  if (!may) return fail('not_allowed');
  ctx.replay.set(replayKey, { sentAt: v.sent_at });
  return { ok: true, payload, payloadBytes, padded, envelope: v };
}

/**
 * §7.5 The server's checks before storing an envelope: §7.6 steps 1-10 with the server's own
 * clock and log; every wrap names a receiving device (bad_wraps); ttl_s in range (bad_ttl); and
 * for a circle envelope, a log head no older than the last change to the set of receiving
 * devices (stale_head) and a wrap for every one of them but the sender (bad_wraps).
 * Returns { ok: true, stored | duplicate } or { ok: false, error }. ctx = { state, now, replay }.
 */
export async function serverCheckEnvelope(ctx, raw) {
  const digest = toHex(await sha256(raw));
  const pre = await envelopeSteps1to10(ctx, raw);
  if (pre.error === 'replay' && ctx.replay.get(pre.replayKey).digest === digest) return { ok: true, duplicate: true };
  if (pre.error) return { ok: false, error: pre.error };
  const { v, replayKey } = pre;
  const receiving = new Set(receivingDevices(ctx.state).map(d => toHex(d.device_id)));
  const named = v.wraps.map(w => toHex(w.recipient_device_id));
  if (!named.every(id => receiving.has(id))) return { ok: false, error: 'bad_wraps' };
  if (v.ttl_s < TTL_MIN_S || v.ttl_s > TTL_MAX_S) return { ok: false, error: 'bad_ttl' };
  if (v.kind === 1) {
    if (ctx.state.hashes.get(toHex(v.log_head)) < ctx.state.receivingChangedSeq) return { ok: false, error: 'stale_head' };
    receiving.delete(toHex(v.sender_device_id));
    // exactly the receiving devices other than the sender
    if (named.length !== receiving.size || !named.every(id => receiving.has(id))) return { ok: false, error: 'bad_wraps' };
  }
  ctx.replay.set(replayKey, { sentAt: v.sent_at, digest });
  return { ok: true, stored: true, envelope: v };
}

// ---------------------------------------------------------------------------
// §8.3 Approximate positions
// ---------------------------------------------------------------------------

function floorDiv(a, b) {
  const q = a / b;
  return (a % b !== 0n && (a < 0n) !== (b < 0n)) ? q - 1n : q;
}

export function approxPosition(lat, lon) {
  const c = 200000n;
  let la = BigInt(lat);
  if (la > 899999999n) la = 899999999n;
  let lo = BigInt(lon);
  if (lo >= 1800000000n) lo -= 3600000000n;
  return { lat: Number(floorDiv(la, c) * c + c / 2n), lon: Number(floorDiv(lo, c) * c + c / 2n) };
}

// ---------------------------------------------------------------------------
// §9 Invites and joining
// ---------------------------------------------------------------------------

/** §2 "Codes": the bytes inside a scanned code such as "KFI0…". Throws ParseError. */
export function readCode(prefix, text) {
  if (typeof text !== 'string' || !text.startsWith(prefix)) throw new ParseError(`not a ${prefix} code`);
  return b64uDecode(text.slice(prefix.length));
}

function text16(r, what) {
  const s = decodeUtf8(r.vec16());
  if (s === null) throw new ParseError(`${what} is not UTF-8`);
  return s;
}

export function parseInvite(bytes) {
  const r = new Reader(bytes);
  const inv = { version: r.u8() };
  if (inv.version !== 0) throw new ParseError('unsupported invite version');
  Object.assign(inv, {
    server_url: text16(r, 'server_url'), server_key: r.bytes(32), circle_id: r.bytes(16), secret: r.bytes(16),
    inviter_ik_pub: r.bytes(32), expires_at: r.u64(), reg_token: r.vec16(), terms_salt: r.bytes(16),
  });
  const start = r.off;
  inv.terms = readMemberTerms(r);
  inv.terms_bytes = bytes.slice(start, r.off);
  inv.circle_name = text16(r, 'circle_name');
  inv.inviter_name = text16(r, 'inviter_name');
  const names = text16(r, 'guardian_names');
  inv.guardian_names = names === '' ? [] : names.split('\n');
  r.end();
  return inv;
}

export function serializeInvite(f) {
  return concat(u8(0), vec16(utf8(f.server_url)), f.server_key, f.circle_id, f.secret, f.inviter_ik_pub,
    u64(f.expires_at), vec16(f.reg_token), f.terms_salt, f.terms_bytes, vec16(utf8(f.circle_name)),
    vec16(utf8(f.inviter_name)), vec16(utf8(f.guardian_names.join('\n'))));
}

export const inviteId = async secret => (await H('invite-id', secret)).slice(0, 16);
export const joinKey = secret => KDF(secret, 'join-key', 32);
export const joinResultKey = secret => KDF(secret, 'join-result-key', 32);
export const inviteCode = invite => 'KFI0' + b64uEncode(invite);
/** `linkBase` is the one HTTPS origin built into the app (§9.1), never a family's own server. */
export const inviteLink = (linkBase, invite) => linkBase + '/join#' + b64uEncode(invite);

/** consent_sig = Sign(IK, "join-consent", circle_id ‖ invite_id ‖ cert ‖ bundle ‖ terms_commit) */
export const joinConsent = (ikSigner, circleId, invId, cert, bundle, commit) =>
  sign(ikSigner, 'join-consent', concat(circleId, invId, cert, bundle, commit));

export async function sealJoinRequest(secret, { cert, chain, bundle, terms_commit, consent_sig, name }, nonce = randomBytes(12)) {
  const head = concat(u8(0), await inviteId(secret));
  const pt = concat(cert, vec16(chain), bundle, terms_commit, consent_sig, vec16(utf8(name)));
  return concat(head, nonce, vec32(await aeadSeal(await joinKey(secret), nonce, pt, head)));
}

/** Decrypt and parse a JoinRequest with the invite secret. Throws ParseError on any failure. */
export async function openJoinRequest(bytes, secret) {
  const r = new Reader(bytes);
  if (r.u8() !== 0) throw new ParseError('unsupported join request version');
  const invite_id = r.bytes(16);
  const nonce = r.bytes(12);
  const ct = r.vec32();
  r.end();
  if (!bytesEqual(invite_id, await inviteId(secret))) throw new ParseError('invite_id does not match');
  const pt = await aeadOpen(await joinKey(secret), nonce, ct, bytes.slice(0, 17));
  if (!pt) throw new ParseError('join request does not decrypt');
  const p = new Reader(pt);
  const cert = p.bytes(CERT_LEN), chain = p.vec16(), bundle = p.bytes(BUNDLE_LEN);
  const terms_commit = p.bytes(32), consent_sig = p.bytes(64);
  const name = text16(p, 'name');
  p.end();
  parseChain(chain);
  return { invite_id, nonce, cert, chain, bundle, terms_commit, consent_sig, name };
}

/** What the inviter's device checks before showing Allow (§9.2). `invite` is its own parsed invite. */
export async function checkJoinRequest(jr, invite, now) {
  const cert = parseDeviceCert(jr.cert);
  const bundle = parseKeyBundle(jr.bundle);
  return {
    certValid: await deviceCertWellFormed(cert) && await chainProves(cert, parseChain(jr.chain)) && isPhoneOrTablet(cert.device_kind),
    bundleValid: await keyBundleValidFor(bundle, cert.dsk_pub, cert.account_id) && keyBundleCurrent(bundle, now),
    termsMatch: bytesEqual(jr.terms_commit, await termsCommit(invite.terms_salt, invite.terms_bytes)),
    consentValid: await verify(cert.ik_pub, 'join-consent',
      concat(invite.circle_id, jr.invite_id, jr.cert, jr.bundle, jr.terms_commit), jr.consent_sig),
    cert, bundle,
  };
}

// §9.3 Result
export const JOIN_ADDED = 1;
export const JOIN_DECLINED = 2;

export async function sealJoinResult(secret, outcome, head, nonce = randomBytes(12)) {
  const hdr = concat(u8(0), await inviteId(secret));
  return concat(hdr, nonce, vec32(await aeadSeal(await joinResultKey(secret), nonce, concat(u8(outcome), head), hdr)));
}

export async function openJoinResult(bytes, secret) {
  const r = new Reader(bytes);
  if (r.u8() !== 0) throw new ParseError('unsupported join result version');
  const invite_id = r.bytes(16), nonce = r.bytes(12), ct = r.vec32();
  r.end();
  if (!bytesEqual(invite_id, await inviteId(secret))) throw new ParseError('invite_id does not match');
  const pt = await aeadOpen(await joinResultKey(secret), nonce, ct, bytes.slice(0, 17));
  if (!pt) throw new ParseError('join result does not decrypt');
  const ok = pt.length === 33 && (pt[0] === JOIN_ADDED || (pt[0] === JOIN_DECLINED && isZero(pt.slice(1))));
  if (!ok) throw new ParseError('bad join result');
  return { outcome: pt[0], head: pt.slice(1), nonce };
}

// ---------------------------------------------------------------------------
// §10 Linking devices and recovery
// ---------------------------------------------------------------------------

export function parseLink(bytes) {
  const r = new Reader(bytes);
  const l = { version: r.u8(), direction: r.u8() };
  if (l.version !== 0) throw new ParseError('unsupported link version');
  if (l.direction !== 1 && l.direction !== 2) throw new ParseError('bad link direction');
  Object.assign(l, { server_url: text16(r, 'server_url'), server_key: r.bytes(32), secret: r.bytes(16), expires_at: r.u64() });
  if (l.direction === 1) { l.account_id = r.bytes(16); l.ik_pub = r.bytes(32); }
  r.end();
  return l;
}

export function serializeLink(l) {
  const base = concat(u8(0), u8(l.direction), vec16(utf8(l.server_url)), l.server_key, l.secret, u64(l.expires_at));
  return l.direction === 1 ? concat(base, l.account_id, l.ik_pub) : base;
}

export const linkId = async secret => (await H('link-id', secret)).slice(0, 16);
export const linkKey = secret => KDF(secret, 'link-key', 32);
export const linkConfirm = secret => KDF(secret, 'link-confirm', 16);
/** What the QR code holds. It is never a URL, and apps take it only from their own scanner (§10.1). */
export const linkCodeText = link => 'KFL0' + b64uEncode(link);
export const LINK_OFFER = 1;
export const LINK_REQUEST = 2;
export const LINK_COMMIT = 3;
export const LINK_NONCE = 4;

export async function sealLinkMessage(secret, msgType, plaintext, nonce = randomBytes(12)) {
  const head = concat(u8(0), await linkId(secret), u8(msgType));
  return concat(head, nonce, vec32(await aeadSeal(await linkKey(secret), nonce, plaintext, head)));
}

export async function openLinkMessage(bytes, secret) {
  const r = new Reader(bytes);
  if (r.u8() !== 0) throw new ParseError('unsupported link message version');
  const link_id = r.bytes(16);
  const msg_type = r.u8();
  const nonce = r.bytes(12);
  const ct = r.vec32();
  r.end();
  if (!bytesEqual(link_id, await linkId(secret))) throw new ParseError('link_id does not match');
  const plaintext = await aeadOpen(await linkKey(secret), nonce, ct, bytes.slice(0, 18));
  if (!plaintext) throw new ParseError('link message does not decrypt');
  return { link_id, msg_type, nonce, plaintext };
}

export function parseOffer(pt) {
  const r = new Reader(pt);
  const o = { account_id: r.bytes(16), ik_pub: r.bytes(32) };
  r.end();
  return o;
}

/** request body = dsk_pub ‖ u8 device_kind ‖ KeyBundle ‖ vec16 device_name */
export function parseLinkRequestBody(body) {
  const r = new Reader(body);
  const q = { dsk_pub: r.bytes(32), device_kind: r.u8(), bundle: r.bytes(BUNDLE_LEN) };
  q.device_name = text16(r, 'device name');
  r.end();
  return q;
}

/** What the new device posts first: H("link-commit", link_id ‖ r_new ‖ request body). */
export const linkCommit = (lid, rNew, body) => H('link-commit', lid, rNew, body);

/** code = u32(H("link-code", link_id ‖ r_old ‖ r_new ‖ request body)[0:4]) mod 1,000,000, 6 digits. */
export async function linkCode(lid, rOld, rNew, body) {
  const h = await H('link-code', lid, rOld, rNew, body);
  const v = ((h[0] << 24) >>> 0) + (h[1] << 16) + (h[2] << 8) + h[3];
  return String(v % 1000000).padStart(6, '0');
}

/**
 * §10.2 step 5, on the existing device: it holds the commit, has sent r_old, and now has the
 * request. Returns { ok: true, request, code } or { ok: false, error }.
 */
export async function checkLinkRequest({ secret, direction, accountId, commitMessage, rOld, requestMessage, now }) {
  const fail = error => ({ ok: false, error });
  let commit, req;
  try {
    commit = await openLinkMessage(commitMessage, secret);
    req = await openLinkMessage(requestMessage, secret);
  } catch (x) { if (x instanceof ParseError) return fail('unreadable'); throw x; }
  if (commit.msg_type !== LINK_COMMIT || req.msg_type !== LINK_REQUEST) return fail('wrong message type');
  if (commit.plaintext.length !== 32 || req.plaintext.length < 32) return fail('malformed');
  const lid = await linkId(secret);
  const rNew = req.plaintext.slice(0, 32), body = req.plaintext.slice(32);
  if (!bytesEqual(await linkCommit(lid, rNew, body), commit.plaintext)) return fail('request is not the one committed to');
  let request;
  try { request = parseLinkRequestBody(body); } catch (x) { if (x instanceof ParseError) return fail('malformed'); throw x; }
  const fits = direction === 1 ? isPhoneOrTablet(request.device_kind)
    : request.device_kind === KIND.WEB || request.device_kind === KIND.HOME_ASSISTANT;
  if (!fits) return fail('device kind does not fit the direction');
  const bundle = parseKeyBundle(request.bundle);
  if (!await keyBundleValidFor(bundle, request.dsk_pub, accountId) || !keyBundleCurrent(bundle, now)) return fail('bad bundle');
  return { ok: true, request, rNew, body, code: await linkCode(lid, rOld, rNew, body) };
}

export const linkResponseInfo = (lid, newDeviceId) => H('link-info', lid, newDeviceId);

/** Build a LinkResponse. `payload` is the JSON plaintext bytes; `ikmE` for test vectors only. */
export async function sealLinkResponse({ lid, senderCert, senderSigner, newDeviceId, newDekPub, payload, ikmE }) {
  const { enc, ct } = await hpkeSeal(newDekPub, await linkResponseInfo(lid, newDeviceId), payload, ikmE);
  const unsigned = concat(u8(0), lid, senderCert, enc, vec32(ct));
  return concat(unsigned, await sign(senderSigner, 'link-response', unsigned));
}

export function parseLinkResponse(bytes) {
  const r = new Reader(bytes);
  const v = { version: r.u8() };
  if (v.version !== 0) throw new ParseError('unsupported link response version');
  v.link_id = r.bytes(16);
  v.sender_cert = parseDeviceCert(r.bytes(CERT_LEN));
  v.enc = r.bytes(32);
  v.ct = r.vec32();
  v.sig = r.bytes(64);
  r.end();
  v.signed = bytes.slice(0, bytes.length - 64);
  return v;
}

/**
 * The new device's checks on a LinkResponse (§10.3). `me` = { dsk_pub, device_kind, dek: {key, pub} };
 * `expected` = { account_id, ik_pub } from the code (direction 1) or the offer (direction 2).
 * Returns { ok, failures: [...], payload, cert }.
 */
export async function openLinkResponse(bytes, secret, me, expected) {
  const failures = [];
  const v = parseLinkResponse(bytes);
  const lid = await linkId(secret);
  if (!bytesEqual(v.link_id, lid)) failures.push('link_id');
  if (!await deviceCertWellFormed(v.sender_cert) || !isPhoneOrTablet(v.sender_cert.device_kind)) failures.push('sender_cert invalid');
  if (!bytesEqual(v.sender_cert.ik_pub, expected.ik_pub) || !bytesEqual(v.sender_cert.account_id, expected.account_id)) failures.push('sender_cert identity key');
  if (!await verify(v.sender_cert.dsk_pub, 'link-response', v.signed, v.sig)) failures.push('signature');
  const myId = await deviceIdOf(me.dsk_pub);
  const pt = await hpkeOpen(v.enc, me.dek, await linkResponseInfo(lid, myId), v.ct);
  if (!pt) return { ok: false, failures: [...failures, 'does not decrypt'] };
  const payload = parsePayloadObject(pt);
  if (!payload) return { ok: false, failures: [...failures, 'payload JSON'] };
  let cert = null;
  try {
    if (!bytesEqual(b64uDecode(payload.confirm), await linkConfirm(secret))) failures.push('confirm');
    cert = parseDeviceCert(b64uDecode(payload.cert));
    if (!await deviceCertWellFormed(cert)) failures.push('cert invalid');
    if (!bytesEqual(cert.dsk_pub, me.dsk_pub) || cert.device_kind !== me.device_kind || !bytesEqual(cert.account_id, expected.account_id)
      || !bytesEqual(cert.ik_pub, expected.ik_pub)) failures.push('cert is not for this device and account');
    if (payload.ik !== undefined) {   // direction 1 only: the identity key and the chain that proves the account
      if (!await seedMatchesPublic(b64uDecode(payload.ik), expected.ik_pub)) failures.push('ik does not derive the identity key');
      if (!await chainProves(cert, parseChain(b64uDecode(payload.chain ?? '')))) failures.push('chain does not prove the account');
    }
    if (!Array.isArray(payload.circles)) failures.push('circles');
  } catch (x) {
    if (!(x instanceof ParseError)) throw x;
    failures.push('payload field: ' + x.message);
  }
  return { ok: failures.length === 0, failures, payload, cert, plaintext: pt };
}

function parsePayloadObject(bytes) {
  const text = decodeUtf8(bytes);
  if (text === null) return null;
  try {
    const o = JSON.parse(text);
    return o && typeof o === 'object' && !Array.isArray(o) ? o : null;
  } catch { return null; }
}

// §10.4 Recovery kit

export function parseRecoveryKit(bytes) {
  const r = new Reader(bytes);
  if (r.u8() !== 0) throw new ParseError('unsupported recovery kit version');
  const k = {
    server_url: text16(r, 'server_url'), server_key: r.bytes(32), account_id: r.bytes(16), ik_seed: r.bytes(32),
    chain: r.vec16(), recovery_dsk_seed: r.bytes(32), created_at: r.u64(),
  };
  r.end();
  k.links = parseChain(k.chain);
  return k;
}

export function serializeRecoveryKit(k) {
  return concat(u8(0), vec16(utf8(k.server_url)), k.server_key, k.account_id, k.ik_seed, vec16(k.chain),
    k.recovery_dsk_seed, u64(k.created_at));
}
/** Printed or written down; never kept on a phone, a server or a cloud drive (§10.4). */
export const recoveryCode = kit => 'KFR0' + b64uEncode(kit);

// ---------------------------------------------------------------------------
// §11 Safety codes
// ---------------------------------------------------------------------------

/** 30 digits from a public key: SHA-512 iterated under a label, as §11 and §13.1 do. */
async function keyDigits(purpose, key) {
  let h = concat(vec16(label(purpose)), key);
  for (let i = 0; i < 5200; i++) h = await sha512(concat(h, key));
  let out = '';
  for (let i = 0; i < 30; i += 5) {
    let v = 0n;
    for (const x of h.slice(i, i + 5)) v = (v << 8n) | BigInt(x);
    out += String(v % 100000n).padStart(5, '0');
  }
  return out;
}

/** 30 digits for one person's current identity key. */
export const safetyHalf = ikPub => keyDigits('safety', ikPub);

/** §13.1: the server key's fingerprint, six groups of five digits. */
export async function serverFingerprint(serverKey) {
  return (await keyDigits('server-fingerprint', serverKey)).match(/.{5}/g).join(' ');
}

/** 60 digits, shown as twelve groups of five; the same whichever key is "a". */
export async function safetyCode(a, b) {
  const [lo, hi] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
  const digits = (await safetyHalf(lo)) + (await safetyHalf(hi));
  return {
    digits,
    display: digits.match(/.{5}/g).join(' '),
    qr: 'KFV0' + b64uEncode(concat(u8(0), lo, hi)),
  };
}

// ---------------------------------------------------------------------------
// §12 Share links
// ---------------------------------------------------------------------------

export const shareLinkId = async secret => (await H('share-id', secret)).slice(0, 16);
export const shareKey = secret => KDF(secret, 'share-key', 32);
export const shareUrl = async (serverUrl, secret) =>
  serverUrl + '/s/' + b64uEncode(await shareLinkId(secret)) + '#' + b64uEncode(secret);

export async function sealShareUpdate(secret, { seq, expires_at }, payload, nonce = randomBytes(12)) {
  const head = concat(u8(0), await shareLinkId(secret), u64(seq), u64(expires_at));
  return concat(head, nonce, vec32(await aeadSeal(await shareKey(secret), nonce, pad(payload), head)));
}

export async function openShareUpdate(bytes, secret) {
  const r = new Reader(bytes);
  if (r.u8() !== 0) throw new ParseError('unsupported share update version');
  const link_id = r.bytes(16);
  const seq = r.u64();
  const expires_at = r.u64();
  const nonce = r.bytes(12);
  const ct = r.vec32();
  r.end();
  if (!bytesEqual(link_id, await shareLinkId(secret))) throw new ParseError('link_id does not match');
  const padded = await aeadOpen(await shareKey(secret), nonce, ct, bytes.slice(0, 33));
  if (!padded) throw new ParseError('share update does not decrypt');
  const payloadBytes = unpad(padded);
  if (!payloadBytes) throw new ParseError('bad padding');
  const payload = parsePayloadJSON(payloadBytes);
  if (!payload) throw new ParseError('bad payload');
  return { link_id, seq, expires_at, nonce, payload, payloadBytes };
}

// ---------------------------------------------------------------------------
// §13 Server identity and login
// ---------------------------------------------------------------------------

export function parseServerInfo(bytes) {
  const r = new Reader(bytes);
  const v = { version: r.u8() };
  if (v.version !== 0) throw new ParseError('unsupported server info version');
  v.server_url = decodeUtf8(r.vec16());
  if (v.server_url === null) throw new ParseError('server_url is not UTF-8');
  v.server_key = r.bytes(32);
  v.issued_at = r.u64();
  v.expires_at = r.u64();
  v.sig = r.bytes(64);
  r.end();
  v.signed = bytes.slice(0, bytes.length - 64);
  return v;
}

/** §13.1 client check against the trusted key and the URL it used. */
export async function checkServerInfo(bytes, trustedKey, urlUsed) {
  const v = parseServerInfo(bytes);
  return bytesEqual(v.server_key, trustedKey) && v.server_url === urlUsed
    && await verify(trustedKey, 'server-info', v.signed, v.sig);
}

export async function buildServerInfo(serverSigner, { server_url, issued_at, expires_at }) {
  const unsigned = concat(u8(0), vec16(utf8(server_url)), serverSigner.pub, u64(issued_at), u64(expires_at));
  return concat(unsigned, await sign(serverSigner, 'server-info', unsigned));
}

export const challengeData = (challenge, deviceId, expiresAt) => concat(challenge, deviceId, u64(expiresAt));
export const signChallenge = (serverSigner, challenge, deviceId, expiresAt) =>
  sign(serverSigner, 'auth-challenge', challengeData(challenge, deviceId, expiresAt));
export const verifyChallenge = (serverKey, challenge, deviceId, expiresAt, sig) =>
  verify(serverKey, 'auth-challenge', challengeData(challenge, deviceId, expiresAt), sig);
export const signLogin = (dskSigner, serverKey, challenge, deviceId) =>
  sign(dskSigner, 'auth', concat(serverKey, challenge, deviceId));
export const verifyLogin = (dskPub, serverKey, challenge, deviceId, sig) =>
  verify(dskPub, 'auth', concat(serverKey, challenge, deviceId), sig);

// §13.1 Setup code: how the first device on a server learns the server's key

export function parseSetup(bytes) {
  const r = new Reader(bytes);
  if (r.u8() !== 0) throw new ParseError('unsupported setup version');
  const s = { server_url: text16(r, 'server_url'), server_key: r.bytes(32), reg_token: r.vec16(), expires_at: r.u64() };
  r.end();
  return s;
}
export const serializeSetup = s => concat(u8(0), vec16(utf8(s.server_url)), s.server_key, vec16(s.reg_token), u64(s.expires_at));
export const setupCode = setup => 'KFS0' + b64uEncode(setup);

// §13.3 Moving a server or changing its key

export function parseServerMove(bytes) {
  const r = new Reader(bytes);
  if (r.u8() !== 0) throw new ParseError('unsupported server move version');
  const m = { old_url: text16(r, 'old_url'), old_key: r.bytes(32), new_url: text16(r, 'new_url'), new_key: r.bytes(32), issued_at: r.u64() };
  m.sig = r.bytes(64);
  r.end();
  m.signed = bytes.slice(0, bytes.length - 64);
  return m;
}

/** A client that trusts `trustedKey` at `trustedUrl` follows the notice only if this holds. */
export async function checkServerMove(bytes, trustedKey, trustedUrl) {
  const m = parseServerMove(bytes);
  return bytesEqual(m.old_key, trustedKey) && m.old_url === trustedUrl && await verify(trustedKey, 'server-move', m.signed, m.sig);
}

export async function buildServerMove(oldSigner, { old_url, new_url, new_key, issued_at }) {
  const unsigned = concat(u8(0), vec16(utf8(old_url)), oldSigner.pub, vec16(utf8(new_url)), new_key, u64(issued_at));
  return concat(unsigned, await sign(oldSigner, 'server-move', unsigned));
}

// ---------------------------------------------------------------------------
// §14 Silence watches, wake-ups and push
// ---------------------------------------------------------------------------

export const WATCH_GRANT_LEN = 131;
const GRANT_TBS_LEN = 67;
const GRANT_MAX_MS = 35n * 86400000n;
const GRANT_SKEW_MS = 600000n; // how far issued_at may run ahead of the server's clock

export function parseWatchGrant(bytes) {
  const r = new Reader(bytes);
  const g = { raw: bytes.slice(), version: r.u8(), circle_id: r.bytes(16), watched_device_id: r.bytes(16),
    watcher_account_id: r.bytes(16), after_min: r.u16(), issued_at: r.u64(), not_after: r.u64(), sig: r.bytes(64) };
  r.end();
  return g;
}

export async function buildWatchGrant(dskSigner, { circle_id, watched_device_id, watcher_account_id, after_min, issued_at, not_after }) {
  const body = concat(u8(0), circle_id, watched_device_id, watcher_account_id, u16(after_min), u64(issued_at), u64(not_after));
  return concat(body, await sign(dskSigner, 'watch-grant', body));
}

/** §14.1: may a watch be registered with this grant at time `now`, given the circle's log? */
export async function watchGrantValid(bytes, state, now) {
  let g;
  try { g = parseWatchGrant(bytes); } catch (x) { if (x instanceof ParseError) return false; throw x; }
  const f = findDevice(state, g.watched_device_id);
  const t = BigInt(now);
  return g.version === 0 && bytesEqual(g.circle_id, state.circle_id)
    && !!f && isPhoneOrTablet(f.device.kind)
    && state.members.has(toHex(g.watcher_account_id))
    && g.after_min >= 15 && g.after_min <= 1440
    && g.issued_at <= t + GRANT_SKEW_MS
    && t < g.not_after && g.issued_at < g.not_after && g.not_after <= g.issued_at + GRANT_MAX_MS
    && await verify(f.device.dsk_pub, 'watch-grant', bytes.slice(0, GRANT_TBS_LEN), g.sig);
}

// §14.2 Push messages

export const PUSH = Object.freeze({ WAKE: 1, RECORDS: 2, SILENCE: 3 });
export const PUSH_PLAIN = 2560;
export const PUSH_SEALED = 2616;
export const PUSH_BODY_MAX = 2483;
const PUSH_SKEW_MS = 600000n;

export async function buildPush(serverSigner, recipientDeviceId, type, sentAt, body) {
  if (body.length > PUSH_BODY_MAX) throw new RangeError('push body too long');
  const unsigned = concat(u8(0), u8(type), u64(sentAt), vec16(body));
  return concat(unsigned, await sign(serverSigner, 'push-sig', concat(recipientDeviceId, unsigned)));
}

export const pushInfo = (deviceId, keyId) => H('push', deviceId, keyId);

/** key_id ‖ enc ‖ ciphertext of the push padded to 2,560 bytes: always 2,616 bytes. `ikmE` for test vectors only. */
export async function sealPush(push, deviceId, dekPub, ikmE) {
  const kid = await keyIdOf(dekPub);
  const { enc, ct } = await hpkeSeal(dekPub, await pushInfo(deviceId, kid), padTo(push, PUSH_PLAIN), ikmE);
  return concat(kid, enc, ct);
}

/**
 * What a device does with a push (§14.2). `keys`: Map keyIdHex -> {key, pub}; `now`: its trusted
 * time (§8.4). Returns { ok: true, type, sent_at, … } or { ok: false, error }; a device drops
 * every push that is not ok.
 */
export async function openPush(sealed, deviceId, keys, serverKey, now) {
  const fail = error => ({ ok: false, error });
  if (sealed.length !== PUSH_SEALED) return fail('wrong size');
  const kid = sealed.slice(0, 8);
  const k = keys.get(toHex(kid));
  if (!k) return fail('unknown key');
  const padded = await hpkeOpen(sealed.slice(8, 40), k, await pushInfo(deviceId, kid), sealed.slice(40));
  if (!padded) return fail('does not decrypt');
  const push = unpadTo(padded, PUSH_PLAIN);
  if (!push) return fail('bad padding');
  try {
    const r = new Reader(push);
    const version = r.u8(), type = r.u8(), sent_at = r.u64(), body = r.vec16();
    const signed = push.slice(0, r.off);
    const sig = r.bytes(64);
    r.end();
    if (version !== 0) return fail('unsupported version');
    if (!await verify(serverKey, 'push-sig', concat(deviceId, signed), sig)) return fail('not signed by this device\'s server');
    const skew = sent_at - BigInt(now);
    if (skew > PUSH_SKEW_MS || skew < -PUSH_SKEW_MS) return fail('more than 10 minutes from trusted time');
    const out = { ok: true, type, sent_at, body };
    if (type === PUSH.WAKE) {
      if (body.length !== 0) return fail('a wake carries no body');
    } else if (type === PUSH.RECORDS) {
      const b = new Reader(body);
      out.records = [];
      while (b.off < body.length) {
        const rec = new Reader(b.vec32());
        out.records.push({ received_at: rec.u64(), envelope: rec.take(rec.buf.length - 8) });
      }
      if (out.records.length === 0) return fail('no records');
    } else if (type === PUSH.SILENCE) {
      const b = new Reader(body);
      Object.assign(out, { circle_id: b.bytes(16), watched_device_id: b.bytes(16), last_seen_at: b.u64() });
      b.end();
    } else {
      return fail('unknown type');
    }
    return out;
  } catch (x) {
    if (x instanceof ParseError) return fail('malformed');
    throw x;
  }
}

// §14.4 The iOS relay
export const RELAY_DELIVERY = Object.freeze({ alert: 1, background: 2, location: 3 });
const relayData = (capability, sealed, sentAt, delivery) => concat(capability, sealed, u64(sentAt), u8(delivery));
export const signRelayPush = (serverSigner, capability, sealed, sentAt, delivery) =>
  sign(serverSigner, 'relay-push', relayData(capability, sealed, sentAt, delivery));
/** What the relay checks before it forwards anything: the size, a known delivery type, and the server's signature. */
export const verifyRelayPush = async (serverKey, capability, sealed, sentAt, delivery, sig) =>
  sealed.length === PUSH_SEALED && Object.values(RELAY_DELIVERY).includes(delivery)
    && await verify(serverKey, 'relay-push', relayData(capability, sealed, sentAt, delivery), sig);
