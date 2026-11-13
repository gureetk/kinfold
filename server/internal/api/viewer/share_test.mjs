// SPDX-License-Identifier: AGPL-3.0-or-later

// Checks share.js against the vectors' share_link group, and that it refuses what it must.
// Run: node share_test.mjs path/to/kinfold-v0.json (internal/api runs it when node is found).

import { readFileSync } from 'node:fs';
import { b64uDecode, b64uEncode, linkId, shareKey, openUpdate, unpad } from './share.js';

const hex = s => Uint8Array.from(s.match(/../g) ?? [], h => parseInt(h, 16));
const toHex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
let failed = 0;
const check = (what, ok) => { if (!ok) { failed++; console.error('FAIL', what); } };
async function refuses(what, fn) {
  try { await fn(); check(what + ' is refused', false); } catch { check(what, true); }
}

const sl = JSON.parse(readFileSync(process.argv[2], 'utf8')).share_link;
const secret = hex(sl.secret);
const id = await linkId(secret);
const key = await shareKey(secret);
check('link_id', toHex(id) === sl.link_id);
check('share_key', toHex(key) === sl.share_key);
const [, fragment] = sl.url.split('#');
check('the url carries the secret', toHex(b64uDecode(fragment)) === sl.secret);
check('and the link ID', sl.url.includes('/s/' + b64uEncode(id) + '#'));

const msg = hex(sl.update.message);
const u = await openUpdate(key, id, msg);
check('seq', u.seq === BigInt(sl.update.seq));
check('expires_at', u.expiresAt === Number(sl.update.expires_at));
check('payload', JSON.stringify(u.payload) === new TextDecoder().decode(hex(sl.payload_bytes)));

const flip = (b, i) => { const c = b.slice(); c[i] ^= 1; return c; };
await refuses('a changed ciphertext', () => openUpdate(key, id, flip(msg, msg.length - 1)));
await refuses('a changed seq (aad)', () => openUpdate(key, id, flip(msg, 24)));
await refuses('another link', () => openUpdate(key, flip(id, 0), msg));
await refuses('a short update', () => openUpdate(key, id, msg.subarray(0, msg.length - 1)));
await refuses('another key', () => openUpdate(flip(key, 0), id, msg));
await refuses('padding of no bucket size', () => unpad(new Uint8Array(300)));
await refuses('padding without its 0x80', () => unpad(new Uint8Array(256)));
for (const bad of ['a', 'AA=', 'AB', 'A+/w', '-_-_-']) {
  await refuses(`base64url ${JSON.stringify(bad)}`, () => b64uDecode(bad));
}
check('base64url round trip', toHex(b64uDecode(b64uEncode(hex('00ff10e7')))) === '00ff10e7');

if (failed) {
  process.exit(1);
}
console.log('share.js: all checks pass');
