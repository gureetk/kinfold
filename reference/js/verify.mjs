#!/usr/bin/env node
// Checks spec/vectors/kinfold-v0.json against kinfold.mjs.
// Usage: node verify.mjs [path/to/kinfold-v0.json]
// A relative path is tried against the working directory, then the repository root, then this
// script's directory, so `node reference/js/verify.mjs spec/vectors/kinfold-v0.json` works from
// the repository root and from anywhere else.

import { readFile, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, isAbsolute, resolve } from 'node:path';
import * as K from './kinfold.mjs';

const { fromHex: X, toHex, bytesEqual, concat, utf8 } = K;

async function findVectors(arg) {
  const here = dirname(fileURLToPath(import.meta.url));
  const repoRoot = resolve(here, '../..');
  if (!arg) return resolve(repoRoot, 'spec/vectors/kinfold-v0.json');
  if (isAbsolute(arg)) return arg;
  for (const base of [process.cwd(), repoRoot, here]) {
    const p = resolve(base, arg);
    try { await access(p); return p; } catch { /* try the next base */ }
  }
  return resolve(process.cwd(), arg);
}
const vectorPath = await findVectors(process.argv[2]);
const V = JSON.parse(await readFile(vectorPath, 'utf8'));

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

const groups = new Map();
const notes = [];
let current = null;
function group(name) {
  if (!groups.has(name)) groups.set(name, { pass: 0, fail: 0, failures: [] });
  current = groups.get(name);
}
function check(name, ok, detail = '') {
  if (ok) current.pass++;
  else { current.fail++; current.failures.push(detail ? `${name}: ${detail}` : name); }
  return !!ok;
}
function norm(x) {
  if (x instanceof Uint8Array) return toHex(x);
  if (typeof x === 'bigint') return Number(x);
  if (Array.isArray(x)) return x.map(norm);
  if (x && typeof x === 'object') {
    const o = {};
    for (const k of Object.keys(x).sort()) o[k] = norm(x[k]);
    return o;
  }
  return x;
}
const canon = x => JSON.stringify(norm(x));
function diff(a, b, path = '$', out = []) {
  if (out.length >= 6) return out;
  const na = norm(a), nb = norm(b);
  if (JSON.stringify(na) === JSON.stringify(nb)) return out;
  if (na && nb && typeof na === 'object' && typeof nb === 'object' && Array.isArray(na) === Array.isArray(nb)) {
    const keys = new Set([...Object.keys(na), ...Object.keys(nb)]);
    for (const k of keys) diff(na[k], nb[k], `${path}.${k}`, out);
    return out;
  }
  const show = v => { const s = JSON.stringify(v); return s && s.length > 200 ? s.slice(0, 200) + '…' : s; };
  out.push(`${path}: got ${show(na)} want ${show(nb)}`);
  return out;
}
function checkEq(name, got, want) {
  const ok = canon(got) === canon(want);
  return check(name, ok, ok ? '' : diff(got, want).join('; '));
}
async function attempt(name, fn) {
  try { return await fn(); } catch (e) { check(name, false, 'threw ' + (e?.stack ?? e)); return undefined; }
}
function throws(fn) { try { fn(); return false; } catch { return true; } }

// ---------------------------------------------------------------------------
// Identities (also builds the key tables every later group uses)
// ---------------------------------------------------------------------------

const people = new Map();          // name -> person
const personOfAccount = new Map(); // account_id hex -> person
const devices = new Map();         // label -> device
const devicesById = new Map();     // device_id hex -> device
const dekByKeyId = new Map();      // key_id hex -> { sk, pub, key_id, device, imported }

/** The signer for one of a person's identity keys, past or current. */
const ikSignerFor = (person, ikPubHex) => person.ikSigners[person.ik_pubs.indexOf(ikPubHex)];
/** The person's identity chain as it stood when `ikPubHex` was their current key. */
const chainUpTo = (person, ikPubHex) => X(person.chain).slice(0, K.LINK_LEN * person.ik_pubs.indexOf(ikPubHex));

group('identities');
for (const [pname, p] of Object.entries(V.identities)) {
  const person = { name: pname, ...p, ikSigners: [] };
  people.set(pname, person);
  personOfAccount.set(p.account_id, person);
  await attempt(`${pname} identity keys`, async () => {
    checkEq(`${pname} one public key per seed`, p.ik_pubs.length, p.ik_seeds.length);
    for (const [i, seed] of p.ik_seeds.entries()) {
      checkEq(`${pname} ik_pubs[${i}] from ik_seeds[${i}]`, toHex(await K.ed25519PublicFromSeed(X(seed))), p.ik_pubs[i]);
      person.ikSigners.push(await K.importSigningKey(X(seed), X(p.ik_pubs[i])));
    }
    person.ikSigner = person.ikSigners.at(-1);
    checkEq(`${pname} ik_seed / ik_pub are the current (last) key`, [p.ik_seed, p.ik_pub], [p.ik_seeds.at(-1), p.ik_pubs.at(-1)]);
    // §4.2: the account ID comes from the first identity key and never changes.
    checkEq(`${pname} account_id = H(account-id, first identity key)`, toHex(await K.accountIdOf(X(p.ik_pubs[0]))), p.account_id);
    const links = K.parseChain(X(p.chain));
    checkEq(`${pname} chain has one link per rotation`, links.length, p.ik_seeds.length - 1);
    const rebuilt = [];
    for (const [i, l] of links.entries()) {
      checkEq(`${pname} link ${i} joins key ${i} to key ${i + 1}`, [l.old_ik_pub, l.new_ik_pub], [p.ik_pubs[i], p.ik_pubs[i + 1]]);
      check(`${pname} link ${i} valid`, await K.identityLinkValid(X(p.account_id), l));
      check(`${pname} link ${i} is not valid for another account`, !await K.identityLinkValid(X(p.account_id).fill(7, 0, 1), l));
      rebuilt.push(await K.buildIdentityLink(X(p.account_id), person.ikSigners[i], person.ikSigners[i + 1]));
    }
    checkEq(`${pname} chain rebuilt (both keys sign each link)`, toHex(concat(...rebuilt)), p.chain);
  });
  for (const [dname, d] of Object.entries(p.devices)) {
    const dev = { ...d, person };
    devices.set(d.label, dev);
    devicesById.set(d.device_id, dev);
    await attempt(`${d.label}`, async () => {
      checkEq(`${d.label} label`, d.label, `${pname}/${dname}`);
      checkEq(`${d.label} dsk_pub from dsk_seed`, toHex(await K.ed25519PublicFromSeed(X(d.dsk_seed))), d.dsk_pub);
      checkEq(`${d.label} device_id`, toHex(await K.deviceIdOf(X(d.dsk_pub))), d.device_id);
      dev.signer = await K.importSigningKey(X(d.dsk_seed), X(d.dsk_pub));

      const cert = K.parseDeviceCert(X(d.cert));
      checkEq(`${d.label} cert fields`,
        { version: cert.version, suite: cert.suite, account_id: cert.account_id, dsk_pub: cert.dsk_pub, kind: cert.device_kind, ik_pub: cert.ik_pub },
        { version: 0, suite: 1, account_id: p.account_id, dsk_pub: d.dsk_pub, kind: d.kind, ik_pub: p.ik_pub });
      check(`${d.label} cert well-formed`, await K.deviceCertWellFormed(cert));
      check(`${d.label} cert proves the account with the person's chain`, await K.chainProves(cert, K.parseChain(X(p.chain))));
      if (p.ik_seeds.length > 1) check(`${d.label} cert does not prove the account without the chain`, !await K.chainProves(cert, []));
      checkEq(`${d.label} cert rebuilt (Sign IK over first 60 bytes)`,
        toHex(await K.buildDeviceCert(person.ikSigner, { account_id: cert.account_id, device_kind: cert.device_kind, issued_at: cert.issued_at, dsk_pub: cert.dsk_pub })), d.cert);

      checkEq(`${d.label} bundles/deks count`, d.bundles.length, d.deks.length);
      // §4.1: a recovery device signs and never receives, so it has no encryption key.
      check(`${d.label} has an encryption key unless it is a recovery device`, (d.kind === K.KIND.RECOVERY) === (d.deks.length === 0));
      for (const [i, k] of d.deks.entries()) {
        checkEq(`${d.label} dek[${i}] pub from sk`, toHex(await K.x25519PublicFromPrivate(X(k.sk))), k.pub);
        checkEq(`${d.label} dek[${i}] key_id`, toHex(await K.keyIdOf(X(k.pub))), k.key_id);
        const imported = await K.importDecryptionKey(X(k.sk), X(k.pub));
        check(`${d.label} dek[${i}] JWK import`, !!imported);
        dekByKeyId.set(k.key_id, { ...k, device: dev, imported });
      }
      for (const [i, hexBundle] of d.bundles.entries()) {
        const b = K.parseKeyBundle(X(hexBundle));
        checkEq(`${d.label} bundle[${i}] fields`,
          { version: b.version, suite: b.suite, account_id: b.account_id, device_id: b.device_id, dek_pub: b.dek_pub },
          { version: 0, suite: 1, account_id: p.account_id, device_id: d.device_id, dek_pub: d.deks[i]?.pub });
        check(`${d.label} bundle[${i}] valid for device`, await K.keyBundleValidFor(b, X(d.dsk_pub), X(p.account_id)));
        checkEq(`${d.label} bundle[${i}] rebuilt`,
          toHex(await K.buildKeyBundle(dev.signer, { account_id: b.account_id, dek_pub: b.dek_pub, not_before: b.not_before,
            not_after: b.not_after, proto_max: b.proto_max, features: b.features })),
          hexBundle);
      }
    });
  }
}

async function keysFor(map) {
  // receiver key tables: key_id hex -> { key, pub }, imported through JWK
  const keys = new Map();
  for (const [kid, sk] of Object.entries(map)) {
    const pub = dekByKeyId.get(kid)?.pub ? X(dekByKeyId.get(kid).pub) : await K.x25519PublicFromPrivate(X(sk));
    keys.set(kid, await K.importDecryptionKey(X(sk), pub));
  }
  return keys;
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

group('primitives');
checkEq('label prefix', V.primitives.label_prefix, K.LABEL_PREFIX);
for (const t of V.primitives.H) checkEq(`H(${t.label})`, toHex(await K.hashLabeled(t.label, X(t.data))), t.out);
for (const t of V.primitives.kdf) checkEq(`KDF(${t.label}, ${t.length})`, toHex(await K.kdfLabeled(X(t.ikm), t.label, t.length)), t.out);
for (const t of V.primitives.sign) {
  await attempt('sign', async () => {
    const signer = await K.importSigningKey(X(t.seed));
    checkEq(`Sign(${t.label})`, toHex(await K.signLabeled(signer, t.label, X(t.data))), t.sig);
    check(`Verify(${t.label})`, await K.verifyLabeled(signer.pub, t.label, X(t.data), X(t.sig)));
    check('Verify rejects a modified message', !await K.verifyLabeled(signer.pub, t.label, X(t.data + '00'), X(t.sig)));
    // §3.3: S + L is the same signature with a non-canonical S and MUST be rejected.
    const sig = X(t.sig);
    let s = 0n;
    for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
    s += (1n << 252n) + 27742317777372353535851937790883648493n;
    const bad = sig.slice();
    for (let i = 32; i < 64; i++) { bad[i] = Number(s & 0xffn); s >>= 8n; }
    check('Verify rejects S >= L', !await K.verifyLabeled(signer.pub, t.label, X(t.data), bad));
  });
}
for (const t of V.primitives.b64u) {
  checkEq(`b64u encode ${t.bytes || '(empty)'}`, K.b64uEncode(X(t.bytes)), t.text);
  checkEq(`b64u decode ${JSON.stringify(t.text)}`, toHex(K.b64uDecode(t.text)), t.bytes);
}
for (const bad of ['-w==', '-w=', '-x', 'A', '+_8', '-/8', '-_8 ', 'AAAAA']) check(`b64u decoder rejects ${JSON.stringify(bad)}`, throws(() => K.b64uDecode(bad)));

// ---------------------------------------------------------------------------
// HPKE (RFC 9180 test case)
// ---------------------------------------------------------------------------

group('hpke_rfc9180');
await attempt('hpke', async () => {
  const h = V.hpke_rfc9180;
  checkEq('suite', [h.mode, h.kem_id, h.kdf_id, h.aead_id], [0, 0x20, 1, 2]);
  const kpE = await K.hpkeDeriveKeyPair(X(h.ikmE));
  checkEq('DeriveKeyPair(ikmE)', kpE, { sk: h.skEm, pk: h.pkEm });
  const kpR = await K.hpkeDeriveKeyPair(X(h.ikmR));
  checkEq('DeriveKeyPair(ikmR)', kpR, { sk: h.skRm, pk: h.pkRm });
  const ctxS = await K.hpkeSetupS(X(h.pkRm), X(h.info), X(h.ikmE));
  checkEq('SetupS enc / shared_secret / key / base_nonce',
    { enc: ctxS.enc, ss: ctxS.sharedSecret, key: ctxS.key, n: ctxS.baseNonce },
    { enc: h.enc, ss: h.shared_secret, key: h.key, n: h.base_nonce });
  const ctxR = await K.hpkeSetupR(X(h.enc), await K.importDecryptionKey(X(h.skRm), X(h.pkRm)), X(h.info));
  checkEq('SetupR shared_secret / key / base_nonce',
    { ss: ctxR.sharedSecret, key: ctxR.key, n: ctxR.baseNonce }, { ss: h.shared_secret, key: h.key, n: h.base_nonce });
  for (const [i, x] of h.encryptions.entries()) {
    checkEq(`encryption ${i} nonce`, toHex(K.hpkeNonce(ctxS.baseNonce, i)), x.nonce);
    checkEq(`encryption ${i} seal`, toHex(await K.hpkeContextSeal(ctxS, i, X(x.aad), X(x.pt))), x.ct);
    checkEq(`encryption ${i} open`, toHex(await K.hpkeContextOpen(ctxR, i, X(x.aad), X(x.ct)) ?? new Uint8Array()), x.pt);
  }
});

// ---------------------------------------------------------------------------
// Ed25519 and X25519 edge cases (§3.3, §3.5)
// ---------------------------------------------------------------------------

/** What this platform's Ed25519 says when handed the bytes directly, with none of §3.3's byte checks. */
async function platformVerify(pub, msg, sig) {
  try {
    const k = await globalThis.crypto.subtle.importKey('raw', pub, { name: 'Ed25519' }, true, ['verify']);
    return await globalThis.crypto.subtle.verify({ name: 'Ed25519' }, k, sig, msg);
  } catch {
    return false;
  }
}

group('ed25519');
{
  const lax = [];      // refused by §3.3, accepted by the platform alone
  const strict = [];   // accepted by the bare equation, refused by the platform alone
  for (const t of V.ed25519.signatures) {
    const [pub, msg, sig] = [X(t.pub), X(t.msg), X(t.sig)];
    checkEq(`${t.name} (${t.description})`, await K.verifyRaw(pub, msg, sig), t.valid);
    const bare = await platformVerify(pub, msg, sig);
    // Where the byte checks pass, the verdict is the library's own: no cofactor, k reduced mod L.
    if (t.valid) check(`${t.name}: the platform alone accepts it too`, bare);
    if (!t.valid && bare) lax.push(t.name);
    if (t.without_byte_checks && !bare) strict.push(t.name);
  }
  notes.push(`Ed25519 on this platform, without kinfold.mjs's byte checks: accepts ${lax.length} of the `
    + `${V.ed25519.signatures.filter(t => !t.valid).length} signatures §3.3 refuses`
    + (lax.length ? ` (${lax.join(', ')})` : '') + '. The byte checks in verifyRaw are what make every platform agree.');
  if (strict.length) notes.push(`It refuses on its own: ${strict.join(', ')}.`);
  for (const t of V.ed25519.keys) checkEq(`key ${t.pub.slice(0, 16)}… (${t.note}) invalid`, K.ed25519KeyInvalid(X(t.pub)), t.invalid);
  check('a key of the wrong length is invalid', K.ed25519KeyInvalid(new Uint8Array(31)) && K.ed25519KeyInvalid(new Uint8Array(33)));
}

group('x25519');
for (const t of V.x25519.keys) checkEq(`key ${t.pub.slice(0, 16)}… (${t.note}) invalid`, K.x25519KeyInvalid(X(t.pub)), t.invalid);
await attempt('x25519 low-order keys in HPKE', async () => {
  // §3.5: sealing to an invalid key must never be attempted; a bundle with one is not valid.
  const jordan = devices.get('jordan/phone');
  const good = K.parseKeyBundle(X(jordan.bundles[0]));
  for (const t of V.x25519.keys.filter(k => k.invalid)) {
    const forged = await K.buildKeyBundle(jordan.signer, { account_id: good.account_id, dek_pub: X(t.pub), not_before: good.not_before, not_after: good.not_after });
    check(`a correctly signed bundle with the key ${t.pub.slice(0, 16)}… (${t.note}) is not valid`,
      !await K.keyBundleValidFor(K.parseKeyBundle(forged), X(jordan.dsk_pub), good.account_id));
  }
});

// ---------------------------------------------------------------------------
// Log: main entries and cases, client mode and public (server) mode
// ---------------------------------------------------------------------------

const L = V.log;
const baseSecrets = new Map(Object.entries(L.epoch_secrets).map(([k, v]) => [Number(k), X(v)]));
// vectors/README.md: the public state is the state JSON without these private fields.
const PRIVATE_STATE_FIELDS = ['name', 'flags', 'private_unknown_from', 'state_hash'];
const PRIVATE_MEMBER_FIELDS = ['role', 'teen_until', 'guardians', 'rules', 'pauses'];
const without = (o, keys) => Object.fromEntries(Object.entries(o).filter(([k]) => !keys.includes(k)));
const publicSubset = st => ({
  ...without(st, PRIVATE_STATE_FIELDS),
  members: st.members.map(m => without(m, PRIVATE_MEMBER_FIELDS)),
});

/** The entry's framing and body, or null if it doesn't parse. */
function parseEntry(raw) {
  try {
    const e = K.parseEntryFraming(raw);
    return { e, b: K.parseEntryBody(e.type, e.body) };
  } catch (x) {
    if (x instanceof K.ParseError) return null;
    throw x;
  }
}

/** Decrypt an entry's details with the known epoch secrets (for details_plaintext checks). */
async function decryptDetails(raw, secrets) {
  const p = parseEntry(raw);
  if (!p || !p.b.details || !secrets.has(p.e.epoch)) return null;
  return K.openDetailsWith(secrets.get(p.e.epoch), p.e.header, p.b.details);
}

/**
 * Checks shared by main-log entries and case entries. `secrets` are what the client under test
 * holds (a case's withheld epochs removed); `allSecrets` also open withheld details for the
 * details_plaintext check. Returns the new {client, pub} states.
 */
async function checkEntry(tag, ent, states, secrets, allSecrets = secrets) {
  const raw = X(ent.raw);
  checkEq(`${tag} hash`, toHex(await K.entryHash(raw)), ent.hash);
  const rc = await K.processEntry(states.client, raw, { mode: 'client', secrets });
  const rp = await K.processEntry(states.pub, raw, { mode: 'public' });
  checkEq(`${tag} client outcome`, [rc.result, rc.reason], [ent.result, ent.reason]);
  if (rc.result !== 'fatal') check(`${tag} private state frozen exactly when deferred`, rc.privateUnknown === (ent.result === 'deferred'));
  checkEq(`${tag} public outcome`, [rp.result, rp.reason], [ent.public_result, ent.public_reason]);
  if (rc.result !== 'fatal') checkEq(`${tag} seq field`, Number(rc.entry.seq), ent.seq);
  const authorDev = devices.get(ent.author);
  if (rc.entry && authorDev) checkEq(`${tag} author field`, toHex(rc.entry.author), authorDev.device_id);
  if ('state_after' in ent) {
    checkEq(`${tag} client state_after`, K.stateToJSON(rc.state), ent.state_after);
    checkEq(`${tag} public state_after`, K.stateToJSON(rp.state, { publicOnly: true }), publicSubset(ent.state_after));
  }
  if (ent.result === 'fatal') {
    checkEq(`${tag} fatal leaves client state unchanged`, K.stateToJSON(rc.state), K.stateToJSON(states.client));
    checkEq(`${tag} fatal leaves public state unchanged`, K.stateToJSON(rp.state, { publicOnly: true }), K.stateToJSON(states.pub, { publicOnly: true }));
  }
  if ('details_plaintext' in ent) {
    // Details either open to details_plaintext, or don't open at all (then the outcome is bad_details).
    const pt = await attempt(`${tag} details decrypt`, () => decryptDetails(raw, allSecrets));
    if (pt === null) check(`${tag} details that don't open under the circle's key give bad_details`, ent.reason === 'bad_details' || ent.result === 'fatal');
    else if (pt !== undefined) checkEq(`${tag} details_plaintext`, toHex(pt), ent.details_plaintext);
  }
  const parsed = parseEntry(raw);
  if ('invite_secret' in ent && parsed) {
    checkEq(`${tag} invite_id = H(invite-id, invite_secret)`, toHex(await K.inviteId(X(ent.invite_secret))), ent.invite_id);
    checkEq(`${tag} body invite_id`, toHex(parsed.b.invite_id), ent.invite_id);
  }
  if ('terms_commit' in ent) {
    checkEq(`${tag} terms_commit = H(member-terms, terms_salt ‖ terms)`, toHex(await K.termsCommit(X(ent.terms_salt), X(ent.terms))), ent.terms_commit);
  }
  if ('new_epoch_secret' in ent && parsed && parsed.b.epoch_commit) {
    checkEq(`${tag} new_epoch = epoch + 1`, ent.new_epoch, parsed.e.epoch + 1);
    if (ent.result !== 'fatal') {
      checkEq(`${tag} epoch_commit`, toHex(await K.epochCommit(ent.new_epoch, X(ent.new_epoch_secret))), toHex(parsed.b.epoch_commit));
    }
  }
  return { client: rc.state, pub: rp.state, rc };
}

group('log');
const mainStates = []; // client/public state after each main entry
const preStates = [];  // client state before each main entry
{
  let states = { client: K.emptyState(), pub: K.emptyState() };
  for (const [i, ent] of L.entries.entries()) {
    preStates.push(states.client);
    checkEq(`entry ${i} seq`, ent.seq, i);
    check(`entry ${i} has a state_after`, 'state_after' in ent);
    const r = await attempt(`entry ${i}`, () => checkEntry(`entry ${i} (${ent.description})`, ent, states, baseSecrets));
    if (r) states = { client: r.client, pub: r.pub };
    mainStates.push(states);
  }
  const final = mainStates.at(-1).client;
  checkEq('final_seq', Number(final.seq), L.final_seq);
  checkEq('circle_id', toHex(final.circle_id), L.circle_id);
  for (const [ep, secret] of baseSecrets) {
    checkEq(`epoch ${ep} secret matches the log's commitment`,
      toHex(await K.epochCommit(ep, secret)), final.commits.get(ep) ? toHex(final.commits.get(ep)) : null);
  }
  checkEq('epoch_secrets cover every epoch', [...baseSecrets.keys()].sort(), [...final.commits.keys()].sort());
  // §6.9: the state hash two clients compare.
  const sh = L.state_hash;
  const at = mainStates[sh.log_seq].client;
  checkEq(`state bytes at seq ${sh.log_seq}`, toHex(K.stateBytes(at)), sh.state_bytes);
  checkEq(`state hash at seq ${sh.log_seq}`, toHex((await K.H('state-hash', K.stateBytes(at))).slice(0, 8)), sh.state_hash);
  checkEq('state hash is the one in state_after', sh.state_hash, L.entries[sh.log_seq].state_after.state_hash);
  check('the public (server) state carries no state hash', !('state_hash' in K.stateToJSON(mainStates[sh.log_seq].pub, { publicOnly: true })));
}

group('log cases');
const caseCounts = { fatal: 0, rejected: 0, accepted: 0, deferred: 0 };
const caseBases = {};
for (const c of L.cases) {
  await attempt(`case ${c.name}`, async () => {
    const allSecrets = new Map(baseSecrets);
    for (const [k, v] of Object.entries(c.new_epoch_secrets ?? {})) allSecrets.set(Number(k), X(v));
    // `withheld_epochs`: the client under test never received these secrets (§6.5).
    const secrets = new Map(allSecrets);
    for (const ep of c.withheld_epochs ?? []) secrets.delete(Number(ep));
    caseBases[c.base_seq] = (caseBases[c.base_seq] ?? 0) + 1;
    check(`case ${c.name} starts from an empty log, the base log or the whole log`, [-1, L.base_seq, L.final_seq].includes(c.base_seq));
    let states = c.base_seq === -1 ? { client: K.emptyState(), pub: K.emptyState() } : { ...mainStates[c.base_seq] };
    for (const [i, ent] of c.entries.entries()) {
      const r = await checkEntry(`case ${c.name} [${i}]`, ent, states, secrets, allSecrets);
      states = { client: r.client, pub: r.pub };
    }
    const last = c.entries.at(-1);
    caseCounts[last.result]++;
    check(`case ${c.name}: its last entry shows the state it leaves, unless that entry is fatal`, ('state_after' in last) === (last.result !== 'fatal'));
  });
}
checkEq('case counts by the outcome of the last entry (spec/vectors/README.md)', caseCounts, { fatal: 99, rejected: 21, accepted: 33, deferred: 1 });
checkEq('case counts by starting point: empty log, base log, whole log',
  [caseBases[-1], caseBases[L.base_seq], caseBases[L.final_seq]], [9, 96, 49]);

// ---------------------------------------------------------------------------
// Epoch wraps: every recipient opens its wrap and checks the commitment
// ---------------------------------------------------------------------------

group('epoch wraps');
const epochEntries = [
  ...L.entries.map((ent, i) => ({ tag: `entry ${i}`, ent })),
  ...L.cases.flatMap(c => c.entries.map((ent, i) => ({ tag: `case ${c.name} [${i}]`, ent }))),
].filter(x => 'new_epoch_secret' in x.ent && x.ent.result !== 'fatal');
for (const { tag, ent } of epochEntries) {
  await attempt(tag, async () => {
    const e = K.parseEntryFraming(X(ent.raw));
    const b = K.parseEntryBody(e.type, e.body);
    checkEq(`${tag} wrap recipients = wrap_ikm keys`, b.wraps.map(w => toHex(w.recipient_device_id)), Object.keys(ent.wrap_ikm).sort());
    for (const w of b.wraps) {
      const did = toHex(w.recipient_device_id);
      const dek = dekByKeyId.get(toHex(w.key_id));
      if (!check(`${tag} wrap for ${did}: key_id is one of that device's DEKs`, dek && dek.device.device_id === did)) continue;
      check(`${tag} no wrap goes to a recovery device`, dek.device.kind !== K.KIND.RECOVERY);
      const opened = await K.openWrap(b.wraps, w.recipient_device_id, new Map([[dek.key_id, dek.imported]]),
        x => K.epochWrapInfo(e.circle_id, e.seq, e.prev_hash, e.epoch + 1, x.recipient_device_id, x.key_id));
      checkEq(`${tag} ${dek.device.label} opens its wrap`, opened.secret ? toHex(opened.secret) : opened.error, ent.new_epoch_secret);
      if (opened.secret) {
        checkEq(`${tag} ${dek.device.label} secret matches epoch_commit`,
          toHex(await K.epochCommit(e.epoch + 1, opened.secret)), toHex(b.epoch_commit));
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Byte-exact rebuild of every main log entry (certificates and identity links re-signed from the
// seeds, details re-sealed with the nonce found in the entry, epoch wraps re-sealed from
// wrap_ikm, consent and signatures recomputed)
// ---------------------------------------------------------------------------

group('log rebuild (seal)');
/** Re-issue a certificate found in the log, under the identity key it names. */
async function reissue(cert) {
  const person = personOfAccount.get(toHex(cert.account_id));
  return K.buildDeviceCert(ikSignerFor(person, toHex(cert.ik_pub)),
    { account_id: cert.account_id, device_kind: cert.device_kind, issued_at: cert.issued_at, dsk_pub: cert.dsk_pub });
}
const rebuiltTypes = new Set();
for (const [i, ent] of L.entries.entries()) {
  await attempt(`rebuild entry ${i}`, async () => {
    const raw = X(ent.raw);
    const st = preStates[i];
    const e = K.parseEntryFraming(raw);
    const b = K.parseEntryBody(e.type, e.body);
    const author = devices.get(ent.author);
    const header = { type: e.type, circle_id: e.circle_id, seq: e.seq, prev_hash: e.prev_hash, created_at: e.created_at, author: X(author.device_id), epoch: e.epoch };
    const hdr = K.serializeEntryHeader(header);
    const reseal = async () => K.sealDetails(baseSecrets.get(e.epoch), hdr, X(ent.details_plaintext), b.details.slice(0, 12));
    const identityBundleFor = (dev, dekPub) => {
      const idx = dev.deks.findIndex(k => k.pub === toHex(dekPub));
      return X(dev.bundles[idx]);
    };
    const epochWraps = async required => K.sealWraps(
      required.map(d => ({ device_id: d.device_id, key_id: d.key_id, dek_pub: d.dek_pub, ikmE: X(ent.wrap_ikm[toHex(d.device_id)]) })),
      X(ent.new_epoch_secret),
      r => K.epochWrapInfo(e.circle_id, e.seq, e.prev_hash, e.epoch + 1, r.device_id, r.key_id));
    // Epoch secrets go to the receiving devices (kinds 1 to 4); a recovery device has no key.
    const receiving = K.receivingDevices(st);
    let nb;
    switch (e.type) {
      case K.ENTRY.GENESIS:
        nb = { founder_cert: await reissue(b.founder_cert), chain: chainUpTo(author.person, toHex(b.founder_cert.ik_pub)),
          founder_bundle: identityBundleFor(author, b.founder_bundle.dek_pub),
          epoch_commit: await K.epochCommit(0, baseSecrets.get(0)), details: await reseal() };
        break;
      case K.ENTRY.ADD_MEMBER: {
        const dev = devicesById.get(toHex(await K.deviceIdOf(b.cert.dsk_pub)));
        const ik = toHex(b.cert.ik_pub);
        const invId = await K.inviteId(X(ent.invite_secret));
        const cert = await reissue(b.cert), bundle = identityBundleFor(dev, b.bundle.dek_pub);
        const commit = await K.termsCommit(X(ent.terms_salt), X(ent.terms));
        checkEq(`entry ${i} details are terms_salt ‖ terms`, ent.details_plaintext, ent.terms_salt + ent.terms);
        nb = { cert, chain: chainUpTo(dev.person, ik), bundle, invite_id: invId, terms_commit: commit,
          consent_sig: await K.joinConsent(ikSignerFor(dev.person, ik), st.circle_id, invId, cert, bundle, commit),
          admin: b.admin, details: await reseal() };
        break;
      }
      case K.ENTRY.REMOVE_MEMBER:
        // A removal that starts no epoch (§6.4) carries a zero commitment and no wraps.
        nb = ent.new_epoch_secret
          ? { account_id: b.account_id, epoch_commit: await K.epochCommit(e.epoch + 1, X(ent.new_epoch_secret)),
            wraps: await epochWraps(receiving.filter(d => !bytesEqual(d.account_id, b.account_id))) }
          : { account_id: b.account_id, epoch_commit: new Uint8Array(32), wraps: [] };
        break;
      case K.ENTRY.ADD_DEVICE: {
        const dev = devicesById.get(toHex(await K.deviceIdOf(b.cert.dsk_pub)));
        nb = { cert: await reissue(b.cert), bundle: identityBundleFor(dev, b.bundle.dek_pub) };
        break;
      }
      case K.ENTRY.REMOVE_DEVICE:
        nb = ent.new_epoch_secret
          ? { device_id: b.device_id, epoch_commit: await K.epochCommit(e.epoch + 1, X(ent.new_epoch_secret)),
            wraps: await epochWraps(receiving.filter(d => !bytesEqual(d.device_id, b.device_id))) }
          : { device_id: b.device_id, epoch_commit: new Uint8Array(32), wraps: [] };
        break;
      case K.ENTRY.UPDATE_KEY:
        nb = { bundle: identityBundleFor(author, b.bundle.dek_pub) };
        break;
      case K.ENTRY.POLICY:
        nb = { details: await reseal() };
        break;
      case K.ENTRY.REKEY:
        nb = { epoch_commit: await K.epochCommit(e.epoch + 1, X(ent.new_epoch_secret)), wraps: await epochWraps(receiving) };
        break;
      case K.ENTRY.SET_ADMIN:
        nb = { account_id: b.account_id, admin: b.admin };
        break;
      case K.ENTRY.ADD_RECOVERY:
        nb = { cert: await reissue(b.cert) };
        break;
      case K.ENTRY.SET_OPTIONS:
        nb = { options: b.options };
        break;
      case K.ENTRY.ROTATE_IDENTITY: {
        const person = author.person;
        nb = { link: await K.buildIdentityLink(X(person.account_id), ikSignerFor(person, toHex(b.link.old_ik_pub)), ikSignerFor(person, toHex(b.link.new_ik_pub))) };
        break;
      }
    }
    rebuiltTypes.add(e.type);
    const rebuilt = await K.buildEntry(header, K.serializeEntryBody(e.type, nb), author.signer);
    checkEq(`entry ${i} (${ent.description}) rebuilt byte-for-byte`, toHex(rebuilt), ent.raw);
  });
}
checkEq('the main log uses, and this rebuilds, every entry type but REMOVE_MEMBER',
  [...rebuiltTypes].sort((a, b) => a - b), Object.values(K.ENTRY).filter(t => t !== K.ENTRY.REMOVE_MEMBER));

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

group('envelopes');
const NOW = V.envelopes.receiver_now;
const receiverCtx = async (logSeq, deviceId, keyMap) =>
  ({ state: mainStates[logSeq].client, now: NOW, deviceId: X(deviceId), keys: await keysFor(keyMap), replay: K.newReplayRecord() });
// The server works from the public state only.
const serverCtx = logSeq => ({ state: mainStates[logSeq].pub, now: NOW, replay: K.newReplayRecord() });
const outcome = r => (r.ok ? 'ok' : r.error);
// §7.5: a first post is stored; the same bytes again succeed as a duplicate.
const serverOutcome = r => (r.ok ? (r.duplicate ? 'duplicate' : 'stored') : r.error);
const typesSeen = new Set();
for (const ev of V.envelopes.valid) {
  await attempt(`envelope ${ev.name}`, async () => {
    const st = mainStates[ev.log_seq].client;
    checkEq(`${ev.name} stored by the server (§7.5)`, serverOutcome(await K.serverCheckEnvelope(serverCtx(ev.log_seq), X(ev.raw))), 'stored');
    const sender = devices.get(ev.sender);
    const env = K.parseEnvelope(X(ev.raw));
    checkEq(`${ev.name} header fields`,
      { kind: env.kind, circle: env.circle_id, sender: env.sender_device_id, seq: env.seq, sent_at: env.sent_at, ttl_s: env.ttl_s, head: env.log_head },
      { kind: ev.kind, circle: L.circle_id, sender: sender.device_id, seq: ev.seq, sent_at: ev.sent_at, ttl_s: ev.ttl_s, head: ev.log_head });
    const headSeq = st.hashes.get(ev.log_head);
    check(`${ev.name} log_head is an entry of the log at log_seq`, headSeq !== undefined);
    // §7.5: a circle envelope's head is no older than the last change to the set of receiving devices.
    if (ev.kind === 1) check(`${ev.name} circle envelope: log_head is current enough`, headSeq >= st.receivingChangedSeq);
    const wrapIds = env.wraps.map(w => toHex(w.recipient_device_id));
    checkEq(`${ev.name} wraps = recipients`, wrapIds, ev.recipients.map(r => r.device_id).sort());
    checkEq(`${ev.name} wraps = wrap_ikm keys`, wrapIds, Object.keys(ev.wrap_ikm).sort());
    if (ev.kind === 1) {
      checkEq(`${ev.name} circle envelope goes to every receiving device but the sender (§7.2)`, wrapIds,
        K.receivingDevices(st).map(d => toHex(d.device_id)).filter(id => id !== sender.device_id));
    }
    checkEq(`${ev.name} padded_length`, K.pad(X(ev.payload_bytes)).length, ev.padded_length);
    typesSeen.add(ev.payload.t);
    for (const rcp of ev.recipients) {
      checkEq(`${ev.name} recipient ${rcp.device} device_id`, devices.get(rcp.device)?.device_id, rcp.device_id);
      const res = await K.receiveEnvelope(await receiverCtx(ev.log_seq, rcp.device_id, rcp.keys), X(ev.raw));
      if (!check(`${ev.name} opened by ${rcp.device}`, res.ok, res.error)) continue;
      checkEq(`${ev.name} ${rcp.device} payload`, res.payload, ev.payload);
      checkEq(`${ev.name} ${rcp.device} payload bytes`, toHex(res.payloadBytes), ev.payload_bytes);
      checkEq(`${ev.name} ${rcp.device} padded length`, res.padded.length, ev.padded_length);
    }
    // Byte-exact rebuild (§3.5 "seal" check: fixed message secret and HPKE ephemeral keys).
    const recipients = env.wraps.map(w => {
      const f = K.findDevice(st, w.recipient_device_id);
      return { device_id: f.device.device_id, key_id: f.device.key_id, dek_pub: f.device.dek_pub, ikmE: X(ev.wrap_ikm[toHex(w.recipient_device_id)]) };
    });
    const rebuilt = await K.sealEnvelope({
      header: { kind: ev.kind, circle_id: X(L.circle_id), sender_device_id: X(sender.device_id), seq: ev.seq, sent_at: ev.sent_at, ttl_s: ev.ttl_s, log_head: X(ev.log_head) },
      recipients, payload: X(ev.payload_bytes), signer: sender.signer, messageSecret: X(ev.message_secret),
    });
    checkEq(`${ev.name} rebuilt byte-for-byte`, toHex(rebuilt), ev.raw);
  });
}
for (const ev of V.envelopes.invalid) {
  await attempt(`invalid envelope ${ev.name}`, async () => {
    const res = await K.receiveEnvelope(await receiverCtx(ev.log_seq, ev.receiver_device_id, ev.receiver_keys), X(ev.raw));
    checkEq(`invalid ${ev.name} (${ev.description})`, outcome(res), ev.error);
    checkEq(`invalid ${ev.name} receiver_device_id`, devices.get(ev.receiver)?.device_id, ev.receiver_device_id);
    // `server_error` is what a server answers (§7.5); null means it has no grounds to refuse and stores it.
    checkEq(`invalid ${ev.name}: server outcome`, serverOutcome(await K.serverCheckEnvelope(serverCtx(ev.log_seq), X(ev.raw))), ev.server_error ?? 'stored');
  });
}
await attempt('replay', async () => {
  const rp = V.envelopes.replay;
  const ctx = await receiverCtx(rp.log_seq, rp.receiver_device_id, rp.receiver_keys);
  const results = [];
  for (const raw of rp.sequence) results.push(outcome(await K.receiveEnvelope(ctx, X(raw))));
  checkEq('replay sequence', results, rp.results);
  // Retention (§7.6): the pair may be forgotten 31 days after sent_at, when step 8 refuses it anyway.
  const sentAt = Number(K.parseEnvelope(X(rp.sequence[0])).sent_at);
  const later = sentAt + Number(K.MAX_ENVELOPE_AGE_MS) + 1;
  K.pruneReplayRecord(ctx.replay, later);
  checkEq('after pruning, the old envelope is refused as expired', outcome(await K.receiveEnvelope({ ...ctx, now: later }, X(rp.sequence[0]))), 'expired');
});
await attempt('server_repost', async () => {
  // §7.5: posting is idempotent. The same bytes again are a success; other bytes under the same (sender, seq) are a replay.
  const rp = V.envelopes.server_repost;
  const sctx = serverCtx(rp.log_seq);
  const results = [];
  for (const raw of rp.sequence) results.push(serverOutcome(await K.serverCheckEnvelope(sctx, X(raw))));
  checkEq('server repost sequence', results, rp.results);
});
for (const ev of V.envelopes.server_rejects) {
  await attempt(`server_rejects ${ev.name}`, async () => {
    checkEq(`server_rejects ${ev.name} (${ev.description}): server`, serverOutcome(await K.serverCheckEnvelope(serverCtx(ev.log_seq), X(ev.raw))), ev.server_error);
    const res = await K.receiveEnvelope(await receiverCtx(ev.log_seq, ev.receiver_device_id, ev.receiver_keys), X(ev.raw));
    if (check(`server_rejects ${ev.name}: ${ev.receiver} still opens it`, res.ok, res.error)) {
      checkEq(`server_rejects ${ev.name}: payload`, res.payload, ev.payload);
    }
  });
}
await attempt('payload limits', async () => {
  // §8.1, by hand: the edges on both sides, independent of the vectors.
  const ok = o => K.parsePayloadJSON(utf8(typeof o === 'string' ? o : JSON.stringify(o))) !== null;
  const nest = n => { let v = 1; for (let i = 1; i < n; i++) v = { a: v }; return { t: 'x', v }; };
  check('8 levels are accepted and 9 refused', ok(nest(8)) && !ok(nest(9)));
  check('a 4,096-byte string is accepted and 4,097 refused', ok({ t: 'x', s: 'a'.repeat(4096) }) && !ok({ t: 'x', s: 'a'.repeat(4097) }));
  check('string length is counted in UTF-8 bytes', !ok({ t: 'x', s: 'é'.repeat(2049) }) && ok({ t: 'x', s: 'é'.repeat(2048) }));
  check('a key longer than 4,096 bytes is refused', !ok({ t: 'x', ['k'.repeat(4097)]: 1 }));
  check('a top-level avatar may hold 43,700 bytes, and no more', ok({ t: 'profile', avatar: 'A'.repeat(43700) }) && !ok({ t: 'profile', avatar: 'A'.repeat(43701) })
    && !ok({ t: 'profile', avatar: 'é'.repeat(21851) }));
  check('an avatar deeper down is an ordinary string', !ok({ t: 'profile', x: { avatar: 'A'.repeat(4097) } }));
  check('256 array items are accepted and 257 refused', ok({ t: 'x', a: new Array(256).fill(0) }) && !ok({ t: 'x', a: new Array(257).fill(0) }));
  check('whole numbers up to 2^53 - 1 either side of zero', ok('{"t":"x","n":9007199254740991}') && ok('{"t":"x","n":-9007199254740991}')
    && !ok('{"t":"x","n":9007199254740992}') && !ok('{"t":"x","n":-9007199254740992}'));
  check('1.0 and 1e3 are whole; 1.5 and 1e-1 are not', ok('{"t":"x","n":1.0}') && ok('{"t":"x","n":1e3}') && !ok('{"t":"x","n":1.5}') && !ok('{"t":"x","n":1e-1}'));
  check('true, false and null are allowed', ok('{"t":"x","a":true,"b":false,"c":null}'));
  check('an unpaired surrogate is refused, in a value, a key or an avatar',
    !ok('{"t":"x","s":"\\ud800"}') && !ok('{"t":"x","\\udc00":1}') && !ok('{"t":"profile","avatar":"\\ud800"}') && ok('{"t":"x","s":"\\ud83d\\ude00"}'));
  check('NaN and Infinity are not JSON', !ok('{"t":"x","n":NaN}') && !ok('{"t":"x","n":Infinity}'));
  check('the top level must be an object with a string "t"', !ok('[1]') && !ok('"x"') && !ok('{"t":1}') && !ok('{}') && ok('{"t":""}'));
});
checkEq('the valid envelopes carry every payload type of §8.2, a type nobody knows and the limits test',
  [...typesSeen].sort(),
  ['chat', 'checkin', 'evt', 'future_thing', 'hb', 'ik', 'loc', 'pause_deny', 'pause_req', 'place', 'profile', 'refresh',
    'refresh_req', 'sig', 'sos', 'test_limits', 'watch_grant', 'welcome']);

// ---------------------------------------------------------------------------
// Padding, approx, safety codes
// ---------------------------------------------------------------------------

group('padding');
for (const t of V.padding.valid) {
  const p = new Uint8Array(t.payload_length).fill(parseInt(t.payload_byte, 16));
  const padded = K.pad(p);
  checkEq(`pad(${t.payload_length}) length`, padded.length, t.padded_length);
  checkEq(`pad(${t.payload_length}) sha256`, toHex(await K.sha256(padded)), t.padded_sha256);
  checkEq(`unpad(pad(${t.payload_length}))`, toHex(K.unpad(padded) ?? new Uint8Array([0xde, 0xad])), toHex(p));
}
for (const t of V.padding.pad_to) {
  // §7.4 PadTo: a fixed size, used for log details (512) and pushes (2,560).
  const p = new Uint8Array(t.payload_length).fill(parseInt(t.payload_byte, 16));
  const padded = K.padTo(p, t.to);
  checkEq(`padTo(${t.payload_length}, ${t.to}) length`, padded.length, t.to);
  checkEq(`padTo(${t.payload_length}, ${t.to}) sha256`, toHex(await K.sha256(padded)), t.padded_sha256);
  checkEq(`unpadTo(padTo(${t.payload_length}, ${t.to}))`, toHex(K.unpadTo(padded, t.to) ?? new Uint8Array([0xde, 0xad])), toHex(p));
  check(`unpadTo(${t.to}) refuses another length`, K.unpadTo(concat(padded, new Uint8Array(1)), t.to) === null && K.unpadTo(padded.slice(0, -1), t.to) === null);
}
for (const t of V.padding.invalid) check(`unpad rejects: ${t.description}`, K.unpad(X(t.padded)) === null);
check('pad rejects 65,536 bytes', throws(() => K.pad(new Uint8Array(65536))));
check('padTo rejects a payload that leaves no room for the marker', throws(() => K.padTo(new Uint8Array(512), 512)) && !throws(() => K.padTo(new Uint8Array(511), 512)));

group('approx');
for (const t of V.approx) checkEq(`approx(${t.lat}, ${t.lon})`, K.approxPosition(t.lat, t.lon), { lat: t.approx_lat, lon: t.approx_lon });

group('safety_codes');
for (const t of V.safety_codes) {
  await attempt(`safety ${t.a}/${t.b}`, async () => {
    // §11: the code follows each person's current identity key.
    checkEq(`${t.a} ik_pub`, t.ik_pub_a, people.get(t.a).ik_pub);
    checkEq(`${t.b} ik_pub`, t.ik_pub_b, people.get(t.b).ik_pub);
    checkEq(`half(${t.a})`, await K.safetyHalf(X(t.ik_pub_a)), t.half_a);
    checkEq(`half(${t.b})`, await K.safetyHalf(X(t.ik_pub_b)), t.half_b);
    const ab = await K.safetyCode(X(t.ik_pub_a), X(t.ik_pub_b));
    const ba = await K.safetyCode(X(t.ik_pub_b), X(t.ik_pub_a));
    checkEq(`code(${t.a}, ${t.b})`, ab.display, t.code);
    checkEq(`code(${t.b}, ${t.a})`, ba.display, t.code);
    check(`code(${t.a}, ${t.b}) is 60 digits in twelve groups of five`, /^(\d{5} ){11}\d{5}$/.test(t.code) && ab.digits.length === 60);
    checkEq(`qr(${t.a}, ${t.b})`, ab.qr, t.qr);
    checkEq(`qr(${t.b}, ${t.a})`, ba.qr, t.qr);
    const [lo, hi] = [t.ik_pub_a, t.ik_pub_b].sort();
    checkEq(`qr(${t.a}, ${t.b}) holds version 0 and both keys, lower first`, toHex(K.readCode('KFV0', t.qr)), '00' + lo + hi);
  });
}

// ---------------------------------------------------------------------------
// Invite, join request and join result
// ---------------------------------------------------------------------------

group('invite');
await attempt('invite', async () => {
  const iv = V.invite;
  const bytes = X(iv.invite);
  const f = K.parseInvite(bytes);
  checkEq('invite fields', {
    server_url: f.server_url, server_key: f.server_key, circle_id: f.circle_id, secret: f.secret,
    inviter_ik_pub: f.inviter_ik_pub, expires_at: f.expires_at, reg_token: f.reg_token, terms_salt: f.terms_salt,
    terms: f.terms_bytes, circle_name: f.circle_name, inviter_name: f.inviter_name, guardian_names: f.guardian_names,
  }, iv.fields);
  // The terms travel in the invite, so the invitee sees what they are agreeing to before they join.
  checkEq('invite terms', { role: f.terms.role, teen_until: f.terms.teen_until, guardians: f.terms.guardians, rules: f.terms.rules }, iv.terms);
  checkEq('terms re-serialized', toHex(K.serializeMemberTerms(f.terms)), iv.fields.terms);
  check('one guardian name per guardian', f.guardian_names.length === f.terms.guardians.length);
  checkEq('invite re-serialized', toHex(K.serializeInvite(f)), iv.invite);
  checkEq('code', K.inviteCode(bytes), iv.code);
  checkEq('code read back', toHex(K.readCode('KFI0', iv.code)), iv.invite);
  check('a code with another prefix is refused', throws(() => K.readCode('KFL0', iv.code)));
  checkEq('link', K.inviteLink(iv.link_base, bytes), iv.link);
  check('the link is on the app\'s own origin, never the family\'s server', !iv.link.startsWith(f.server_url) && iv.link.startsWith(iv.link_base + '/join#'));
  checkEq('invite_id', toHex(await K.inviteId(f.secret)), iv.invite_id);
  checkEq('join_key', toHex(await K.joinKey(f.secret)), iv.join_key);
  checkEq('join_result_key', toHex(await K.joinResultKey(f.secret)), iv.join_result_key);
  checkEq('terms_commit', toHex(await K.termsCommit(f.terms_salt, f.terms_bytes)), iv.terms_commit);
  checkEq('invite circle_id is the log circle', toHex(f.circle_id), L.circle_id);
  checkEq('invite server_key is the server key', toHex(f.server_key), V.auth.server_key);

  const jrv = iv.join_request;
  const jr = await K.openJoinRequest(X(jrv.message), f.secret);
  checkEq('join request contents',
    { nonce: jr.nonce, cert: jr.cert, chain: jr.chain, bundle: jr.bundle, commit: jr.terms_commit, consent: jr.consent_sig, name: jr.name },
    { nonce: jrv.nonce, cert: jrv.cert, chain: jrv.chain, bundle: jrv.bundle, commit: iv.terms_commit, consent: jrv.consent, name: jrv.name });
  checkEq('join request invite_id', toHex(jr.invite_id), iv.invite_id);
  const c = await K.checkJoinRequest(jr, f, jrv.now);
  check('join request certificate well-formed, proves its account, from a phone or tablet', c.certValid);
  check('join request bundle valid for the certificate and current', c.bundleValid);
  check('join request commits to the terms in the invite', c.termsMatch);
  check('join request consent signature valid', c.consentValid);
  const other = { ...f, terms_bytes: K.serializeMemberTerms({ ...f.terms, teen_until: f.terms.teen_until + 1n }) };
  check('the same request against other terms is refused', !(await K.checkJoinRequest(jr, other, jrv.now)).termsMatch);
  const maya = people.get('maya');
  checkEq('consent recomputed with the invitee IK',
    toHex(await K.joinConsent(maya.ikSigner, f.circle_id, jr.invite_id, jr.cert, jr.bundle, jr.terms_commit)), jrv.consent);
  checkEq('join request rebuilt byte-for-byte',
    toHex(await K.sealJoinRequest(f.secret, { cert: jr.cert, chain: jr.chain, bundle: jr.bundle, terms_commit: jr.terms_commit, consent_sig: jr.consent_sig, name: jr.name }, jr.nonce)), jrv.message);

  // The log entry that adds Maya carries the same invite, terms commitment and consent.
  const ent = L.entries[iv.log_entry_seq];
  const e = K.parseEntryFraming(X(ent.raw));
  const b = K.parseEntryBody(e.type, e.body);
  checkEq(`log entry ${iv.log_entry_seq} is ADD_MEMBER with the same invite_id, terms_commit, consent, cert and bundle`,
    { type: e.type, invite_id: b.invite_id, commit: b.terms_commit, consent: b.consent_sig, cert: b.cert.raw, bundle: b.bundle.raw },
    { type: K.ENTRY.ADD_MEMBER, invite_id: iv.invite_id, commit: iv.terms_commit, consent: jrv.consent, cert: jrv.cert, bundle: jrv.bundle });
  checkEq(`log entry ${iv.log_entry_seq} invite_secret`, ent.invite_secret, iv.fields.secret);
  checkEq(`log entry ${iv.log_entry_seq} terms are the invite's`, [ent.terms_salt, ent.terms], [iv.fields.terms_salt, iv.fields.terms]);

  // §9.3: the inviter's device answers through the same mailbox.
  for (const [name, r] of Object.entries(iv.join_result)) {
    const got = await K.openJoinResult(X(r.message), f.secret);
    checkEq(`join result ${name}`, { outcome: got.outcome, head: got.head, nonce: got.nonce }, { outcome: r.outcome, head: r.head, nonce: r.nonce });
    checkEq(`join result ${name} rebuilt byte-for-byte`, toHex(await K.sealJoinResult(f.secret, r.outcome, X(r.head), X(r.nonce))), r.message);
  }
  checkEq('join result "added" carries the hash of the ADD_MEMBER entry', iv.join_result.added.head, ent.hash);
  checkEq('join result outcomes', [iv.join_result.added.outcome, iv.join_result.declined.outcome], [K.JOIN_ADDED, K.JOIN_DECLINED]);
  check('a join result is not readable with the join request key',
    await K.aeadOpen(await K.joinKey(f.secret), X(iv.join_result.added.nonce), X(iv.join_result.added.message).slice(33), X(iv.join_result.added.message).slice(0, 17)) === null);

  // §9.2 checks by the new member's client.
  checkEq('genesis hash gives the invite circle_id', toHex((await K.H('circle-id', X(L.entries[0].raw))).slice(0, 16)), toHex(f.circle_id));
  const authorAtAdd = K.findDevice(mainStates[iv.log_entry_seq - 1].client, e.author);
  checkEq('ADD_MEMBER authored by a device of inviter_ik_pub', authorAtAdd ? toHex(authorAtAdd.member.ik_pub) : null, toHex(f.inviter_ik_pub));
  const me = mainStates[iv.log_entry_seq].client.members.get(toHex(c.cert.account_id));
  checkEq('the log gives the new member exactly the terms of the invite',
    { role: me?.role, teen_until: me?.teen_until, guardians: me?.guardians, rules: me?.rules },
    { role: f.terms.role === 2 ? 'teen' : 'adult', teen_until: f.terms.teen_until, guardians: f.terms.guardians.map(toHex), rules: f.terms.rules });
});

// ---------------------------------------------------------------------------
// Device linking
// ---------------------------------------------------------------------------

group('device_link');
for (const vname of ['from_existing', 'from_new', 'from_existing_rotated']) {
  await attempt(`device_link.${vname}`, async () => {
    const D = V.device_link[vname];
    const T = s => `${vname}: ${s}`;
    const existing = devices.get(D.existing_device);
    const fresh = devices.get(D.new_device);
    const person = existing.person;
    const linkBytes = X(D.link);
    const link = K.parseLink(linkBytes);
    checkEq(T('link fields'),
      { direction: link.direction, secret: link.secret, server_key: link.server_key, server_url: link.server_url },
      { direction: D.direction, secret: D.secret, server_key: V.auth.server_key, server_url: V.auth.server_url });
    checkEq(T('link re-serialized'), toHex(K.serializeLink(link)), D.link);
    checkEq(T('code text'), K.linkCodeText(linkBytes), D.code_text);
    checkEq(T('code text read back'), toHex(K.readCode('KFL0', D.code_text)), D.link);
    check(T('the code is not a URL'), !/^[a-z][a-z0-9+.-]*:/i.test(D.code_text));
    checkEq(T('link_id'), toHex(await K.linkId(link.secret)), D.link_id);
    checkEq(T('link_key'), toHex(await K.linkKey(link.secret)), D.link_key);
    checkEq(T('link_confirm'), toHex(await K.linkConfirm(link.secret)), D.confirm);
    const lid = X(D.link_id);

    // Who the account is: in the code itself (direction 1), or in the existing device's offer (direction 2).
    let who;
    if (link.direction === 1) {
      who = { account_id: link.account_id, ik_pub: link.ik_pub };
      check(T('direction 1 has no offer'), !('offer' in D));
    } else {
      check(T('a direction 2 code names no account'), link.account_id === undefined && link.ik_pub === undefined);
      const offer = await K.openLinkMessage(X(D.offer), link.secret);
      checkEq(T('offer type / nonce'), { t: offer.msg_type, nonce: offer.nonce }, { t: K.LINK_OFFER, nonce: D.offer_nonce });
      who = K.parseOffer(offer.plaintext);
      checkEq(T('offer rebuilt byte-for-byte'), toHex(await K.sealLinkMessage(link.secret, K.LINK_OFFER, offer.plaintext, X(D.offer_nonce))), D.offer);
    }
    checkEq(T('account and identity key'), who, { account_id: D.account_id, ik_pub: D.ik_pub });
    checkEq(T('they are the existing device\'s account and its current identity key'), [D.account_id, D.ik_pub], [person.account_id, person.ik_pub]);

    // §10.2: commit, then the existing device's nonce, then the request. Neither side can steer the code.
    const messages = [
      ['commit', K.LINK_COMMIT, D.commit_message, D.commit_nonce, D.commit],
      ['nonce', K.LINK_NONCE, D.nonce_message, D.nonce_nonce, D.r_old],
      ['request', K.LINK_REQUEST, D.request, D.request_nonce, D.r_new + D.request_body],
    ];
    for (const [what, type, message, nonce, plaintext] of messages) {
      const m = await K.openLinkMessage(X(message), link.secret);
      checkEq(T(`${what} type / nonce / plaintext`), { t: m.msg_type, nonce: m.nonce, pt: m.plaintext }, { t: type, nonce, pt: plaintext });
      checkEq(T(`${what} rebuilt byte-for-byte`), toHex(await K.sealLinkMessage(link.secret, type, X(plaintext), X(nonce))), message);
    }
    checkEq(T('commit = H(link-commit, link_id ‖ r_new ‖ request body)'), toHex(await K.linkCommit(lid, X(D.r_new), X(D.request_body))), D.commit);
    checkEq(T('6-digit code'), await K.linkCode(lid, X(D.r_old), X(D.r_new), X(D.request_body)), D.code);
    check(T('the code depends on both nonces'),
      await K.linkCode(lid, X(D.r_new), X(D.r_old), X(D.request_body)) !== D.code || D.r_new === D.r_old);

    const chk = await K.checkLinkRequest({ secret: link.secret, direction: link.direction, accountId: who.account_id,
      commitMessage: X(D.commit_message), rOld: X(D.r_old), requestMessage: X(D.request), now: D.now });
    if (!check(T('the existing device accepts the request'), chk.ok, chk.error)) return;
    checkEq(T('the existing device computes the same code'), chk.code, D.code);
    const rq = chk.request;
    checkEq(T('request names the new device'), { dsk_pub: rq.dsk_pub, kind: rq.device_kind, name: rq.device_name },
      { dsk_pub: fresh.dsk_pub, kind: fresh.kind, name: D.device_name });
    check(T('request bundle is one of the new device\'s bundles'), fresh.bundles.includes(toHex(rq.bundle)));
    check(T('the kind fits the direction: phones and tablets scan, browsers and Home Assistant show'),
      link.direction === 1 ? K.isPhoneOrTablet(rq.device_kind) : rq.device_kind === K.KIND.WEB || rq.device_kind === K.KIND.HOME_ASSISTANT);

    const dekPub = await K.x25519PublicFromPrivate(X(D.new_device_dek_sk));
    checkEq(T('new_device_dek_sk is the key in the request bundle'), toHex(dekPub), toHex(K.parseKeyBundle(rq.bundle).dek_pub));
    const me = { dsk_pub: rq.dsk_pub, device_kind: rq.device_kind, dek: await K.importDecryptionKey(X(D.new_device_dek_sk), dekPub) };
    const res = await K.openLinkResponse(X(D.response), link.secret, me, who);
    check(T('response passes the new device\'s checks'), res.ok, res.failures.join(', '));
    checkEq(T('response plaintext = response_payload'), res.plaintext ? new TextDecoder().decode(res.plaintext) : null, D.response_payload);
    const resp = K.parseLinkResponse(X(D.response));
    checkEq(T('sender_cert is the existing device\'s certificate'), toHex(resp.sender_cert.raw), existing.cert);
    checkEq(T('response cert is the new device\'s certificate'), res.cert ? toHex(res.cert.raw) : null, fresh.cert);
    if (link.direction === 1) {
      // A phone or tablet gets the identity key, and the chain that ties it to the account ID.
      checkEq(T('response carries the identity key seed'), res.payload?.ik === undefined ? null : toHex(K.b64uDecode(res.payload.ik)), person.ik_seed);
      checkEq(T('response carries the identity chain'), res.payload?.chain === undefined ? null : toHex(K.b64uDecode(res.payload.chain)), person.chain);
    } else {
      check(T('response carries no identity key (web and Home Assistant never hold it)'), !!res.payload && !('ik' in res.payload) && !('chain' in res.payload));
    }
    // "fetches each circle's log, finds its ADD_DEVICE entry and checks each epoch secret against the log"
    const circles = res.payload?.circles ?? [];
    checkEq(T('response lists the one circle'), circles.map(c => toHex(K.b64uDecode(c.id))), [L.circle_id]);
    const addIdx = L.entries.findIndex(en => {
      const p = parseEntry(X(en.raw));
      return p.e.type === K.ENTRY.ADD_DEVICE && toHex(p.b.cert.raw) === fresh.cert && toHex(p.b.bundle.raw) === toHex(rq.bundle);
    });
    if (check(T('the log has the ADD_DEVICE entry with this cert and the request bundle'), addIdx >= 0)) {
      const at = mainStates[addIdx].client;
      for (const c of circles) {
        for (const [ep, s] of c.epochs.entries()) {
          checkEq(T(`epoch ${ep} secret from the response matches the log`), toHex(await K.epochCommit(ep, K.b64uDecode(s))), at.commits.get(ep) ? toHex(at.commits.get(ep)) : null);
        }
        checkEq(T('response has every epoch up to the ADD_DEVICE entry'), c.epochs.length, at.epoch + 1);
      }
    }
    const rebuilt = await K.sealLinkResponse({
      lid, senderCert: X(existing.cert), senderSigner: existing.signer, newDeviceId: X(fresh.device_id),
      newDekPub: dekPub, payload: utf8(D.response_payload), ikmE: X(D.response_ikm),
    });
    checkEq(T('response rebuilt byte-for-byte'), toHex(rebuilt), D.response);
    // The same response is refused by a device expecting another identity key.
    const wrong = await K.openLinkResponse(X(D.response), link.secret, me, { account_id: who.account_id, ik_pub: X(people.get('maya').ik_pub) });
    check(T('response refused when the identity key is not the expected one'), !wrong.ok);
  });
}
for (const t of V.device_link.refused) {
  await attempt(`device_link refused ${t.name}`, async () => {
    const r = await K.checkLinkRequest({ secret: X(t.secret), direction: t.direction, accountId: X(t.account_id),
      commitMessage: X(t.commit_message), rOld: X(t.r_old), requestMessage: X(t.request), now: t.now });
    check(`refused: ${t.name} (${t.description})`, !r.ok);
  });
}

// ---------------------------------------------------------------------------
// Recovery kits, setup codes, server moves
// ---------------------------------------------------------------------------

group('recovery_kits');
for (const t of V.recovery_kits) {
  await attempt(`recovery kit ${t.owner}`, async () => {
    const owner = people.get(t.owner);
    const bytes = K.readCode('KFR0', t.code);
    checkEq(`${t.owner} code holds the kit`, toHex(bytes), t.kit);
    checkEq(`${t.owner} code`, K.recoveryCode(X(t.kit)), t.code);
    const kit = K.parseRecoveryKit(bytes);
    checkEq(`${t.owner} kit fields`,
      { server_url: kit.server_url, server_key: kit.server_key, account_id: kit.account_id, ik_seed: kit.ik_seed, chain: kit.chain,
        recovery_dsk_seed: kit.recovery_dsk_seed, created_at: kit.created_at },
      { server_url: V.auth.server_url, server_key: V.auth.server_key, account_id: t.account_id, ik_seed: t.ik_seed, chain: t.chain,
        recovery_dsk_seed: t.recovery_dsk_seed, created_at: t.created_at });
    checkEq(`${t.owner} kit re-serialized`, toHex(K.serializeRecoveryKit(kit)), t.kit);
    checkEq(`${t.owner} kit is the owner's account, current identity key and chain`, [t.account_id, t.ik_seed, t.chain], [owner.account_id, owner.ik_seed, owner.chain]);
    const recoveryPub = await K.ed25519PublicFromSeed(kit.recovery_dsk_seed);
    checkEq(`${t.owner} recovery device ID`, toHex(await K.deviceIdOf(recoveryPub)), t.recovery_device_id);
    // What the kit is for: with nothing else, its holder can certify a new phone that the log will accept.
    const ik = await K.importSigningKey(kit.ik_seed);
    const cert = K.parseDeviceCert(await K.buildDeviceCert(ik, { account_id: kit.account_id, device_kind: K.KIND.PHONE, issued_at: kit.created_at, dsk_pub: recoveryPub }));
    check(`${t.owner} a certificate made from the kit is well-formed and proves the account`, await K.deviceCertWellFormed(cert) && await K.chainProves(cert, kit.links));
  });
}
await attempt('recovery kit in the log', async () => {
  const jr = devices.get('jordan/recovery');
  const kit = V.recovery_kits.find(k => k.owner === 'jordan');
  checkEq('Jordan\'s kit holds the recovery device of the log', [kit.recovery_device_id, kit.recovery_dsk_seed], [jr.device_id, jr.dsk_seed]);
  const f = K.findDevice(mainStates[L.final_seq].client, X(jr.device_id));
  check('it is active in the final state, as kind 5 with no encryption key', !!f && f.device.kind === K.KIND.RECOVERY && f.device.key_id === null);
});

group('setup');
await attempt('setup', async () => {
  const su = V.setup;
  const bytes = K.readCode('KFS0', su.code);
  checkEq('code holds the setup bytes', toHex(bytes), su.setup);
  checkEq('code', K.setupCode(X(su.setup)), su.code);
  const s = K.parseSetup(bytes);
  checkEq('setup fields', { server_url: s.server_url, server_key: s.server_key, reg_token: s.reg_token, expires_at: s.expires_at },
    { server_url: su.server_url, server_key: su.server_key, reg_token: su.reg_token, expires_at: su.expires_at });
  checkEq('setup re-serialized', toHex(K.serializeSetup(s)), su.setup);
  checkEq('setup names the server of these vectors', [su.server_url, su.server_key], [V.auth.server_url, V.auth.server_key]);
});

group('server_moves');
for (const t of V.server_moves) {
  await attempt(`server move ${t.name}`, async () => {
    const m = K.parseServerMove(X(t.move));
    checkEq(`${t.name} fields`, { old_url: m.old_url, old_key: m.old_key, new_url: m.new_url, new_key: m.new_key, issued_at: m.issued_at },
      { old_url: t.old_url, old_key: t.old_key, new_url: t.new_url, new_key: t.new_key, issued_at: t.issued_at });
    // §13.3: followed only when the key the client already trusts signed it.
    checkEq(`${t.name} (${t.description}) accepted by a client that trusts the old key`,
      await K.checkServerMove(X(t.move), X(V.auth.server_key), V.auth.server_url), t.valid);
    check(`${t.name} refused by a client that trusts another key`, !await K.checkServerMove(X(t.move), X(t.new_key === t.old_key ? people.get('jordan').ik_pub : t.new_key), V.auth.server_url));
    check(`${t.name} refused by a client that used another URL`, !await K.checkServerMove(X(t.move), X(V.auth.server_key), t.new_url));
    if (t.valid) {
      const server = await K.importSigningKey(X(V.auth.server_seed));
      checkEq(`${t.name} rebuilt`, toHex(await K.buildServerMove(server, { old_url: t.old_url, new_url: t.new_url, new_key: X(t.new_key), issued_at: t.issued_at })), t.move);
    }
  });
}

// ---------------------------------------------------------------------------
// Share link
// ---------------------------------------------------------------------------

group('share_link');
await attempt('share_link', async () => {
  const sl = V.share_link;
  const secret = X(sl.secret);
  checkEq('link_id', toHex(await K.shareLinkId(secret)), sl.link_id);
  checkEq('share_key', toHex(await K.shareKey(secret)), sl.share_key);
  checkEq('url', await K.shareUrl(sl.server_url, secret), sl.url);
  const u = await K.openShareUpdate(X(sl.update.message), secret);
  checkEq('update fields', { seq: u.seq, expires_at: u.expires_at, nonce: u.nonce }, { seq: sl.update.seq, expires_at: sl.update.expires_at, nonce: sl.update.nonce });
  checkEq('update payload bytes', toHex(u.payloadBytes), sl.payload_bytes);
  checkEq('update payload', u.payload, sl.update.payload);
  checkEq('payload is a loc object plus name', u.payload.t, 'loc');
  checkEq('update rebuilt byte-for-byte',
    toHex(await K.sealShareUpdate(secret, { seq: sl.update.seq, expires_at: sl.update.expires_at }, X(sl.payload_bytes), X(sl.update.nonce))),
    sl.update.message);
});

// ---------------------------------------------------------------------------
// Server identity and login
// ---------------------------------------------------------------------------

group('auth');
await attempt('auth', async () => {
  const a = V.auth;
  const serverKey = X(a.server_key);
  checkEq('server_key from server_seed', toHex(await K.ed25519PublicFromSeed(X(a.server_seed))), a.server_key);
  const server = await K.importSigningKey(X(a.server_seed), serverKey);
  const info = K.parseServerInfo(X(a.server_info));
  checkEq('server_info fields', { url: info.server_url, key: info.server_key }, { url: a.server_url, key: a.server_key });
  check('server_info issued_at < expires_at', info.issued_at < info.expires_at);
  check('server_info verifies against the trusted key and URL', await K.checkServerInfo(X(a.server_info), serverKey, a.server_url));
  check('server_info rejected for another URL', !await K.checkServerInfo(X(a.server_info), serverKey, a.server_url + '/'));
  check('server_info rejected for another key', !await K.checkServerInfo(X(a.server_info), X(people.get('jordan').ik_pub), a.server_url));
  checkEq('server_info rebuilt', toHex(await K.buildServerInfo(server, { server_url: info.server_url, issued_at: info.issued_at, expires_at: info.expires_at })), a.server_info);
  const dev = devices.get(a.device);
  checkEq('device_id', a.device_id, dev.device_id);
  check('challenge_sig verifies', await K.verifyChallenge(serverKey, X(a.challenge), X(a.device_id), a.expires_at, X(a.challenge_sig)));
  checkEq('challenge_sig recomputed', toHex(await K.signChallenge(server, X(a.challenge), X(a.device_id), a.expires_at)), a.challenge_sig);
  check('device_sig verifies', await K.verifyLogin(X(dev.dsk_pub), serverKey, X(a.challenge), X(a.device_id), X(a.device_sig)));
  checkEq('device_sig recomputed', toHex(await K.signLogin(dev.signer, serverKey, X(a.challenge), X(a.device_id))), a.device_sig);
  check('device_sig does not verify for another server key', !await K.verifyLogin(X(dev.dsk_pub), X(people.get('jordan').ik_pub), X(a.challenge), X(a.device_id), X(a.device_sig)));
});

// ---------------------------------------------------------------------------
// Silence watches, pushes and the relay signature (§14)
// ---------------------------------------------------------------------------

group('watch_grants');
await attempt('watch_grants', async () => {
  const W = V.watch_grants;
  // A server judges a grant from the public log alone.
  const st = mainStates[W.log_seq].pub;
  for (const t of W.grants) {
    checkEq(`${t.name} length`, X(t.grant).length, K.WATCH_GRANT_LEN);
    checkEq(`${t.name} (${t.description})`, await K.watchGrantValid(X(t.grant), st, W.now), t.valid);
  }
  const g = K.parseWatchGrant(X(W.grants[0].grant));
  checkEq('fields of the first grant',
    { circle_id: g.circle_id, watched_device_id: g.watched_device_id, watcher_account_id: g.watcher_account_id, after_min: g.after_min, not_after: g.not_after },
    W.fields);
  const watched = devicesById.get(W.fields.watched_device_id);
  checkEq('the first grant rebuilt with the watched device\'s key',
    toHex(await K.buildWatchGrant(watched.signer, { circle_id: g.circle_id, watched_device_id: g.watched_device_id,
      watcher_account_id: g.watcher_account_id, after_min: g.after_min, not_after: g.not_after })), W.grants[0].grant);
  check('a grant that is cut short is not valid', !await K.watchGrantValid(X(W.grants[0].grant).slice(0, -1), st, W.now));
  check('the first grant stops being valid at not_after', await K.watchGrantValid(X(W.grants[0].grant), st, W.fields.not_after - 1)
    && !await K.watchGrantValid(X(W.grants[0].grant), st, W.fields.not_after));
});

group('push');
await attempt('push', async () => {
  const P = V.push;
  const serverKey = X(P.server_key);
  checkEq('server_key is the server of these vectors', P.server_key, V.auth.server_key);
  const server = await K.importSigningKey(X(V.auth.server_seed), serverKey);
  for (const t of P.valid) {
    const sealed = X(t.sealed);
    checkEq(`${t.name} sealed length`, sealed.length, K.PUSH_SEALED);
    const got = await K.openPush(sealed, X(t.device_id), await keysFor(t.keys), serverKey, t.now);
    if (!check(`${t.name} (${t.description}) opens`, got.ok, got.error)) continue;
    checkEq(`${t.name} type / sent_at / body`, { type: got.type, sent_at: got.sent_at, body: got.body }, { type: t.type, sent_at: t.sent_at, body: t.body });
    checkEq(`${t.name} push rebuilt (server signature over device_id ‖ push)`, toHex(await K.buildPush(server, X(t.device_id), t.type, t.sent_at, X(t.body))), t.push);
    const kid = toHex(sealed.slice(0, 8));
    checkEq(`${t.name} sealed rebuilt byte-for-byte`, toHex(await K.sealPush(X(t.push), X(t.device_id), X(dekByKeyId.get(kid).pub), X(t.ikm))), t.sealed);
    if (t.type === K.PUSH.RECORDS) {
      checkEq(`${t.name} records re-serialized`,
        toHex(concat(...got.records.map(r => K.vec32(concat(K.u64(r.received_at), r.envelope))))), t.body);
      // Each record is an envelope the device then treats like any other (§7.6).
      for (const r of got.records) {
        const ev = V.envelopes.valid.find(e => e.raw === toHex(r.envelope));
        if (!check(`${t.name} record is one of the valid envelopes`, !!ev)) continue;
        const res = await K.receiveEnvelope(await receiverCtx(ev.log_seq, t.device_id, t.keys), r.envelope);
        check(`${t.name} record opens on ${t.device}`, res.ok, res.error);
      }
    }
    if (t.type === K.PUSH.SILENCE) {
      checkEq(`${t.name} body`, toHex(concat(got.circle_id, got.watched_device_id, K.u64(got.last_seen_at))), t.body);
      checkEq(`${t.name} names the circle`, toHex(got.circle_id), L.circle_id);
    }
    check(`${t.name} is dropped by a device with another ID`, !(await K.openPush(sealed, X(devices.get('maya/phone').device_id), await keysFor(t.keys), serverKey, t.now)).ok);
  }
  for (const t of P.invalid) {
    const got = await K.openPush(X(t.sealed), X(t.device_id), await keysFor(t.keys), serverKey, t.now);
    check(`dropped: ${t.name} (${t.description})`, !got.ok);
  }
  const R = P.relay;
  const args = [X(R.capability), X(R.sealed), R.sent_at];
  check('relay signature verifies for its delivery type', await K.verifyRelayPush(serverKey, ...args, R.delivery, X(R.sig)));
  for (const d of Object.values(K.RELAY_DELIVERY).filter(x => x !== R.delivery)) {
    check(`relay signature does not verify as delivery ${d}`, !await K.verifyRelayPush(serverKey, ...args, d, X(R.sig)));
  }
  checkEq('relay signature recomputed', toHex(await K.signRelayPush(server, ...args, R.delivery)), R.sig);
  check('relay refuses a delivery type it does not know', !await K.verifyRelayPush(serverKey, ...args, 4, await K.signRelayPush(server, ...args, 4)));
});

// ---------------------------------------------------------------------------
// Self-tests of the sending side with fresh randomness (not from the vectors): what a real
// client does, with random message secrets, details nonces and HPKE ephemeral keys.
// ---------------------------------------------------------------------------

group('fresh round trips');
await attempt('fresh round trips', async () => {
  const st = mainStates[L.final_seq].client;
  const keysOf = d => { const k = dekByKeyId.get(toHex(d.key_id)); return new Map([[k.key_id, k.imported]]); };
  // A circle envelope from Alex to every other receiving device.
  const sender = devices.get('alex/phone');
  const recipients = K.receivingDevices(st).filter(d => toHex(d.device_id) !== sender.device_id);
  const payload = utf8(JSON.stringify({ t: 'chat', id: K.b64uEncode(K.randomBytes(8)), text: 'dinner at 7?' }));
  const raw = await K.sealEnvelope({
    header: { kind: 1, circle_id: st.circle_id, sender_device_id: X(sender.device_id), seq: 99, sent_at: 1793808360000, ttl_s: 86400, log_head: st.head },
    recipients, payload, signer: sender.signer,
  });
  checkEq('fresh envelope stored by the server', serverOutcome(await K.serverCheckEnvelope({ state: mainStates[L.final_seq].pub, now: 1793808370000, replay: K.newReplayRecord() }, raw)), 'stored');
  for (const d of recipients) {
    const res = await K.receiveEnvelope({ state: st, now: 1793808370000, deviceId: d.device_id, keys: keysOf(d), replay: K.newReplayRecord() }, raw);
    check(`fresh envelope opened by ${devicesById.get(toHex(d.device_id)).label}`, res.ok && bytesEqual(res.payloadBytes, payload), res.error);
  }
  check('no fresh envelope goes to the recovery device', !recipients.some(d => d.kind === K.KIND.RECOVERY) && K.activeDevices(st).some(d => d.kind === K.KIND.RECOVERY));
  // A REKEY by Jordan (an admin) with a fresh secret, processed in both modes and opened by every
  // receiving device; the same entry from Maya (not an admin) is fatal.
  const jordan = devices.get('jordan/phone');
  const secret = K.randomBytes(32);
  const buildRekey = async dev => {
    const hdr = { type: K.ENTRY.REKEY, circle_id: st.circle_id, seq: st.seq + 1n, prev_hash: st.head, created_at: 1793808420000n, author: X(dev.device_id), epoch: st.epoch };
    const wr = await K.sealWraps(K.receivingDevices(st), secret,
      r => K.epochWrapInfo(hdr.circle_id, hdr.seq, hdr.prev_hash, hdr.epoch + 1, r.device_id, r.key_id));
    return { hdr, raw: await K.buildEntry(hdr, K.serializeEntryBody(K.ENTRY.REKEY, { epoch_commit: await K.epochCommit(st.epoch + 1, secret), wraps: wr }), dev.signer) };
  };
  const { hdr: header, raw: rekey } = await buildRekey(jordan);
  const secrets = new Map(baseSecrets).set(st.epoch + 1, secret);
  const byMaya = await K.processEntry(st, (await buildRekey(devices.get('maya/phone'))).raw, { mode: 'public' });
  checkEq('fresh REKEY by a non-admin is fatal', [byMaya.result, byMaya.reason], ['fatal', 'not_admin']);
  const byWeb = await K.processEntry(st, (await buildRekey(devices.get('jordan/web'))).raw, { mode: 'public' });
  checkEq('fresh REKEY by an admin\'s browser is fatal: a web device may not write it', [byWeb.result, byWeb.reason], ['fatal', 'kind_not_allowed']);
  const rc = await K.processEntry(st, rekey, { mode: 'client', secrets });
  const rp = await K.processEntry(mainStates[L.final_seq].pub, rekey, { mode: 'public' });
  checkEq('fresh REKEY outcome (client, public)', [rc.result, rp.result, rc.state.epoch], ['accepted', 'accepted', st.epoch + 1]);
  for (const d of K.receivingDevices(st)) {
    const o = await K.openWrap(rc.body.wraps, d.device_id, keysOf(d),
      w => K.epochWrapInfo(header.circle_id, header.seq, header.prev_hash, header.epoch + 1, w.recipient_device_id, w.key_id));
    check(`fresh epoch wrap opened by ${devicesById.get(toHex(d.device_id)).label}`, o.secret && bytesEqual(o.secret, secret), o.error);
  }
  // A rename by Jordan in the new epoch, details sealed with a random nonce.
  const h2 = { type: K.ENTRY.POLICY, circle_id: st.circle_id, seq: header.seq + 1n, prev_hash: rc.hash, created_at: 1793808480000n, author: X(jordan.device_id), epoch: st.epoch + 1 };
  const name = 'Rivera–Okafor family';
  const det = await K.sealDetails(secret, K.serializeEntryHeader(h2), concat(K.u8(K.POLICY_SUBTYPE.SET_CIRCLE_NAME), K.vec16(utf8(name))));
  checkEq('fresh details are always 540 bytes', det.length, K.DETAILS_LEN);
  const rename = await K.buildEntry(h2, K.serializeEntryBody(K.ENTRY.POLICY, { details: det }), jordan.signer);
  const r2 = await K.processEntry(rc.state, rename, { mode: 'client', secrets });
  checkEq('fresh rename accepted in the new epoch', [r2.result, r2.state.name], ['accepted', name]);
  const r3 = await K.processEntry(rc.state, rename, { mode: 'client', secrets: baseSecrets });
  checkEq('same rename without the new epoch secret: deferred, private state frozen at its last known values (§6.5)',
    [r3.result, r3.reason, K.stateToJSON(r3.state).name, K.stateToJSON(r3.state).private_unknown_from, K.stateToJSON(r3.state).state_hash],
    ['deferred', null, K.stateToJSON(rc.state).name, Number(h2.seq), null]);

  // A fresh identity rotation (§4.3): a new key, a link both keys sign, a certificate under the new key.
  const oldIk = await K.generateSigningKey(), newIk = await K.generateSigningKey(), dsk = await K.generateSigningKey();
  const acc = await K.accountIdOf(oldIk.pub);
  const link = await K.buildIdentityLink(acc, oldIk, newIk);
  const cert = K.parseDeviceCert(await K.buildDeviceCert(newIk, { account_id: acc, device_kind: K.KIND.PHONE, issued_at: 1793808000000, dsk_pub: dsk.pub }));
  check('fresh rotation: the chain proves the certificate', await K.deviceCertWellFormed(cert) && await K.chainProves(cert, K.parseChain(link)));
  check('fresh rotation: without the chain it does not', !await K.chainProves(cert, []));
  check('fresh rotation: a link made for another account does not', !await K.chainProves(cert, K.parseChain(await K.buildIdentityLink(K.randomBytes(16), oldIk, newIk))));
  check('fresh rotation: a chain of nine links is refused', throws(() => K.parseChain(new Uint8Array(K.LINK_LEN * 9))) && !throws(() => K.parseChain(new Uint8Array(K.LINK_LEN * 8))));

  // A fresh push, sealed with a random ephemeral key.
  const server = await K.importSigningKey(X(V.auth.server_seed));
  const jd = K.findDevice(st, X(jordan.device_id)).device;
  const body = concat(st.circle_id, X(devices.get('maya/phone').device_id), K.u64(1793808000000));
  const sealed = await K.sealPush(await K.buildPush(server, jd.device_id, K.PUSH.SILENCE, 1793808400000, body), jd.device_id, jd.dek_pub);
  const opened = await K.openPush(sealed, jd.device_id, keysOf(jd), server.pub, 1793808400000);
  check('fresh push opens and is always 2,616 bytes', opened.ok && sealed.length === K.PUSH_SEALED && opened.type === K.PUSH.SILENCE, opened.error);
  check('fresh push: the largest body fits and one byte more does not',
    (await K.buildPush(server, jd.device_id, K.PUSH.RECORDS, 1, new Uint8Array(K.PUSH_BODY_MAX))).length === K.PUSH_PLAIN - 1
    && await K.buildPush(server, jd.device_id, K.PUSH.RECORDS, 1, new Uint8Array(K.PUSH_BODY_MAX + 1)).then(() => false, () => true));
});

// ---------------------------------------------------------------------------
// §6.5 "Missing secrets" (the vectors hold one deferred case; these go further)
// ---------------------------------------------------------------------------

group('missing secrets');
await attempt('missing secrets', async () => {
  const replayWith = async secrets => {
    let st = K.emptyState();
    const results = [];
    for (const ent of L.entries) {
      const r = await K.processEntry(st, X(ent.raw), { mode: 'client', secrets });
      results.push(r);
      st = r.state;
    }
    return { st, results };
  };
  const parsed = L.entries.map(ent => K.parseEntryFraming(X(ent.raw)));
  const withDetails = t => t === K.ENTRY.GENESIS || t === K.ENTRY.ADD_MEMBER || t === K.ENTRY.POLICY;
  // Only entries with details need a secret, so the freeze starts at the first of those in the epoch.
  const firstNeeding = ep => parsed.findIndex(e => e.epoch === ep && withDetails(e.type));
  const scenarios = [
    { name: 'only the epoch-0 secret', secrets: new Map([[0, baseSecrets.get(0)]]), from: firstNeeding(1) },
    { name: 'a wrong epoch-2 secret (discarded)', secrets: new Map(baseSecrets).set(2, baseSecrets.get(1)), from: firstNeeding(2) },
    { name: 'a wrong epoch-0 secret (discarded)', secrets: new Map(baseSecrets).set(0, baseSecrets.get(2)), from: 0 },
  ];
  // The frozen state: public fields as the log goes on, private fields as they were before the freeze.
  const frozenExpectation = (i, from) => {
    const now = L.entries[i].state_after;
    const before = from > 0 ? L.entries[from - 1].state_after : { name: '', flags: [], members: [] };
    const priv = new Map(before.members.map(m => [m.account_id, m]));
    const dflt = { role: 'adult', teen_until: 0, guardians: [], rules: null, pauses: [] };
    return {
      ...publicSubset(now), name: before.name, flags: before.flags, private_unknown_from: from, state_hash: null,
      members: now.members.map(m => {
        const p = priv.get(m.account_id) ?? dflt;
        return { ...without(m, PRIVATE_MEMBER_FIELDS), role: p.role, teen_until: p.teen_until, guardians: p.guardians, rules: p.rules, pauses: p.pauses };
      }),
    };
  };
  for (const sc of scenarios) {
    const { st, results } = await replayWith(sc.secrets);
    check(`${sc.name}: the log has an entry with details in that epoch`, sc.from >= 0);
    checkEq(`${sc.name}: the first deferred entry is the first one with details in that epoch`, results.findIndex(r => r.result === 'deferred'), sc.from);
    check(`${sc.name}: before it, outcomes and state match the vectors`, results.every((r, i) =>
      i >= sc.from || (r.result === L.entries[i].result && r.reason === L.entries[i].reason && canon(K.stateToJSON(r.state)) === canon(L.entries[i].state_after))));
    check(`${sc.name}: from it on, every entry is deferred (never bad_details or rejected)`,
      results.every((r, i) => i < sc.from || (r.result === 'deferred' && r.reason === null)));
    check(`${sc.name}: public state unaffected`, results.every((r, i) =>
      canon(K.stateToJSON(r.state, { publicOnly: true })) === canon(publicSubset(L.entries[i].state_after))));
    check(`${sc.name}: frozen private fields keep their last known values, and there is no state hash`, results.every((r, i) =>
      i < sc.from || canon(K.stateToJSON(r.state)) === canon(frozenExpectation(i, sc.from))));
    const resumed = await K.resumePrivate(st, baseSecrets);
    checkEq(`${sc.name}: once the secret arrives, re-running the private rules gives the full state`, K.stateToJSON(resumed), L.entries.at(-1).state_after);
  }
  // §7.6: a client with frozen private state can't judge the sender rules that need roles. It holds
  // those payloads, neither accepting nor refusing them, and opens them once it has caught up.
  {
    const { st: frozen } = await replayWith(new Map([[0, baseSecrets.get(0)]]));
    const byName = name => [...V.envelopes.valid, ...V.envelopes.invalid].find(e => e.name === name);
    const open = async (state, ev, rcp) => K.receiveEnvelope(
      { state, now: NOW, deviceId: X(rcp.device_id ?? rcp.receiver_device_id), keys: await keysFor(rcp.keys ?? rcp.receiver_keys), replay: K.newReplayRecord() }, X(ev.raw));
    for (const [name, what] of [['f9', 'pause_deny'], ['f8', 'place'], ['not_allowed_pause_request_from_adult', 'pause_req'],
      ['not_allowed_place_id_mismatch', 'place with a wrong id']]) {
      const ev = byName(name);
      const r = await open(frozen, ev, ev.recipients ? ev.recipients[0] : ev);
      check(`frozen client holds a ${what} (${name})`, !r.ok && r.held === true && r.error === undefined);
    }
    for (const name of ['f1', 'f5', 'f6', 'f7', 'f10']) {
      const ev = byName(name);
      const r = await open(frozen, ev, ev.recipients[0]);
      check(`frozen client still opens ${name} (${ev.payload.t}): its rule needs no roles`, r.ok, r.error);
    }
    const web = byName('not_allowed_web_sends_location');
    checkEq('frozen client still refuses a location from a web device', (await open(frozen, web, web)).error, 'not_allowed');
    const caughtUp = await K.resumePrivate(frozen, baseSecrets);
    const f9 = byName('f9'), bad = byName('not_allowed_pause_request_from_adult');
    check('once caught up, the held pause_deny is accepted', (await open(caughtUp, f9, f9.recipients[0])).ok);
    checkEq('once caught up, the held pause request from an adult is refused', (await open(caughtUp, bad, bad)).error, 'not_allowed');
  }
  // The vectors' deferred case, resumed once the withheld secret arrives.
  const dc = L.cases.find(c => c.withheld_epochs?.length);
  if (check('a case withholds an epoch secret', !!dc)) {
    const all = new Map(baseSecrets);
    for (const [k, v] of Object.entries(dc.new_epoch_secrets ?? {})) all.set(Number(k), X(v));
    const held = new Map(all);
    for (const ep of dc.withheld_epochs) held.delete(Number(ep));
    let frozen = mainStates[dc.base_seq].client;
    let full = mainStates[dc.base_seq].client;
    for (const ent of dc.entries) {
      frozen = (await K.processEntry(frozen, X(ent.raw), { mode: 'client', secrets: held })).state;
      full = (await K.processEntry(full, X(ent.raw), { mode: 'client', secrets: all })).state;
    }
    checkEq(`${dc.name}: resuming with the withheld secret equals processing with every secret`,
      K.stateToJSON(await K.resumePrivate(frozen, all)), K.stateToJSON(full));
    check(`${dc.name}: and then nothing is frozen`, K.stateToJSON(full).private_unknown_from === null && K.stateToJSON(full).state_hash !== null);
  }
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

let totalFail = 0;
let totalPass = 0;
console.log(`Kinfold v0 vectors (${V.status}): ${vectorPath}\n`);
for (const [name, g] of groups) {
  totalPass += g.pass;
  totalFail += g.fail;
  console.log(`${name.padEnd(20)} ${String(g.pass).padStart(4)} passed  ${g.fail ? `${g.fail} FAILED` : ''}`);
}
console.log(`${'total'.padEnd(20)} ${String(totalPass).padStart(4)} passed  ${totalFail ? `${totalFail} FAILED` : ''}`);
if (notes.length) console.log('\n' + notes.map(n => `note: ${n}`).join('\n'));
if (totalFail) {
  console.log('\nFailures:');
  for (const [name, g] of groups) for (const f of g.failures) console.log(`  [${name}] ${f}`);
  process.exitCode = 1;
}
