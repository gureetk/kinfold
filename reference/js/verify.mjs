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
  out.push(`${path}: got ${JSON.stringify(na)} want ${JSON.stringify(nb)}`);
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

const people = new Map();      // name -> person
const devices = new Map();     // label -> device
const devicesById = new Map(); // device_id hex -> device
const dekByKeyId = new Map();  // key_id hex -> { sk, pub, key_id, device }

group('identities');
for (const [pname, p] of Object.entries(V.identities)) {
  const person = { name: pname, ...p };
  people.set(pname, person);
  await attempt(`${pname} identity key`, async () => {
    checkEq(`${pname} ik_pub from ik_seed`, toHex(await K.ed25519PublicFromSeed(X(p.ik_seed))), p.ik_pub);
    checkEq(`${pname} account_id`, toHex(await K.accountIdOf(X(p.ik_pub))), p.account_id);
    person.ikSigner = await K.importSigningKey(X(p.ik_seed), X(p.ik_pub));
    check(`${pname} JWK import of IK`, !!person.ikSigner);
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
      check(`${d.label} cert valid`, await K.deviceCertValid(cert));
      checkEq(`${d.label} cert rebuilt (Sign IK over first 60 bytes)`,
        toHex(await K.buildDeviceCert(person.ikSigner, { device_kind: cert.device_kind, issued_at: cert.issued_at, dsk_pub: cert.dsk_pub })), d.cert);

      checkEq(`${d.label} bundles/deks count`, d.bundles.length, d.deks.length);
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
          toHex(await K.buildKeyBundle(dev.signer, { account_id: b.account_id, dek_pub: b.dek_pub, not_before: b.not_before, not_after: b.not_after })),
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
// Log: main entries and cases, client mode and public (server) mode
// ---------------------------------------------------------------------------

const L = V.log;
const baseSecrets = new Map(Object.entries(L.epoch_secrets).map(([k, v]) => [Number(k), X(v)]));
// vectors/README.md: the public state is the state JSON without these private fields.
const PRIVATE_STATE_FIELDS = ['name', 'flags', 'private_unknown_from'];
const PRIVATE_MEMBER_FIELDS = ['role', 'teen_until', 'guardians', 'rules', 'pauses'];
const without = (o, keys) => Object.fromEntries(Object.entries(o).filter(([k]) => !keys.includes(k)));
const publicSubset = st => ({
  ...without(st, PRIVATE_STATE_FIELDS),
  members: st.members.map(m => without(m, PRIVATE_MEMBER_FIELDS)),
});

/** Decrypt an entry's details with the known epoch secrets (for details_plaintext checks). */
async function decryptDetails(raw, secrets) {
  const e = K.parseEntryFraming(raw);
  const b = K.parseEntryBody(e.type, e.body);
  if (!b.details || !secrets.has(e.epoch)) return null;
  return K.openDetailsWith(secrets.get(e.epoch), e.header, b.details);
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
    if (pt === null) check(`${tag} details that don't open under the circle's key give bad_details`, ent.reason === 'bad_details');
    else checkEq(`${tag} details_plaintext`, toHex(pt), ent.details_plaintext);
  }
  if ('invite_secret' in ent) {
    const b = K.parseEntryBody(K.parseEntryFraming(raw).type, K.parseEntryFraming(raw).body);
    checkEq(`${tag} invite_id = H(invite-id, invite_secret)`, toHex(await K.inviteId(X(ent.invite_secret))), ent.invite_id);
    checkEq(`${tag} body invite_id`, toHex(b.invite_id), ent.invite_id);
  }
  if ('new_epoch_secret' in ent) {
    const e = K.parseEntryFraming(raw);
    const b = K.parseEntryBody(e.type, e.body);
    checkEq(`${tag} new_epoch = epoch + 1`, ent.new_epoch, e.epoch + 1);
    checkEq(`${tag} epoch_commit`, toHex(await K.epochCommit(ent.new_epoch, X(ent.new_epoch_secret))), toHex(b.epoch_commit));
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
}

group('log cases');
const caseCounts = { fatal: 0, rejected: 0, accepted: 0, deferred: 0 };
let emptyLogCases = 0;
for (const c of L.cases) {
  await attempt(`case ${c.name}`, async () => {
    const allSecrets = new Map(baseSecrets);
    for (const [k, v] of Object.entries(c.new_epoch_secrets ?? {})) allSecrets.set(Number(k), X(v));
    // `withheld_epochs`: the client under test never received these secrets (§6.5).
    const secrets = new Map(allSecrets);
    for (const ep of c.withheld_epochs ?? []) secrets.delete(Number(ep));
    if (c.base_seq === -1) emptyLogCases++;
    let states = c.base_seq === -1 ? { client: K.emptyState(), pub: K.emptyState() } : { ...mainStates[c.base_seq] };
    for (const [i, ent] of c.entries.entries()) {
      const r = await checkEntry(`case ${c.name} [${i}]`, ent, states, secrets, allSecrets);
      states = { client: r.client, pub: r.pub };
    }
    const last = c.entries.at(-1);
    caseCounts[last.result]++;
    if ('state_after' in c) {
      checkEq(`case ${c.name} state_after`, K.stateToJSON(states.client), c.state_after);
      checkEq(`case ${c.name} public state_after`, K.stateToJSON(states.pub, { publicOnly: true }), publicSubset(c.state_after));
    } else {
      check(`case ${c.name} has no state_after only when its last entry is fatal`, last.result === 'fatal');
    }
  });
}
checkEq('case counts (§17: 36 fatal, 15 rejected, 15 accepted, 1 deferred; 5 on an empty log)',
  { ...caseCounts, emptyLog: emptyLogCases }, { fatal: 36, rejected: 15, accepted: 15, deferred: 1, emptyLog: 5 });

// ---------------------------------------------------------------------------
// Epoch wraps: every recipient opens its wrap and checks the commitment
// ---------------------------------------------------------------------------

group('epoch wraps');
const epochEntries = [
  ...L.entries.map((ent, i) => ({ tag: `entry ${i}`, ent })),
  ...L.cases.flatMap(c => c.entries.map((ent, i) => ({ tag: `case ${c.name} [${i}]`, ent }))),
].filter(x => 'new_epoch_secret' in x.ent);
for (const { tag, ent } of epochEntries) {
  await attempt(tag, async () => {
    const e = K.parseEntryFraming(X(ent.raw));
    const b = K.parseEntryBody(e.type, e.body);
    checkEq(`${tag} wrap recipients = wrap_ikm keys`, b.wraps.map(w => toHex(w.recipient_device_id)), Object.keys(ent.wrap_ikm).sort());
    for (const w of b.wraps) {
      const did = toHex(w.recipient_device_id);
      const dek = dekByKeyId.get(toHex(w.key_id));
      if (!check(`${tag} wrap for ${did}: key_id is one of that device's DEKs`, dek && dek.device.device_id === did)) continue;
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
// Byte-exact rebuild of every main log entry (details re-sealed with the nonce found in the
// entry, epoch wraps re-sealed from wrap_ikm, consent and signatures recomputed)
// ---------------------------------------------------------------------------

group('log rebuild (seal)');
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
    const active = K.activeDevices(st);
    let nb;
    switch (e.type) {
      case K.ENTRY.GENESIS:
        nb = { founder_cert: X(author.cert), founder_bundle: X(author.bundles[0]),
          epoch_commit: await K.epochCommit(0, baseSecrets.get(0)), details: await reseal() };
        break;
      case K.ENTRY.ADD_MEMBER: {
        const dev = devicesById.get(toHex(await K.deviceIdOf(b.cert.dsk_pub)));
        const invId = await K.inviteId(X(ent.invite_secret));
        const cert = X(dev.cert), bundle = identityBundleFor(dev, b.bundle.dek_pub);
        nb = { cert, bundle, invite_id: invId, consent_sig: await K.joinConsent(dev.person.ikSigner, st.circle_id, invId, cert, bundle),
          admin: b.admin, details: await reseal() };
        break;
      }
      case K.ENTRY.REMOVE_MEMBER:
        // A removal that starts no epoch (§6.4) carries a zero commitment and no wraps.
        nb = ent.new_epoch_secret
          ? { account_id: b.account_id, epoch_commit: await K.epochCommit(e.epoch + 1, X(ent.new_epoch_secret)),
            wraps: await epochWraps(active.filter(d => !bytesEqual(d.account_id, b.account_id))) }
          : { account_id: b.account_id, epoch_commit: new Uint8Array(32), wraps: [] };
        break;
      case K.ENTRY.ADD_DEVICE: {
        const dev = devicesById.get(toHex(await K.deviceIdOf(b.cert.dsk_pub)));
        nb = { cert: X(dev.cert), bundle: identityBundleFor(dev, b.bundle.dek_pub) };
        break;
      }
      case K.ENTRY.REMOVE_DEVICE:
        nb = ent.new_epoch_secret
          ? { device_id: b.device_id, epoch_commit: await K.epochCommit(e.epoch + 1, X(ent.new_epoch_secret)),
            wraps: await epochWraps(active.filter(d => !bytesEqual(d.device_id, b.device_id))) }
          : { device_id: b.device_id, epoch_commit: new Uint8Array(32), wraps: [] };
        break;
      case K.ENTRY.UPDATE_KEY:
        nb = { bundle: identityBundleFor(author, b.bundle.dek_pub) };
        break;
      case K.ENTRY.POLICY:
        nb = { details: await reseal() };
        break;
      case K.ENTRY.REKEY:
        nb = { epoch_commit: await K.epochCommit(e.epoch + 1, X(ent.new_epoch_secret)), wraps: await epochWraps(active) };
        break;
      case K.ENTRY.SET_ADMIN:
        nb = { account_id: b.account_id, admin: b.admin };
        break;
    }
    const rebuilt = await K.buildEntry(header, K.serializeEntryBody(e.type, nb), author.signer);
    checkEq(`entry ${i} (${ent.description}) rebuilt byte-for-byte`, toHex(rebuilt), ent.raw);
  });
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

group('envelopes');
const NOW = V.envelopes.receiver_now;
// §7.5: a server runs §7.6 steps 1-10 (these codes), then its own wrap and ttl checks.
const STEP_1_TO_10_CODES = new Set(['malformed', 'bad_version', 'bad_kind', 'wrong_circle', 'unknown_log_head',
  'sender_not_active', 'bad_signature', 'expired', 'bad_time', 'replay', 'bad_wraps']);
const receiverCtx = async (logSeq, deviceId, keyMap) =>
  ({ state: mainStates[logSeq].client, now: NOW, deviceId: X(deviceId), keys: await keysFor(keyMap), replay: K.newReplayRecord() });
// The server works from the public state only.
const serverCtx = logSeq => ({ state: mainStates[logSeq].pub, now: NOW, replay: K.newReplayRecord() });
const outcome = r => (r.ok ? 'ok' : r.error);
for (const ev of V.envelopes.valid) {
  await attempt(`envelope ${ev.name}`, async () => {
    const st = mainStates[ev.log_seq].client;
    checkEq(`${ev.name} accepted by the server (§7.5)`, outcome(await K.serverCheckEnvelope(serverCtx(ev.log_seq), X(ev.raw))), 'ok');
    const sender = devices.get(ev.sender);
    const env = K.parseEnvelope(X(ev.raw));
    checkEq(`${ev.name} header fields`,
      { kind: env.kind, circle: env.circle_id, sender: env.sender_device_id, seq: env.seq, sent_at: env.sent_at, ttl_s: env.ttl_s, head: env.log_head },
      { kind: ev.kind, circle: L.circle_id, sender: sender.device_id, seq: ev.seq, sent_at: ev.sent_at, ttl_s: ev.ttl_s, head: ev.log_head });
    checkEq(`${ev.name} log_head is the head at log_seq`, toHex(st.head), ev.log_head);
    const wrapIds = env.wraps.map(w => toHex(w.recipient_device_id));
    checkEq(`${ev.name} wraps = recipients`, wrapIds, ev.recipients.map(r => r.device_id).sort());
    checkEq(`${ev.name} wraps = wrap_ikm keys`, wrapIds, Object.keys(ev.wrap_ikm).sort());
    if (ev.kind === 1) {
      checkEq(`${ev.name} circle envelope goes to every active device but the sender (§7.2)`, wrapIds,
        K.activeDevices(st).map(d => toHex(d.device_id)).filter(id => id !== sender.device_id));
    }
    checkEq(`${ev.name} padded_length`, K.pad(X(ev.payload_bytes)).length, ev.padded_length);
    for (const rcp of ev.recipients) {
      const res = await K.receiveEnvelope(await receiverCtx(ev.log_seq, rcp.device_id, rcp.keys), X(ev.raw));
      if (!check(`${ev.name} opened by ${rcp.device}`, res.ok, res.error)) continue;
      checkEq(`${ev.name} ${rcp.device} payload`, res.payload, rcp.payload);
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
    // README: refused by servers too when the error is one of §7.5's steps 1-10; otherwise a
    // server has no grounds to refuse it (§7.5 lists every server check).
    const want = STEP_1_TO_10_CODES.has(ev.error) ? ev.error : 'ok';
    checkEq(`invalid ${ev.name}: server outcome`, outcome(await K.serverCheckEnvelope(serverCtx(ev.log_seq), X(ev.raw))), want);
  });
}
await attempt('replay', async () => {
  const rp = V.envelopes.replay;
  const ctx = await receiverCtx(rp.log_seq, rp.receiver_device_id, rp.receiver_keys);
  const results = [];
  for (const raw of rp.sequence) results.push(outcome(await K.receiveEnvelope(ctx, X(raw))));
  checkEq('replay sequence', results, rp.results);
  const sctx = serverCtx(rp.log_seq);
  const serverResults = [];
  for (const raw of rp.sequence) serverResults.push(outcome(await K.serverCheckEnvelope(sctx, X(raw))));
  checkEq('replay sequence at the server (§7.5 runs step 9)', serverResults, rp.results);
  // Retention (§7.6): the pair may be forgotten 31 days after sent_at, when step 8 refuses it anyway.
  const sentAt = Number(K.parseEnvelope(X(rp.sequence[0])).sent_at);
  const later = sentAt + Number(K.MAX_ENVELOPE_AGE_MS) + 1;
  K.pruneReplayRecord(ctx.replay, later);
  checkEq('after pruning, the old envelope is refused as expired', outcome(await K.receiveEnvelope({ ...ctx, now: later }, X(rp.sequence[0]))), 'expired');
});
for (const ev of V.envelopes.server_rejects) {
  await attempt(`server_rejects ${ev.name}`, async () => {
    checkEq(`server_rejects ${ev.name} (${ev.description}): server`, outcome(await K.serverCheckEnvelope(serverCtx(ev.log_seq), X(ev.raw))), ev.server_error);
    const res = await K.receiveEnvelope(await receiverCtx(ev.log_seq, ev.receiver_device_id, ev.receiver_keys), X(ev.raw));
    if (check(`server_rejects ${ev.name}: ${ev.receiver} still opens it`, res.ok, res.error)) {
      checkEq(`server_rejects ${ev.name}: payload`, res.payload, ev.payload);
    }
  });
}

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
for (const t of V.padding.invalid) check(`unpad rejects: ${t.description}`, K.unpad(X(t.padded)) === null);
check('pad rejects 65,536 bytes', throws(() => K.pad(new Uint8Array(65536))));

group('approx');
for (const t of V.approx) checkEq(`approx(${t.lat}, ${t.lon})`, K.approxPosition(t.lat, t.lon), { lat: t.approx_lat, lon: t.approx_lon });

group('safety_codes');
for (const t of V.safety_codes) {
  await attempt(`safety ${t.a}/${t.b}`, async () => {
    checkEq(`${t.a} ik_pub`, t.ik_pub_a, people.get(t.a).ik_pub);
    checkEq(`${t.b} ik_pub`, t.ik_pub_b, people.get(t.b).ik_pub);
    checkEq(`half(${t.a})`, await K.safetyHalf(X(t.ik_pub_a)), t.half_a);
    checkEq(`half(${t.b})`, await K.safetyHalf(X(t.ik_pub_b)), t.half_b);
    const ab = await K.safetyCode(X(t.ik_pub_a), X(t.ik_pub_b));
    const ba = await K.safetyCode(X(t.ik_pub_b), X(t.ik_pub_a));
    checkEq(`code(${t.a}, ${t.b})`, ab.display, t.code);
    checkEq(`code(${t.b}, ${t.a})`, ba.display, t.code);
    checkEq(`qr(${t.a}, ${t.b})`, ab.qr, t.qr);
    checkEq(`qr(${t.b}, ${t.a})`, ba.qr, t.qr);
  });
}

// ---------------------------------------------------------------------------
// Invite and join request
// ---------------------------------------------------------------------------

group('invite');
await attempt('invite', async () => {
  const iv = V.invite;
  const bytes = X(iv.invite);
  const f = K.parseInvite(bytes);
  checkEq('invite fields', {
    server_url: f.server_url, server_key: f.server_key, circle_id: f.circle_id, secret: f.secret,
    inviter_ik_pub: f.inviter_ik_pub, role_hint: f.role_hint, expires_at: f.expires_at, reg_token: f.reg_token,
  }, iv.fields);
  checkEq('invite re-serialized', toHex(K.serializeInvite(f)), iv.invite);
  checkEq('app link', K.inviteAppLink(bytes), iv.app_link);
  checkEq('web link', K.inviteWebLink(f.server_url, bytes), iv.web_link);
  checkEq('invite_id', toHex(await K.inviteId(f.secret)), iv.invite_id);
  checkEq('join_key', toHex(await K.joinKey(f.secret)), iv.join_key);
  checkEq('invite circle_id is the log circle', toHex(f.circle_id), L.circle_id);
  checkEq('invite server_key is the server key', toHex(f.server_key), V.auth.server_key);

  const jrv = iv.join_request;
  const jr = await K.openJoinRequest(X(jrv.message), f.secret);
  checkEq('join request contents', { nonce: jr.nonce, cert: jr.cert, bundle: jr.bundle, consent: jr.consent_sig, name: jr.name },
    { nonce: jrv.nonce, cert: jrv.cert, bundle: jrv.bundle, consent: jrv.consent, name: jrv.name });
  checkEq('join request invite_id', toHex(jr.invite_id), iv.invite_id);
  const c = await K.checkJoinRequest(jr, f.circle_id);
  check('join request certificate valid', c.certValid);
  check('join request bundle valid for the certificate', c.bundleValid);
  check('join request consent signature valid', c.consentValid);
  const maya = people.get('maya');
  checkEq('consent recomputed with the invitee IK', toHex(await K.joinConsent(maya.ikSigner, f.circle_id, jr.invite_id, jr.cert, jr.bundle)), jrv.consent);
  checkEq('join request rebuilt byte-for-byte',
    toHex(await K.sealJoinRequest(f.secret, { cert: jr.cert, bundle: jr.bundle, consent_sig: jr.consent_sig, name: jr.name }, jr.nonce)), jrv.message);

  // The log entry that adds Maya carries the same invite and consent.
  const ent = L.entries[iv.log_entry_seq];
  const e = K.parseEntryFraming(X(ent.raw));
  const b = K.parseEntryBody(e.type, e.body);
  checkEq(`log entry ${iv.log_entry_seq} is ADD_MEMBER with the same invite_id, consent, cert and bundle`,
    { type: e.type, invite_id: b.invite_id, consent: b.consent_sig, cert: b.cert.raw, bundle: b.bundle.raw },
    { type: K.ENTRY.ADD_MEMBER, invite_id: iv.invite_id, consent: jrv.consent, cert: jrv.cert, bundle: jrv.bundle });
  checkEq(`log entry ${iv.log_entry_seq} invite_secret`, ent.invite_secret, iv.fields.secret);
  // §9.2 checks by the new member's client.
  checkEq('genesis hash gives the invite circle_id', toHex((await K.H('circle-id', X(L.entries[0].raw))).slice(0, 16)), toHex(f.circle_id));
  const authorAtAdd = K.findDevice(mainStates[iv.log_entry_seq - 1].client, e.author);
  checkEq('ADD_MEMBER authored by a device of inviter_ik_pub', authorAtAdd ? toHex(authorAtAdd.member.ik_pub) : null, toHex(f.inviter_ik_pub));
  const me = mainStates[iv.log_entry_seq].client.members.get(toHex(c.cert.account_id));
  checkEq('new member role matches role_hint', me?.role, f.role_hint === 2 ? 'teen' : 'adult');
});

// ---------------------------------------------------------------------------
// Device linking
// ---------------------------------------------------------------------------

group('device_link');
await attempt('device_link.from_existing', async () => {
  const fe = V.device_link.from_existing;
  const jordan = people.get('jordan');
  const phone = devices.get('jordan/phone');
  const tablet = devices.get(fe.new_device);
  const linkBytes = X(fe.link);
  const link = K.parseLink(linkBytes);
  checkEq('direction 1 link fields',
    { direction: link.direction, secret: link.secret, account_id: link.account_id, ik_pub: link.ik_pub, server_key: link.server_key, server_url: link.server_url },
    { direction: 1, secret: fe.secret, account_id: jordan.account_id, ik_pub: jordan.ik_pub, server_key: V.auth.server_key, server_url: V.auth.server_url });
  checkEq('link re-serialized', toHex(K.serializeLink(link)), fe.link);
  checkEq('app link', K.linkAppLink(linkBytes), fe.app_link);
  checkEq('link_id', toHex(await K.linkId(link.secret)), fe.link_id);
  checkEq('link_key', toHex(await K.linkKey(link.secret)), fe.link_key);
  checkEq('link_confirm', toHex(await K.linkConfirm(link.secret)), fe.confirm);

  const req = await K.openLinkMessage(X(fe.request), link.secret);
  checkEq('request type / nonce / plaintext', { t: req.msg_type, nonce: req.nonce, pt: req.plaintext }, { t: K.LINK_REQUEST, nonce: fe.request_nonce, pt: fe.request_plaintext });
  checkEq('request rebuilt byte-for-byte', toHex(await K.sealLinkMessage(link.secret, K.LINK_REQUEST, X(fe.request_plaintext), X(fe.request_nonce))), fe.request);
  const rq = K.parseLinkRequest(req.plaintext);
  checkEq('request names the new device', { dsk_pub: rq.dsk_pub, kind: rq.device_kind, bundle: rq.bundle }, { dsk_pub: tablet.dsk_pub, kind: tablet.kind, bundle: tablet.bundles[0] });
  check('request bundle valid for the new device in the account', await K.keyBundleValidFor(K.parseKeyBundle(rq.bundle), rq.dsk_pub, link.account_id));
  check('request device name is text', typeof rq.device_name === 'string' && rq.device_name.length > 0);
  checkEq('6-digit code', await K.linkCode(X(fe.link_id), req.plaintext), fe.code);

  const dekPub = await K.x25519PublicFromPrivate(X(fe.new_device_dek_sk));
  checkEq('new_device_dek_sk is the key in the request bundle', toHex(dekPub), toHex(K.parseKeyBundle(rq.bundle).dek_pub));
  const me = { dsk_pub: rq.dsk_pub, device_kind: rq.device_kind, dek: await K.importDecryptionKey(X(fe.new_device_dek_sk), dekPub) };
  const res = await K.openLinkResponse(X(fe.response), link.secret, me, { account_id: link.account_id, ik_pub: link.ik_pub });
  check('response passes the new device checks', res.ok, res.failures.join(', '));
  checkEq('response plaintext = response_payload', res.plaintext ? new TextDecoder().decode(res.plaintext) : null, fe.response_payload);
  const resp = K.parseLinkResponse(X(fe.response));
  checkEq('sender_cert is the existing phone', toHex(resp.sender_cert.raw), phone.cert);
  checkEq('response cert is the tablet certificate', res.cert ? toHex(res.cert.raw) : null, tablet.cert);
  check('response carries the IK seed (phone/tablet)', res.payload?.ik !== undefined && toHex(K.b64uDecode(res.payload.ik)) === jordan.ik_seed);
  // "fetches each circle's log, finds its ADD_DEVICE entry and checks each epoch secret against the log"
  const circles = res.payload?.circles ?? [];
  checkEq('response lists the one circle', circles.map(c => toHex(K.b64uDecode(c.id))), [L.circle_id]);
  const addIdx = L.entries.findIndex(en => {
    const e = K.parseEntryFraming(X(en.raw));
    if (e.type !== K.ENTRY.ADD_DEVICE) return false;
    const b = K.parseEntryBody(e.type, e.body);
    return toHex(b.cert.raw) === tablet.cert && toHex(b.bundle.raw) === toHex(rq.bundle);
  });
  check('log has the ADD_DEVICE entry with this cert and the request bundle', addIdx >= 0);
  for (const c of circles) {
    const commits = mainStates[addIdx].client.commits;
    for (const [ep, s] of c.epochs.entries()) {
      checkEq(`epoch ${ep} secret from the response matches the log`, toHex(await K.epochCommit(ep, K.b64uDecode(s))), commits.get(ep) ? toHex(commits.get(ep)) : null);
    }
    checkEq('response has every epoch up to the ADD_DEVICE entry', c.epochs.length, mainStates[addIdx].client.epoch + 1);
  }
  const rebuilt = await K.sealLinkResponse({
    lid: X(fe.link_id), senderCert: X(phone.cert), senderSigner: phone.signer, newDeviceId: X(tablet.device_id),
    newDekPub: dekPub, payload: utf8(fe.response_payload), ikmE: X(fe.response_ikm),
  });
  checkEq('response rebuilt byte-for-byte', toHex(rebuilt), fe.response);
});
await attempt('device_link.from_new', async () => {
  const fn = V.device_link.from_new;
  const linkBytes = X(fn.link);
  const link = K.parseLink(linkBytes);
  checkEq('direction 2 link fields', { direction: link.direction, secret: link.secret, server_key: link.server_key, server_url: link.server_url, account_id: link.account_id },
    { direction: 2, secret: fn.secret, server_key: V.auth.server_key, server_url: V.auth.server_url, account_id: undefined });
  checkEq('link re-serialized', toHex(K.serializeLink(link)), fn.link);
  checkEq('app link', K.linkAppLink(linkBytes), fn.app_link);
  checkEq('link_id', toHex(await K.linkId(link.secret)), fn.link_id);
  const offer = await K.openLinkMessage(X(fn.offer), link.secret);
  checkEq('offer type / nonce', { t: offer.msg_type, nonce: offer.nonce }, { t: K.LINK_OFFER, nonce: fn.offer_nonce });
  const o = K.parseOffer(offer.plaintext);
  checkEq('offer contents', o, { account_id: fn.account_id, ik_pub: fn.ik_pub });
  checkEq('offer is Jordan\'s identity', { a: fn.account_id, k: fn.ik_pub }, { a: people.get('jordan').account_id, k: people.get('jordan').ik_pub });
  checkEq('offer rebuilt byte-for-byte', toHex(await K.sealLinkMessage(link.secret, K.LINK_OFFER, offer.plaintext, X(fn.offer_nonce))), fn.offer);

  // Direction 2 continues with the new device's request, the code and the phone's response.
  const web = devices.get(fn.new_device);
  const phone = devices.get('jordan/phone');
  const req = await K.openLinkMessage(X(fn.request), link.secret);
  checkEq('direction 2 request type / nonce / plaintext', { t: req.msg_type, nonce: req.nonce, pt: req.plaintext },
    { t: K.LINK_REQUEST, nonce: fn.request_nonce, pt: fn.request_plaintext });
  checkEq('direction 2 request rebuilt byte-for-byte',
    toHex(await K.sealLinkMessage(link.secret, K.LINK_REQUEST, X(fn.request_plaintext), X(fn.request_nonce))), fn.request);
  const rq = K.parseLinkRequest(req.plaintext);
  checkEq('direction 2 request names the new device', { dsk_pub: rq.dsk_pub, kind: rq.device_kind, bundle: rq.bundle },
    { dsk_pub: web.dsk_pub, kind: web.kind, bundle: web.bundles[0] });
  check('direction 2 request bundle valid for the new device in the offered account',
    await K.keyBundleValidFor(K.parseKeyBundle(rq.bundle), rq.dsk_pub, o.account_id));
  checkEq('direction 2 code', await K.linkCode(X(fn.link_id), req.plaintext), fn.code);
  const dekPub = await K.x25519PublicFromPrivate(X(fn.new_device_dek_sk));
  checkEq('direction 2 new_device_dek_sk is the request bundle key', toHex(dekPub), toHex(K.parseKeyBundle(rq.bundle).dek_pub));
  const me = { dsk_pub: rq.dsk_pub, device_kind: rq.device_kind, dek: await K.importDecryptionKey(X(fn.new_device_dek_sk), dekPub) };
  const res = await K.openLinkResponse(X(fn.response), link.secret, me, { account_id: o.account_id, ik_pub: o.ik_pub });
  check('direction 2 response passes the new device checks (identity from the offer)', res.ok, res.failures.join(', '));
  checkEq('direction 2 response plaintext = response_payload', res.plaintext ? new TextDecoder().decode(res.plaintext) : null, fn.response_payload);
  check('direction 2 response carries no ik (web device)', !!res.payload && !('ik' in res.payload));
  checkEq('direction 2 response cert is the web device certificate', res.cert ? toHex(res.cert.raw) : null, web.cert);
  checkEq('direction 2 sender_cert is the phone that posted the offer', toHex(K.parseLinkResponse(X(fn.response)).sender_cert.raw), phone.cert);
  const final = mainStates[L.final_seq].client;
  const circles = res.payload?.circles ?? [];
  checkEq('direction 2 response lists the one circle', circles.map(c => toHex(K.b64uDecode(c.id))), [L.circle_id]);
  for (const c of circles) {
    for (const [ep, sec] of c.epochs.entries()) {
      checkEq(`direction 2 epoch ${ep} secret matches the log`, toHex(await K.epochCommit(ep, K.b64uDecode(sec))),
        final.commits.get(ep) ? toHex(final.commits.get(ep)) : null);
    }
    checkEq('direction 2 epochs run from 0 to the circle\'s current epoch (§10)', c.epochs.length, final.epoch + 1);
  }
  const rebuilt = await K.sealLinkResponse({
    lid: X(fn.link_id), senderCert: X(phone.cert), senderSigner: phone.signer, newDeviceId: X(web.device_id),
    newDekPub: dekPub, payload: utf8(fn.response_payload), ikmE: X(fn.response_ikm),
  });
  checkEq('direction 2 response rebuilt byte-for-byte', toHex(rebuilt), fn.response);
});

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
});

// ---------------------------------------------------------------------------
// Self-tests of the sending side with fresh randomness (not from the vectors): what a real
// client does, with random message secrets, details nonces and HPKE ephemeral keys.
// ---------------------------------------------------------------------------

group('fresh round trips');
await attempt('fresh round trips', async () => {
  const st = mainStates[L.final_seq].client;
  const keysOf = d => { const k = dekByKeyId.get(toHex(d.key_id)); return new Map([[k.key_id, k.imported]]); };
  // A circle envelope from Alex to every other active device.
  const sender = devices.get('alex/phone');
  const recipients = K.activeDevices(st).filter(d => toHex(d.device_id) !== sender.device_id);
  const payload = utf8(JSON.stringify({ t: 'chat', id: K.b64uEncode(K.randomBytes(8)), text: 'dinner at 7?' }));
  const raw = await K.sealEnvelope({
    header: { kind: 1, circle_id: st.circle_id, sender_device_id: X(sender.device_id), seq: 2, sent_at: 1793808060000, ttl_s: 86400, log_head: st.head },
    recipients, payload, signer: sender.signer,
  });
  for (const d of recipients) {
    const res = await K.receiveEnvelope({ state: st, now: 1793808070000, deviceId: d.device_id, keys: keysOf(d), replay: K.newReplayRecord() }, raw);
    check(`fresh envelope opened by ${devicesById.get(toHex(d.device_id)).label}`, res.ok && bytesEqual(res.payloadBytes, payload), res.error);
  }
  // A REKEY by Jordan (an admin) with a fresh secret, processed in both modes and opened by every
  // device; the same entry from Maya (not an admin) is fatal.
  const jordan = devices.get('jordan/phone');
  const secret = K.randomBytes(32);
  const buildRekey = async dev => {
    const hdr = { type: K.ENTRY.REKEY, circle_id: st.circle_id, seq: st.seq + 1n, prev_hash: st.head, created_at: 1793808120000n, author: X(dev.device_id), epoch: st.epoch };
    const wr = await K.sealWraps(K.activeDevices(st), secret,
      r => K.epochWrapInfo(hdr.circle_id, hdr.seq, hdr.prev_hash, hdr.epoch + 1, r.device_id, r.key_id));
    return { hdr, raw: await K.buildEntry(hdr, K.serializeEntryBody(K.ENTRY.REKEY, { epoch_commit: await K.epochCommit(st.epoch + 1, secret), wraps: wr }), dev.signer) };
  };
  const { hdr: header, raw: rekey } = await buildRekey(jordan);
  const secrets = new Map(baseSecrets).set(st.epoch + 1, secret);
  const byMaya = await K.processEntry(st, (await buildRekey(devices.get('maya/phone'))).raw, { mode: 'public' });
  checkEq('fresh REKEY by a non-admin is fatal', [byMaya.result, byMaya.reason], ['fatal', 'not_admin']);
  const rc = await K.processEntry(st, rekey, { mode: 'client', secrets });
  const rp = await K.processEntry(mainStates[L.final_seq].pub, rekey, { mode: 'public' });
  checkEq('fresh REKEY outcome (client, public)', [rc.result, rp.result, rc.state.epoch], ['accepted', 'accepted', st.epoch + 1]);
  for (const d of K.activeDevices(st)) {
    const o = await K.openWrap(rc.body.wraps, d.device_id, keysOf(d),
      w => K.epochWrapInfo(header.circle_id, header.seq, header.prev_hash, header.epoch + 1, w.recipient_device_id, w.key_id));
    check(`fresh epoch wrap opened by ${devicesById.get(toHex(d.device_id)).label}`, o.secret && bytesEqual(o.secret, secret), o.error);
  }
  // A rename by Jordan in the new epoch, details sealed with a random nonce.
  const h2 ={ type: K.ENTRY.POLICY, circle_id: st.circle_id, seq: header.seq + 1n, prev_hash: rc.hash, created_at: 1793808180000n, author: X(jordan.device_id), epoch: st.epoch + 1 };
  const name = 'Rivera–Okafor family';
  const det = await K.sealDetails(secret, K.serializeEntryHeader(h2), concat(K.u8(K.POLICY_SUBTYPE.SET_CIRCLE_NAME), K.vec16(utf8(name))));
  const rename = await K.buildEntry(h2, K.serializeEntryBody(K.ENTRY.POLICY, { details: det }), jordan.signer);
  const r2 = await K.processEntry(rc.state, rename, { mode: 'client', secrets });
  checkEq('fresh rename accepted in the new epoch', [r2.result, r2.state.name], ['accepted', name]);
  const r3 = await K.processEntry(rc.state, rename, { mode: 'client', secrets: baseSecrets });
  checkEq('same rename without the new epoch secret: deferred, private state frozen at its last known values (§6.5)',
    [r3.result, r3.reason, K.stateToJSON(r3.state).name, K.stateToJSON(r3.state).private_unknown_from],
    ['deferred', null, K.stateToJSON(rc.state).name, Number(h2.seq)]);
});

// ---------------------------------------------------------------------------
// §6.5 "Missing secrets" (not covered by the vectors, which always give every secret)
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
      ...publicSubset(now), name: before.name, flags: before.flags, private_unknown_from: from,
      members: now.members.map(m => {
        const p = priv.get(m.account_id) ?? dflt;
        return { account_id: m.account_id, admin: m.admin, devices: m.devices, role: p.role, teen_until: p.teen_until, guardians: p.guardians, rules: p.rules, pauses: p.pauses };
      }),
    };
  };
  for (const sc of scenarios) {
    const { st, results } = await replayWith(sc.secrets);
    checkEq(`${sc.name}: the first deferred entry is the first one with details in that epoch`, results.findIndex(r => r.result === 'deferred'), sc.from);
    check(`${sc.name}: before it, outcomes and state match the vectors`, results.every((r, i) =>
      i >= sc.from || (r.result === L.entries[i].result && r.reason === L.entries[i].reason && canon(K.stateToJSON(r.state)) === canon(L.entries[i].state_after))));
    check(`${sc.name}: from it on, every entry is deferred (never bad_details or rejected)`,
      results.every((r, i) => i < sc.from || (r.result === 'deferred' && r.reason === null)));
    check(`${sc.name}: public state unaffected`, results.every((r, i) =>
      canon(K.stateToJSON(r.state, { publicOnly: true })) === canon(publicSubset(L.entries[i].state_after))));
    check(`${sc.name}: frozen private fields keep their last known values`, results.every((r, i) =>
      i < sc.from || canon(K.stateToJSON(r.state)) === canon(frozenExpectation(i, sc.from))));
    const resumed = await K.resumePrivate(st, baseSecrets);
    checkEq(`${sc.name}: once the secret arrives, re-running the private rules gives the full state`, K.stateToJSON(resumed), L.entries.at(-1).state_after);
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
    check(`${dc.name}: and then nothing is frozen`, K.stateToJSON(full).private_unknown_from === null);
  }
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

let totalFail = 0;
let totalPass = 0;
console.log(`Kinfold v0 vectors: ${vectorPath}\n`);
for (const [name, g] of groups) {
  totalPass += g.pass;
  totalFail += g.fail;
  console.log(`${name.padEnd(20)} ${String(g.pass).padStart(4)} passed  ${g.fail ? `${g.fail} FAILED` : ''}`);
}
console.log(`${'total'.padEnd(20)} ${String(totalPass).padStart(4)} passed  ${totalFail ? `${totalFail} FAILED` : ''}`);
if (totalFail) {
  console.log('\nFailures:');
  for (const [name, g] of groups) for (const f of g.failures) console.log(`  [${name}] ${f}`);
  process.exitCode = 1;
}
