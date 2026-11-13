// SPDX-License-Identifier: AGPL-3.0-or-later

// The share-link viewer (API.md §11): it takes the secret from the address's fragment,
// which never reaches the server, fetches the link's latest update and shows it.

import { b64uDecode, b64uEncode, linkId, shareKey, openUpdate } from './share.js';

const $ = id => document.getElementById(id);
const sleep = ms => new Promise(r => setTimeout(r, ms));

function say(text) {
  $('status').textContent = text;
}

function ended() {
  $('where').hidden = true;
  $('open').hidden = true;
  say('This link has ended.');
}

function ago(ts) {
  const min = Math.round((Date.now() - ts) / 60000);
  if (min < 1) return 'just now';
  if (min < 60) return `${min} min ago`;
  return new Date(ts).toLocaleString();
}

function show(p) {
  if (!Number.isInteger(p.lat) || !Number.isInteger(p.lon) || !Number.isInteger(p.ts)) {
    return;
  }
  const lat = (p.lat / 1e7).toFixed(5), lon = (p.lon / 1e7).toFixed(5);
  if (typeof p.name === 'string' && p.name !== '') {
    $('name').textContent = p.name; // text, never markup
  }
  $('pos').textContent = `${lat}, ${lon}`;
  $('acc').textContent = Number.isInteger(p.acc) ? `within ${p.acc} m${p.prec === 'approx' ? ' (approximate)' : ''}` : '';
  $('when').textContent = ago(p.ts);
  $('geo').href = `geo:${lat},${lon}`;
  $('where').hidden = false;
  $('open').hidden = false;
  say('');
}

async function main() {
  let secret;
  try {
    secret = b64uDecode(location.hash.slice(1));
  } catch {
    secret = null;
  }
  if (!secret || secret.length !== 16) {
    say('This link is incomplete: copy the whole address, including the part after #.');
    return;
  }
  const id = await linkId(secret);
  const key = await shareKey(secret);
  const latest = `/v1/shares/${b64uEncode(id)}/latest`;
  let after = 0n;
  let expiresAt = 0;
  for (;;) {
    if (expiresAt && Date.now() >= expiresAt) {
      return ended();
    }
    let res;
    try {
      res = await fetch(`${latest}?after=${after}&wait=25`,
        { cache: 'no-store', referrerPolicy: 'no-referrer', headers: { 'Kinfold-Api': '1' } });
    } catch {
      say('Can’t reach the server; trying again.');
      await sleep(10000);
      continue;
    }
    if (res.status === 404 || res.status === 410) {
      return ended();
    }
    if (res.status === 200) {
      try {
        const u = await openUpdate(key, id, new Uint8Array(await res.arrayBuffer()));
        if (u.seq > after) { // only newer updates count
          after = u.seq;
          expiresAt = u.expiresAt;
          show(u.payload);
        }
      } catch {
        await sleep(10000); // an update that doesn't open is ignored
      }
    } else if (res.status !== 204) {
      await sleep(10000);
    }
  }
}

main();
