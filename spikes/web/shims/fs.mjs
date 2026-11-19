// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
// node:fs/promises, as far as verify.mjs uses it: files are fetched from the page's own origin.
export async function readFile(path, encoding) {
  const r = await fetch(new URL(path, location.origin), { cache: 'no-store' });
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return encoding ? r.text() : new Uint8Array(await r.arrayBuffer());
}

export async function access(path) {
  const r = await fetch(new URL(path, location.origin), { method: 'HEAD', cache: 'no-store' });
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
}
