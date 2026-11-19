// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
// node:path, as far as verify.mjs uses it, for the slash-separated paths of the page's origin.
export function isAbsolute(p) {
  return p.startsWith('/');
}

export function dirname(p) {
  const i = p.replace(/\/+$/, '').lastIndexOf('/');
  return i <= 0 ? '/' : p.slice(0, i);
}

export function resolve(...parts) {
  let path = '/';
  for (const part of parts) path = part.startsWith('/') ? part : `${path}/${part}`;
  const out = [];
  for (const seg of path.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return '/' + out.join('/');
}
