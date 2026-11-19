// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
// node:url, as far as verify.mjs uses it: a module's URL becomes its path on the page's origin.
export function fileURLToPath(url) {
  return decodeURIComponent(new URL(url).pathname);
}
