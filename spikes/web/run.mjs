// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
// Runs reference/js/verify.mjs, unchanged, in the browser, and shows what it prints.
const out = document.getElementById('out');
const verdict = document.getElementById('verdict');
const copy = document.getElementById('copy');
document.getElementById('browser').textContent = navigator.userAgent;

const lines = [];
const show = (...args) => {
  const line = args.map(String).join(' ');
  lines.push(line);
  out.textContent += line + '\n';
};
console.log = show;
console.error = show;
console.warn = show;

// What verify.mjs reads of Node's process: the vectors' path, the working directory, the exit code.
globalThis.process = { argv: ['browser', 'verify.mjs', 'spec/vectors/kinfold-v0.json'], cwd: () => '/', exitCode: undefined, env: {} };

function finish(text, ok) {
  verdict.textContent = text;
  verdict.className = ok ? 'pass' : 'fail';
  copy.disabled = false;
}

copy.addEventListener('click', async () => {
  const text = [navigator.userAgent, verdict.textContent, '', ...lines].join('\n');
  try {
    await navigator.clipboard.writeText(text);
    copy.textContent = 'Copied';
  } catch {
    copy.textContent = 'Copying failed: select the text below instead';
  }
});

if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
  finish("This page has no WebCrypto: open it over https, or from localhost on this device.", false);
} else {
  try {
    await import('../../reference/js/verify.mjs');
    if (process.exitCode) finish('Some checks failed: see the list below.', false);
    else finish('Every check passed.', true);
  } catch (e) {
    show(String(e && e.stack || e));
    finish('The checks stopped with an error: see below.', false);
  }
}
