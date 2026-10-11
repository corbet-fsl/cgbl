// Inert metadata exercises the original CLI; no Cargo or network is invoked.
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const checker = resolve('.github/check-licenses.mjs');
const registry = 'registry+https://github.com/rust-lang/crates.io-index';
function check(packages, accepted) {
  const directory = mkdtempSync(join(tmpdir(), 'cgbl-license-fixture-'));
  writeFileSync(join(directory, 'dependency-metadata.json'), JSON.stringify({ packages }));
  const result = spawnSync(process.execPath, [checker], { cwd: directory, encoding: 'utf8' });
  assert.equal(result.status, accepted ? 0 : 1, result.stderr);
}
const packages = [
  ...['base64urlsafedata', 'webauthn-attestation-ca', 'webauthn-authenticator-rs',
    'webauthn-rs', 'webauthn-rs-core', 'webauthn-rs-proto'].map(name =>
    ({ name, version: '0.5.5', source: registry, license: 'MPL-2.0' })),
  { name: 'blake3', version: '1.8.7', source: registry,
    license: 'CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception' },
  { name: 'borrow-or-share', version: '0.2.4', source: registry, license: 'MIT-0' },
  { name: 'finl_unicode', version: '1.5.0', source: registry,
    license: '(MIT OR Apache-2.0) AND Unicode-DFS-2016' },
  ...['cblc', 'cgts', 'cplc'].map(name => ({ name, version: '0.0.0',
    source: `git+https://git.corbet.ch/corbet-libs/${name}?branch=main#${'a'.repeat(40)}`,
    license: 'FSL-1.1-ALv2' })),
];
check(packages, true);
for (const item of packages) {
  check([{ ...item, name: `unreviewed-${item.name}` }], false);
  check([{ ...item, version: '99.0.0' }], false);
  check([{ ...item, license: 'GPL-3.0-only' }], false);
  check([{ ...item, source: 'registry+https://unreviewed.example/index' }], false);
  check([{ ...item, source: null }], false);
}
check([{ name: 'cgbl', source: null, license: 'FSL-1.1-ALv2' }], true);
check([{ name: 'cgbl', source: registry, license: 'FSL-1.1-ALv2' }], false);
for (const suffix of ['?branch=v01#' + 'a'.repeat(40), '?branch=main#a',
  '?branch=main#' + 'a'.repeat(40) + '-extra']) {
  check([{ ...packages.at(-1), source: 'git+https://git.corbet.ch/corbet-libs/cplc' + suffix }], false);
}
check([{ name: 'original-permissive', license: 'MIT' }], true);
check([{ name: 'unknown', license: null }], false);
console.log('Reviewed exact packages and rejected altered license/source/version identities');
