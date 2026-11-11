// Reviewed expressions from the locked graph. Unknown licenses require review.
// For dual licenses, select the permissive alternative (including self_cell).
import { readFileSync } from 'node:fs';

const allowed = new Set([
  "MIT OR Apache-2.0 OR Zlib",
  "CC0-1.0 OR MIT-0 OR Apache-2.0",
  "ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)",
  "ISC AND (Apache-2.0 OR ISC)",
  "(MIT OR Apache-2.0) AND Unicode-3.0",
  "0BSD",
  "0BSD OR MIT OR Apache-2.0",
  "Apache-2.0",
  "Apache-2.0 / MIT",
  "Apache-2.0 AND ISC",
  "Apache-2.0 OR GPL-2.0-only",
  "Apache-2.0 OR ISC OR MIT",
  "Apache-2.0 OR MIT",
  "Apache-2.0 WITH LLVM-exception",
  "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
  "Apache-2.0/MIT",
  "BSD-2-Clause OR Apache-2.0 OR MIT",
  "BSD-2-Clause OR MIT OR Apache-2.0",
  "BSD-3-Clause",
  "BSL-1.0",
  "CC0-1.0",
  "CDLA-Permissive-2.0",
  "ISC",
  "LGPL-3.0-only WITH LGPL-3.0-linking-exception",
  "MIT",
  "MIT OR Apache-2.0",
  "MIT OR Apache-2.0 OR BSD-1-Clause", // fiat-crypto: select MIT.
  "MIT OR Apache-2.0 OR LGPL-2.1-or-later",
  "MIT OR Apache-2.0 WITH LLVM-exception",
  "MIT OR Zlib OR Apache-2.0",
  "MIT/Apache-2.0",
  "Unicode-3.0",
  "Unlicense OR MIT",
  "Unlicense/MIT",
  "Zlib",
  "Zlib OR Apache-2.0 OR MIT"
]);
const metadata = JSON.parse(readFileSync('dependency-metadata.json', 'utf8'));
// These additions are confined to the reviewed packages and original sources.
// Preserve upstream notices in docs/licenses; unknown versions need review.
const registry = "registry+https://github.com/rust-lang/crates.io-index";
const reviewed = new Map([
  ["base64urlsafedata", ["0.5.5", "MPL-2.0"]],
  ["webauthn-attestation-ca", ["0.5.5", "MPL-2.0"]],
  ["webauthn-authenticator-rs", ["0.5.5", "MPL-2.0"]],
  ["webauthn-rs", ["0.5.5", "MPL-2.0"]],
  ["webauthn-rs-core", ["0.5.5", "MPL-2.0"]],
  ["webauthn-rs-proto", ["0.5.5", "MPL-2.0"]],
  ["blake3", ["1.8.7", "CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception"]],
  ["borrow-or-share", ["0.2.4", "MIT-0"]],
  ["finl_unicode", ["1.5.0", "(MIT OR Apache-2.0) AND Unicode-DFS-2016"]],
]);
const owned = new Set(["cblc", "cgts", "cplc"]);
function reviewedPackage(p) {
  if (p.name === "cgbl" && p.source == null && p.license === "FSL-1.1-ALv2") return true;
  if (owned.has(p.name) && p.version === "0.0.0" && p.license === "FSL-1.1-ALv2") {
    const prefix = `git+https://git.corbet.ch/corbet-fsl/${p.name}?branch=main#`;
    return typeof p.source === "string" && p.source.startsWith(prefix)
      && /^[0-9a-f]{40}$/.test(p.source.slice(prefix.length));
  }
  const entry = reviewed.get(p.name);
  return p.source === registry && entry !== undefined
    && p.version === entry[0] && p.license === entry[1];
}
const rejected = metadata.packages.filter(p => !allowed.has(p.license) && !reviewedPackage(p));
for (const p of rejected) {
  console.error(`Unreviewed license: ${p.name} ${p.version}: ${p.license ?? 'missing'}`);
}
if (rejected.length) process.exit(1);
console.log(`Reviewed license expressions for ${metadata.packages.length} locked packages`);
