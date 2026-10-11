# Dependency licenses

The package license remains FSL-1.1-ALv2. Third-party source retains its
original grants and notices. The license checker keeps the existing expression
list and confines the following additions to exact reviewed package versions
and their original registry or canonical first-party source.

| Packages | Version | Declared license and selection |
| --- | --- | --- |
| base64urlsafedata; webauthn-attestation-ca; webauthn-authenticator-rs; webauthn-rs; webauthn-rs-core; webauthn-rs-proto | 0.5.5 | MPL-2.0; original files remain under MPL |
| blake3 | 1.8.7 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception; select Apache-2.0 |
| borrow-or-share | 0.2.4 | MIT-0 |
| finl_unicode | 1.5.0 | (MIT OR Apache-2.0) AND Unicode-DFS-2016; select MIT and retain Unicode notices |
| cblc; cgts; cplc | 0.0.0, canonical main | FSL-1.1-ALv2; separately owned packages keep their original license |

The WebAuthn packages come from the original
[webauthn-rs repository](https://github.com/kanidm/webauthn-rs).
The unmodified versioned sources are available in each original crates.io
package archive, for example
[webauthn-rs 0.5.5](https://crates.io/api/v1/crates/webauthn-rs/0.5.5/download).
Their source remains available under the
[Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/).
No upstream WebAuthn file is relicensed by this package.

[MIT-0](https://spdx.org/licenses/MIT-0.html) grants use, copying, modification,
distribution and sublicensing without the MIT attribution paragraph. The
original borrow-or-share notice is retained in
[licenses/borrow-or-share-LICENSE](licenses/borrow-or-share-LICENSE).

The checksum-verified finl_unicode 1.5.0 archive declares Unicode-DFS-2016
but its LICENSE-UNICODE file contains Unicode License V3 (1991–2023).
The checker preserves the declared expression. The unmodified shipped
[Unicode notice](licenses/finl_unicode-LICENSE-UNICODE) and
[MIT notice](licenses/finl_unicode-LICENSE-MIT) remain with these docs;
the declared [Unicode-DFS-2016 terms](https://spdx.org/licenses/Unicode-DFS-2016.html)
also require preservation of the copyright and permission notice in copies
or associated documentation. Unicode's name must not be used to promote the
software without permission. Distributors must preserve these applicable
upstream notices; the package's own license does not replace them.

The retained license files were read from original crates.io archives whose
SHA-256 values match Cargo.lock:

| Package | Archive SHA-256 |
| --- | --- |
| borrow-or-share 0.2.4 | dc0b364ead1874514c8c2855ab558056ebfeb775653e7ae45ff72f28f8f3166c |
| finl_unicode 1.5.0 | 80bb028c8b4148c9ee0cca68fcd9add6044e81d3619f48577ddf13a263d047a2 |

For these added expressions, unknown package versions or replacement sources
still refuse; unknown license expressions also refuse.
These license checks do not replace advisory review or execution tests.
