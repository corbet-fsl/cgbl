# Coverage contract

CI targets 100% of reachable production lines and branches. Stable Rust runs
the existing native and wasm checks. Nightly Rust is used only for LLVM branch
instrumentation, which currently requires it. Both jobs use the same resolved
Cargo.lock snapshot; all build and test commands after resolution use --locked.

The coverage job executes real tests with cargo-llvm-cov and retains the raw JSON
even when the gate fails. The checker compares integer covered/total counts for
both metrics; rounded percentages cannot pass. An empty report cannot pass.
The report excludes integration-test harness files under tests/, not production
code. Three exact unreachable native branch arms are excluded as documented below.

A failing gate is missing evidence, not permission to lower the threshold or
change domain behavior. Add meaningful failure and round-trip tests. Document
any genuinely unreachable defensive branch precisely before excluding it. Native
coverage does not establish browser execution; keep the actual wasm vectors.

First-party declarations follow main. Their resolved full revisions remain in
Cargo.lock, with exactly one source per first-party crate. Final verification
uses the committed resolution with --locked; it does not refresh dependencies.
Dependency updates are separate candidates and must retain their tested lockfile.
The coverage result applies to that exact source and dependency snapshot.

## Emitted source metric

The acceptance metric is now 100% of upstream LLVM LCOV's emitted production
source line counters (DA) and branch counters (BRDA), from the same execution as
the retained raw JSON. This is source coverage, not every generic instantiation.
LLVM JSON and LCOV summary totals can count generic copies differently from
the merged source records. The original JSON checker remains diagnostic code;
its stricter instantiation totals are not described as passed.

The source gate requires a nonempty report, an exact file inventory matching the
companion JSON, matching raw summary metadata, complete emitted branch counts
and no duplicate, unknown or zero counters. Raw reports retain every production counter. The three precise branch exceptions below are applied only after validating the complete report inventories.
Actual browser/device execution remains separate from native coverage.

The coverage job sets `CARGO_PROFILE_TEST_OPT_LEVEL=0` for this workspace. The
ordinary native/performance and release/browser profiles are unchanged; the
existing upstream pairing dependency optimization override remains. An earlier
optimized profile reported zero for an accessor exercised by real assertions.
The [rustc coverage guide](https://doc.rust-lang.org/rustc/instrument-coverage.html)
explains that optimizing functions away can invalidate coverage mapping. This
measurement configuration retains owned bodies instead of excluding them. It
is a diagnostic correction, not evidence that the remaining gaps are covered.

## Proposed invariant exceptions

These are source-bound exclusions used by the gate, not covered branches or
independent security acceptance. The original evidence run
36938685007,
head `1ed3789b427ff9877e05a45f610ca411be05fb74`, executed all 1,057
production lines and 229 of 232 emitted branch arms. Ordinary native,
all-feature, strict Clippy and release suites passed. The real cached-publication
concurrent-write test now executes the previously missing revision-conflict line;
no race, storage error, cryptographic error or resource failure is excluded.

Only these three native arms are excluded:

- `src/facade.rs:197`, block 0 arm 0: `gate.gate == "development"` cannot be true
  here in production mode. `Global::open` rejects any production issuer whose
  catalogue contains that gate. `install_policy` first rejects gates absent from
  the same catalogue at line 189. The issuer is a private, owned field with no
  replacement API. The exact CPSD source bound in the manifest gives its public
  key private fields and read-only catalogue access. The other reserved-provider
  arm is reachable and executed; it remains required.
- `src/facade.rs:709`, block 0 arm 1: an issuer mismatch cannot arise from this
  private cache. Its sole installation path is `signed_status`, which constructs
  `Status.issuer_public_key` from the immutable `self.binding.issuer`, signs that
  payload, and installs those exact bytes. The cache starts empty on every open;
  neither the cache nor the binding has a public mutable accessor or importer.
  The bound Beacon implementation retains the exact installed signed bytes in an
  immutable `Arc<[u8]>`; the bound Signatures implementation authenticates those
  payload bytes. Imported storage binding changes are refused by `read` before
  the cache path. Tests exercise policy-version rollback, changed shared expiry,
  valid cache reuse, actual signer invalidation and concurrent storage changes.
- `src/facade.rs:799`, block 0 arm 0: a scope mismatch is impossible after the two
  preceding checks. The first requires `ring.issuer() == format!("cgbl:{scope}")`;
  `validate_publication` then requires that same issuer to equal the same literal
  prefix plus `value.scope`. Prefix concatenation is injective. The bound key-ring
  API returns an immutable issuer string and this code cannot change it. Epoch
  and revision refusal arms on the same compound condition remain required.

Each exception binds the exact source line/arm, the SHA-256 of the complete owned
source file and the unique full Git identity of relevant upstream packages in
Cargo.lock. An upstream change requires renewed proof; unrelated dependency
refreshes do not silently invalidate or broaden the exception. The checker still
reconciles raw JSON, LCOV and annotated source before subtracting only these
three arms. All emitted production lines remain required. Seventeen checker regressions cover
missing/duplicate counters, changed source, package identity drift and invalid
exceptions. No production code was changed to satisfy these proofs.

Upstream evidence: [CPSD immutable issuer API](https://github.com/corbet-foss/cpsd/blob/a23616e906ffa924aa5bda667e7ea1edf3a692d4/src/issuer.rs),
[Beacon exact-byte cache](https://github.com/corbet-foss/cbcn/blob/53ed942cdc1439fcedbc9914cf6cc44f83020d29/src/document.rs),
[Signatures](https://github.com/corbet-foss/csgn/tree/fac7f49eeb4e4bb9b72de640b46e55d8fe99119c).

Payment-adapter dependency refresh (2026-10-10): rechecked the existing three
proofs against CPSD `da700af6`, Beacon `d374cf91`, and Signatures `427b82cd`.
CPSD's `src/issuer.rs` and the complete Beacon/Signatures `src` trees have no
diff from the previously recorded proof revisions. Their private fields,
immutable accessors and authenticated exact-byte cache retain the invariants
above. Only the recorded dependency identities changed; no exception was added.

## Earlier measured result

Crow 283/30 at `16f00aba` reported 1,199/1,199 production source lines and
237/237 required branch arms. The raw branch result is 237/240 (98.75%);
subtracting the three source-bound unreachable arms gives the enforced 100%.
The older counts above describe the original invariant review, not current totals.


Reviewed contact/self-ban integration refresh (2026-10-11): the exact original
three defensive arms remain unchanged at lines 193, 728 and 818. The facade now
has read-only contact authorization, original-account status/eligibility access,
and permanent self-ban for a wallet before its first gate. These additions do
not replace the private issuer binding, add a cache importer, or alter policy
catalogue validation, signed_status construction, or scope-prefix validation.
The same locked CPSD, Beacon and Signatures identities remain in this owner's
Cargo.lock. Only the complete facade evidence hash and two relocated line
numbers were refreshed; no new line, branch, category or threshold is excluded.

Actual Crow 283/36 at 20205a56 passed 47 default native tests plus four doctests,
and 64 development native tests plus four doctests. Coverage stopped at the
stale source-evidence hash before validating the new coverage result. These
native results do not establish current complete source coverage or browser
qualification.

Wallet publication-owner refresh (2026-10-11): the facade gained only the
crate-private wallet instance token, wallet barrier and store visibility. The
three defensive arms are unchanged and moved to lines 197, 732 and 822. Only the
complete facade evidence hash and these line numbers were refreshed; no new line,
branch, category or threshold is excluded.

Dependency identity re-review (2026-10-11): the bound CPSD now locks 3a9c9c1
and CBCN 3ff7de1. CPSD still gives `IssuerPublicKey` private fields with the
read-only `gates()` accessor and no replacement API, so the line 197 argument
holds. The CBCN change is additive (balance and root-board documents); the
exact-bytes status cache and its sole `signed_status` installation path are
unchanged, so the line 732 argument holds. The third arm needs no upstream
package. No line, branch, category or threshold was added or broadened.

Operator-suspension removal refresh (2026-10-11): the temporary suspension, warning
flag and operator `warn` were deleted; only the legal-order and self-ban permanent
suspensions remain. The three defensive arms are unchanged and moved to lines 197, 709, 799. Only the complete facade evidence hash and line numbers were refreshed;
no new line, branch, category or threshold is excluded.
