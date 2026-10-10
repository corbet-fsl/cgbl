#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"

rustc --version
cargo fmt --all --check
node --test .github/check-pins.test.mjs
cargo metadata --locked --format-version 1 > dependency-metadata.json
node .github/check-pins.mjs dependency-metadata.json
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --all-features -- -D warnings
python3 -B .ci/test-issuance-deadline-control.py
python3 -B .ci/issuance-deadline-control.py
cargo test --locked -- --nocapture
cargo test --locked --all-features -- --nocapture
cargo test --locked --release --all-features

mkdir -p examples
if [ -e examples/development_gate_probe.rs ]; then
  echo 'examples/development_gate_probe.rs already exists; refusing to overwrite' >&2
  exit 2
fi
cp .ci/development_gate_probe.rs examples/development_gate_probe.rs
cleanup_probe() { rm -f examples/development_gate_probe.rs; }
trap cleanup_probe EXIT
if CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true cargo check --locked --release --all-features --example development_gate_probe > release-probe.log 2>&1; then
  echo 'The development gate must not compile in release builds' >&2
  exit 1
fi
cat release-probe.log
grep -F 'could not find `development` in `cgbl`' release-probe.log
trap - EXIT
cleanup_probe

cargo metadata --locked --format-version 1 > dependency-metadata.json
node .github/check-licenses.mjs
node .github/check-pins.mjs dependency-metadata.json

python3 .github/check-first-party.py

export CARGO_PROFILE_TEST_OPT_LEVEL='0'
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
# Bug 2 isolation: llvm-cov derives its target dir from the ambient shared
# cargo target, embedding this job's checkout path in coverage data; the next
# job's gate then refuses the foreign paths (cgbl 283/13). Scope the coverage
# target to this job only (native gates above keep the shared warm target).
# Outside the source worktree per the resolve invariant; cleaned on exit.
coverage_target="$(mktemp -d)"
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
printf 'coverage-setup pwd=%s coverage_target=%s\n' "$PWD" "$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --version
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '/tests/' --json --output-path coverage.json 2>&1
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov 2>&1
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --text --output-path coverage.txt 2>&1
cp coverage.json coverage.lcov coverage.txt "$ARTIFACT_ROOT/"
python3 .github/test-source-coverage.py 2>&1
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt 2>&1
