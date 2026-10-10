#!/usr/bin/env python3
"""Require a real protocol assertion when deadline callback refusal is ignored."""
import os
from pathlib import Path
import re
import subprocess

SOURCE = Path("src/facade.rs")
GUARD = b"guard(PendingIssuanceDeadline {\n            inclusive: pending.deadline,\n        })?;"
WEAKENED = b"let _ = guard(PendingIssuanceDeadline {\n            inclusive: pending.deadline,\n        });"
TEST = "refusing_the_deadline_guard_preserves_the_nonce_and_first_holder_binding"
MARKER = "a refusing deadline guard must stop issuance before nonce consumption"


def run():
    result = subprocess.run(
        ["cargo", "test", "--locked", "--all-features", "--test", "global", TEST,
         "--", "--exact", "--nocapture"], capture_output=True, text=True, timeout=900,
        env={**os.environ, "CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"},
    )
    return result.returncode, result.stdout + result.stderr


def selected(output, verdict):
    return re.search(r"^test " + re.escape(TEST) + r" \.\.\. " + verdict + r"$",
                     output, re.M) is not None


def baseline(status, output):
    return (status == 0 and selected(output, "ok")
            and "test result: ok. 1 passed; 0 failed; 0 ignored;" in output)


def assertion(status, output):
    return (status == 101 and selected(output, "FAILED")
            and "test result: FAILED. 0 passed; 1 failed; 0 ignored;" in output
            and re.search(r"thread '" + re.escape(TEST)
                          + r"'(?: \([0-9]+\))? panicked at tests/global\.rs:[0-9]+:[0-9]+:", output)
            and MARKER in output and "error[E" not in output
            and "could not compile" not in output)


def main():
    original = SOURCE.read_bytes()
    if original.count(GUARD) != 1:
        raise SystemExit("Issuance deadline control source drift")
    status, output = run()
    if not baseline(status, output):
        print(output)
        raise SystemExit("Issuance deadline control needs a passing exact baseline")
    try:
        SOURCE.write_bytes(original.replace(GUARD, WEAKENED))
        status, output = run()
        if not assertion(status, output):
            print(output)
            raise SystemExit("Ignored deadline refusal did not fail its exact protocol assertion")
        print("Ignored issuance deadline refusal rejected by real protocol assertion")
    finally:
        SOURCE.write_bytes(original)
    if SOURCE.read_bytes() != original:
        raise SystemExit("Issuance deadline source restoration failed")


if __name__ == "__main__":
    main()
