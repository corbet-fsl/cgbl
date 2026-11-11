#!/usr/bin/env python3
"""Select only the locked original Keyhole owner's existing native environment."""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

packages = json.loads(Path(sys.argv[1]).read_text())["packages"]
selected = [package for package in packages if package["name"] == "ckyh"]
if len(selected) != 1:
    raise SystemExit("Expected exactly one actual Keyhole owner")
package = selected[0]
match = re.fullmatch(
    r"git\+https://git\.corbet\.ch/corbet-libre/ckyh\?branch=main#([0-9a-f]{40})",
    package.get("source") or "",
)
if not match:
    raise SystemExit("Keyhole owner source differs")
manifest = Path(package["manifest_path"])
if not manifest.is_absolute() or not manifest.is_file():
    raise SystemExit("Actual Keyhole source is unavailable")
root = manifest.resolve().parent
revision = match[1]
head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
if head != revision:
    raise SystemExit("Actual Keyhole checkout differs from the locked owner")
shell = root / ".ci/check-shell.nix"
original = subprocess.check_output(["git", "-C", str(root), "show", revision + ":.ci/check-shell.nix"])
if not shell.is_file() or shell.read_bytes() != original:
    raise SystemExit("Actual original Keyhole shell differs from its committed bytes")
if hashlib.sha256(original).hexdigest() != "ad10a14b9173db3cbba9bd8489926934658a07068c9a7469f4625d7ef219553b":
    raise SystemExit("Original reviewed native environment differs")
print(shell)
