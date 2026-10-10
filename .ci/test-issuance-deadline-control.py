#!/usr/bin/env python3
"""Inert evidence and restoration tests; no Cargo is invoked."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "control", Path(__file__).with_name("issuance-deadline-control.py")
)
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


def report(verdict="FAILED", pid=" (123)"):
    summary = "FAILED. 0 passed; 1 failed" if verdict == "FAILED" else "ok. 1 passed; 0 failed"
    return (f"thread '{control.TEST}'{pid} panicked at tests/global.rs:42:5:\n"
            f"{control.MARKER}\ntest {control.TEST} ... {verdict}\n"
            f"test result: {summary}; 0 ignored; 0 measured; 0 filtered out\n")


class Evidence(unittest.TestCase):
    def test_exact_owned_panic_with_and_without_process_id(self):
        for pid in ["", " (123)"]:
            self.assertTrue(control.assertion(101, report(pid=pid)))

    def test_compiler_missing_test_and_unrelated_failures_refuse(self):
        for status, output in [(0, report()), (101, ""),
                               (101, report().replace(control.TEST, "other_test")),
                               (101, report().replace(control.MARKER, "other assertion")),
                               (101, report().replace("tests/global.rs", "other.rs")),
                               (101, report().replace("0 passed; 1 failed", "0 passed; 2 failed")),
                               (101, report() + "error[E0308]"),
                               (101, report() + "could not compile")]:
            self.assertFalse(control.assertion(status, output))

    def test_baseline_requires_exactly_one_selected_success(self):
        self.assertTrue(control.baseline(0, report("ok")))
        for status, output in [(101, report("ok")), (0, ""), (0, report()),
                               (0, report("ok").replace("1 passed", "2 passed"))]:
            self.assertFalse(control.baseline(status, output))

    def test_source_restores_after_acceptance_rejection_and_exception(self):
        for outcome in [(101, report()), (101, "could not compile"), RuntimeError("interrupted")]:
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "facade.rs"
                original = b"before\n" + control.GUARD + b"\nafter\n"
                source.write_bytes(original)
                with patch.object(control, "SOURCE", source), patch.object(
                    control, "run", side_effect=[(0, report("ok")), outcome]
                ), contextlib.redirect_stdout(io.StringIO()):
                    if isinstance(outcome, RuntimeError):
                        with self.assertRaises(RuntimeError):
                            control.main()
                    elif outcome[1] == "could not compile":
                        with self.assertRaises(SystemExit):
                            control.main()
                    else:
                        control.main()
                self.assertEqual(source.read_bytes(), original)

    def test_missing_or_duplicate_guard_refuses_before_cargo(self):
        for content in [b"missing", control.GUARD * 2]:
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "facade.rs"
                source.write_bytes(content)
                with patch.object(control, "SOURCE", source), patch.object(control, "run") as run:
                    with self.assertRaises(SystemExit):
                        control.main()
                    run.assert_not_called()
                self.assertEqual(source.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
