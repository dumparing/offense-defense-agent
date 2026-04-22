"""Tests for tools.gdb_runner."""

import os
import unittest
from pathlib import Path

from tools.gdb_runner import _validate_binary, _signal_name

TARGETS_DIR = Path(__file__).resolve().parent.parent / "targets"
VULN_BOF = str(TARGETS_DIR / "vuln_bof")

HAVE_TARGETS = os.path.isfile(VULN_BOF)


class TestValidation(unittest.TestCase):
    def test_valid_binary(self):
        if not HAVE_TARGETS:
            self.skipTest("Targets not compiled")
        result = _validate_binary(VULN_BOF)
        self.assertTrue(os.path.isabs(result))

    def test_nonexistent_binary(self):
        with self.assertRaises(FileNotFoundError):
            _validate_binary("/nonexistent/file")

    def test_non_executable(self):
        # A .py file exists but isn't +x (usually)
        test_file = __file__
        if not os.access(test_file, os.X_OK):
            with self.assertRaises(PermissionError):
                _validate_binary(test_file)


class TestSignalName(unittest.TestCase):
    def test_known_signals(self):
        import signal
        self.assertEqual(_signal_name(signal.SIGSEGV), "SIGSEGV")
        self.assertEqual(_signal_name(signal.SIGABRT), "SIGABRT")

    def test_unknown_signal(self):
        name = _signal_name(999)
        self.assertIn("999", name)


@unittest.skipUnless(HAVE_TARGETS, "Targets not compiled — run: cd targets && make")
class TestGDBRunner(unittest.TestCase):
    def test_crash_detection(self):
        from tools.gdb_runner import run_gdb_analysis

        result = run_gdb_analysis(VULN_BOF, stdin_input="A" * 200)
        self.assertIsNone(result["error"])
        self.assertTrue(result["crashed"])
        self.assertIsNotNone(result["signal"])

    def test_no_crash_normal_input(self):
        from tools.gdb_runner import run_gdb_analysis

        result = run_gdb_analysis(VULN_BOF, stdin_input="hello")
        self.assertIsNone(result["error"])
        self.assertFalse(result["crashed"])

    def test_nonexistent_binary_error(self):
        from tools.gdb_runner import run_gdb_analysis

        with self.assertRaises(FileNotFoundError):
            run_gdb_analysis("/nonexistent/binary")


if __name__ == "__main__":
    unittest.main()
