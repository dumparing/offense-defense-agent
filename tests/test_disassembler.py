"""Tests for tools.disassembler."""

import os
import unittest
from pathlib import Path

# Skip these tests if target binaries aren't compiled
TARGETS_DIR = Path(__file__).resolve().parent.parent / "targets"
VULN_BOF = str(TARGETS_DIR / "vuln_bof")
VULN_FMT = str(TARGETS_DIR / "vuln_fmt")
VULN_UAF = str(TARGETS_DIR / "vuln_uaf")
VULN_HEAP = str(TARGETS_DIR / "vuln_heap")

HAVE_TARGETS = all(
    os.path.isfile(p) for p in [VULN_BOF, VULN_FMT, VULN_UAF, VULN_HEAP]
)


@unittest.skipUnless(HAVE_TARGETS, "Targets not compiled — run: cd targets && make")
class TestDisassembler(unittest.TestCase):
    def test_disassemble_finds_functions(self):
        from tools.disassembler import disassemble_binary

        result = disassemble_binary(VULN_BOF)
        self.assertIsNone(result["error"])
        func_names = [f["name"] for f in result["functions"]]
        self.assertIn("main", func_names)
        self.assertIn("vulnerable_function", func_names)

    def test_vuln_bof_detects_gets(self):
        from tools.disassembler import disassemble_binary

        result = disassemble_binary(VULN_BOF)
        func_names = [c["function"] for c in result["dangerous_calls"]]
        self.assertIn("gets", func_names)

    def test_vuln_bof_detects_buffer_overflow_pattern(self):
        from tools.disassembler import disassemble_binary

        result = disassemble_binary(VULN_BOF)
        vuln_types = [v["vulnerability"] for v in result["vulnerability_patterns"]]
        self.assertIn("buffer_overflow", vuln_types)

    def test_vuln_fmt_detects_format_string(self):
        from tools.disassembler import disassemble_binary

        result = disassemble_binary(VULN_FMT)
        vuln_types = [v["vulnerability"] for v in result["vulnerability_patterns"]]
        self.assertIn("format_string", vuln_types)

    def test_vuln_uaf_detects_use_after_free(self):
        from tools.disassembler import disassemble_binary

        result = disassemble_binary(VULN_UAF)
        vuln_types = [v["vulnerability"] for v in result["vulnerability_patterns"]]
        self.assertIn("use_after_free", vuln_types)

    def test_vuln_heap_detects_strcpy(self):
        from tools.disassembler import disassemble_binary

        result = disassemble_binary(VULN_HEAP)
        func_names = [c["function"] for c in result["dangerous_calls"]]
        self.assertIn("strcpy", func_names)

    def test_binary_info_arch(self):
        from tools.disassembler import get_binary_info

        info = get_binary_info(VULN_BOF)
        self.assertIn(info["arch"], ("x86_64", "i386", "arm64", "ARM"))
        self.assertIn(info["bits"], (32, 64))
        self.assertIsNotNone(info["endian"])

    def test_binary_info_stripped(self):
        from tools.disassembler import get_binary_info

        info = get_binary_info(VULN_BOF)
        # Compiled with -g, should not be stripped
        self.assertFalse(info["stripped"])

    def test_get_strings(self):
        from tools.disassembler import get_strings

        result = get_strings(VULN_BOF)
        self.assertIsNone(result["error"])
        # On macOS, strings may be in the .dSYM bundle, so total could be 0
        self.assertIsInstance(result["total_strings"], int)

    def test_nonexistent_binary(self):
        from tools.disassembler import disassemble_binary

        with self.assertRaises(FileNotFoundError):
            disassemble_binary("/nonexistent/binary")


class TestDisassemblerNoFormat(unittest.TestCase):
    """Test that printf-only binaries without input sources don't get flagged."""

    def test_no_false_positive_without_input(self):
        from tools.disassembler import _analyze_vulnerability_patterns

        # Simulate a binary that only has printf (no user input)
        dangerous_calls = [
            {"function": "printf", "category": "format_string",
             "address": "0x1000", "severity": "medium",
             "description": "printf"}
        ]
        patterns = _analyze_vulnerability_patterns("", dangerous_calls)
        vuln_types = [p["vulnerability"] for p in patterns]
        # printf alone should NOT produce a format_string vulnerability
        self.assertNotIn("format_string", vuln_types)


if __name__ == "__main__":
    unittest.main()
