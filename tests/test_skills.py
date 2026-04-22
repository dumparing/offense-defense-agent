"""Tests for skills (gdb_debug and disassemble)."""

import os
import unittest
from pathlib import Path

TARGETS_DIR = Path(__file__).resolve().parent.parent / "targets"
VULN_BOF = str(TARGETS_DIR / "vuln_bof")
VULN_FMT = str(TARGETS_DIR / "vuln_fmt")

HAVE_TARGETS = os.path.isfile(VULN_BOF)


@unittest.skipUnless(HAVE_TARGETS, "Targets not compiled — run: cd targets && make")
class TestGDBDebugSkill(unittest.TestCase):
    def test_execute_finds_crashes(self):
        from skills.gdb_debug import GDBDebugSkill

        skill = GDBDebugSkill()
        result = skill.execute(binary_path=VULN_BOF)
        self.assertTrue(result["success"])
        data = result["data"]
        self.assertTrue(data["any_crash"])
        self.assertGreater(data["crashes_found"], 0)

    def test_execute_with_custom_input(self):
        from skills.gdb_debug import GDBDebugSkill

        skill = GDBDebugSkill()
        result = skill.execute(binary_path=VULN_BOF, input_data="A" * 300)
        self.assertTrue(result["success"])
        self.assertTrue(result["data"]["any_crash"])

    def test_missing_binary(self):
        from skills.gdb_debug import GDBDebugSkill

        skill = GDBDebugSkill()
        result = skill.execute(binary_path="/nonexistent")
        self.assertFalse(result["success"])

    def test_missing_input_validation(self):
        from skills.gdb_debug import GDBDebugSkill

        skill = GDBDebugSkill()
        result = skill.execute()  # no binary_path
        self.assertFalse(result["success"])
        self.assertIn("Missing", result["error"])


@unittest.skipUnless(HAVE_TARGETS, "Targets not compiled — run: cd targets && make")
class TestDisassembleSkill(unittest.TestCase):
    def test_execute_vuln_bof(self):
        from skills.disassemble import DisassembleSkill

        skill = DisassembleSkill()
        result = skill.execute(binary_path=VULN_BOF)
        self.assertTrue(result["success"])
        data = result["data"]
        self.assertIn("vulnerability_patterns", data)
        vuln_types = [v["vulnerability"] for v in data["vulnerability_patterns"]]
        self.assertIn("buffer_overflow", vuln_types)

    def test_execute_vuln_fmt(self):
        from skills.disassemble import DisassembleSkill

        skill = DisassembleSkill()
        result = skill.execute(binary_path=VULN_FMT)
        self.assertTrue(result["success"])
        vuln_types = [
            v["vulnerability"] for v in result["data"]["vulnerability_patterns"]
        ]
        self.assertIn("format_string", vuln_types)

    def test_risk_level_present(self):
        from skills.disassemble import DisassembleSkill

        skill = DisassembleSkill()
        result = skill.execute(binary_path=VULN_BOF)
        self.assertIn(
            result["data"]["risk_level"],
            ("critical", "high", "medium", "low"),
        )

    def test_architecture_info(self):
        from skills.disassemble import DisassembleSkill

        skill = DisassembleSkill()
        result = skill.execute(binary_path=VULN_BOF)
        arch = result["data"]["architecture"]
        self.assertIsNotNone(arch["arch"])
        self.assertIsNotNone(arch["bits"])


if __name__ == "__main__":
    unittest.main()
