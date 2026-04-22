"""Tests for agent.agent — planner and chain logic."""

import os
import unittest
from pathlib import Path

from agent.agent import SecurityAgent, KEYWORD_SKILL_MAP
from core.memory_manager import MemoryManager
from core.skill_registry import SkillRegistry
from skills.gdb_debug import GDBDebugSkill
from skills.disassemble import DisassembleSkill
from skills.network_scan import NetworkScanSkill

TARGETS_DIR = Path(__file__).resolve().parent.parent / "targets"
VULN_BOF = str(TARGETS_DIR / "vuln_bof")
HAVE_TARGETS = os.path.isfile(VULN_BOF)


class TestKeywordFallback(unittest.TestCase):
    """Test the keyword-based planner fallback."""

    def _make_agent(self):
        registry = SkillRegistry()
        registry.register(GDBDebugSkill())
        registry.register(DisassembleSkill())
        registry.register(NetworkScanSkill())
        return SecurityAgent(registry)

    def test_scan_keywords(self):
        agent = self._make_agent()
        plan = agent._keyword_fallback(
            "scan the target for open ports", {"target_ip": "127.0.0.1"}
        )
        self.assertEqual(plan["skill"], "network_scan")

    def test_debug_keywords(self):
        agent = self._make_agent()
        plan = agent._keyword_fallback(
            "debug this binary for crashes",
            {"binary_path": "/tmp/test"},
        )
        self.assertEqual(plan["skill"], "gdb_debug")

    def test_chain_avoids_repeat(self):
        """After gdb_debug has been used, fallback should pick disassemble."""
        agent = self._make_agent()
        # Simulate having already used gdb_debug
        agent.memory.record_action(
            skill="gdb_debug",
            arguments={"binary_path": "/tmp/test"},
            success=True,
            summary="Found crashes",
        )
        plan = agent._keyword_fallback(
            "continue analyzing the binary",
            {"binary_path": "/tmp/test"},
        )
        self.assertEqual(plan["skill"], "disassemble")

    def test_chain_stops_after_both_skills(self):
        """After both skills used, fallback should return 'none'."""
        agent = self._make_agent()
        agent.memory.record_action(
            skill="gdb_debug", arguments={}, success=True, summary=""
        )
        agent.memory.record_action(
            skill="disassemble", arguments={}, success=True, summary=""
        )
        plan = agent._keyword_fallback(
            "continue analyzing the binary",
            {"binary_path": "/tmp/test"},
        )
        self.assertEqual(plan["skill"], "none")


@unittest.skipUnless(HAVE_TARGETS, "Targets not compiled")
class TestAgentChain(unittest.TestCase):
    """Integration test: run a full chain on a vulnerable binary."""

    def test_chain_completes(self):
        registry = SkillRegistry()
        registry.register(GDBDebugSkill())
        registry.register(DisassembleSkill())
        memory = MemoryManager()
        agent = SecurityAgent(registry, memory=memory)

        result = agent.run_chain(
            "Analyze vuln_bof for vulnerabilities",
            context={"binary_path": VULN_BOF},
            max_steps=4,
        )

        self.assertGreater(result["total_steps"], 1)
        skills_used = result["final_report"]["skills_used"]
        self.assertIn("gdb_debug", skills_used)
        self.assertIn("disassemble", skills_used)

    def test_chain_finds_vulnerabilities(self):
        registry = SkillRegistry()
        registry.register(GDBDebugSkill())
        registry.register(DisassembleSkill())
        memory = MemoryManager()
        agent = SecurityAgent(registry, memory=memory)

        result = agent.run_chain(
            "Analyze vuln_bof",
            context={"binary_path": VULN_BOF},
            max_steps=4,
        )

        vulns = result["final_report"]["vulnerabilities"]
        vuln_types = [v["vulnerability"] for v in vulns]
        self.assertIn("buffer_overflow", vuln_types)

    def test_chain_has_crash_data(self):
        registry = SkillRegistry()
        registry.register(GDBDebugSkill())
        registry.register(DisassembleSkill())
        memory = MemoryManager()
        agent = SecurityAgent(registry, memory=memory)

        result = agent.run_chain(
            "Analyze vuln_bof",
            context={"binary_path": VULN_BOF},
            max_steps=4,
        )

        crash_data = result["final_memory"]["crash_data"]
        self.assertGreater(len(crash_data), 0)


if __name__ == "__main__":
    unittest.main()
