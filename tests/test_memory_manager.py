"""Tests for core.memory_manager."""

import json
import unittest
from core.memory_manager import MemoryManager


class TestMemoryManager(unittest.TestCase):
    def setUp(self):
        self.mem = MemoryManager()

    def test_initial_state(self):
        snapshot = self.mem.get_context_snapshot()
        self.assertIsNone(snapshot["current_target"])
        self.assertEqual(snapshot["discovered_open_ports"], [])
        self.assertEqual(snapshot["findings"], [])
        self.assertEqual(snapshot["crash_data"], [])
        self.assertEqual(snapshot["vulnerabilities"], [])

    def test_record_scan_results(self):
        self.mem.record_scan_results(
            target="192.168.1.1",
            open_ports=[22, 80, 443],
            services={"22": "ssh", "80": "http"},
        )
        snapshot = self.mem.get_context_snapshot()
        self.assertEqual(snapshot["current_target"], "192.168.1.1")
        self.assertEqual(snapshot["discovered_open_ports"], [22, 80, 443])
        self.assertEqual(snapshot["discovered_services"]["22"], "ssh")

    def test_record_scan_deduplicates_ports(self):
        self.mem.record_scan_results("t", [22, 80], {})
        self.mem.record_scan_results("t", [80, 443], {})
        self.assertEqual(self.mem.discovered_open_ports, [22, 80, 443])

    def test_record_action(self):
        self.mem.record_action(
            skill="network_scan",
            arguments={"target_ip": "1.2.3.4"},
            success=True,
            summary="Found 3 ports",
        )
        snapshot = self.mem.get_context_snapshot()
        self.assertEqual(len(snapshot["actions_taken"]), 1)
        self.assertEqual(snapshot["actions_taken"][0]["skill"], "network_scan")

    def test_record_crash(self):
        self.mem.record_crash(
            binary="vuln_bof",
            signal="SIGSEGV",
            fault_address="0xdeadbeef",
            backtrace=["#0 main"],
            input_label="overflow_200",
        )
        self.assertEqual(len(self.mem.crash_data), 1)
        self.assertEqual(self.mem.crash_data[0]["signal"], "SIGSEGV")

    def test_record_binary_analysis(self):
        self.mem.record_binary_analysis(
            binary="vuln_bof",
            arch={"arch": "x86_64", "bits": 64},
            protections={"nx": False, "pie": False},
            dangerous_calls=[{"function": "gets"}],
            vulnerability_patterns=[
                {"vulnerability": "buffer_overflow", "confidence": "high",
                 "description": "gets found"}
            ],
            risk_level="critical",
        )
        self.assertIn("vuln_bof", self.mem.analyzed_binaries)
        self.assertEqual(len(self.mem.vulnerabilities), 1)
        self.assertEqual(
            self.mem.vulnerabilities[0]["vulnerability"], "buffer_overflow"
        )

    def test_record_findings_deduplicates(self):
        self.mem.record_findings(["finding 1", "finding 2"])
        self.mem.record_findings(["finding 2", "finding 3"])
        self.assertEqual(len(self.mem.findings), 3)

    def test_to_json(self):
        self.mem.record_findings(["test finding"])
        j = self.mem.to_json()
        parsed = json.loads(j)
        self.assertIn("test finding", parsed["findings"])


if __name__ == "__main__":
    unittest.main()
