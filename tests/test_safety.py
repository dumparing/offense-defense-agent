"""Tests for safety.risk_analysis."""

import unittest
from safety.risk_analysis import (
    SafetyGuardrails,
    RISK_TAXONOMY,
    generate_risk_report,
    risk_summary_json,
)


class TestSafetyGuardrails(unittest.TestCase):
    def setUp(self):
        self.guardrails = SafetyGuardrails()

    def test_blocks_system_path(self):
        ok, msg = self.guardrails.check_binary_path("/usr/bin/ls")
        self.assertFalse(ok)
        self.assertIn("system", msg.lower())

    def test_allows_local_path(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            ok, msg = self.guardrails.check_binary_path(path)
            self.assertTrue(ok)
        finally:
            os.unlink(path)

    def test_private_ip_allowed(self):
        ok, msg = self.guardrails.check_target_ip("192.168.1.1")
        self.assertTrue(ok)
        self.assertEqual(msg, "OK")

    def test_public_ip_warning(self):
        ok, msg = self.guardrails.check_target_ip("8.8.8.8")
        self.assertTrue(ok)  # allowed but with warning
        self.assertIn("WARNING", msg)

    def test_localhost_allowed(self):
        ok, msg = self.guardrails.check_target_ip("127.0.0.1")
        self.assertTrue(ok)

    def test_skill_argument_check_gdb(self):
        ok, msg = self.guardrails.check_skill_arguments(
            "gdb_debug", {"binary_path": "/usr/bin/ls"}
        )
        self.assertFalse(ok)

    def test_audit_log_populated(self):
        self.guardrails.check_target_ip("127.0.0.1")
        log = self.guardrails.get_audit_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["action"], "ALLOWED")


class TestRiskTaxonomy(unittest.TestCase):
    def test_taxonomy_not_empty(self):
        self.assertGreater(len(RISK_TAXONOMY), 0)

    def test_all_risks_have_required_fields(self):
        for risk in RISK_TAXONOMY:
            self.assertTrue(risk.id)
            self.assertTrue(risk.category)
            self.assertTrue(risk.title)
            self.assertTrue(risk.severity)
            self.assertIn(risk.severity, ("critical", "high", "medium", "low"))

    def test_report_generates(self):
        report = generate_risk_report()
        self.assertIn("SAFETY AND RISK ANALYSIS", report)
        self.assertIn("ARCHITECTURAL SAFEGUARDS", report)

    def test_json_summary(self):
        summary = risk_summary_json()
        self.assertIn("total_risks", summary)
        self.assertEqual(summary["total_risks"], len(RISK_TAXONOMY))
        self.assertIn("by_severity", summary)


if __name__ == "__main__":
    unittest.main()
