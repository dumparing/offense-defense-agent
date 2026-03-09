"""
network_scan.py — Skill: discover open services on a target host.

This is the first skill in the system. It wraps the nmap tool runner and
provides a clean interface that the agent can invoke.

Flow:
    Agent → NetworkScanSkill.execute(target_ip="x.x.x.x")
          → tools.nmap_runner.run_nmap_service_scan()
          → parsed results returned to agent
"""

from __future__ import annotations

from typing import Any

from core.skill_base import SkillBase
from tools.nmap_runner import run_nmap_service_scan


class NetworkScanSkill(SkillBase):
    """Scan a target host for open ports and running services using Nmap."""

    @property
    def name(self) -> str:
        return "network_scan"

    @property
    def description(self) -> str:
        return (
            "Scan a target IP for open ports and identify running services "
            "using Nmap service-version detection (-sV)."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "target_ip": {
                "type": "str",
                "description": "IPv4 or IPv6 address of the target host",
            }
        }

    def execute(self, **kwargs) -> dict[str, Any]:
        """Run the network scan and return structured results."""
        # Validate inputs using the base-class helper
        errors = self.validate_inputs(**kwargs)
        if errors:
            return {"success": False, "data": None, "error": "; ".join(errors)}

        target_ip = kwargs["target_ip"]

        # Delegate to the nmap tool wrapper
        result = run_nmap_service_scan(target_ip)

        if result["error"]:
            return {
                "success": False,
                "data": result,
                "error": result["error"],
            }

        return {
            "success": True,
            "data": {
                "target": target_ip,
                "services_found": len(result["services"]),
                "services": result["services"],
                "raw_output": result["raw_output"],
            },
            "error": None,
        }
