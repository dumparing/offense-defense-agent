"""
gdb_debug.py — Skill: debug a binary to find crash points and crash context.

Runs a target binary under GDB with crafted input to trigger crashes,
then captures the signal, fault address, backtrace, and register state.

This skill is used in the analysis chain after a binary has been identified
as a target. It answers: "Does this binary crash, and where?"

Flow:
    Agent → GDBDebugSkill.execute(binary_path="...", input_data="...")
          → tools.gdb_runner.run_gdb_analysis()
          → crash info returned to agent
"""

from __future__ import annotations

import os
import string
from typing import Any

from core.skill_base import SkillBase
from tools.gdb_runner import run_gdb_analysis


# Standard test inputs that commonly trigger vulnerabilities
FUZZ_INPUTS = [
    # Buffer overflow: long input
    "A" * 200,
    # Longer overflow to overwrite return address
    "A" * 500,
    # Pattern with format string specifiers
    "%x." * 50,
    # Format string attack
    "%s%s%s%s%s%s%s%s%s%s",
    # Null bytes and special chars
    "A" * 100 + "\x00" + "B" * 100,
]


def generate_cyclic_pattern(length: int = 300) -> str:
    """
    Generate a De Bruijn-like cyclic pattern for finding offsets.
    Each 4-byte substring is unique, making it easy to identify
    which part of the input overwrote a register.
    """
    pattern = []
    for upper in string.ascii_uppercase[:26]:
        for lower in string.ascii_lowercase[:26]:
            for digit in string.digits[:10]:
                pattern.append(f"{upper}{lower}{digit}")
                if len("".join(pattern)) >= length:
                    return "".join(pattern)[:length]
    return "".join(pattern)[:length]


def find_pattern_offset(pattern: str, value: str) -> int | None:
    """Find the offset of a 4-byte value within a cyclic pattern."""
    # Convert hex value to ASCII if possible
    try:
        if value.startswith("0x"):
            hex_val = value[2:]
            # Pad to 8 chars for 32-bit or 16 for 64-bit
            hex_val = hex_val.zfill(8)
            # Convert to bytes (little-endian)
            byte_str = bytes.fromhex(hex_val)[::-1]
            ascii_str = byte_str.decode("ascii", errors="ignore")
            idx = pattern.find(ascii_str)
            if idx >= 0:
                return idx
    except (ValueError, UnicodeDecodeError):
        pass
    return None


class GDBDebugSkill(SkillBase):
    """Debug a binary under GDB to identify crash points and crash context."""

    @property
    def name(self) -> str:
        return "gdb_debug"

    @property
    def description(self) -> str:
        return (
            "Run a binary under GDB with test inputs to find crash points. "
            "Captures signal, fault address, backtrace, and registers. "
            "Use this to determine if and where a binary crashes."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "binary_path": {
                "type": "str",
                "description": "Path to the binary to debug",
            },
        }

    def execute(self, **kwargs) -> dict[str, Any]:
        """Run the binary under GDB with multiple test inputs."""
        errors = self.validate_inputs(**kwargs)
        if errors:
            return {"success": False, "data": None, "error": "; ".join(errors)}

        binary_path = kwargs["binary_path"]
        custom_input = kwargs.get("input_data")
        args = kwargs.get("args")

        if not os.path.isfile(binary_path):
            return {
                "success": False,
                "data": None,
                "error": f"Binary not found: {binary_path}",
            }

        # If custom input is provided, use only that
        if custom_input:
            result = run_gdb_analysis(
                binary_path, stdin_input=custom_input, args=args
            )
            return self._build_result(binary_path, [(custom_input[:50], result)])

        # Otherwise, fuzz with standard inputs + cyclic pattern
        cyclic = generate_cyclic_pattern(300)
        all_inputs = FUZZ_INPUTS + [cyclic]
        input_labels = [
            "overflow_200", "overflow_500", "format_hex",
            "format_string", "null_injection", "cyclic_pattern",
        ]

        crash_results = []
        for label, test_input in zip(input_labels, all_inputs):
            result = run_gdb_analysis(
                binary_path, stdin_input=test_input, args=args
            )
            crash_results.append((label, result))

            # If we found a crash with cyclic pattern, try to find offset
            if result["crashed"] and label == "cyclic_pattern":
                for reg_name, reg_val in result.get("registers", {}).items():
                    offset = find_pattern_offset(cyclic, reg_val)
                    if offset is not None:
                        result["pattern_offset"] = {
                            "register": reg_name,
                            "offset": offset,
                            "value": reg_val,
                        }

        return self._build_result(binary_path, crash_results)

    def _build_result(
        self,
        binary_path: str,
        results: list[tuple[str, dict]],
    ) -> dict[str, Any]:
        """Build a structured result from all GDB runs."""
        crashes = []
        all_results = []

        for label, result in results:
            entry = {
                "input_label": label,
                "crashed": result["crashed"],
                "signal": result["signal"],
                "fault_address": result["fault_address"],
                "backtrace": result["backtrace"][:5],  # top 5 frames
                "registers": result.get("registers", {}),
                "error": result["error"],
            }

            if "pattern_offset" in result:
                entry["pattern_offset"] = result["pattern_offset"]

            all_results.append(entry)

            if result["crashed"]:
                crashes.append(entry)

        any_crash = len(crashes) > 0

        # Determine vulnerability indicators
        vuln_indicators = []
        for crash in crashes:
            sig = crash.get("signal", "")
            if sig in ("SIGSEGV", "SIGBUS"):
                vuln_indicators.append("memory_corruption")
            if sig == "SIGSEGV":
                vuln_indicators.append("segmentation_fault")
            elif sig == "SIGABRT":
                vuln_indicators.append("abort_signal")
            elif sig == "SIGBUS":
                vuln_indicators.append("bus_error")

            # Check if different inputs cause crashes at different addresses
            if crash.get("fault_address"):
                vuln_indicators.append(f"crash_at_{crash['fault_address']}")

            if crash.get("pattern_offset"):
                vuln_indicators.append("controllable_crash_offset")

        return {
            "success": True,
            "data": {
                "binary": binary_path,
                "total_tests": len(results),
                "crashes_found": len(crashes),
                "any_crash": any_crash,
                "vulnerability_indicators": list(set(vuln_indicators)),
                "crashes": crashes,
                "all_results": all_results,
            },
            "error": None,
        }
