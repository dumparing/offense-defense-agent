#!/usr/bin/env python3
"""
preflight.py — Pre-demo checklist.

Run this before your presentation to verify everything works:
    1. Python version
    2. Required tools (objdump, nm, strings, file)
    3. Ollama running + model available
    4. Target binaries compiled
    5. Quick smoke test

Usage:
    python examples/preflight.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def check(label: str, ok: bool, detail: str = "") -> bool:
    status = "PASS" if ok else "FAIL"
    suffix = f" — {detail}" if detail else ""
    print(f"  [{status}] {label}{suffix}")
    return ok


def main() -> None:
    print("=" * 60)
    print("  PRE-DEMO CHECKLIST")
    print("=" * 60)
    all_ok = True

    # 1. Python version
    v = sys.version_info
    all_ok &= check(
        "Python 3.8+",
        v.major == 3 and v.minor >= 8,
        f"Python {v.major}.{v.minor}.{v.micro}",
    )

    # 2. Required CLI tools
    print()
    tools = {
        "objdump": "disassembly (part of binutils / Xcode CLT)",
        "nm": "symbol table (part of binutils / Xcode CLT)",
        "strings": "string extraction",
        "file": "binary identification",
    }
    for tool, desc in tools.items():
        found = shutil.which(tool)
        all_ok &= check(f"{tool}", found is not None, desc)

    # Optional tools
    debugger = shutil.which("gdb") or shutil.which("lldb")
    check("debugger (gdb/lldb)", debugger is not None,
          f"{'gdb' if shutil.which('gdb') else 'lldb'}" if debugger else "neither found")

    # 3. Ollama
    print()
    ollama_ok = False
    model_ok = False

    try:
        import urllib.request
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            models = [m["name"] for m in data.get("models", [])]
            ollama_ok = True
            check("Ollama running", True, f"{len(models)} model(s) available")

            # Check for recommended model
            from core.llm_client import OLLAMA_MODEL
            model_ok = any(OLLAMA_MODEL in m for m in models)
            check(
                f"Model '{OLLAMA_MODEL}'",
                model_ok,
                "ready" if model_ok else f"not found — run: ollama pull {OLLAMA_MODEL}",
            )

            if not model_ok and models:
                print(f"         Available models: {', '.join(models)}")

    except Exception as e:
        check("Ollama running", False, "not reachable — run: ollama serve")
        check(f"Model", False, "skipped (Ollama not running)")

    # 4. Quick LLM test
    if ollama_ok and model_ok:
        try:
            from core.llm_client import LLMClient
            llm = LLMClient()
            response = llm.generate_text("Reply with only the word 'OK'.")
            llm_works = "ok" in response.lower()
            check("LLM responds", llm_works, response[:50])
        except Exception as e:
            check("LLM responds", False, str(e)[:60])
    else:
        print("  [SKIP] LLM response test")

    # 5. Target binaries
    print()
    targets_dir = PROJECT_ROOT / "targets"
    expected = ["vuln_bof", "vuln_fmt", "vuln_uaf", "vuln_heap"]
    for target in expected:
        path = targets_dir / target
        exists = path.is_file()
        all_ok &= check(f"Target: {target}", exists)

    if not all(os.path.isfile(targets_dir / t) for t in expected):
        print(f"         Run: cd targets && make")

    # 6. Quick smoke test
    print()
    try:
        from tools.disassembler import disassemble_binary
        vuln_bof = str(targets_dir / "vuln_bof")
        if os.path.isfile(vuln_bof):
            result = disassemble_binary(vuln_bof)
            funcs = [c["function"] for c in result["dangerous_calls"]]
            has_gets = "gets" in funcs
            check("Smoke test: disassembler", has_gets,
                  f"found gets={has_gets}, {len(funcs)} dangerous calls")
        else:
            print("  [SKIP] Smoke test (targets not compiled)")
    except Exception as e:
        check("Smoke test", False, str(e)[:60])

    # 7. Test suite
    print()
    try:
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"],
            capture_output=True, text=True, timeout=60,
            cwd=str(PROJECT_ROOT),
        )
        tests_pass = result.returncode == 0
        # Extract count from output like "57 tests in 0.6s"
        lines = (result.stderr + result.stdout).strip().splitlines()
        summary = lines[-1] if lines else ""
        check("Test suite", tests_pass, summary)
    except Exception as e:
        check("Test suite", False, str(e)[:60])

    # Summary
    print()
    print("=" * 60)
    if all_ok and ollama_ok and model_ok:
        print("  ALL SYSTEMS GO — ready for demo")
    elif all_ok and not (ollama_ok and model_ok):
        print("  CORE READY — Ollama needs setup for LLM features")
        print("  Run: ollama serve  (in a separate terminal)")
        print("  Run: ollama pull llama3:8b")
        print("  The demo works without Ollama (keyword fallback) but")
        print("  the LLM planner makes it significantly more impressive.")
    else:
        print("  ISSUES FOUND — fix the items above before presenting")
    print("=" * 60)


if __name__ == "__main__":
    main()
