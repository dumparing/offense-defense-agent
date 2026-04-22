#!/usr/bin/env python3
"""
demo_full_chain.py — End-to-end demo of the autonomous security analysis agent.

This is the PRIMARY DEMO SCRIPT for the final presentation. It shows:

    1. Agent initialization with all registered skills
    2. Multi-step attack chain on a vulnerable binary:
       Step 1: GDB debugging → find crash points
       Step 2: Disassembly  → classify the vulnerability
       Step 3: Final report  → planner synthesizes findings
    3. Memory state evolution across steps
    4. Safety guardrail checks
    5. Final vulnerability report

Usage:
    # Analyze the buffer overflow binary (default)
    python examples/demo_full_chain.py

    # Analyze a specific binary
    python examples/demo_full_chain.py targets/vuln_fmt

    # Analyze all targets
    python examples/demo_full_chain.py --all

    # Quiet mode (less output)
    python examples/demo_full_chain.py --quiet

Prerequisites:
    - Vulnerable binaries compiled: cd targets && make
    - Optional: Ollama running (ollama serve && ollama pull llama3:8b)
      Falls back to keyword planner without Ollama.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent.agent import SecurityAgent
from core.llm_client import LLMClient
from core.memory_manager import MemoryManager
from core.skill_registry import SkillRegistry
from skills.network_scan import NetworkScanSkill
from skills.gdb_debug import GDBDebugSkill
from skills.disassemble import DisassembleSkill
from safety.risk_analysis import SafetyGuardrails, generate_risk_report


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

BANNER = r"""
 ╔════════════════════════════════════════════════════════════════════╗
 ║                                                                    ║
 ║   Autonomous Offensive/Defensive Security Agent                    ║
 ║   ──────────────────────────────────────────────                   ║
 ║                                                                    ║
 ║   LLM-Driven Vulnerability Analysis Pipeline                      ║
 ║   Plan → Debug → Disassemble → Report                             ║
 ║                                                                    ║
 ║   Local LLM: Llama 3 via Ollama                                   ║
 ║   Tools:     GDB, objdump, nmap                                   ║
 ║                                                                    ║
 ║   ⚠  AUTHORIZED DEFENSIVE TESTING ONLY                           ║
 ╚════════════════════════════════════════════════════════════════════╝
"""


def section(title: str) -> None:
    """Print a section header."""
    print(f"\n{'━' * 66}")
    print(f"  {title}")
    print(f"{'━' * 66}")


def subsection(title: str) -> None:
    """Print a subsection header."""
    print(f"\n  {'─' * 58}")
    print(f"  {title}")
    print(f"  {'─' * 58}")


def kv(key: str, value: str, indent: int = 4) -> None:
    """Print a key-value pair."""
    pad = " " * indent
    print(f"{pad}{key:.<30s} {value}")


# ---------------------------------------------------------------------------
# Demo: analyze one binary
# ---------------------------------------------------------------------------

def demo_single_binary(binary_path: str, quiet: bool = False) -> dict:
    """Run the full analysis chain on one binary."""

    if not os.path.isfile(binary_path):
        print(f"\n  [ERROR] Binary not found: {binary_path}")
        print(f"  Run: cd targets && make")
        return {}

    binary_name = os.path.basename(binary_path)

    section(f"ANALYZING: {binary_name}")
    print(f"  Path: {binary_path}")

    # --- Safety pre-check ---
    guardrails = SafetyGuardrails()
    safe, msg = guardrails.check_binary_path(binary_path)
    kv("Safety check", f"{'PASS' if safe else 'BLOCKED'} — {msg}")

    if not safe:
        print(f"\n  Aborting: {msg}")
        return {}

    # --- Initialize agent ---
    subsection("Initializing Agent")

    llm = LLMClient()
    memory = MemoryManager()
    registry = SkillRegistry()
    registry.register(GDBDebugSkill())
    registry.register(DisassembleSkill())
    registry.register(NetworkScanSkill())

    agent = SecurityAgent(registry, memory=memory, llm=llm)

    # Check if Ollama is available
    planner_mode = "LLM (Llama 3 via Ollama)"
    try:
        import urllib.request
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=3) as resp:
            pass
    except Exception:
        planner_mode = "Keyword fallback (Ollama not running)"

    kv("LLM", str(llm))
    kv("Planner mode", planner_mode)
    kv("Skills", ", ".join(s["name"] for s in registry.list_skills()))
    kv("Memory", str(memory))

    # --- Run the chain ---
    subsection("Running Analysis Chain")
    print()

    task = (
        f"Analyze the binary at {binary_path} for security vulnerabilities. "
        f"Debug it with gdb_debug to find crash points, then disassemble it "
        f"to identify dangerous function calls and classify the vulnerability."
    )

    step_count = [0]
    start = time.time()

    def on_step(step_num: int, result: dict) -> None:
        step_count[0] = step_num
        skill = result.get("skill_used", "none")
        success = result.get("success", False)
        summary = result.get("summary", "")
        reasoning = result.get("reasoning", "")

        if skill == "none" or skill is None:
            print(f"    Step {step_num}: [DONE] Analysis complete")
            return
        status = "OK" if success else "ERR"
        print(f"    Step {step_num}: [{status}] {skill}")
        if reasoning and not quiet:
            print(f"           Reason: {reasoning[:90]}")

        if not quiet:
            # Show key details per skill
            if skill == "gdb_debug":
                skill_data = result.get("skill_result", {}).get("data", {})
                crashes = skill_data.get("crashes_found", 0)
                indicators = skill_data.get("vulnerability_indicators", [])
                print(f"           Crashes found: {crashes}")
                if indicators:
                    print(f"           Indicators: {', '.join(indicators)}")

            elif skill == "disassemble":
                skill_data = result.get("skill_result", {}).get("data", {})
                risk = skill_data.get("risk_level", "?")
                vulns = skill_data.get("vulnerability_patterns", [])
                missing = skill_data.get("missing_protections", [])
                print(f"           Risk level: {risk}")
                for v in vulns:
                    print(f"           Found: {v['vulnerability']} "
                          f"({v['confidence']} confidence)")
                if missing:
                    print(f"           Missing: {', '.join(missing)}")

            print(f"           Summary: {summary[:100]}")
        print()

    chain_result = agent.run_chain(
        task,
        context={"binary_path": binary_path},
        max_steps=4,
        on_step=on_step,
    )

    elapsed = time.time() - start

    # --- Results ---
    subsection("Analysis Results")

    report = chain_result.get("final_report", {})
    final_memory = chain_result.get("final_memory", {})

    kv("Steps completed", str(chain_result.get("total_steps", 0)))
    kv("Skills used", ", ".join(report.get("skills_used", [])))
    kv("Wall time", f"{elapsed:.1f}s")

    # Crash data — deduplicate by signal and show summary
    crash_data = final_memory.get("crash_data", [])
    if crash_data:
        subsection("Crash Analysis")

        # Group by signal for cleaner output
        by_signal: dict = {}
        for crash in crash_data:
            sig = crash.get("signal", "unknown")
            by_signal.setdefault(sig, []).append(crash)

        for sig, crashes_in_group in by_signal.items():
            inputs = [c.get("input_label", "?") for c in crashes_in_group]
            print(f"    Signal: {sig} ({len(crashes_in_group)} crash(es))")
            print(f"      Triggered by: {', '.join(inputs)}")

            # Explain signal for presentation
            sig_desc = {
                "SIGSEGV": "Segmentation fault — invalid memory access",
                "SIGBUS": "Bus error — misaligned or invalid memory access (common on ARM64)",
                "SIGABRT": "Abort — triggered by failed assertion or heap corruption",
                "SIGTRAP": "Trap — debugger breakpoint or heap corruption detected",
            }
            if sig in sig_desc:
                print(f"      Meaning: {sig_desc[sig]}")

            # Show backtrace if available
            bt = crashes_in_group[0].get("backtrace", [])
            if bt:
                print(f"      Backtrace:")
                for frame in bt[:3]:
                    print(f"        {frame}")
            print()

    # Vulnerability findings
    vulns = final_memory.get("vulnerabilities", [])
    if vulns:
        subsection("Vulnerabilities Found")
        for v in vulns:
            print(f"    [{v.get('confidence', '?').upper()}] "
                  f"{v.get('vulnerability', '?')}")
            print(f"      {v.get('description', '')}")
            print()

    # Binary analysis
    analyzed = final_memory.get("analyzed_binaries", {})
    if analyzed:
        subsection("Binary Analysis")
        for path, info in analyzed.items():
            kv("Binary", os.path.basename(path))
            arch = info.get("architecture", {})
            if arch:
                kv("Architecture", f"{arch.get('arch', '?')} "
                   f"{arch.get('bits', '?')}-bit "
                   f"{arch.get('endian', '?')}-endian")
            protections = info.get("protections", {})
            if protections:
                prot_strs = []
                for k, v_val in protections.items():
                    if v_val is True:
                        prot_strs.append(f"{k}=enabled")
                    elif v_val is False:
                        prot_strs.append(f"{k}=DISABLED")
                    elif v_val is not None:
                        prot_strs.append(f"{k}={v_val}")
                kv("Protections", ", ".join(prot_strs))
            kv("Risk level", info.get("risk_level", "?").upper())
            kv("Dangerous call sites", str(info.get("dangerous_calls_count", 0)))

    # All findings
    findings = final_memory.get("findings", [])
    if findings:
        subsection("All Findings")
        for i, finding in enumerate(findings, 1):
            print(f"    {i}. {finding}")

    # Safety audit
    audit = guardrails.get_audit_log()
    if audit:
        subsection("Safety Audit Log")
        for entry in audit:
            print(f"    [{entry['action']}] {entry['detail']}")

    return chain_result


# ---------------------------------------------------------------------------
# Demo: analyze all targets
# ---------------------------------------------------------------------------

def demo_all_targets(quiet: bool = False) -> None:
    """Run analysis on all vulnerable targets."""
    targets_dir = PROJECT_ROOT / "targets"
    binaries = sorted(targets_dir.glob("vuln_*"))
    # Filter out .c files and .dSYM directories
    binaries = [
        b for b in binaries
        if not str(b).endswith(".c") and ".dSYM" not in str(b)
        and b.is_file()
    ]

    if not binaries:
        print(f"\n  No compiled binaries found in {targets_dir}")
        print(f"  Run: cd targets && make")
        return

    print(f"\n  Found {len(binaries)} target(s):")
    for b in binaries:
        print(f"    - {b.name}")

    results = {}
    for binary in binaries:
        result = demo_single_binary(str(binary), quiet=quiet)
        results[binary.name] = result

    # Summary table
    section("SUMMARY TABLE")
    print(f"    {'Binary':<15s} {'Steps':<8s} {'Crashes':<10s} "
          f"{'Vulns':<12s} {'Risk':<10s}")
    print(f"    {'─'*15} {'─'*8} {'─'*10} {'─'*12} {'─'*10}")

    for name, result in results.items():
        if not result:
            print(f"    {name:<15s} {'SKIP':<8s}")
            continue
        mem = result.get("final_memory", {})
        steps = result.get("total_steps", 0)
        crashes = len(mem.get("crash_data", []))
        vulns = len(mem.get("vulnerabilities", []))
        analyzed = mem.get("analyzed_binaries", {})
        risk = "?"
        for info in analyzed.values():
            risk = info.get("risk_level", "?")
        print(f"    {name:<15s} {steps:<8d} {crashes:<10d} "
              f"{vulns:<12d} {risk:<10s}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Full chain demo — autonomous vulnerability analysis"
    )
    parser.add_argument(
        "binary", nargs="?",
        default=str(PROJECT_ROOT / "targets" / "vuln_bof"),
        help="Path to binary to analyze (default: targets/vuln_bof)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Analyze all targets in targets/",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Reduce output verbosity",
    )
    parser.add_argument(
        "--safety-report", action="store_true",
        help="Print the safety/risk analysis report and exit",
    )
    args = parser.parse_args()

    print(BANNER)

    if args.safety_report:
        print(generate_risk_report())
        return

    if args.all:
        demo_all_targets(quiet=args.quiet)
    else:
        demo_single_binary(args.binary, quiet=args.quiet)

    section("DEMO COMPLETE")
    print("  The agent autonomously:")
    print("    1. Planned the analysis chain using the LLM planner")
    print("    2. Debugged the binary under GDB to find crash points")
    print("    3. Disassembled the binary to classify vulnerabilities")
    print("    4. Synthesized findings into a structured report")
    print("    5. Maintained memory across all steps")
    print()
    print("  All processing was local — no data left this machine.")
    print()


if __name__ == "__main__":
    main()
