#!/usr/bin/env python3
"""
run_scan.py — Single-turn demo of the LLM-driven agent pipeline.

Usage:
    python examples/run_scan.py                  # scans 127.0.0.1 (localhost)
    python examples/run_scan.py 192.168.1.10     # scans a specific target

What happens:
    1. The skill registry is populated with available skills.
    2. A SecurityAgent is created with an LLM client and memory manager.
    3. The local Llama planner selects the best skill for the task.
    4. The skill executes (nmap scan), output is summarized by the LLM.
    5. Structured findings are stored in memory.
    6. The full result, memory snapshot, and decision trace are displayed.

Prerequisites:
    - nmap must be installed (`brew install nmap` / `apt install nmap`)
    - Ollama must be running with a model pulled:
        ollama serve
        ollama pull llama3:8b
    - Only scan targets you have EXPLICIT AUTHORIZATION to test.
"""

import json
import sys
from pathlib import Path

# Ensure project root is on the Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent.agent import SecurityAgent
from core.llm_client import LLMClient
from core.memory_manager import MemoryManager
from core.skill_registry import SkillRegistry
from skills.network_scan import NetworkScanSkill


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║     LLM Security Testing Agent — Research Prototype          ║
║                                                              ║
║  ⚠  AUTHORIZED DEFENSIVE TESTING ONLY                       ║
║  ⚠  Only scan systems you have explicit permission to test   ║
╚══════════════════════════════════════════════════════════════╝
"""


def main() -> None:
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    task = "Scan the target machine for open services"

    print(BANNER)
    print(f"  Task   : {task}")
    print(f"  Target : {target_ip}")
    print("=" * 62)

    # --- Initialize components ---
    llm = LLMClient()
    memory = MemoryManager()
    registry = SkillRegistry()
    registry.register(NetworkScanSkill())

    print(f"\n[init] LLM client : {llm}")
    print(f"[init] Memory     : {memory}")
    print(f"[init] Skills     : {registry}")

    # --- Run the agent ---
    agent = SecurityAgent(registry, memory=memory, llm=llm)
    result = agent.run(task, context={"target_ip": target_ip})

    # --- Display: Planner Decision ---
    print("\n" + "=" * 62)
    print("PLANNER DECISION")
    print("=" * 62)
    print(f"  Skill chosen : {result.get('skill_used', 'none')}")
    print(f"  Arguments    : {result.get('skill_arguments', {})}")
    print(f"  Reasoning    : {result.get('reasoning', '')}")

    # --- Display: Summary ---
    print("\n" + "=" * 62)
    print("SUMMARIZED FINDINGS")
    print("=" * 62)
    print(result.get("summary", "No summary available."))

    # --- Display: Structured Findings ---
    summarized = result.get("summarized_result", {})
    structured = summarized.get("structured", {})
    if structured:
        print("\n" + "-" * 62)
        print("STRUCTURED DATA")
        print("-" * 62)
        print(json.dumps(structured, indent=2))

    # --- Display: Memory Snapshot ---
    print("\n" + "=" * 62)
    print("MEMORY SNAPSHOT")
    print("=" * 62)
    snapshot = result.get("memory_snapshot", {})
    print(json.dumps(snapshot, indent=2))

    # --- Display: Decision Trace ---
    print("\n" + "=" * 62)
    print("DECISION TRACE")
    print("=" * 62)
    for step in result.get("trace", []):
        event = step.get("event", "unknown")
        detail = {k: v for k, v in step.items() if k != "event"}
        detail_str = json.dumps(detail, indent=4, default=str)
        # Truncate very long entries for readability
        if len(detail_str) > 400:
            detail_str = detail_str[:400] + "\n    ..."
        print(f"  [{event}]")
        if detail:
            print(f"    {detail_str}")

    # --- Status ---
    print("\n" + "=" * 62)
    if result.get("success"):
        print("STATUS: SUCCESS")
    else:
        print("STATUS: FAILED")
        print(f"  Detail: {result.get('summary', 'unknown error')}")
    print("=" * 62)


if __name__ == "__main__":
    main()
