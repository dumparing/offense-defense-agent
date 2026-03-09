#!/usr/bin/env python3
"""
run_scan.py — Runnable example that exercises the full agent pipeline.

Usage:
    python examples/run_scan.py                  # scans 127.0.0.1 (localhost)
    python examples/run_scan.py 192.168.1.10     # scans a specific target

What happens:
    1. The skill registry is populated with all available skills.
    2. A SecurityAgent is created with that registry.
    3. The agent receives a natural-language task and a target IP.
    4. It selects the network_scan skill, runs nmap, and summarizes results.
    5. The agent's decision trace is printed for inspection.

Prerequisites:
    - nmap must be installed (`brew install nmap` / `apt install nmap`)
    - Scanning hosts you don't own may be illegal. Only scan targets you
      have explicit authorization to test (e.g. localhost, lab VMs).
"""

import json
import sys
from pathlib import Path

# Ensure the project root is on the Python path so imports work when
# running this script directly (e.g. `python examples/run_scan.py`).
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent.agent import SecurityAgent
from core.skill_registry import SkillRegistry
from skills.network_scan import NetworkScanSkill


def main() -> None:
    # --- Configuration ---
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    task = "Scan the target machine for open services"

    print("=" * 60)
    print("  LLM Security Testing Agent — Research Prototype")
    print("=" * 60)
    print(f"  Task   : {task}")
    print(f"  Target : {target_ip}")
    print("=" * 60)

    # --- Build the skill registry ---
    registry = SkillRegistry()
    registry.register(NetworkScanSkill())
    print(f"\n[init] Registered skills: {registry}")

    # --- Run the agent ---
    agent = SecurityAgent(registry)
    result = agent.run(task, context={"target_ip": target_ip})

    # --- Display results ---
    print("\n" + "-" * 60)
    print("AGENT SUMMARY")
    print("-" * 60)
    print(result["summary"])

    print("\n" + "-" * 60)
    print("AGENT DECISION TRACE")
    print("-" * 60)
    for step in result["trace"]:
        print(f"  [{step['event']}]")
        detail = {k: v for k, v in step.items() if k != "event"}
        if detail:
            # Pretty-print but keep it compact
            print(f"    {json.dumps(detail, indent=4, default=str)[:500]}")

    print("\n" + "-" * 60)
    if result["success"]:
        print("STATUS: SUCCESS")
    else:
        print("STATUS: FAILED")
        print(f"Error : {result.get('summary', 'unknown')}")
    print("-" * 60)


if __name__ == "__main__":
    main()
