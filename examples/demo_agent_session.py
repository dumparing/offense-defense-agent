#!/usr/bin/env python3
"""
demo_agent_session.py — Multi-turn demo showing memory persistence.

Demonstrates two sequential agent turns sharing the same memory object:
    Turn 1: "Scan the target machine for open services"
    Turn 2: "Summarize the most important findings so far"

The second turn uses the memory snapshot (populated by turn 1) to produce
a summary without re-running any tools. This shows how the agent avoids
context bloat across multiple steps.

Usage:
    python examples/demo_agent_session.py                 # target: 127.0.0.1
    python examples/demo_agent_session.py 192.168.1.10    # specific target

Prerequisites:
    - nmap installed
    - Ollama running with a model pulled (ollama pull llama3:8b)
    - Only scan AUTHORIZED targets
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent.agent import SecurityAgent
from core.llm_client import LLMClient
from core.memory_manager import MemoryManager
from core.skill_registry import SkillRegistry
from skills.network_scan import NetworkScanSkill


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║     Multi-Turn Agent Session Demo                            ║
║                                                              ║
║  Shows how memory persists across turns and prevents          ║
║  context bloat by summarizing instead of accumulating.        ║
║                                                              ║
║  ⚠  AUTHORIZED DEFENSIVE TESTING ONLY                       ║
╚══════════════════════════════════════════════════════════════╝
"""


def print_turn_result(turn_num: int, task: str, result: dict) -> None:
    """Pretty-print the result of one agent turn."""
    print(f"\n{'━' * 62}")
    print(f"  TURN {turn_num} RESULTS")
    print(f"  Task: {task}")
    print(f"{'━' * 62}")

    print(f"\n  Skill used : {result.get('skill_used', 'none')}")
    print(f"  Reasoning  : {result.get('reasoning', 'N/A')}")
    print(f"  Success    : {result.get('success')}")

    print(f"\n  Summary:")
    print(f"  {result.get('summary', 'No summary.')}")

    # Structured findings
    summarized = result.get("summarized_result", {})
    structured = summarized.get("structured", {})
    if structured:
        print(f"\n  Structured findings:")
        print(f"  {json.dumps(structured, indent=4)}")


def main() -> None:
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"

    print(BANNER)
    print(f"  Target: {target_ip}")
    print("=" * 62)

    # --- Shared components (persist across turns) ---
    llm = LLMClient()
    memory = MemoryManager()
    registry = SkillRegistry()
    registry.register(NetworkScanSkill())

    print(f"\n[init] LLM: {llm}")
    print(f"[init] Memory: {memory}")
    print(f"[init] Skills: {registry}")

    # ================================================================
    # TURN 1: Scan for open services
    # ================================================================
    task_1 = "Scan the target machine for open services"
    print(f"\n{'=' * 62}")
    print(f"  TURN 1: {task_1}")
    print(f"{'=' * 62}")

    agent = SecurityAgent(registry, memory=memory, llm=llm)
    result_1 = agent.run(task_1, context={"target_ip": target_ip})
    print_turn_result(1, task_1, result_1)

    # Show memory state between turns
    print(f"\n{'─' * 62}")
    print("  MEMORY STATE (between turns)")
    print(f"{'─' * 62}")
    print(f"  {memory.to_json()}")

    # ================================================================
    # TURN 2: Summarize findings (uses memory, not a new scan)
    # ================================================================
    task_2 = "Summarize the most important findings so far"
    print(f"\n\n{'=' * 62}")
    print(f"  TURN 2: {task_2}")
    print(f"{'=' * 62}")

    # Create a new agent instance but SAME memory — simulates next turn
    agent_2 = SecurityAgent(registry, memory=memory, llm=llm)
    result_2 = agent_2.run(task_2)
    print_turn_result(2, task_2, result_2)

    # Final memory state
    print(f"\n{'═' * 62}")
    print("  FINAL MEMORY STATE")
    print(f"{'═' * 62}")
    print(json.dumps(memory.get_context_snapshot(), indent=2))

    # Decision traces
    print(f"\n{'═' * 62}")
    print("  DECISION TRACES")
    print(f"{'═' * 62}")
    for i, (label, result) in enumerate(
        [("Turn 1", result_1), ("Turn 2", result_2)], 1
    ):
        print(f"\n  --- {label} ---")
        for step in result.get("trace", []):
            print(f"    [{step.get('event')}]")

    print(f"\n{'═' * 62}")
    print("  SESSION COMPLETE")
    print(f"{'═' * 62}")


if __name__ == "__main__":
    main()
