#!/usr/bin/env python3
"""
evaluate.py — Evaluation framework for the security agent.

Runs the agent on CTF-style vulnerable binaries and measures:
    1. Completion rate — did the agent finish the analysis chain?
    2. Correctness     — did it identify the right vulnerability class?
    3. Efficiency      — how many agent turns / LLM calls did it take?
    4. Coverage        — did it use all relevant skills?

Each target has a ground-truth label specifying the vulnerability class.
The evaluator compares agent findings against ground truth.

Usage:
    python evaluation/evaluate.py                  # run all targets
    python evaluation/evaluate.py --target vuln_bof # run one target
    python evaluation/evaluate.py --verbose         # detailed output

Prerequisites:
    - Vulnerable binaries compiled (cd targets && make)
    - Ollama running (optional — falls back to keyword planner)
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent.agent import SecurityAgent
from core.llm_client import LLMClient
from core.memory_manager import MemoryManager
from core.skill_registry import SkillRegistry
from skills.network_scan import NetworkScanSkill
from skills.gdb_debug import GDBDebugSkill
from skills.disassemble import DisassembleSkill


# ---------------------------------------------------------------------------
# Ground truth definitions
# ---------------------------------------------------------------------------

@dataclass
class TargetSpec:
    """Ground truth for a vulnerable binary."""
    name: str
    binary: str
    vulnerability_class: str
    expected_dangerous_functions: list[str]
    expected_crash: bool
    expected_signals: list[str] = field(default_factory=list)
    description: str = ""


TARGETS_DIR = PROJECT_ROOT / "targets"

GROUND_TRUTH: list[TargetSpec] = [
    TargetSpec(
        name="vuln_bof",
        binary=str(TARGETS_DIR / "vuln_bof"),
        vulnerability_class="buffer_overflow",
        expected_dangerous_functions=["gets"],
        expected_crash=True,
        expected_signals=["SIGSEGV"],
        description="Stack buffer overflow via gets()",
    ),
    TargetSpec(
        name="vuln_fmt",
        binary=str(TARGETS_DIR / "vuln_fmt"),
        vulnerability_class="format_string",
        expected_dangerous_functions=["printf"],
        expected_crash=True,  # format string with %s%s... causes crash
        expected_signals=["SIGSEGV"],
        description="Format string via printf(user_input)",
    ),
    TargetSpec(
        name="vuln_uaf",
        binary=str(TARGETS_DIR / "vuln_uaf"),
        vulnerability_class="use_after_free",
        expected_dangerous_functions=["malloc", "free"],
        expected_crash=True,
        expected_signals=["SIGSEGV", "SIGABRT"],
        description="Use-after-free via dangling pointer",
    ),
    TargetSpec(
        name="vuln_heap",
        binary=str(TARGETS_DIR / "vuln_heap"),
        vulnerability_class="buffer_overflow",
        expected_dangerous_functions=["strcpy"],
        expected_crash=True,  # heap overflow triggers heap corruption detection
        expected_signals=["SIGTRAP", "SIGABRT"],
        description="Heap overflow via strcpy() into small buffer",
    ),
]


# ---------------------------------------------------------------------------
# Evaluation metrics
# ---------------------------------------------------------------------------

@dataclass
class EvalResult:
    """Results for a single target evaluation."""
    target_name: str
    completed: bool
    correct_vuln_class: bool
    found_dangerous_functions: list[str]
    expected_dangerous_functions: list[str]
    dangerous_func_overlap: float  # 0.0 - 1.0
    crash_detected: bool
    expected_crash: bool
    crash_detection_correct: bool
    steps_taken: int
    skills_used: list[str]
    wall_time_seconds: float
    findings: list[str]
    vulnerabilities: list[dict]
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

class AgentEvaluator:
    """Run the agent on CTF targets and measure performance."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self.results: list[EvalResult] = []

    def evaluate_target(self, spec: TargetSpec) -> EvalResult:
        """Run the agent on one target and score the result."""
        print(f"\n{'─' * 60}")
        print(f"  Evaluating: {spec.name}")
        print(f"  Expected:   {spec.vulnerability_class}")
        print(f"  Binary:     {spec.binary}")
        print(f"{'─' * 60}")

        # Check binary exists
        if not os.path.isfile(spec.binary):
            print(f"  [SKIP] Binary not found: {spec.binary}")
            print(f"         Run: cd targets && make")
            return EvalResult(
                target_name=spec.name,
                completed=False,
                correct_vuln_class=False,
                found_dangerous_functions=[],
                expected_dangerous_functions=spec.expected_dangerous_functions,
                dangerous_func_overlap=0.0,
                crash_detected=False,
                expected_crash=spec.expected_crash,
                crash_detection_correct=False,
                steps_taken=0,
                skills_used=[],
                wall_time_seconds=0.0,
                findings=[],
                vulnerabilities=[],
                errors=["Binary not found"],
            )

        # Set up agent
        llm = LLMClient()
        memory = MemoryManager()
        registry = SkillRegistry()
        registry.register(GDBDebugSkill())
        registry.register(DisassembleSkill())
        registry.register(NetworkScanSkill())

        agent = SecurityAgent(registry, memory=memory, llm=llm)

        # Run the chain
        task = (
            f"Analyze the binary at {spec.binary} for security vulnerabilities. "
            f"Debug it to find crashes and disassemble it to identify "
            f"dangerous function calls and vulnerability patterns."
        )

        start = time.time()

        def on_step(step_num: int, result: dict) -> None:
            if self.verbose:
                print(f"    Step {step_num}: {result.get('skill_used', 'none')} "
                      f"— {result.get('summary', '')[:80]}")

        chain_result = agent.run_chain(
            task,
            context={"binary_path": spec.binary},
            max_steps=4,
            on_step=on_step,
        )

        elapsed = time.time() - start

        # Score the results
        return self._score(spec, chain_result, elapsed)

    def _score(
        self,
        spec: TargetSpec,
        chain_result: dict,
        elapsed: float,
    ) -> EvalResult:
        """Score agent output against ground truth."""
        report = chain_result.get("final_report", {})
        memory = chain_result.get("final_memory", {})

        steps = chain_result.get("steps", [])
        skills_used = report.get("skills_used", [])
        findings = report.get("all_findings", [])
        vulns = report.get("vulnerabilities", [])

        # 1. Completion: did it run at least 2 skills?
        completed = len(skills_used) >= 2

        # 2. Correct vulnerability class
        found_vuln_classes = [v.get("vulnerability", "") for v in vulns]
        correct_vuln_class = spec.vulnerability_class in found_vuln_classes

        # 3. Dangerous functions found
        found_funcs = set()
        for v in memory.get("analyzed_binaries", {}).values():
            # Check in detailed dangerous calls from findings
            pass
        # Also check findings text
        all_text = " ".join(findings).lower()
        for func in spec.expected_dangerous_functions:
            if func.lower() in all_text:
                found_funcs.add(func)
        # Check vulnerability pattern evidence
        for v in vulns:
            desc = v.get("description", "").lower()
            for func in spec.expected_dangerous_functions:
                if func.lower() in desc:
                    found_funcs.add(func)

        expected = set(spec.expected_dangerous_functions)
        overlap = len(found_funcs & expected) / len(expected) if expected else 1.0

        # 4. Crash detection
        crash_data = memory.get("crash_data", [])
        crash_detected = len(crash_data) > 0
        crash_correct = crash_detected == spec.expected_crash

        result = EvalResult(
            target_name=spec.name,
            completed=completed,
            correct_vuln_class=correct_vuln_class,
            found_dangerous_functions=list(found_funcs),
            expected_dangerous_functions=spec.expected_dangerous_functions,
            dangerous_func_overlap=overlap,
            crash_detected=crash_detected,
            expected_crash=spec.expected_crash,
            crash_detection_correct=crash_correct,
            steps_taken=len(steps),
            skills_used=skills_used,
            wall_time_seconds=elapsed,
            findings=findings,
            vulnerabilities=vulns,
        )

        self.results.append(result)
        self._print_result(result)
        return result

    def _print_result(self, r: EvalResult) -> None:
        """Pretty-print one evaluation result."""
        check = lambda b: "PASS" if b else "FAIL"

        print(f"\n  Results for {r.target_name}:")
        print(f"    Completion:         [{check(r.completed)}] "
              f"({r.steps_taken} steps, skills: {', '.join(r.skills_used)})")
        print(f"    Vuln class:         [{check(r.correct_vuln_class)}] "
              f"(found: {[v.get('vulnerability') for v in r.vulnerabilities]})")
        print(f"    Dangerous funcs:    [{check(r.dangerous_func_overlap > 0)}] "
              f"(found: {r.found_dangerous_functions}, "
              f"expected: {r.expected_dangerous_functions})")
        print(f"    Crash detection:    [{check(r.crash_detection_correct)}] "
              f"(detected={r.crash_detected}, expected={r.expected_crash})")
        print(f"    Time:               {r.wall_time_seconds:.1f}s")

    def run_all(self, targets: list[TargetSpec] | None = None) -> dict:
        """Run evaluation on all (or specified) targets."""
        targets = targets or GROUND_TRUTH

        print("=" * 60)
        print("  SECURITY AGENT EVALUATION")
        print(f"  Targets: {len(targets)}")
        print("=" * 60)

        for spec in targets:
            self.evaluate_target(spec)

        return self.summary()

    def summary(self) -> dict:
        """Print and return aggregate metrics."""
        n = len(self.results)
        if n == 0:
            print("\n  No results to summarize.")
            return {}

        completed = sum(1 for r in self.results if r.completed)
        correct_vuln = sum(1 for r in self.results if r.correct_vuln_class)
        correct_crash = sum(1 for r in self.results if r.crash_detection_correct)
        avg_steps = sum(r.steps_taken for r in self.results) / n
        avg_time = sum(r.wall_time_seconds for r in self.results) / n
        avg_func_overlap = sum(r.dangerous_func_overlap for r in self.results) / n

        print(f"\n{'═' * 60}")
        print(f"  EVALUATION SUMMARY")
        print(f"{'═' * 60}")
        print(f"  Targets evaluated:        {n}")
        print(f"  Completion rate:          {completed}/{n} ({100*completed/n:.0f}%)")
        print(f"  Vuln class accuracy:      {correct_vuln}/{n} ({100*correct_vuln/n:.0f}%)")
        print(f"  Crash detection accuracy: {correct_crash}/{n} ({100*correct_crash/n:.0f}%)")
        print(f"  Dangerous func coverage:  {100*avg_func_overlap:.0f}%")
        print(f"  Avg steps per target:     {avg_steps:.1f}")
        print(f"  Avg time per target:      {avg_time:.1f}s")
        print(f"{'═' * 60}")

        metrics = {
            "targets_evaluated": n,
            "completion_rate": completed / n,
            "vuln_class_accuracy": correct_vuln / n,
            "crash_detection_accuracy": correct_crash / n,
            "dangerous_func_coverage": avg_func_overlap,
            "avg_steps": avg_steps,
            "avg_time_seconds": avg_time,
            "per_target": [
                {
                    "name": r.target_name,
                    "completed": r.completed,
                    "correct_vuln_class": r.correct_vuln_class,
                    "crash_correct": r.crash_detection_correct,
                    "func_overlap": r.dangerous_func_overlap,
                    "steps": r.steps_taken,
                    "time": r.wall_time_seconds,
                }
                for r in self.results
            ],
        }

        return metrics


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate security agent on CTF targets")
    parser.add_argument("--target", type=str, help="Run only this target (e.g. vuln_bof)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show step-by-step output")
    parser.add_argument("--json", action="store_true", help="Output metrics as JSON")
    args = parser.parse_args()

    evaluator = AgentEvaluator(verbose=args.verbose)

    if args.target:
        specs = [s for s in GROUND_TRUTH if s.name == args.target]
        if not specs:
            print(f"Unknown target: {args.target}")
            print(f"Available: {', '.join(s.name for s in GROUND_TRUTH)}")
            sys.exit(1)
        metrics = evaluator.run_all(specs)
    else:
        metrics = evaluator.run_all()

    if args.json:
        print("\n" + json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
