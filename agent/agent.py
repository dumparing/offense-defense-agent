"""
agent.py — LLM-driven agent loop with local Llama planner.

This module implements the core "reason → act → observe" cycle:
    1. Receive a natural-language task from the user.
    2. Read the current memory snapshot (what we already know).
    3. Ask the local Llama planner which skill to use and with what arguments.
    4. Execute the chosen skill.
    5. Summarize/compress the raw output via the summarizer.
    6. Update structured memory with the new findings.
    7. Return a clean result object with full decision trace.

The planner uses a local Llama model via Ollama, keeping all data on-machine.
If Ollama is unavailable, the agent falls back to keyword-based skill selection
so the demo still works without a running model.
"""

from __future__ import annotations

import json
import re
from typing import Any

from core.llm_client import LLMClient, OllamaError
from core.memory_manager import MemoryManager
from core.skill_registry import SkillRegistry
from core.summarizer import Summarizer


# ---------------------------------------------------------------------------
# Planner system prompt
# ---------------------------------------------------------------------------

PLANNER_SYSTEM = (
    "You are a defensive cybersecurity agent planner. Your job is to select "
    "the best skill to execute for a given task. You operate in an AUTHORIZED "
    "testing environment only.\n\n"
    "Rules:\n"
    "- Choose exactly one skill from the available list.\n"
    "- Extract the required arguments from the task and context.\n"
    "- Respond with ONLY valid JSON, no markdown, no explanation.\n"
    "- Do NOT suggest exploitation or unauthorized actions.\n"
    "- If no skill fits, or if all relevant analysis is done, set skill to \"none\".\n"
    "- For binary analysis tasks, the logical order is:\n"
    "  1. gdb_debug (find crashes) → 2. disassemble (classify vulnerability)\n"
    "- Do NOT repeat a skill that has already been used (check CURRENT MEMORY STATE).\n"
    "- The binary_path argument should be copied exactly from the CONTEXT or task.\n"
)


# ---------------------------------------------------------------------------
# Keyword fallback (used when Ollama is unavailable)
# ---------------------------------------------------------------------------

KEYWORD_SKILL_MAP: dict[str, list[str]] = {
    "network_scan": [
        "scan", "port", "service", "nmap", "recon", "reconnaissance",
    ],
    "gdb_debug": [
        "debug", "gdb", "crash", "fuzz", "overflow", "segfault", "binary",
        "exploit", "buffer",
    ],
    "disassemble": [
        "disassemble", "disasm", "objdump", "analyze", "reverse",
        "vulnerability", "static", "format string", "uaf", "assembly",
    ],
}


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class SecurityAgent:
    """
    LLM-driven agent loop for authorized defensive security testing.

    Architecture:
        User Task
            ↓
        [Memory Snapshot] — what do we already know?
            ↓
        [Planner LLM]    — which skill should we use?
            ↓
        [Skill Execution] — run the chosen skill
            ↓
        [Summarizer]      — compress raw output
            ↓
        [Memory Update]   — store structured findings
            ↓
        Result + Trace
    """

    def __init__(
        self,
        registry: SkillRegistry,
        memory: MemoryManager | None = None,
        llm: LLMClient | None = None,
    ) -> None:
        self.registry = registry
        self.memory = memory or MemoryManager()
        self.llm = llm or LLMClient()
        self.summarizer = Summarizer(self.llm)
        # Decision trace — records every step for observability
        self.trace: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def run_chain(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        max_steps: int = 5,
        on_step: Any = None,
    ) -> dict:
        """
        Execute a multi-step attack chain, orchestrated by the planner.

        The planner decides which skill to run at each step based on the
        accumulated memory. The chain stops when:
            - The planner selects "done" (analysis complete)
            - max_steps is reached
            - A critical error occurs

        Args:
            task:      High-level objective (e.g. "Analyze vuln_bof for vulnerabilities").
            context:   Initial context dict.
            max_steps: Maximum number of agent turns.
            on_step:   Optional callback(step_num, step_result) for live reporting.

        Returns:
            Dict with: steps (list of per-step results), final_memory,
            final_report, total_steps.
        """
        context = context or {}
        steps: list[dict] = []
        self._log("chain_started", {"task": task, "max_steps": max_steps})

        # Preserve key context across steps (e.g. binary_path, target_ip)
        persistent_context = dict(context)

        for step_num in range(1, max_steps + 1):
            # Build the chain-aware task prompt
            chain_task = self._build_chain_prompt(task, step_num, max_steps)

            step_result = self.run(chain_task, context=persistent_context)
            steps.append({
                "step": step_num,
                "skill_used": step_result.get("skill_used"),
                "success": step_result.get("success"),
                "summary": step_result.get("summary"),
                "reasoning": step_result.get("reasoning"),
            })

            if on_step:
                on_step(step_num, step_result)

            # Check if the planner signaled completion
            if step_result.get("skill_used") is None:
                self._log("chain_complete", {"reason": "planner said done", "steps": step_num})
                break

        # Build final report
        final_report = self._build_chain_report(task, steps)

        return {
            "steps": steps,
            "total_steps": len(steps),
            "final_memory": self.memory.get_context_snapshot(),
            "final_report": final_report,
            "trace": self.trace,
        }

    def _build_chain_prompt(
        self, original_task: str, step_num: int, max_steps: int
    ) -> str:
        """Build a step-aware prompt that guides the planner through the chain."""
        memory = self.memory.get_context_snapshot()
        actions = memory.get("actions_taken", [])
        skills_used = [a["skill"] for a in actions]

        if step_num == 1:
            return original_task

        # Guide the planner based on what's been done
        prompt_parts = [f"Continue analyzing: {original_task}"]
        prompt_parts.append(f"Step {step_num}/{max_steps}.")
        prompt_parts.append(f"Skills already used: {', '.join(skills_used)}.")

        # Suggest next logical skill
        if "gdb_debug" not in skills_used and "disassemble" not in skills_used:
            prompt_parts.append(
                "Consider debugging the binary with gdb_debug to find crash points, "
                "or disassembling it to find dangerous function calls."
            )
        elif "gdb_debug" in skills_used and "disassemble" not in skills_used:
            prompt_parts.append(
                "Crash analysis is done. Now disassemble the binary to classify "
                "the vulnerability and identify the root cause."
            )
        elif "disassemble" in skills_used and "gdb_debug" not in skills_used:
            prompt_parts.append(
                "Static analysis is done. Now debug the binary with gdb_debug "
                "to confirm the vulnerability is triggerable."
            )
        else:
            prompt_parts.append(
                "Both debugging and disassembly are done. "
                "If analysis is complete, select skill 'none' to finish."
            )

        return " ".join(prompt_parts)

    def _build_chain_report(
        self, task: str, steps: list[dict]
    ) -> dict[str, Any]:
        """Build a final summary report from a completed chain."""
        memory = self.memory.get_context_snapshot()

        return {
            "task": task,
            "steps_completed": len(steps),
            "skills_used": [s["skill_used"] for s in steps if s["skill_used"]],
            "all_findings": memory.get("findings", []),
            "vulnerabilities": memory.get("vulnerabilities", []),
            "crash_data": memory.get("crash_data", []),
            "analyzed_binaries": memory.get("analyzed_binaries", {}),
        }

    def run(self, task: str, context: dict[str, Any] | None = None) -> dict:
        """
        Execute one full agent turn for a given task.

        Args:
            task:    Natural-language task description.
            context: Optional dict with pre-extracted parameters
                     (e.g. {"target_ip": "192.168.1.1"}).

        Returns:
            Dict with: success, summary, skill_result, summarized_result,
                       memory_snapshot, and full decision trace.
        """
        context = context or {}
        self._log("task_received", {"task": task, "context": context})

        # --- Step 1: Read current memory ---
        memory_snapshot = self.memory.get_context_snapshot()
        self._log("memory_read", {"snapshot": memory_snapshot})

        # --- Step 2: Ask planner LLM which skill to use ---
        plan = self._plan(task, context, memory_snapshot)
        skill_name = plan.get("skill")
        arguments = plan.get("arguments", {})
        reasoning = plan.get("reasoning_summary", "")

        self._log("planner_decision", {
            "skill": skill_name,
            "arguments": arguments,
            "reasoning": reasoning,
        })

        # Validate: does this skill exist?
        if not skill_name or skill_name == "none":
            self._log("no_skill_selected", {"reasoning": reasoning})
            return self._result(
                success=False,
                summary="The planner could not find a matching skill for this task.",
                reasoning=reasoning,
            )

        skill = self.registry.get(skill_name)
        if skill is None:
            self._log("skill_not_registered", {"skill": skill_name})
            return self._result(
                success=False,
                summary=f"Planner selected '{skill_name}', but it is not registered.",
                reasoning=reasoning,
            )

        # --- Step 3: Merge context into arguments ---
        # The planner may have extracted args; context overrides them
        merged_args = {**arguments, **context}
        self._log("executing_skill", {"skill": skill_name, "arguments": merged_args})

        # --- Step 4: Execute the skill ---
        skill_result = skill.execute(**merged_args)
        self._log("skill_result", {"success": skill_result.get("success"), "brief": _brief(skill_result)})

        # --- Step 5: Summarize / compress the output ---
        summarized = self.summarizer.summarize_generic(skill_name, skill_result)
        nl_summary = summarized.get("natural_language_summary", "")
        structured = summarized.get("structured", {})
        self._log("summarized", {"summary": nl_summary, "structured_keys": list(structured.keys())})

        # --- Step 6: Update memory ---
        self.memory.record_action(
            skill=skill_name,
            arguments=merged_args,
            success=skill_result.get("success", False),
            summary=nl_summary,
        )

        # Skill-specific memory updates
        if skill_name == "network_scan" and skill_result.get("success"):
            self.memory.record_scan_results(
                target=merged_args.get("target_ip", "unknown"),
                open_ports=structured.get("open_ports", []),
                services=structured.get("services", {}),
            )

        if skill_name == "gdb_debug" and skill_result.get("success"):
            data = skill_result.get("data", {})
            for crash in data.get("crashes", []):
                self.memory.record_crash(
                    binary=data.get("binary", "unknown"),
                    signal=crash.get("signal"),
                    fault_address=crash.get("fault_address"),
                    backtrace=crash.get("backtrace", []),
                    input_label=crash.get("input_label", ""),
                )

        if skill_name == "disassemble" and skill_result.get("success"):
            data = skill_result.get("data", {})
            self.memory.record_binary_analysis(
                binary=data.get("binary", "unknown"),
                arch=data.get("architecture"),
                protections=data.get("protections"),
                dangerous_calls=data.get("dangerous_calls"),
                vulnerability_patterns=data.get("vulnerability_patterns"),
                risk_level=data.get("risk_level"),
            )

        if structured.get("findings"):
            self.memory.record_findings(structured["findings"])

        self.memory.record_summary(nl_summary)

        updated_snapshot = self.memory.get_context_snapshot()
        self._log("memory_updated", {"snapshot": updated_snapshot})

        # --- Step 7: Return clean result ---
        return self._result(
            success=skill_result.get("success", False),
            summary=nl_summary,
            reasoning=reasoning,
            skill_used=skill_name,
            skill_arguments=merged_args,
            skill_result=skill_result,
            summarized_result=summarized,
            memory_snapshot=updated_snapshot,
        )

    # ------------------------------------------------------------------
    # Planner — LLM-based skill selection
    # ------------------------------------------------------------------

    def _plan(
        self,
        task: str,
        context: dict[str, Any],
        memory: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Ask the local Llama model to choose a skill and extract arguments.

        Falls back to keyword matching if Ollama is unavailable.
        """
        skills_catalog = self.registry.list_skills()

        prompt = (
            f"TASK: {task}\n\n"
            f"CONTEXT: {json.dumps(context)}\n\n"
            f"CURRENT MEMORY STATE:\n{json.dumps(memory, indent=2)}\n\n"
            f"AVAILABLE SKILLS:\n{json.dumps(skills_catalog, indent=2)}\n\n"
            "Select the best skill for this task. "
            "Respond with ONLY this JSON format:\n"
            "{\n"
            '  "skill": "skill_name",\n'
            '  "arguments": {"arg1": "value1"},\n'
            '  "reasoning_summary": "Why you chose this skill"\n'
            "}\n\n"
            "If no skill applies, set skill to \"none\".\n"
        )

        try:
            plan = self.llm.generate_json(prompt, system_prompt=PLANNER_SYSTEM)
            self._log("planner_llm_used", {"model": self.llm.model})
            return plan
        except OllamaError as exc:
            # Fall back to keyword matching
            self._log("planner_llm_fallback", {"reason": str(exc)})
            return self._keyword_fallback(task, context)

    def _keyword_fallback(
        self, task: str, context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Simple keyword-based skill selection (fallback when LLM is unavailable).

        Aware of already-used skills to avoid repeating the same one.
        If the chain prompt mentions skills already used, the fallback
        picks the next unused skill in the logical order.
        """
        task_lower = task.lower()

        # Check what skills have already been used
        actions = self.memory.get_context_snapshot().get("actions_taken", [])
        used_skills = set(a["skill"] for a in actions)

        # If chain prompt says "all done" or we've used both analysis skills, stop
        if "analysis is complete" in task_lower or "select skill 'none'" in task_lower:
            return {
                "skill": "none",
                "arguments": {},
                "reasoning_summary": "[Keyword fallback] All analysis steps completed.",
            }

        # Logical chain ordering for binary analysis
        chain_order = ["gdb_debug", "disassemble"]

        # If we have binary_path context and haven't done all chain steps,
        # pick the next unused step
        if "binary_path" in context or any(
            kw in task_lower for kw in ["binary", "debug", "disassemble", "analyze", "crash", "vulnerability"]
        ):
            for skill_name in chain_order:
                if skill_name not in used_skills:
                    best_skill = skill_name
                    best_score = 1
                    break
            else:
                # All chain steps done
                return {
                    "skill": "none",
                    "arguments": context,
                    "reasoning_summary": (
                        "[Keyword fallback] All analysis skills already used. "
                        "Chain complete."
                    ),
                }
        else:
            # General keyword matching
            best_skill = None
            best_score = 0
            for skill_name, keywords in KEYWORD_SKILL_MAP.items():
                if skill_name in used_skills:
                    continue  # Skip already-used skills
                score = sum(1 for kw in keywords if kw in task_lower)
                if score > best_score:
                    best_score = score
                    best_skill = skill_name

        # Try to extract arguments from task or context
        arguments: dict[str, Any] = {}

        # Extract target_ip
        if "target_ip" in context:
            arguments["target_ip"] = context["target_ip"]
        else:
            ip_match = re.search(
                r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", task
            )
            if ip_match:
                arguments["target_ip"] = ip_match.group()

        # Extract binary_path
        if "binary_path" in context:
            arguments["binary_path"] = context["binary_path"]
        else:
            # Look for file paths in the task
            path_match = re.search(r"[./\w]+(?:vuln_\w+|\.elf|\.bin)", task)
            if path_match:
                arguments["binary_path"] = path_match.group()

        return {
            "skill": best_skill or "none",
            "arguments": arguments,
            "reasoning_summary": (
                f"[Keyword fallback] Matched '{best_skill}' with score {best_score}. "
                "LLM planner was unavailable."
            ),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log(self, event: str, data: dict[str, Any]) -> None:
        """Append an entry to the agent's decision trace."""
        self.trace.append({"event": event, **data})

    def _result(self, **kwargs: Any) -> dict[str, Any]:
        """Build the final result dict, attaching the full trace."""
        return {**kwargs, "trace": self.trace}


def _brief(result: dict) -> dict:
    """Return a shortened version of a skill result (omit raw output for logging)."""
    brief = {k: v for k, v in result.items() if k != "data"}
    data = result.get("data")
    if isinstance(data, dict):
        brief["services_found"] = data.get("services_found")
    return brief
