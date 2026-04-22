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
import os
import re
from typing import Any

from core.llm_client import LLMClient, OllamaError
from core.memory_manager import MemoryManager
from core.skill_registry import SkillRegistry
from core.summarizer import Summarizer

DEFAULT_MEMORY_PATH = ".agent_memory.json"

# Skill names that record exploitation results in memory
_EXPLOIT_SKILL_NAMES = {
    "exploit", "ret2win", "heap_exploit", "uaf_exploit",
    "format_exploit", "exploit_sub_agent",
}

_VULN_PRIORITY = ["use_after_free", "buffer_overflow", "format_string"]


def _pick_vuln_class(vulns: list[dict], binary_name: str = "") -> str | None:
    """
    Pick the most relevant vulnerability class from a list of findings.
    Uses binary_name as a strong hint to override generic priority ordering
    (e.g. heap binaries that use malloc/free can be falsely flagged as UAF).
    """
    if not vulns:
        return None
    found = {v.get("vulnerability", "") for v in vulns}
    if binary_name:
        if ("bof" in binary_name or "heap" in binary_name) and "buffer_overflow" in found:
            return "buffer_overflow"
        if "uaf" in binary_name and "use_after_free" in found:
            return "use_after_free"
        if "fmt" in binary_name and "format_string" in found:
            return "format_string"
    return next((p for p in _VULN_PRIORITY if p in found), vulns[0].get("vulnerability"))


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
    "  1. gdb_debug (find crashes) → 2. disassemble (classify vulnerability)"
    " → 3. exploit (attempt exploitation)\n"
    "- Do NOT repeat a skill that has already been used (check CURRENT MEMORY STATE).\n"
    "- The binary_path argument should be copied exactly from the CONTEXT or task.\n"
)


# ---------------------------------------------------------------------------
# Keyword fallback (used when Ollama is unavailable)
# ---------------------------------------------------------------------------

KEYWORD_SKILL_MAP: dict[str, list[str]] = {
    "network_scan": [
        "scan", "port", "service", "nmap",
    ],
    "recon": [
        "recon", "reconnaissance", "scan network", "discover services",
    ],
    "gdb_debug": [
        "debug", "gdb", "crash", "fuzz", "segfault",
    ],
    "disassemble": [
        "disassemble", "disasm", "objdump", "static", "assembly",
    ],
    "binary_analysis": [
        "analyze binary", "binary analysis", "full analysis", "binary", "overflow",
        "vulnerability", "analyze", "reverse", "uaf", "format string",
    ],
    "exploit_sub_agent": [
        "exploit", "attack", "payload", "pwn", "gain access", "escalate",
    ],
    "ret2win": [
        "ret2win", "stack overflow", "secret_function", "return address",
    ],
    "heap_exploit": [
        "heap overflow", "heap exploit", "is_admin", "heap",
    ],
    "uaf_exploit": [
        "use after free", "use-after-free", "uaf exploit", "function pointer",
    ],
    "format_exploit": [
        "format string exploit", "printf exploit", "format leak", "memory leak",
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
        memory_path: str = DEFAULT_MEMORY_PATH,
        persist_memory: bool = True,
    ) -> None:
        self.registry = registry
        self.llm = llm or LLMClient()
        self.summarizer = Summarizer(self.llm)
        self.memory_path = memory_path
        self.persist_memory = persist_memory
        # Decision trace — records every step for observability
        self.trace: list[dict[str, Any]] = []

        # Auto-load from disk if no memory was explicitly passed
        if memory is not None:
            self.memory = memory
        elif persist_memory and os.path.isfile(memory_path):
            try:
                self.memory = MemoryManager.load(memory_path)
            except Exception:
                self.memory = MemoryManager()
        else:
            self.memory = MemoryManager()

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

        # Persist memory to disk so it survives process restarts
        if self.persist_memory:
            try:
                self.memory.save(self.memory_path)
                self._log("memory_saved", {"path": self.memory_path})
            except Exception as exc:
                self._log("memory_save_failed", {"error": str(exc)})

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

        # Suggest next logical skill — handles both flat and sub-agent modes
        analysis_done = (
            "binary_analysis" in skills_used
            or ("gdb_debug" in skills_used and "disassemble" in skills_used)
        )
        exploit_done = (
            "exploit_sub_agent" in skills_used
            or any(s in skills_used for s in ("exploit", "ret2win", "heap_exploit", "uaf_exploit", "format_exploit"))
        )

        if not analysis_done:
            if "binary_analysis" in [s.name for s in self.registry._skills.values()]:
                prompt_parts.append(
                    "Run binary_analysis to debug and disassemble the binary in one step."
                )
            elif "gdb_debug" not in skills_used:
                prompt_parts.append(
                    "Debug the binary with gdb_debug to find crash points."
                )
            else:
                prompt_parts.append(
                    "Crash analysis done. Now disassemble to classify the vulnerability."
                )
        elif not exploit_done:
            if "exploit_sub_agent" in [s.name for s in self.registry._skills.values()]:
                prompt_parts.append(
                    "Analysis complete. Now run exploit_sub_agent to attempt exploitation."
                )
            else:
                prompt_parts.append(
                    "Analysis complete. Choose the correct exploit skill based on the "
                    "vulnerability class found: ret2win (stack BOF), heap_exploit (heap BOF), "
                    "uaf_exploit (use-after-free), or format_exploit (format string)."
                )
        else:
            prompt_parts.append("All steps complete. Select skill 'none' to finish.")

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

        if skill_name in _EXPLOIT_SKILL_NAMES and skill_result.get("success"):
            data = skill_result.get("data") or {}
            self.memory.record_exploit(
                binary=data.get("binary", "unknown"),
                vulnerability_class=data.get("vulnerability_class", "unknown"),
                strategy=data.get("strategy"),
                exploited=data.get("exploited", False),
                flag_found=data.get("flag_found", False),
                output=data.get("output", ""),
            )

        if skill_name == "binary_analysis" and skill_result.get("success"):
            data = skill_result.get("data") or {}
            for crash in data.get("crash_data", []):
                self.memory.crash_data.append(crash)
            for binary, analysis in data.get("analyzed_binaries", {}).items():
                self.memory.analyzed_binaries[binary] = analysis
            for vuln in data.get("vulnerabilities", []):
                if vuln not in self.memory.vulnerabilities:
                    self.memory.vulnerabilities.append(vuln)
            if data.get("findings"):
                self.memory.record_findings(data["findings"])

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

        # Logical chain ordering — prefer sub-agent names if registered
        _full_chain = [
            "binary_analysis", "gdb_debug", "disassemble",
            "exploit_sub_agent", "exploit", "ret2win", "heap_exploit",
            "uaf_exploit", "format_exploit",
        ]
        chain_order = [s for s in _full_chain if self.registry.get(s) is not None]

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

        # For exploit skills: inject vulnerability_class from memory
        if best_skill in _EXPLOIT_SKILL_NAMES or best_skill == "exploit_sub_agent":
            vulns = self.memory.get_context_snapshot().get("vulnerabilities", [])
            binary_path = arguments.get("binary_path") or context.get("binary_path", "")
            binary_name = os.path.basename(binary_path)
            vuln_class_from_memory = _pick_vuln_class(vulns, binary_name)
            if vuln_class_from_memory:
                arguments["vulnerability_class"] = vuln_class_from_memory
            elif "buffer" in task_lower or "overflow" in task_lower:
                arguments["vulnerability_class"] = "buffer_overflow"
            elif "format" in task_lower:
                arguments["vulnerability_class"] = "format_string"
            elif "uaf" in task_lower or "use.after" in task_lower:
                arguments["vulnerability_class"] = "use_after_free"
            else:
                arguments["vulnerability_class"] = "buffer_overflow"

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
