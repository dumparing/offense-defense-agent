"""
skill_registry.py — Central registry that tracks all available skills.

The agent queries this registry to discover which skills exist, match a task
to the right skill, and retrieve skill metadata. New skills are registered
at import time via register().
"""

from __future__ import annotations

from core.skill_base import SkillBase


class SkillRegistry:
    """Maintains a name → skill mapping so the agent can look up skills."""

    def __init__(self) -> None:
        self._skills: dict[str, SkillBase] = {}

    def register(self, skill: SkillBase) -> None:
        """Add a skill instance to the registry."""
        self._skills[skill.name] = skill

    def get(self, name: str) -> SkillBase | None:
        """Retrieve a skill by name, or None if not found."""
        return self._skills.get(name)

    def list_skills(self) -> list[dict]:
        """Return metadata for every registered skill (used by the agent)."""
        return [
            {
                "name": s.name,
                "description": s.description,
                "inputs": s.input_schema,
            }
            for s in self._skills.values()
        ]

    def __repr__(self) -> str:
        names = ", ".join(self._skills.keys())
        return f"<SkillRegistry: [{names}]>"
