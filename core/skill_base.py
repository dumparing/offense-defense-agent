"""
skill_base.py — Abstract base class for all skills.

Every skill in the system inherits from this class. This enforces a uniform
interface so the agent can discover, validate, and invoke any skill without
knowing its internals.

A skill defines:
    name         – unique identifier (e.g. "network_scan")
    description  – one-line summary the agent uses during skill selection
    input_schema – dict describing required inputs and their types
    execute()    – runs the skill and returns structured results
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class SkillBase(ABC):
    """Abstract base class that every skill must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this skill."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description the agent reads when choosing a skill."""
        ...

    @property
    @abstractmethod
    def input_schema(self) -> dict:
        """
        Describes required inputs.

        Example:
            {"target_ip": {"type": "str", "description": "IP address to scan"}}
        """
        ...

    @abstractmethod
    def execute(self, **kwargs) -> dict[str, Any]:
        """
        Run the skill with the given inputs.

        Returns a dict with at least:
            {"success": bool, "data": ..., "error": str | None}
        """
        ...

    def validate_inputs(self, **kwargs) -> list[str]:
        """Check that all required inputs are present. Returns list of errors."""
        errors = []
        for field, spec in self.input_schema.items():
            if field not in kwargs:
                errors.append(f"Missing required input: '{field}'")
        return errors

    def __repr__(self) -> str:
        return f"<Skill: {self.name}>"
