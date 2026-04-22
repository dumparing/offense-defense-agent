"""Tests for core.skill_registry."""

import unittest
from core.skill_base import SkillBase
from core.skill_registry import SkillRegistry


class DummySkill(SkillBase):
    @property
    def name(self):
        return "dummy"

    @property
    def description(self):
        return "A dummy skill for testing"

    @property
    def input_schema(self):
        return {"target": {"type": "str", "description": "test input"}}

    def execute(self, **kwargs):
        return {"success": True, "data": kwargs, "error": None}


class TestSkillRegistry(unittest.TestCase):
    def test_register_and_get(self):
        registry = SkillRegistry()
        skill = DummySkill()
        registry.register(skill)
        self.assertIs(registry.get("dummy"), skill)

    def test_get_missing(self):
        registry = SkillRegistry()
        self.assertIsNone(registry.get("nonexistent"))

    def test_list_skills(self):
        registry = SkillRegistry()
        registry.register(DummySkill())
        skills = registry.list_skills()
        self.assertEqual(len(skills), 1)
        self.assertEqual(skills[0]["name"], "dummy")
        self.assertIn("target", skills[0]["inputs"])

    def test_validate_inputs(self):
        skill = DummySkill()
        errors = skill.validate_inputs()
        self.assertEqual(len(errors), 1)
        self.assertIn("target", errors[0])

        errors = skill.validate_inputs(target="value")
        self.assertEqual(len(errors), 0)


if __name__ == "__main__":
    unittest.main()
