#!/usr/bin/env python3
"""Agent Skills spec checks: the built skill folder must pass tools/validate_skill.py,
and the validator must reject the common cross-agent breakages."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT / "tools"))

import validate_skill as vs  # noqa: E402

try:
    import build_skill  # noqa: E402  (dev repo only)
except ImportError:  # skill-only repo: the skill folder is checked in
    build_skill = None


def _skill_dir(tmp: Path) -> Path:
    if build_skill is not None:
        return build_skill.build(tmp, make_zip=False)
    return _ROOT / "ens-expert-rules"


GOOD_RULE = 'Rule {\n    Target {\n        Match FILE {\n            Include OBJECT_NAME { -v "**\\\\x.exe" }\n            Include -access "CREATE"\n        }\n    }\n}\n'


def _write_skill(base: Path, folder: str, frontmatter: str, body: str = "# T\n") -> Path:
    d = base / folder
    (d / "scripts").mkdir(parents=True)
    linter = _ROOT / "scripts" / "lint_expert_rule.py"
    if not linter.exists():
        linter = _ROOT / "ens-expert-rules" / "scripts" / "lint_expert_rule.py"
    shutil.copy2(linter, d / "scripts" / "lint_expert_rule.py")
    (d / "SKILL.md").write_text(f"---\n{frontmatter}---\n{body}", encoding="utf-8")
    return d


class BuiltSkill(unittest.TestCase):
    def test_built_skill_passes_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill = _skill_dir(Path(tmp))
            errors = vs.validate(skill, skill / "scripts" / "lint_expert_rule.py")
            self.assertEqual(errors, [], "\n".join(errors))


class ValidatorCatchesBreakage(unittest.TestCase):
    def _errors(self, folder: str, fm: str, body: str = "# T\n") -> list:
        with tempfile.TemporaryDirectory() as tmp:
            d = _write_skill(Path(tmp), folder, fm, body)
            return vs.validate(d, d / "scripts" / "lint_expert_rule.py")

    def test_minimal_valid(self) -> None:
        self.assertEqual(self._errors("my-skill", "name: my-skill\ndescription: Does a thing.\n"), [])

    def test_top_level_version_rejected(self) -> None:
        errs = self._errors("my-skill", "name: my-skill\ndescription: x\nversion: 1.0\n")
        self.assertTrue(any(e.startswith("S2") for e in errs), errs)

    def test_name_must_match_folder(self) -> None:
        errs = self._errors("ExpertRulesAiSkill", "name: my-skill\ndescription: x\n")
        self.assertTrue(any("must match folder" in e for e in errs), errs)

    def test_bad_name_rejected(self) -> None:
        errs = self._errors("My--Skill", "name: My--Skill\ndescription: x\n")
        self.assertTrue(any("invalid name" in e for e in errs), errs)

    def test_long_description_rejected(self) -> None:
        errs = self._errors("my-skill", f"name: my-skill\ndescription: {'a' * 1100}\n")
        self.assertTrue(any(e.startswith("S4") for e in errs), errs)

    def test_broken_link_rejected(self) -> None:
        errs = self._errors("my-skill", "name: my-skill\ndescription: x\n",
                            "See [ref](references/missing.md)\n")
        self.assertTrue(any(e.startswith("S6") for e in errs), errs)

    def test_bad_example_rule_rejected(self) -> None:
        errs = self._errors("my-skill", "name: my-skill\ndescription: x\n",
                            "```tcl\nRule {\n    Target {\n        Match NOPE {\n        }\n    }\n}\n```\n")
        self.assertTrue(any(e.startswith("S7") for e in errs), errs)

    def test_good_example_rule_passes(self) -> None:
        errs = self._errors("my-skill", "name: my-skill\ndescription: x\n",
                            f"```tcl\n{GOOD_RULE}```\n")
        self.assertEqual(errs, [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
