#!/usr/bin/env python3
"""Test suite for the ENS Expert Rule linter. Standard-library unittest only."""
from __future__ import annotations

import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from typing import List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
# dev repo keeps the linter in scripts/; the skill-only repo in ens-expert-rules/scripts/
for _cand in (os.path.join(_ROOT, "scripts"),
              os.path.join(_ROOT, "ens-expert-rules", "scripts")):
    if os.path.isfile(os.path.join(_cand, "lint_expert_rule.py")):
        sys.path.insert(0, _cand)
        break

import lint_expert_rule as linter  # noqa: E402

_GOOD_DIR = os.path.join(_HERE, "good")
_BAD_DIR = os.path.join(_HERE, "bad")
_EXPECT_RE = re.compile(r"#\s*expect:\s*([A-Z]\d{3})")


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _tcl_files(directory: str) -> List[str]:
    return sorted(
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if name.endswith(".tcl")
    )


def _expected_code(text: str) -> Optional[str]:
    match = _EXPECT_RE.search(text.splitlines()[0]) if text else None
    return match.group(1) if match else None


class GoodFixtures(unittest.TestCase):
    def test_good_fixtures_have_no_errors(self) -> None:
        for path in _tcl_files(_GOOD_DIR):
            with self.subTest(fixture=os.path.basename(path)):
                findings = linter.lint(_read(path))
                errors = [f for f in findings
                          if f.severity == linter.Severity.ERROR]
                self.assertEqual(
                    errors, [],
                    f"{os.path.basename(path)} reported ERRORs: "
                    f"{[f.code for f in errors]}",
                )


class BadFixtures(unittest.TestCase):
    def test_each_bad_fixture_emits_its_expected_code(self) -> None:
        files = _tcl_files(_BAD_DIR)
        self.assertTrue(files, "no bad fixtures found")
        for path in files:
            name = os.path.basename(path)
            with self.subTest(fixture=name):
                text = _read(path)
                expected = _expected_code(text)
                self.assertIsNotNone(
                    expected, f"{name} lacks a '# expect:<CODE>' first line")
                codes = {f.code for f in linter.lint(text)}
                self.assertIn(
                    expected, codes,
                    f"{name} expected {expected}, got {sorted(codes)}",
                )

    def test_every_finding_code_has_a_bad_fixture(self) -> None:
        covered: set[str] = set()
        for path in _tcl_files(_BAD_DIR):
            code = _expected_code(_read(path))
            if code is not None:
                covered.add(code)
        emitted: set[str] = set()
        for path in _tcl_files(_BAD_DIR):
            emitted.update(f.code for f in linter.lint(_read(path)))
        uncovered = sorted(emitted - covered)
        self.assertEqual(
            uncovered, [],
            f"codes emitted by fixtures but not covered by an expect line: "
            f"{uncovered}",
        )


class Catalogue(unittest.TestCase):
    def test_catalogue_covers_every_emittable_code(self) -> None:
        catalogued = {code for code, _s, _t in linter.RULE_CATALOGUE}
        emitted: set[str] = set()
        for directory in (_GOOD_DIR, _BAD_DIR):
            for path in _tcl_files(directory):
                emitted.update(f.code for f in linter.lint(_read(path)))
        missing = sorted(emitted - catalogued)
        self.assertEqual(
            missing, [],
            f"codes emitted but absent from RULE_CATALOGUE: {missing}")


class ConsoleSuppliedFields(unittest.TestCase):
    """Reaction, Severity, Description and Group are set in the ePO/ENS console form,
    so a bare rule body (the form published upstream) must lint clean."""

    BARE_RULE = (
        "Rule {\n"
        "    Process {\n"
        "        Include OBJECT_NAME { -v \"powershell.exe\" }\n"
        "    }\n"
        "    Target {\n"
        "        Match FILE {\n"
        "            Include OBJECT_NAME { -v \"**\\\\evil.dll\" }\n"
        "            Include -access \"CREATE\"\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    def test_bare_rule_without_console_fields_has_no_findings(self) -> None:
        self.assertEqual(linter.lint(self.BARE_RULE), [])


class TclEscapes(unittest.TestCase):
    def _w203(self, value: str) -> bool:
        text = ("Rule {\n    Target {\n        Match FILE {\n"
                f"            Include OBJECT_NAME {{ -v \"{value}\" }}\n"
                "            Include -access \"CREATE\"\n        }\n    }\n}\n")
        return any(f.code == "W203" for f in linter.lint(text))

    def test_deliberate_escapes_are_not_flagged(self) -> None:
        for value in ("**\\\\\\$Recycle.Bin\\\\**", "*\\[System.Reflection\\]*",
                      "a\\0b\\0\\0"):
            self.assertFalse(self._w203(value), value)

    def test_dropped_backslash_is_flagged(self) -> None:
        self.assertTrue(self._w203("**\\\\Users\\Public"))


class MalformedInput(unittest.TestCase):
    def test_empty_input_produces_no_findings(self) -> None:
        self.assertEqual(linter.lint(""), [])

    def test_whitespace_only_input_has_no_errors_or_warnings(self) -> None:
        findings = linter.lint("\n\n\n")
        self.assertEqual(
            [f for f in findings if f.severity >= linter.Severity.WARNING], [])

    def test_deep_nesting_reports_e102(self) -> None:
        text = "a { " * 20 + "z" + " }" * 20
        codes = {f.code for f in linter.lint(text)}
        self.assertIn("E102", codes)

    def test_unbalanced_brace_reports_e101(self) -> None:
        codes = {f.code for f in linter.lint("Rule {\n    Reaction BLOCK\n")}
        self.assertIn("E101", codes)


class Cli(unittest.TestCase):
    def _run(self, argv: List[str]) -> int:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            return linter.main(argv)

    def test_exit_zero_on_clean_rule(self) -> None:
        path = os.path.join(_GOOD_DIR, "file_startup.tcl")
        self.assertEqual(self._run([path, "--quiet"]), 0)

    def test_exit_one_when_errors_present(self) -> None:
        path = os.path.join(_BAD_DIR, "e121_bad_reaction.tcl")
        self.assertEqual(self._run([path, "--quiet"]), 1)

    def test_exit_two_on_missing_file(self) -> None:
        missing = os.path.join(_HERE, "does-not-exist.tcl")
        self.assertEqual(self._run([missing]), 2)

    def test_multiple_files_exit_reflects_worst(self) -> None:
        good = os.path.join(_GOOD_DIR, "file_startup.tcl")
        bad = os.path.join(_BAD_DIR, "e121_bad_reaction.tcl")
        self.assertEqual(self._run([good, good, "--quiet"]), 0)
        self.assertEqual(self._run([good, bad, "--quiet"]), 1)

    def test_exit_two_on_non_utf8_file(self) -> None:
        handle = tempfile.NamedTemporaryFile(
            suffix=".tcl", delete=False, mode="wb")
        try:
            handle.write(b"Rule {\n    Reaction \xff\xfe BLOCK\n}\n")
            handle.close()
            self.assertEqual(self._run([handle.name]), 2)
        finally:
            os.unlink(handle.name)

    def test_json_format_is_valid(self) -> None:
        import json
        path = os.path.join(_BAD_DIR, "e121_bad_reaction.tcl")
        out = io.StringIO()
        with redirect_stdout(out):
            linter.main([path, "--format", "json"])
        payload = json.loads(out.getvalue())
        self.assertIn("findings", payload)
        self.assertTrue(
            any(f["code"] == "E121" for f in payload["findings"]))

    def test_sarif_format_is_valid(self) -> None:
        import json
        path = os.path.join(_BAD_DIR, "e121_bad_reaction.tcl")
        out = io.StringIO()
        with redirect_stdout(out):
            linter.main([path, "--format", "sarif"])
        sarif = json.loads(out.getvalue())
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], linter.TOOL_NAME)
        self.assertTrue(run["tool"]["driver"]["rules"])
        ids = {r["ruleId"] for r in run["results"]}
        self.assertIn("E121", ids)
        for result in run["results"]:
            loc = result["locations"][0]["physicalLocation"]
            self.assertGreaterEqual(loc["region"]["startLine"], 1)
            self.assertIn("level", result)

    def test_min_severity_filters_info(self) -> None:
        text = "a { " * 20 + "z" + " }" * 20
        findings = linter.lint(text, min_severity=linter.Severity.ERROR)
        self.assertTrue(all(
            f.severity >= linter.Severity.ERROR for f in findings))


if __name__ == "__main__":
    unittest.main()
