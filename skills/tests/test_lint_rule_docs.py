#!/usr/bin/env python3
"""tools/lint_rule_docs.py lints rules embedded in Markdown rule documents."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "tools" / "lint_rule_docs.py"

GOOD = """# Example rule

## Description
Blocks Word from starting PowerShell.

## Rule
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "WINWORD.EXE" }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "powershell.exe" }
            Include -access "CREATE"
        }
    }
}
```
"""

# comment before Rule { -> E122 on the first line of the block (line 4 of the file)
BAD = """# Bad rule

```
# comment before the rule
Rule {
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\\\x.txt" }
            Include -access "CREATE"
        }
    }
}
```
"""


class LintRuleDocsTests(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(_TOOL), *args],
                              capture_output=True, text=True)

    def test_clean_document_passes(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "good.md"
            p.write_text(GOOD, encoding="utf-8")
            r = self.run_tool("--errors-only", str(p))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("1 rule(s): 0 error(s)", r.stderr)

    def test_error_reported_with_markdown_line(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.md"
            p.write_text(BAD, encoding="utf-8")
            r = self.run_tool("--github", str(p))
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertRegex(r.stdout, r"::error file=.*bad\.md,line=4,title=E122::")

    def test_folder_scan_skips_readme_and_non_rule_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "README.md").write_text(BAD, encoding="utf-8")
            (Path(d) / "notes.md").write_text("```\nnot a rule\n```\n", encoding="utf-8")
            r = self.run_tool(d)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("0 file(s), 0 rule(s)", r.stderr)


if __name__ == "__main__":
    unittest.main()
