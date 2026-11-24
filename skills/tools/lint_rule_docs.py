#!/usr/bin/env python3
"""Lint the Expert Rules embedded in Markdown rule documents.

    python3 lint_rule_docs.py TRELLIX COMMUNITY            # whole corpus
    python3 lint_rule_docs.py --github path/to/rule.md     # PR annotations
    python3 lint_rule_docs.py --errors-only --summary TRELLIX

INFO findings (style nits such as trailing whitespace) are hidden unless --info.
Every fenced code block (``` or ```tcl) that contains `Rule {` is linted with the skill's
lint_expert_rule.py. Findings are reported with the line number in the .md file.
Exit code: 0 = no ERRORs, 1 = at least one ERROR, 2 = usage error.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

if sys.version_info < (3, 8):
    sys.stderr.write("lint_rule_docs.py needs Python 3.8 or newer\n")
    sys.exit(2)

_HERE = Path(__file__).resolve().parent
for _cand in (_HERE.parent / "ens-expert-rules" / "scripts", _HERE.parent / "scripts"):
    if (_cand / "lint_expert_rule.py").exists():
        sys.path.insert(0, str(_cand))
        break
import lint_expert_rule as L  # noqa: E402

BLOCK = re.compile(r"^[ \t]*```[ \t]*(\w*)[^\n]*\n(.*?)^[ \t]*```", re.S | re.M)
RULE = re.compile(r"\bRule\s*\{")


def rule_blocks(text: str):
    """Yield (first_line_number_of_block_body, body) for each rule code block."""
    for m in BLOCK.finditer(text):
        lang, body = m.group(1).lower(), m.group(2)
        if lang in ("", "tcl", "text") and RULE.search(body):
            yield text.count("\n", 0, m.start(2)) + 1, body


def md_files(paths):
    for p in paths:
        p = Path(p)
        if p.is_dir():
            yield from sorted(x for x in p.rglob("*.md") if x.name.lower() != "readme.md")
        elif p.suffix.lower() == ".md" and p.name.lower() != "readme.md" and p.exists():
            # README files hold templates/placeholders, not publishable rules
            yield p


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="+", help=".md files or folders")
    ap.add_argument("--github", action="store_true", help="emit GitHub Actions annotations")
    ap.add_argument("--errors-only", action="store_true", help="hide WARNING findings too")
    ap.add_argument("--info", action="store_true", help="also show INFO findings (style nits)")
    ap.add_argument("--summary", action="store_true", help="print totals per finding code")
    args = ap.parse_args()

    n_files = n_rules = n_err = n_warn = 0
    by_code: dict = {}
    for md in md_files(args.paths):
        text = md.read_text(encoding="utf-8", errors="replace")
        blocks = list(rule_blocks(text))
        if not blocks:
            continue
        n_files += 1
        for offset, body in blocks:
            n_rules += 1
            for f in L.lint(body):
                if f.severity == L.Severity.ERROR:
                    n_err += 1
                elif f.severity == L.Severity.WARNING:
                    n_warn += 1
                by_code[f.code] = by_code.get(f.code, 0) + 1
                if args.errors_only and f.severity != L.Severity.ERROR:
                    continue
                if f.severity == L.Severity.INFO and not args.info:
                    continue
                line = offset + f.line - 1
                path = md.as_posix()
                if args.github:
                    level = {"ERROR": "error", "WARNING": "warning"}.get(f.severity.name, "notice")
                    msg = f.message.replace("%", "%25").replace("\r", "").replace("\n", "%0A")
                    print(f"::{level} file={path},line={line},title={f.code}::{msg}")
                else:
                    print(f"{path}:{line}: {f.severity.name} {f.code} {f.message}")
    if args.summary:
        for code in sorted(by_code):
            print(f"  {code}: {by_code[code]}")
    print(f"{n_files} file(s), {n_rules} rule(s): {n_err} error(s), {n_warn} warning(s)",
          file=sys.stderr)
    return 1 if n_err else 0


if __name__ == "__main__":
    sys.exit(main())
