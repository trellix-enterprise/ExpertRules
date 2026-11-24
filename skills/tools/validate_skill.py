#!/usr/bin/env python3
"""Validate an Agent Skill folder against the Agent Skills spec and our own rules.

Standard library only (Python 3.8+). Intended for PR checks:

    python3 tools/validate_skill.py path/to/ens-expert-rules

Checks
  S1  SKILL.md exists and starts with YAML frontmatter
  S2  only spec frontmatter fields (name, description, license, compatibility,
      metadata, allowed-tools)
  S3  name: 1-64 chars, [a-z0-9-], no leading/trailing/double hyphen, == folder name
  S4  description 1-1024 chars; compatibility <= 500 chars; metadata values are strings
  S5  SKILL.md body < 500 lines and ~< 5000 tokens (progressive-disclosure budget)
  S6  every relative Markdown link in SKILL.md / references resolves inside the skill
  S7  every ```tcl example starting with "Rule" lints with zero ERRORs
  S8  no stray development files shipped (tests, caches, internal notes)
Exit code: 0 = pass, 1 = failures, 2 = usage error.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

ALLOWED_FIELDS = {"name", "description", "license", "compatibility", "metadata",
                  "allowed-tools"}
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
TCL_BLOCK_RE = re.compile(r"```tcl[^\n]*\n(.*?)```", re.S)
# Development files that must not be committed inside the skill folder. Interpreter
# caches (__pycache__, .mypy_cache) are git-ignored local artefacts, so they are skipped.
FORBIDDEN = {"tests", "plan.md", "research.md", ".github", "eval"}
CACHE_DIRS = {"__pycache__", ".mypy_cache", ".pytest_cache"}


def parse_frontmatter(text: str) -> Tuple[Dict[str, object], str]:
    """Minimal YAML subset: top-level scalars, folded/literal blocks, one-level maps."""
    if not text.startswith("---"):
        raise ValueError("SKILL.md must start with '---' frontmatter")
    end = text.find("\n---", 3)
    if end < 0:
        raise ValueError("frontmatter is not closed with '---'")
    block, body = text[3:end].strip("\n"), text[end + 4:].lstrip("\n")
    data: Dict[str, object] = {}
    lines = block.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if not m:
            raise ValueError(f"cannot parse frontmatter line: {line!r}")
        key, rest = m.group(1), m.group(2).strip()
        i += 1
        if rest in (">", ">-", "|", "|-", ""):
            sub: List[str] = []
            while i < len(lines) and (lines[i].startswith(" ") or not lines[i].strip()):
                sub.append(lines[i])
                i += 1
            if rest == "" and sub and all(re.match(r"^\s+[A-Za-z0-9_-]+:", s) or not s.strip() for s in sub):
                mapping: Dict[str, object] = {}
                for s in sub:
                    mm = re.match(r"^\s+([A-Za-z0-9_-]+):\s*(.*)$", s)
                    if mm:
                        val = mm.group(2).strip()
                        mapping[mm.group(1)] = val[1:-1] if val[:1] in "\"'" and val[-1:] == val[:1] else val
                data[key] = mapping
            else:
                joiner = " " if rest.startswith(">") else "\n"
                data[key] = joiner.join(s.strip() for s in sub).strip()
        else:
            data[key] = rest[1:-1] if rest[:1] in "\"'" and rest[-1:] == rest[:1] else rest
    return data, body


def validate(skill: Path, linter: Path) -> List[str]:
    errors: List[str] = []
    skill_md = skill / "SKILL.md"
    if not skill_md.is_file():
        return [f"S1 {skill_md} not found"]
    text = skill_md.read_text(encoding="utf-8")
    try:
        fm, body = parse_frontmatter(text)
    except ValueError as exc:
        return [f"S1 {exc}"]

    extra = set(fm) - ALLOWED_FIELDS
    if extra:
        errors.append(f"S2 non-spec frontmatter fields: {sorted(extra)} "
                      f"(put custom keys under metadata:)")

    name = fm.get("name")
    if not isinstance(name, str) or not name:
        errors.append("S3 name is required")
    else:
        if len(name) > 64 or not NAME_RE.match(name):
            errors.append(f"S3 invalid name {name!r}")
        if name != skill.resolve().name:
            errors.append(f"S3 name {name!r} must match folder name {skill.resolve().name!r}")

    desc = fm.get("description")
    if not isinstance(desc, str) or not (1 <= len(desc) <= 1024):
        errors.append(f"S4 description must be 1-1024 chars (got {len(desc) if isinstance(desc, str) else 'none'})")
    comp = fm.get("compatibility")
    if comp is not None and (not isinstance(comp, str) or not (1 <= len(comp) <= 500)):
        errors.append("S4 compatibility must be 1-500 chars")
    meta = fm.get("metadata")
    if meta is not None and (not isinstance(meta, dict) or
                             not all(isinstance(v, str) for v in meta.values())):
        errors.append("S4 metadata must be a map of string values")

    body_lines = body.count("\n") + 1
    approx_tokens = len(body) // 4
    if body_lines >= 500:
        errors.append(f"S5 SKILL.md body is {body_lines} lines (keep < 500)")
    if approx_tokens >= 5000:
        errors.append(f"S5 SKILL.md body is ~{approx_tokens} tokens (keep < 5000)")

    md_files = [skill_md] + sorted((skill / "references").glob("*.md"))
    root = skill.resolve()
    for md in md_files:
        content = md.read_text(encoding="utf-8")
        for target in LINK_RE.findall(content):
            if re.match(r"^(https?:|mailto:|#)", target):
                continue
            path = target.split("#", 1)[0]
            if not path:
                continue
            resolved = (md.parent / path).resolve()
            if not resolved.exists():
                errors.append(f"S6 {md.relative_to(skill)}: broken link {target}")
            elif root not in resolved.parents and resolved != root:
                errors.append(f"S6 {md.relative_to(skill)}: link escapes the skill folder: {target}")

    examples: List[Tuple[str, str]] = []
    for md in md_files:
        for n, block in enumerate(TCL_BLOCK_RE.findall(md.read_text(encoding="utf-8")), 1):
            if block.lstrip().startswith("Rule"):
                examples.append((f"{md.relative_to(skill)} example {n}", block))
    for tcl in sorted((skill / "assets").glob("*.tcl")):
        examples.append((str(tcl.relative_to(skill)), tcl.read_text(encoding="utf-8")))
    for label, code in examples:
        proc = subprocess.run([sys.executable, str(linter), "--quiet", "--min-severity",
                               "ERROR", "-"], input=code, capture_output=True, text=True)
        if proc.returncode != 0:
            first = (proc.stdout or proc.stderr).strip().splitlines()[:2]
            errors.append(f"S7 {label} does not lint clean: {' | '.join(first)}")

    for item in skill.rglob("*"):
        if CACHE_DIRS & set(item.relative_to(skill).parts):
            continue
        if item.name in FORBIDDEN:
            errors.append(f"S8 development file shipped in skill: {item.relative_to(skill)}")
    return errors


def main(argv: List[str] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("skill_dir", type=Path)
    ap.add_argument("--linter", type=Path, default=None,
                    help="linter to use for S7 (default: <skill>/scripts/lint_expert_rule.py)")
    args = ap.parse_args(argv)
    if not args.skill_dir.is_dir():
        print(f"error: {args.skill_dir} is not a directory", file=sys.stderr)
        return 2
    linter = args.linter or args.skill_dir / "scripts" / "lint_expert_rule.py"
    errors = validate(args.skill_dir, linter)
    for e in errors:
        print(f"FAIL {e}")
    print(f"{'PASS' if not errors else 'FAIL'}: {args.skill_dir} ({len(errors)} problem(s))")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
