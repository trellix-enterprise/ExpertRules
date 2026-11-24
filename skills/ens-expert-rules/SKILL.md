---
name: ens-expert-rules
description: >-
  Write, review, fix and lint Trellix ENS (Endpoint Security) Exploit Prevention
  Expert Rules - the TCL-based custom-signature language used in ePO and the ENS
  client. Use when the user asks for an ENS/ePO Expert Rule, custom Exploit
  Prevention signature or Host IPS-style rule to block or report file, registry,
  process, memory-section or disk activity, or wants an existing rule checked.
  Includes a dependency-free Python linter.
license: Apache-2.0
compatibility: >-
  Runs anywhere; linting needs Python 3.8+ (standard library only) and a shell.
  Without a shell, apply the checklist in references/best-practices.md instead.
metadata:
  version: "0.2.0"
  homepage: "https://github.com/trellix-enterprise/ExpertRules/tree/main/skills"
---

# ENS Expert Rules

## When to use

Use this skill when writing, editing, reviewing, or linting a Trellix ENS Exploit
Prevention Expert Rule (also called a custom Exploit Prevention signature, ePO Expert
Rule, or — historically — a Host IPS rule). Expert Rules are an embedded-TCL DSL: the
rule text is evaluated by a TCL interpreter in which each keyword (`Rule`, `Process`,
`Target`, `Match`, `Include`, `Exclude`, `-v`, …) is a registered command.

## Generate a rule (workflow)

1. **Clarify intent.** Identify three things:
   - the *initiator* process (who is acting) — or that there is none named,
   - the *target* object type (`FILE`, `PROCESS`, `VALUE`, `KEY`, `SECTION`, `DISK` or
     `THREAD`), and
   - the *operation* to guard (the access flags).
2. **Map the behaviour with [references/rule-patterns.md](references/rule-patterns.md)
   (read it first).** Its §1 table decides the `Match` type and access flags; the most
   common mappings are:
   - launches / spawns a named process → `Match PROCESS` + `-access "CREATE"`, with
     arguments in the target's `PROCESS_CMD_LINE`; executing files picked by location
     (System32, Temp) → `Match FILE` + `EXECUTE`;
   - loads a DLL / driver → `Match FILE` + `-access "EXECUTE"` (not `SECTION`);
   - drops a file → `Match FILE` + `CREATE`; sets a registry value → `Match VALUE` +
     `CREATE WRITE`.
   Its §2 decides the initiator: list the actor when the request names one; **omit the
   `Process` block entirely** for target-centric requests; for "untrusted / unauthorised /
   everyone except X" use an `Exclude` (an Exclude-only `Process` block is valid). Never
   invent actors, and never use a bare `Include OBJECT_NAME { -v "**" }` without an
   `Exclude` beside it. Its §3 gives exact syntax for
   signer/trust, hashes, privileges, loaded DLLs, AND-ed command lines, and TCL helpers.
3. **Consult the other references as needed.** [references/technique-catalog.md](references/technique-catalog.md)
   maps attacker techniques (credential dumping, persistence, UAC bypass, LOLBIN abuse,
   ransomware, CVE exploits, …) to targets; [references/syntax.md](references/syntax.md)
   has the full grammar and access-flag tables; [references/examples.md](references/examples.md)
   has one worked example per target type; [assets/rule_template.tcl](assets/rule_template.tcl)
   is a starting skeleton.
4. **Lint before presenting (mandatory).** Save the rule to a file, run the linter, fix
   every ERROR, review every WARNING, and re-lint until clean. The script lives in
   **this skill's directory** (the folder containing this `SKILL.md`), not in the user's
   project, so use its full path:

   ```
   python3 <skill-dir>/scripts/lint_expert_rule.py path/to/rule.tcl [more.tcl ...]
   ```

   The interpreter may be called `python3`, `python` or (Windows) `py -3`; it must be
   Python **3.8 or newer** — Python 2 cannot run it. The linter is standard-library only,
   so nothing needs installing.

   **If you cannot run commands** (chat-only environment, no Python), do not skip the
   check: walk the rule through the checklist in
   [references/best-practices.md §10](references/best-practices.md) and the *Key rules of
   thumb* below, and tell the user the rule has not been machine-linted.
5. **Present** the rule plus a one-line explanation of what it blocks and how to test it.

## Lint an existing rule

Run the linter on the file (or pass `-` to read from stdin) and report findings by
severity with line numbers. Offer a fix for each finding. Exit code is `0` when there are
no ERRORs (WARNINGs are allowed), `1` when at least one ERROR is present, and `2` on a
usage error.

```
python3 <skill-dir>/scripts/lint_expert_rule.py rule.tcl                 # human-readable
python3 <skill-dir>/scripts/lint_expert_rule.py --format json rule.tcl   # machine-readable
python3 <skill-dir>/scripts/lint_expert_rule.py --format sarif rule.tcl  # CI code-scanning
```

## Key rules of thumb

- **Reaction, Severity, Description and Group are optional in the rule text.** They are
  normally set in the ePO / ENS console's Expert Rule form, and the published Trellix rules
  omit them. Include them only when the user wants a self-contained rule.
- **One broken Expert Rule disables all Expert Rules** on the endpoint (they compile as one
  group). Always lint, and tell the user to press **Check** in the console's Expert Rule
  Checker before enforcing.
- **One `Rule` per Expert Rule**; inside it, `Include`s of the same match type are OR'd and
  different match types are AND'ed (`AggregateMatch -xtype` makes its own AND group).
  No `Process`/`Initiator` = every process. Several `Target`s or `Match` blocks are OR'd
  (verified live); an Exclude-only `Process` block = every process except those.
- **Each `-v` / `-l` entry on its own line.** `-v "a" -v "b"` on one line compiles but
  never matches (E141); never use `\0`-separated strings (W209). For MULTI_STRING data,
  one `-v` per string matches if any string equals it.
- **Who does the I/O?** Services are written by `services.exe`, scheduled tasks by the
  Task Scheduler service, COM objects run in their own server process, WMI in
  `WmiPrvSE.exe` — scope on those, or on the launcher's command line
  (rule-patterns.md §2).
- `USER_NAME` / `GROUP_NAME` are resolved only when enforced (Check doesn't validate them);
  prefer SIDs when unsure.
- Registry roots `HKCU` (all users), `HKLMS`/`HKCUS` (+Wow6432Node) and `HKCCS` (every
  ControlSet) avoid duplicate entries; never put a wildcard inside the root (W208).
  Initiator `System*` covers both `System` and SMB-served `System:Remote`.
- This skill covers the AAC rule types (Files / Registry / Processes). Buffer Overflow,
  Illegal API Use and Services rule types use the older Host IPS signature syntax.
- **The rule content must start with `Rule {`** — no comment or other line before it, or
  the console cannot insert the form's Reaction and the compile fails with
  `Rule: Reaction was not set` (verified on ENS 10.7; linter E122). Put comments inside
  the `Rule` block.
- `-nt_access` only works on `FILE`, `KEY`, `PROCESS` and `THREAD` targets (E150);
  `-pfx` / `-sfx` take one value on their own line (E140).
- **Access flags are target-type-specific.** `-access` tokens apply to all types;
  `-nt_access` masks are validated against the target object type.
- **`REGVAL_DATA` requires `-type`** (e.g. `-type STRING`).
- **Wildcards:** `*` stops at `\`, `**` crosses directories, `?` is one non-separator char.
  There is no backslash escape — `\` is always a literal path separator.
- **Double all backslashes** inside double-quoted paths; TCL string parsing consumes one
  level (`"C:\\Users\\..."` reaches the matcher as `C:\Users\...`). Escape `$` and `[` as
  `\$` and `\[` (e.g. `"**\\\$Recycle.Bin\\**"`).
- Scope initiators (or omit the `Process` block for target-centric rules) and prefer
  specific access flags over `ALL`. Tell the user what to enter in the console form's
  Reaction, Severity, Description and Group fields.
- The linter checks structure, match-type names (E154) and symbolic bitmask values (E155)
  against the ENS compiler's tables, but not intent or free-form values (paths, hashes,
  command lines). Take value formats from rule-patterns.md §8, not guesses.
- `VTP_PRIVILEGES` is Trellix code-signing trust (`ISG` / `IOCTL`), not Windows admin
  rights; integers are decimal, and two `-v` **lines** make a range (low, high) — strings
  on two lines are OR'd instead; hashes are bare hex.

## Reference files

- [references/rule-patterns.md](references/rule-patterns.md) — **start here**: behaviour →
  `Match` type / access table, initiator decision, field syntax (command line, trust,
  signer, hashes, privileges, loaded DLLs, AggregateMatch), paths, multi-stage rules, TCL
  helpers.
- [references/syntax.md](references/syntax.md) — full grammar: hierarchy, target types,
  access-flag tables (`-access` and `-nt_access`), match/data types, reactions/severities,
  wildcard semantics, and version gating.
- [references/best-practices.md](references/best-practices.md) — false-positive avoidance,
  initiator scoping, performance, metadata, Description house style, and testing guidance.
- [references/examples.md](references/examples.md) — one worked example per target type.
- [references/technique-catalog.md](references/technique-catalog.md) — attacker
  techniques by ATT&CK tactic, each mapped to a target type, access flags, and a
  house-style Description.
