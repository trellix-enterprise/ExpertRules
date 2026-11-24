# Release notes

## Unreleased

- **Published from trellix-enterprise/ExpertRules.** `tools/export_skill_repo.py
  --into-expertrules <clone>` adds the skill under `skills/` with an install guide for every
  agent, a Claude Code plugin marketplace manifest, path-filtered CI (skill checks, rule
  lint on changed rule documents, `skill-v*` release zips). The skill's homepage now points
  there.
- **New `tools/lint_rule_docs.py`** lints the rules inside Markdown rule documents, with
  GitHub annotations (`--github`) and Markdown line numbers.
- **Evaluation harness (`eval/`).** `extract_tasks.py` builds a blind task set from the public
  ExpertRules corpus, `run_agent_eval.py` runs it through Claude Code, Copilot, Gemini, Codex
  or Cursor CLIs with the skill in each agent's project skill folder (`--model`,
  `--vertex-project` for Gemini on Vertex AI, `--prepare-only` for IDE agents), and
  `score.py` scores the output. 41-task sample: Opus 5.5 79.7, Sonnet 5.5 79.6, Haiku 5.5
  74.3; every model discovered the skill and ran the linter.
- **Docs:** integer ranges need two `-v` lines (one line is E141); strings on two lines are
  OR'd.
- **Removed checks E120 (missing `Reaction`) and W204 (missing `Description` / `Group` /
  `Severity`).** The ePO / ENS console's Expert Rule form supplies these fields, and the
  published Trellix ExpertRules corpus omits them from the rule text, so the checks flagged
  283 of 290 upstream rules. Docs, template and SKILL.md now treat them as optional.
- Added `references/technique-catalog.md` and a Description house style.
- Added `references/rule-patterns.md` (read first): behaviour → `Match` type / access table,
  initiator decision (named actor, no `Process` block, `SYSTEM`, Exclude-only), and exact
  syntax for command line, trust / signer, hashes, privileges, `DLL_LOADED`, `AggregateMatch`,
  DAC state, typed registry data, multi-stage rules and TCL helpers. Driven by a blind eval
  against the 286 published ExpertRules descriptions: mean similarity score 75.5 → 78.9
  (holdout 78.0 → 80.3).
- Technique catalog: DLL/driver loads and LOLBIN launches no longer steered to `SECTION`.
- SKILL.md / best-practices: removed the contradiction about always setting metadata.
- Linter: accepts multiple files per run; W203 no longer flags deliberate TCL escapes
  (`\$`, `\[`, `\]`, `\0`).

- Verified against the ENS rule-compiler source (`hostips/Source/ApRc`, syscore `aacapi.h`):
  - New linter checks **E154** (unknown match type, using the compiler's case-sensitive
    table) and **E155** (unknown symbolic value for `FILE_ATTRIBUTES`, `DRIVE_TYPE`,
    `FILE_PROPERTIES`, `DISK_REGION`, `IMAGE_PROPERTIES`, `VTP_PRIVILEGES`, `VTP_TRUST`,
    `PROCESSOR_MODE`).
  - W201 no longer warns on `**` initiators narrowed by an `Exclude`.
  - rule-patterns.md §8: compiler-verified value formats (symbolic bitmask names, decimal
    integer ranges, hash lengths, `USER_NAME`/`GROUP_NAME`, `System:Remote`), the full
    TCL helper list (`iSystem`, `iUser`, `iReg`, `iEnv`, `iList`, `iUtil`, `iTerminate`,
    `iDump`), and a correction: `VTP_PRIVILEGES` is Trellix code-signing trust
    (`ISG`/`IOCTL`), not Windows admin rights.

- Compile-checked 19 eval-generated rules in the ENS 10.7.20 console's Expert Rule
  Checker; findings fed back into the linter (it now matches the console's verdict on
  all 19):
  - **E122**: any line before the first `Rule {` (even a comment) stops the console
    inserting the form's Reaction -> `Rule: Reaction was not set`. Template comments
    moved inside the `Rule` block. Also flags 13 published upstream rules whose code
    blocks start with the prose line "The original rule:".
  - **E140**: `-pfx` / `-sfx` take exactly one value.
  - **E150**: `-nt_access` is rejected on SECTION / NAMEDSECTION / DISK targets.
  - Confirmed compiling: `DRIVE_TYPE DT_REMOVABLE`, `-file_attributes`, Exclude-only
    initiators with `VTP_PRIVILEGES ISG`, `CREATE_BINDLINK`, `AggregateMatch` +
    `DLL_LOADED`, `SHA2_256` lists, `iSystem users_folders` with `-sfx`/`-l`,
    `Next_Process_Behavior`, `REGVAL_DATA`, `USER_NAME`, `PROCESS_STATE_BITS`,
    `TARGET_OBJECT_NAME`, `OBJECT_SIZE`, `CERT_NAME_CHAINED`, `VTP_TRUST`.

- Folded in facts from the official *Writing Expert Rules for McAfee Endpoint Security
  10.7* reference (restated, not copied): one failing Expert Rule disables all Expert
  Rules on the endpoint; one `Rule` per Expert Rule; Include/Exclude AND/OR semantics;
  registry root aliases (`HKCU` = all users, `HKLMS`/`HKCUS`, `HKCCS`, `HKULM`, `HKALL`);
  `System*` covers `System:Remote`; legacy Host IPS rule types (Buffer Overflow, Illegal
  API Use, Services) are out of scope; `iSystem`/`iUser`/`iReg` return values; console
  Check workflow in best-practices.md.
  - New linter warning **W208**: wildcard inside a registry root (never matches).

- Live semantics test on ENS 10.7.20 (Report-only test rules, removed afterwards):
  several `Target` sections / `Match` blocks are OR'd; an Exclude-only `Process` block
  means every process except those; `USER_NAME` bare and `HOST\\name` both match but
  names are only resolved at enforcement (console Check passes unknown users);
  MULTI_STRING `REGVAL_DATA` matches any string, one `-v` line per string.
  - New linter **E141**: several `-v`/`-l` entries on one line (compiles, never matches).
  - New linter **W209**: `\0` in a value (only the first string is compared).
  - rule-patterns.md: "who actually performs the operation" table for services,
    scheduled tasks, COM/DCOM, WMI and SMB.

## v0.1.0 — initial release

First public release of **ens-expert-rules**, a cross-agent Agent Skill for generating and
quality-checking Trellix Endpoint Security (ENS) Exploit Prevention Expert Rules.

### Skill

- `SKILL.md` entry point with a generate-and-lint workflow and rules of thumb.
- References: full grammar (`references/syntax.md`), false-positive/scoping guidance
  (`references/best-practices.md`), and one worked example per target type
  (`references/examples.md`).
- `assets/rule_template.tcl` starter skeleton with a scoped initiator and mandatory metadata.
- Per-agent install instructions and a copy-paste fallback for chat-only assistants in the
  README.

### Linter (`scripts/lint_expert_rule.py`)

- Standard-library Python 3.8+, offline, report-only — no dependencies, no installation.
- Deterministic checks over the ENS rule grammar:
  - **Errors (E1xx):** unbalanced braces/quotes, excessive nesting, invalid hierarchy,
    missing/duplicate mandatory fields, `-nt_access` structural errors, and more.
  - **Warnings (W2xx):** unscoped initiators, costly access flags, duplicate match scoping,
    and undefined `-nt_access` bits.
  - **Info (I3xx):** formatting and `-nt_access` mask decoding to named rights.
- `-nt_access` masks validated per target object type (PROCESS/THREAD/FILE/KEY/SECTION) using
  Windows `ACCESS_MASK` bit tables, with version gating for newer tokens.
- Output formats: human-readable text, JSON, and **SARIF 2.1.0** for CI code scanning.
- Filters: `--select`, `--ignore`, `--min-severity`, `--quiet`.
- Exit codes: `0` (no errors), `1` (at least one error), `2` (usage error).

### Tests & CI

- `unittest` suite covering good fixtures (must lint clean), one bad fixture per code, output
  formats, and malformed input.
- GitHub Actions workflow: test matrix on Python 3.8 / 3.11 / 3.13, plus a SARIF upload job.

### License

Apache-2.0. See `LICENSE` and `NOTICE`.
