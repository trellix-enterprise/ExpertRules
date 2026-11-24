# ENS Expert Rules — AI Agent Skill

This folder contains **`ens-expert-rules`**, an [Agent Skill](https://agentskills.io) that
teaches AI coding assistants to **write, review, fix and lint Trellix ENS Exploit
Prevention Expert Rules**. Ask your assistant for a rule in plain English ("block Word
from launching PowerShell", "report anything writing to the Run keys except installers")
and it produces a rule in the style of the rules in this repository, checks it with the
bundled linter, and tells you what to enter in the ePO Expert Rule form.

It works in every assistant that supports the open Agent Skills standard: **Claude Code,
GitHub Copilot (VS Code and CLI), OpenAI Codex, Cursor, Gemini CLI**, the Claude apps and
others.

**What's in the skill**

- A rule-writing workflow and a behaviour → `Match` type / access-flag cookbook
- Full syntax reference, best practices, worked examples and an ATT&CK technique catalogue
- A dependency-free Python linter (`scripts/lint_expert_rule.py`) whose checks were
  verified against the ENS rule compiler and on a live ENS 10.7 client — including the
  mistakes that silently disable *all* Expert Rules on an endpoint

> Generated rules are a starting point, not a substitute for testing. Always run the
> console's **Expert Rule Checker → Check**, and deploy in report-only mode on test
> systems first (see [Testing](#testing-a-generated-rule)).

## Contents

- [Quick install](#quick-install)
- [Install by agent](#install-by-agent)
- [Manual install](#manual-install)
- [Check that it works](#check-that-it-works)
- [Using the skill](#using-the-skill)
- [Testing a generated rule](#testing-a-generated-rule)
- [Updating and removing](#updating-and-removing)
- [Linting rule documents](#linting-rule-documents)
- [Contributing to the skill](#contributing-to-the-skill)

## Quick install

| Your assistant | Run |
| --- | --- |
| **Any** (Claude Code, Copilot, Codex, Cursor, Gemini CLI, …) | `npx skills add trellix-enterprise/ExpertRules --skill ens-expert-rules` |
| **Claude Code** (plugin) | `claude plugin install ens-expert-rules --marketplace trellix-enterprise/ExpertRules` — or, in a session, `/plugin install ens-expert-rules --marketplace trellix-enterprise/ExpertRules` (Claude Code 2.1.275+; older versions: `claude plugin marketplace add trellix-enterprise/ExpertRules` then `claude plugin install ens-expert-rules@trellix-expert-rules`) |
| **Gemini CLI** | `gemini skills install https://github.com/trellix-enterprise/ExpertRules.git --path skills/ens-expert-rules` |
| **Claude apps** (claude.ai, Desktop) | Download `ens-expert-rules.zip` from the [latest skill release](https://github.com/trellix-enterprise/ExpertRules/releases) and upload it under *Settings → Capabilities → Skills* |

`npx skills` (the open [skills CLI](https://github.com/vercel-labs/skills), needs
Node.js) asks which assistants to install for and whether to install for the current
project or for your user account; add `-a <agent>` (e.g. `-a claude-code`; see the
CLI's [agent list](https://github.com/vercel-labs/skills/blob/main/docs/agents.md)) to
choose up front. No Node.js? Use the [manual install](#manual-install).

**Requirements:** the linter needs **Python 3.8+** (`python3`, `python` or, on Windows,
`py -3`) — standard library only, nothing to install. Without Python the skill still
works; the assistant falls back to a written checklist and says the rule was not
machine-linted.

## Install by agent

Every assistant looks for skills in a *project* folder (shared with everyone who works in
that repository — commit it) and a *user* folder (available in all your projects). The
skill is the folder `ens-expert-rules`; **it must keep exactly that name**, because the
name has to match the `name:` in its `SKILL.md`.

| Agent | Project folder | User folder |
| --- | --- | --- |
| **Claude Code** | `.claude/skills/ens-expert-rules/` | `~/.claude/skills/ens-expert-rules/` |
| **GitHub Copilot** (VS Code, Copilot CLI) | `.github/skills/ens-expert-rules/` | `~/.copilot/skills/ens-expert-rules/` |
| **OpenAI Codex** (CLI, IDE, app) | `.agents/skills/ens-expert-rules/` | `~/.agents/skills/ens-expert-rules/` |
| **Cursor** | `.cursor/skills/` or `.agents/skills/` (also reads `.claude/skills/`) | `~/.cursor/skills/` |
| **Gemini CLI** | `.gemini/skills/` or `.agents/skills/` | `~/.gemini/skills/` or `~/.agents/skills/` |

`~/.agents/skills/` is read by Codex, Cursor and Gemini CLI, so one copy there covers all
three. On Windows `~` is `%USERPROFILE%` (e.g. `C:\Users\you\.claude\skills\`).

Notes per agent:

- **Claude Code** — the plugin route keeps the skill up to date with
  `claude plugin update`; inside a session it appears as `/ens-expert-rules:ens-expert-rules`.
  A plain folder install appears as `/ens-expert-rules`. Either way Claude uses it
  automatically when you ask for an Expert Rule.
- **GitHub Copilot** — use Agent mode in VS Code. Skills must be enabled for your account
  or organisation; if your organisation disables Copilot features, ask your GitHub admin.
- **Codex** — list installed skills with `/skills`.
- **Gemini CLI** — list installed skills with `/skills list`.
- **Chat-only assistants** (no file access) — paste `ens-expert-rules/SKILL.md` into the
  conversation, then `references/rule-patterns.md`. Run the linter yourself and paste its
  output back.

## Manual install

Download only the skill (no rule documents) with a sparse clone, then copy it:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/trellix-enterprise/ExpertRules.git
cd ExpertRules
git sparse-checkout set skills/ens-expert-rules

# pick the folder for your assistant (see the table above), e.g. Claude Code, all projects:
mkdir -p ~/.claude/skills
cp -r skills/ens-expert-rules ~/.claude/skills/
```

Windows PowerShell:

```powershell
git clone --depth 1 --filter=blob:none --sparse https://github.com/trellix-enterprise/ExpertRules.git
cd ExpertRules
git sparse-checkout set skills/ens-expert-rules

# e.g. GitHub Copilot, all projects:
New-Item -ItemType Directory -Force "$env:USERPROFILE\.copilot\skills" | Out-Null
Copy-Item -Recurse skills\ens-expert-rules "$env:USERPROFILE\.copilot\skills\"
```

Or download `ens-expert-rules.zip` from the [releases page](https://github.com/trellix-enterprise/ExpertRules/releases)
and unzip it into the folder — the zip already contains the `ens-expert-rules` folder.

To share the skill with your team, commit it to your own repository under the *project*
folder for the assistants you use (e.g. `.github/skills/ens-expert-rules/` and
`.claude/skills/ens-expert-rules/`).

## Check that it works

Start a new session and ask:

> Write an ENS Expert Rule that blocks Microsoft Word from starting PowerShell.

A working install mentions the `ens-expert-rules` skill, writes a `Rule { … }` block with a
`Process` (WINWORD.EXE) and a `Match PROCESS` target (powershell.exe, `CREATE`), runs
`lint_expert_rule.py` on it and tells you what to put in the console's Reaction,
Severity, Description and Group fields. If the assistant writes a rule without
mentioning the skill, check the folder name and location, then restart the assistant.

You can also run the linter directly:

```bash
python3 ~/.claude/skills/ens-expert-rules/scripts/lint_expert_rule.py my_rule.tcl
```

## Using the skill

Things to ask for:

- **New rules** — "Write an Expert Rule that reports any process except backup software
  deleting volume shadow copies."
- **Reviews and fixes** — "Check this rule and fix it" (paste the rule or give a path).
- **Explanations** — "What does this rule actually match?"
- **Technique coverage** — "Write rules for T1547.001 Run-key persistence."

Tips:

- Name the actor ("when Excel …", "any unsigned process …") and the object ("files in
  System32", "the Winlogon key") — the skill turns those into `Process` and `Target`.
- Say whether you want *Block* or *Report*; the console form sets the reaction.
- Rules must start with `Rule {` when pasted into the console — the skill handles this.

## Testing a generated rule

1. **Lint** — the assistant does this; you can re-run `lint_expert_rule.py` yourself.
2. **Check** — in ePO / the ENS client, paste the rule into the Expert Rule form and press
   **Check**. One rule that fails to compile disables **all** Expert Rules on the
   endpoint, so never skip this.
3. **Report-only first** — deploy with Reaction *Report* to a test group, exercise the
   behaviour, and confirm the event in the Threat Event Log before switching to *Block*.
4. **Logs** — compile errors appear in `EndpointSecurityPlatform_Errors.log`; matching
   detail in `ExploitPrevention_Debug.log` (debug logging enabled).

## Updating and removing

| Installed with | Update | Remove |
| --- | --- | --- |
| `npx skills` | `npx skills update ens-expert-rules` | `npx skills remove ens-expert-rules` |
| Claude Code plugin | `claude plugin update ens-expert-rules@trellix-expert-rules` | `claude plugin uninstall ens-expert-rules@trellix-expert-rules` |
| Gemini CLI | re-run `gemini skills install …` | `gemini skills uninstall ens-expert-rules` |
| Manual copy / zip | replace the folder | delete the folder |

Release notes: [RELEASE_NOTES.md](RELEASE_NOTES.md).

## Linting rule documents

The rule documents in `TRELLIX/` and `COMMUNITY/` can be linted with the same checks:

```bash
python3 skills/tools/lint_rule_docs.py TRELLIX COMMUNITY            # everything
python3 skills/tools/lint_rule_docs.py COMMUNITY/MITRE/my_rule.md   # one document
python3 skills/tools/lint_rule_docs.py --errors-only --summary TRELLIX
```

Pull requests that add or change rule documents are linted automatically by the
**Rule lint** workflow; findings appear as annotations on the changed lines.

## Contributing to the skill

The skill is developed with its tests and evaluation harness in a separate development
repository and synchronised here. Pull requests that touch `skills/` run the
**Skill checks** workflow: the skill is validated against the Agent Skills specification
(name/folder match, frontmatter, size budget, links), every example rule in the
references must lint clean, and the linter's tests run on Windows, macOS and Linux.
Run the same checks locally:

```bash
cd skills
python3 tools/validate_skill.py ens-expert-rules
python3 -m unittest discover -s tests
```

| Path | Purpose |
| --- | --- |
| `skills/ens-expert-rules/` | **The skill** — the folder that gets installed |
| `skills/tests/` | Linter and spec tests |
| `skills/tools/validate_skill.py` | Agent Skills spec, link, size and example-rule validator |
| `skills/tools/lint_rule_docs.py` | Lints the rules inside the repository's Markdown rule documents |
| `.claude-plugin/marketplace.json` | Makes this repository a Claude Code plugin marketplace |
| `.github/workflows/skill-checks.yml`, `rule-lint.yml`, `skill-release.yml` | CI |

Maintainers publish a release by pushing a tag `skill-vX.Y.Z`; the workflow validates the
skill and attaches `ens-expert-rules.zip`.

Licensed under Apache-2.0, like the rest of this repository.
