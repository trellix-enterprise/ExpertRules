## How to contribute

- Create a branch from the master with the following name convention: `{contributor-name}-short-description` or click the pen icon in a file to edit.
- Push the just created branch
- Create a Pull Request (PR) and push changes periodically (so everybody can track/review the progress of the contribution)
- Ask some reviewer to review and merge your changes when it is ready

- Before opening the PR, lint the rules in your documents: `python3 skills/tools/lint_rule_docs.py path/to/rule.md` (Python 3.8+, no dependencies). The **Rule lint** workflow runs the same check on every rule document a PR adds or changes and annotates any problems; ERRORs (for example text before `Rule {`, which stops the console from compiling the rule) must be fixed before merge.
- Changes under `skills/` (the AI agent skill) run the **Skill checks** workflow; see [skills/README.md](skills/README.md#contributing-to-the-skill).

Try to use the PR as main source of collaboration, keeping all discussion in the PR comments. 
Pushing frequently and asking for feedback will increase the chances to make a successful PR.

Thank you for you collaboration.
