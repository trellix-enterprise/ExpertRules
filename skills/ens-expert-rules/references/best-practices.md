# ENS Expert Rules — Best Practices

Guidance for writing Expert Rules that are precise, low-noise, and safe to deploy. These
practices complement the grammar in [syntax.md](syntax.md) and are what the bundled linter
checks for where it can.

---

## 1. Scope the initiator

The single biggest source of false positives and performance cost is an unscoped initiator.

**Avoid** matching every process:

```tcl
Process { Include OBJECT_NAME { -v "**" } }
```

**Prefer** naming the actual actor(s):

```tcl
Process { Include OBJECT_NAME { -v "**\\powershell.exe" } }
```

- If the request is about *what happens to a target* regardless of actor, **omit the
  `Process` block entirely** (the published convention) rather than writing `-v "**"`, and
  keep the **target** highly specific (an exact path or key) so the rule still
  discriminates. Narrow by exclusion (`Exclude VTP_TRUST true`, `Exclude CERT_NAME_CHAINED`,
  `Exclude VTP_PRIVILEGES`) when the request says "untrusted", "unsigned" or "unauthorised".
  See [rule-patterns.md §2](rule-patterns.md).
- Scope initiators by full path where you can, not by bare image name, to avoid matching a
  planted binary with the same name in a different directory.
- Use `Exclude` blocks to carve out known-good actors rather than widening the target.

## 2. Prefer specific access flags over `ALL`

`-access "ALL"` (and `GENERIC_ALL` / `*_ALL_ACCESS` masks) matches far more than most rules
intend and adds evaluation cost.

- List the exact operations you care about: `-access "CREATE WRITE DELETE"`.
- `READ` / `READ_DATA` on `FILE` is high-cost and high-noise — read events are extremely
  frequent. Only guard reads when the target is narrow and the intent is genuinely
  read-detection (e.g. credential theft from a specific file).
- Remember access bits are **object-type-specific**. Validate `-nt_access` masks against the
  chosen `Match` type (see the per-type tables in [syntax.md §3](syntax.md)).

## 3. Metadata: set in the console, optional in the rule text

When a rule is added through the ePO / ENS console, the Expert Rule form supplies these
fields, so the rule body usually omits them (as the published Trellix rules do):

- `Reaction` — the form's Action (block / report).
- `Description` — a human explanation of what the rule protects against.
- `Severity` — `CRITICAL` / `MAJOR` / `MINOR` / `WARNING` / `INFORMATIONAL`.
- `Group` — a category so events are easy to triage in the console.

Always tell the user what to enter in those form fields. Put them in the rule text only
when the user wants a self-contained rule; the linter accepts either form.

### Description house style

Write the `Description` (and any accompanying prose) as a single declarative
sentence, ~15–25 words, that names **what is stopped, who is acting, and what is
targeted**. The established convention across the Trellix community rule set is to
begin with **"This rule prevents…"**, **"This rule detects…"**, or **"This rule
blocks…"** rather than a bare imperative:

- Prefer: `This rule prevents untrusted processes from opening lsass.exe with
  read access to steal credentials from memory.`
- Avoid: `Block LSASS credential dumping.`

Map each rule to the technique it counters:

- Name the **MITRE ATT&CK technique ID** (`T1003.001`, `T1547.001`, …) in the rule
  title or `Group`, since rules are catalogued by technique. See
  [technique-catalog.md](technique-catalog.md).
- For an exploit-prevention rule, cite the **CVE** (`CVE-2021-34527`) in the title.
- Keep ID citations in the title/group; keep the `Description` prose plain.

## 4. Get paths and wildcards right

- **Double every backslash** inside double-quoted paths: `"C:\\Windows\\System32\\…"`.
  TCL string parsing consumes one backslash level, so a single `\` will mis-parse.
- Choose the wildcard deliberately:
  - `*` stops at `\` — matches within one path segment.
  - `**` crosses directory separators — matches any depth.
  - `?` is exactly one non-separator character.
- There is **no escape character** — `\` is always a literal separator. You cannot match a
  literal `*` or `?`.
- Anchor patterns. `"**\\mimikatz.exe"` matches that name anywhere; `"C:\\Tools\\x.exe"`
  matches only that location. Pick the tightest anchor that still catches the threat.

## 5. Choose the right reaction

- `BLOCK` — stop the operation and report. The usual choice for enforcement.
- `REPORT` (via the `SCAN`/report actions) or a low-severity observe-only posture — good for
  a **monitor-first rollout**: deploy in report mode, watch for false positives, then switch
  to `BLOCK`.
- `TERMINATE_PROCESS` — aggressive; reserve for high-confidence malicious behavior.
- `ALLOW` / `EXCEPTIONAL_ALLOW` — use to create precise exceptions ahead of a broader block
  rule.

## 6. Order and combine rules deliberately

- Put narrow `ALLOW` exceptions before broad `BLOCK` rules so known-good activity is not
  caught.
- Use `Exclude` within a `Match` to remove specific known-good objects instead of loosening
  the `Include` pattern.
- Keep one behavior per rule. Several small, well-named rules triage better than one rule
  that tries to cover everything.

## 7. Mind version gating

Some tokens only exist on newer ENS builds (see [syntax.md §7](syntax.md)):

- 15.5+: `READ_DATA`, `WRITE_DATA`, `RENAME`, `LOCK_RANGE`, `SET_FILE_LENGTH`,
  `TARGET_OBJECT_NAME`, `VTP_PRIVILEGES`, `FILE_PROPERTIES`.
- 15.8+: `IS_TRANSACTED`. 18.6+: `REGVAL_DATA`. 26.5+: `CREATE_BINDLINK`.

If the rule must run on an older client, avoid the gated token or gate the rule by
`OS_VERSION` / deployment.

## 8. Registry value data needs a type

When matching registry value **data** with `REGVAL_DATA`, always supply `-type`
(e.g. `-type STRING`, `-type INT32`). Without it the compiler cannot interpret the value:
`"Smart <arg> not supported yet, add -type option"`. `-name` and `-key` are mutually
exclusive — pick one.

## 9. Test before you ship

> **Why this matters:** ENS compiles all Expert Rules on an endpoint as one group. If a
> single rule fails to compile, **no** Expert Rules are enforced on that endpoint — one bad
> rule silently disables every other custom protection.

1. **Lint** — run `python scripts/lint_expert_rule.py rule.tcl` and clear every ERROR;
   review each WARNING.
2. **Check in the console** — in the ENS client (Settings → Threat Prevention → Show
   Advanced → Exploit Prevention → Signatures → *Add Expert Rule*) paste the rule and press
   **Check**, which compiles it without enforcing. On failure the reason is in
   `EndpointSecurityPlatform_Errors.log` (e.g. `Syntax error: …`).
3. **Deploy to a test system** and reproduce the behavior you intend to catch; confirm the
   rule loaded (`ExploitPrevention_Debug.log`: `ProcessExpertRules … loaded`; the Exploit
   Prevention Activity log reports "Errors occurred during rule processing" if any rule
   failed) and that the event fires with the expected severity and reaction.
4. **Watch for false positives** in report mode across a representative set of machines.
5. **Promote to BLOCK** once the noise is understood and acceptable.
6. Keep rules under source control and re-lint on every change (see the CI workflow in the
   repository).

## 10. Quick checklist

- [ ] Reaction, Description, Group, Severity: given to the user for the console form (or
      in the rule text if a self-contained rule was requested).
- [ ] `Match` type and access chosen from [rule-patterns.md §1](rule-patterns.md)
      (launch → `PROCESS`+`CREATE`; DLL/driver load → `FILE`+`EXECUTE`; value → `VALUE`).
- [ ] Initiator scoped to the named actor, omitted for a target-centric rule, or an
      `Exclude` for "everyone except…" (never a bare `**` with no `Exclude`).
- [ ] Access flags specific to intent and valid for the target type.
- [ ] Backslashes doubled; wildcards chosen deliberately.
- [ ] `REGVAL_DATA` has `-type`; no `-name`+`-key` clash.
- [ ] No version-gated token the target clients lack.
- [ ] Lints clean; tested on a real system.
