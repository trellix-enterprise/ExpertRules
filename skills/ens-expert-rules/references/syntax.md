# ENS Expert Rules — Syntax Reference

A customer-facing grammar reference for Trellix Endpoint Security (ENS) Exploit Prevention
Expert Rules. Everything here reflects how the ENS rule compiler actually parses and
validates rules.

Expert Rules are an **embedded-TCL DSL**. The rule text is evaluated by a TCL interpreter
in which each keyword (`Rule`, `Process`, `Target`, `Match`, `Include`, `Exclude`, `-v`, …)
is a registered command. Because it is real TCL, constructs such as `set`, `if`, `for`, and
`lappend` are available and can be interleaved with the declarative rule commands.

A rule pairs an **initiator** (`Process` / `Initiator`) with a **target**
(`Target { Match <TYPE> { … } }`), an **access mask**, and a **reaction** (normally set in the console's Expert Rule form
rather than in the rule text).

---

## 1. Command hierarchy

Parent → allowed direct children. Using a command outside its allowed parent produces
`"<cmd> is not a valid child of <parent>"`.

```
Policy          → Description, Aggregate, Rule, Severity
Rule            → Description, Group, Reaction, Severity, Process, Target, Initiator
Process         → Include, Exclude
Initiator       → Match            (object type MUST be PROCESS)
Target          → Match, Next_Process_Behavior
Match           → Include, Exclude
Include/Exclude → -pfx, -sfx, -v, -l, AggregateMatch
Aggregate       → Description, Include, Exclude
AggregateMatch  → Include, Exclude
Reaction / Severity / Group / Description → (leaf)
```

### Canonical structure

```tcl
Policy -sticky -id "" -block_id nn -allow_id nn {
    Description "xxx"
    Severity    CRITICAL/MAJOR/MINOR/WARNING/INFORMATIONAL
    Rule -disable -noreport -id "" -no_trusted_apps -block_id nn -allow_id nn {
        Description "xxx"
        Group       "ggg"
        Reaction    BLOCK
        Severity    MAJOR
        Process {
            Include ...
            Exclude ...
        }
        Target {
            Match FILE {
                Include ...
                Exclude ...
            }
        }
    }
}
```

A bare `Rule { … }` (no `Policy` wrapper) is what most hand-authored rules use.
`Reaction`, `Severity`, `Description` and `Group` are optional in the rule text: the ePO /
ENS console's Expert Rule form supplies them.

### Argument counts (enforced)

| Command | Required args |
|---------|---------------|
| `Rule` | ≥ 2 |
| `Process` / `Initiator` / `Target` | exactly 2 (name + `{body}`) |
| `Match` | exactly 3 (`Match TYPE {body}`) |
| `Reaction` | ≥ 2 (the SCAN form takes 5) |
| `Include` / `Exclude` | 3, 5, or 7 |
| `-v` | ≠ 1 (must be given at least one value) |

**Nesting depth cap:** 12 levels (`MAX_CMD_LEVEL`). Deeper nesting is rejected.

---

## 2. Target (object) types

Used as `Match <TYPE> { … }`. Both the bare and `AAC_OBJECT_`-prefixed forms are accepted.
An unknown type produces `"Match: Unknown object type <arg>"`.

| Type | Notes |
|------|-------|
| `FILE` | File and directory operations. |
| `KEY` | Registry key. |
| `VALUE` | Registry value — **`-access` only**, no `-nt_access` map. |
| `PROCESS` | The **only** type allowed under `Initiator` / `Process`. |
| `THREAD` | Thread operations. |
| `SECTION` / `NAMEDSECTION` | PE section / module load. |
| `DISK` | Raw disk. |
| `SERVICE` | ENS/Endpoint service extension. |

The initiator subrule enforces:
`"Match: Object type can only be PROCESS for Initiators <arg>"`.

---

## 3. Access flags

Access is declared with `-access` (the AAC mask, valid for all object types) or
`-nt_access` (native Windows `ACCESS_MASK`, interpreted per object type).

### 3.1 `-access` (AAC — all object types)

```
CREATE, WRITE, DELETE, READ, EXECUTE, ENUM, START_DEVICE, LOAD_KEY, REPLACE_KEY,
RESTORE_KEY, LOAD_IMAGE, TERMINATING, OPEN_NAMEDSECTION, WRITE_ATTRIBUTE, OBJECT_EXISTS,
CLEANUP, SET_REPARSE, CLOSE, CONNECT_NAMED_PIPE, QUERY, SET_SECURITY, LOCK_RANGE,
WRITE_DATA, READ_DATA, RENAME, SET_FILE_LENGTH, CREATE_BINDLINK, POST
```

`ALL` expands to every AAC bit except `UNDEFINED` and `POST`.

Version-gated tokens: `LOCK_RANGE`, `WRITE_DATA`, `READ_DATA`, `RENAME`,
`SET_FILE_LENGTH` require **ENS 15.5+**; `CREATE_BINDLINK` requires **26.5+**.

### 3.2 Named `-nt_access` tokens (per object type)

- **FILE:** `DELETE`, `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`, `SYNCHRONIZE`,
  `STANDARD_RIGHTS_*`, `GENERIC_ALL/READ/WRITE/EXECUTE`, `READ_DATA`, `WRITE_DATA`,
  `LIST_DIRECTORY`, `ADD_FILE`, `APPEND_DATA`, `ADD_SUBDIRECTORY`, `READ_EA`, `WRITE_EA`,
  `EXECUTE`, `TRAVERSE`, `DELETE_CHILD`, `READ_ATTRIBUTES`, `WRITE_ATTRIBUTES`, `ALL`,
  `READ`, `WRITE`.
- **KEY:** `DELETE`, `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`, `ALL_ACCESS`,
  `QUERY_VALUE`, `SET_VALUE`, `CREATE_SUB_KEY`, `ENUMERATE_SUB_KEYS`, `NOTIFY`,
  `CREATE_LINK`, `WOW64_32KEY`, `WOW64_64KEY`, `WOW64_RES`, `READ`, `WRITE`, `EXECUTE`.
- **PROCESS:** `DELETE`, `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`, `SYNCHRONIZE`, `ALL`,
  `TERMINATE`, `CREATE_THREAD`, `SET_SESSIONID`, `VM_OPERATION`, `VM_READ`, `VM_WRITE`,
  `DUP_HANDLE`, `CREATE_PROCESS`, `SET_QUOTA`, `SET_INFORMATION`, `QUERY_INFORMATION`,
  `SUSPEND_RESUME`, `QUERY_LIMITED_INFORMATION`, and the `EX_PROC_*` extension tokens.
- **THREAD:** `DELETE`, `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`, `SYNCHRONIZE`, `ALL`,
  `TERMINATE`, `GET_CONTEXT`, `SET_CONTEXT`, `QUERY_INFORMATION`, `SUSPEND_RESUME`,
  `QUERY_LIMITED_INFORMATION`, `DIRECT_IMPERSONATION`, `SET_INFORMATION`,
  `SET_THREAD_TOKEN`, `IMPERSONATE`, `SET_LIMITED_INFORMATION`.
- **SERVICE:** `SRV_CONTINUE`, `SRV_CREATE`, `SRV_DELETE`, `SRV_LOGON`, `SRV_PAUSE`,
  `SRV_PROFILE_DISABLE`, `SRV_PROFILE_ENABLE`, `SRV_START`, `SRV_STARTUP`, `SRV_STOP`.
- **VALUE:** no `-nt_access` map (registry value access is expressed via the parent `KEY`).

### 3.3 The access mini-language

Tokens in an `-access` / `-nt_access` string are separated by space, comma, `|`, or tab.
Prefixes:

- `!` — the bit is included **and** required.
- `+` — the bit is **only** required (not part of the match set on its own).
- `*` — (after `!` or `+`) all bits required.

Matching is case-insensitive. Any token that is not a known name must be numeric
(hex `0x…`, decimal, or binary `0B…`); otherwise it is an error. Representative errors:
`"Cvt2AccessBits no input string."`, `"Cvt2AccessBits orphaned <c> character"`,
`"Convert2Bits invalid numeric entry <x>"`,
`"Cvt2AccessBits unknown object type for NT_ACCESS_MASK …"`.

### 3.4 `-nt_access` numeric mask values (Windows `ACCESS_MASK`)

Rules may give a raw mask directly (the corpus commonly does, e.g. `-nt_access "0x10"`,
`-nt_access "!0x20"`). **Bits are object-type-specific** — the same low value means
different things per type. Values below are from the Windows SDK, the authoritative source.

**Standard + generic rights (identical for every object type):**

| Bit | Name | Bit | Name |
|-----|------|-----|------|
| `0x00010000` | DELETE | `0x001F0000` | STANDARD_RIGHTS_ALL |
| `0x00020000` | READ_CONTROL | `0x0000FFFF` | SPECIFIC_RIGHTS_ALL |
| `0x00040000` | WRITE_DAC | `0x01000000` | ACCESS_SYSTEM_SECURITY |
| `0x00080000` | WRITE_OWNER | `0x02000000` | MAXIMUM_ALLOWED |
| `0x00100000` | SYNCHRONIZE | `0x10000000` | GENERIC_ALL |
| `0x000F0000` | STANDARD_RIGHTS_REQUIRED | `0x20000000` | GENERIC_EXECUTE |
| | | `0x40000000` | GENERIC_WRITE |
| | | `0x80000000` | GENERIC_READ |

`STANDARD_RIGHTS_READ` = `STANDARD_RIGHTS_WRITE` = `STANDARD_RIGHTS_EXECUTE` =
`READ_CONTROL` (`0x00020000`).

**PROCESS** (`PROCESS_ALL_ACCESS` = `0x1FFFFF` on Vista+):

| Bit | Name | Bit | Name |
|-----|------|-----|------|
| `0x0001` | TERMINATE | `0x0080` | CREATE_PROCESS |
| `0x0002` | CREATE_THREAD | `0x0100` | SET_QUOTA |
| `0x0004` | SET_SESSIONID | `0x0200` | SET_INFORMATION |
| `0x0008` | VM_OPERATION | `0x0400` | QUERY_INFORMATION |
| `0x0010` | VM_READ | `0x0800` | SUSPEND_RESUME |
| `0x0020` | VM_WRITE | `0x1000` | QUERY_LIMITED_INFORMATION |
| `0x0040` | DUP_HANDLE | `0x2000` | SET_LIMITED_INFORMATION |

**THREAD** (`THREAD_ALL_ACCESS` = `0x1FFFFF` on Vista+):

| Bit | Name | Bit | Name |
|-----|------|-----|------|
| `0x0001` | TERMINATE | `0x0100` | IMPERSONATE |
| `0x0002` | SUSPEND_RESUME | `0x0200` | DIRECT_IMPERSONATION |
| `0x0008` | GET_CONTEXT | `0x0400` | SET_LIMITED_INFORMATION |
| `0x0010` | SET_CONTEXT | `0x0800` | QUERY_LIMITED_INFORMATION |
| `0x0020` | SET_INFORMATION | `0x1000` | RESUME |
| `0x0040` | QUERY_INFORMATION | `0x0080` | SET_THREAD_TOKEN |

**FILE / directory / pipe** (low bits are context-dependent; `FILE_ALL_ACCESS` = `0x1F01FF`):

| Bit | File / pipe | Directory |
|-----|-------------|-----------|
| `0x0001` | FILE_READ_DATA | FILE_LIST_DIRECTORY |
| `0x0002` | FILE_WRITE_DATA | FILE_ADD_FILE |
| `0x0004` | FILE_APPEND_DATA / FILE_CREATE_PIPE_INSTANCE | FILE_ADD_SUBDIRECTORY |
| `0x0008` | FILE_READ_EA | FILE_READ_EA |
| `0x0010` | FILE_WRITE_EA | FILE_WRITE_EA |
| `0x0020` | FILE_EXECUTE | FILE_TRAVERSE |
| `0x0040` | — | FILE_DELETE_CHILD |
| `0x0080` | FILE_READ_ATTRIBUTES | FILE_READ_ATTRIBUTES |
| `0x0100` | FILE_WRITE_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |

Aggregates: `FILE_GENERIC_READ` = `0x120089`, `FILE_GENERIC_WRITE` = `0x120116`,
`FILE_GENERIC_EXECUTE` = `0x1200A0`.

**KEY** (`KEY_ALL_ACCESS` = `0xF003F`, `KEY_READ`/`KEY_EXECUTE` = `0x20019`,
`KEY_WRITE` = `0x20006`):

| Bit | Name | Bit | Name |
|-----|------|-----|------|
| `0x0001` | KEY_QUERY_VALUE | `0x0020` | KEY_CREATE_LINK |
| `0x0002` | KEY_SET_VALUE | `0x0100` | KEY_WOW64_64KEY |
| `0x0004` | KEY_CREATE_SUB_KEY | `0x0200` | KEY_WOW64_32KEY |
| `0x0008` | KEY_ENUMERATE_SUB_KEYS | `0x0300` | KEY_WOW64_RES |
| `0x0010` | KEY_NOTIFY | | |

**SECTION** (`SECTION_ALL_ACCESS` = `0xF001F`):

| Bit | Name | Bit | Name |
|-----|------|-----|------|
| `0x0001` | SECTION_QUERY | `0x0010` | SECTION_EXTEND_SIZE |
| `0x0002` | SECTION_MAP_WRITE | `0x0020` | SECTION_MAP_EXECUTE_EXPLICIT |
| `0x0004` | SECTION_MAP_READ | | |
| `0x0008` | SECTION_MAP_EXECUTE | | |

---

## 4. Include / Exclude options

**Options:** `-access`, `-nt_access`, `-file_properties`, `-file_attributes`,
`-vtp_privileges`, `-disk_region`, `-image_properties`, `-vtp_trust`, `-processor_mode`,
`-type`, `-name` (name/value), `-key` (key/value), `-xtype` (custom aggregate types),
`-ref`.

**Value emitters inside `{}`:** `-v` (values), `-l` (a TCL list), `-pfx` (prefix, persists
until reset by an empty `-pfx`), `-sfx` (suffix).

Documented layouts:

```
Include/Exclude -ref "ref name"
Include/Exclude -access "access values"
Include|Exclude MatchName <-type Type> <-name Name> { -v ... -l ... -pfx x -sfx y }
Include|Exclude AggregateMatch -xtype "ext match type" { ... }
```

`-name` and `-key` are **mutually exclusive**. `-type PATH` is treated as `STRING` with a
trailing `\` or `/` stripped.

---

## 5. Reactions, severity, match types, data types

### Reaction (optional in the rule text; usually set in the console form)

`ALLOW`, `ASK_PP`, `ASK_KERNEL`, `BLOCK`, `BREAK`, `TERMINATE_PROCESS`, `EXCEPTIONAL_ALLOW`.

Plus the SCAN form (5 args):

```
Reaction SCAN ACTOR_PROCESS|TARGET_PROCESS SCANACTION <action>
```

where `<action>` is one of `CLEAN_PROCESS`, `DELETE_PROCESS`, `CLEAN_DELETE_PROCESS`,
`REPORT`, `REPORT_CLEAN_PROCESS`, `REPORT_DELETE_PROCESS`, `REPORT_CLEAN_DELETE_PROCESS`.

### Severity

| Name | Value |
|------|-------|
| CRITICAL | 5 |
| MAJOR | 4 |
| MINOR | 3 |
| WARNING / WARN | 2 |
| INFO / INFORMATIONAL | 1 |

### Match types (with default data type)

`OBJECT_NAME` (STRING), `TARGET_OBJECT_NAME` (STRING, 15.5+), `PROCESS_CMD_LINE`,
`USER_SID`, `GROUP_SID` (MULTI_SZ),
`ACCESS_MASK` / `NT_ACCESS_MASK` / `FILE_ATTRIBUTES` / `IMAGE_PROPERTIES` / `DISK_REGION` /
`VTP_VALIDATION_STATE` (BITMASK), `PROCESS_STATE_BITS` / `DLL_LOADED` (NAME_VALUE_BITMASK),
`CACHE_ATTRIBUTE` (KEY_VALUE_BITMASK), `VERSION_RESOURCE` (NAME_VALUE_STRING),
`MD5` / `SHA1` / `SHA2_256/384/512` / `PE_*` / `CERT_HASH` (BLOB),
`OS_VERSION`, `PROCESSOR_MODE`, `IS_DIRECTORY` / `WOW64` / `IS_TRANSACTED` (INT8),
`OBJECT_SIZE` / `LBA` / `FILE_CTIME/MTIME/ATIME` (INT64), `REGVAL_DATA` (VARIABLE, 18.6+).

Aliases: `USER_NAME` → `USER_SID`, `GROUP_NAME` → `GROUP_SID`,
`DRIVE_TYPE` → `FILE_PROPERTIES`.

### Data types (`-type`)

`INT8`, `INT16`, `INT32`, `INT64`, `STRING`, `BLOB` / `BINARY`, `BITMASK`,
`MULTI_SZ` / `MULTI_STRING`, `EXPANDABLE_STRING`, `VARIABLE`, `PATH`.

---

## 6. Wildcards and path semantics

Wildcards are interpreted **only in the rule pattern**, never in the actual object string.
Both matchers are **case-insensitive**.

**Path matcher** (used for `OBJECT_NAME` and paths):

- `?` — any single char **except** the path separator.
- `*` — 0-n chars **except** the path separator.
- `**` — 0-n chars **including** path separators (crosses directories).
- `**\` — 0-n chars ending in a separator.
- The path separator is backslash `\`. **There is no escape mechanism** — `\` is always a
  literal separator.

**String matcher** (non-path matches): `?` = any single char, `*` = 0-n chars, with no
separator exception.

**Backslash / escaping nuance.** The double backslashes in sample rules (`"C:\\Users\\…"`)
are consumed by **TCL string parsing**, which passes a single `\` to the matcher, where it
is a literal separator. So authors must double backslashes inside double-quoted TCL strings.
A single backslash inside a double-quoted path is a likely error — TCL will mis-parse it.

---

## 7. Constraints and limits

- **Reaction is required** in every Rule; a `Next_Process_Behavior` block **requires a
  `Target`** section.
- A Policy with no Rules is dropped.
- Command nesting depth ≤ 12; wildcard backtracking depth ≤ 40; string inputs < 64K chars.
- Policy id and Rule id must be unique; `-id` may appear only once per Rule.
- `-name` and `-key` are mutually exclusive; the Initiator object type must be `PROCESS`.
- SIDs must start with `S`; they may contain `*`/`?` wildcards, digits, and `-`.

**Version gating:**

| Version | Tokens gated at this version |
|---------|------------------------------|
| 15.5 | `LOCK_RANGE`, `WRITE_DATA`, `READ_DATA`, `RENAME`, `SET_FILE_LENGTH`, `TARGET_OBJECT_NAME`, `VTP_PRIVILEGES`, `FILE_PROPERTIES` |
| 15.8 | `IS_TRANSACTED` |
| 18.6 | `REGVAL_DATA` |
| 26.5 | `CREATE_BINDLINK` |

`SERVICE` and the `ENDP_*` tokens are ENS extensions.

---

## 8. Common validation errors

The compiler reports errors as strings; the linter mirrors these where possible.

**Hierarchy / structure**
- `"<cmd> is not a valid child of <parent>"`
- `"<cmd> is not allowed here."`
- `"<cmd>: Invalid number of arguments"`

**Rule / Reaction**
- `"Rule: Reaction was not set"` — raised only when no reaction reaches the compiler at
  all; the console form normally supplies one.
- `"Reaction: Unknown value <arg>"`
- `"Rule: Invalid id"`, `"Multiple -id options"`, `"Rule: Unknown option <arg>"`

**Match / Include / Exclude**
- `"Match: Unknown object type <arg>"`
- `"Match: Object type can only be PROCESS for Initiators <arg>"`
- `"<cmd>: Unknown match type <arg>"`, `"<cmd>: unknown -type <val>"`
- `"<cmd>: can not specify both -name and -key"`
- `"Smart <arg> not supported yet, add -type option"`

**Policy / Aggregate / Severity**
- `"Unknown Severity level <arg>"`, `"Duplicate Policy id found"`,
  `"Duplicate Rule id found"`, `"No Rules defined for Policy.  Policy not added"`.
