# ENS Expert Rules — Rule Patterns Cookbook

How published Trellix Expert Rules turn a request into a rule. Read this **before**
writing a rule. It answers the two questions that most often go wrong: *which `Match`
type and access flags express this behaviour?* and *should the rule have an initiator?*

All snippets are rule bodies as pasted into the ePO / ENS Expert Rule form (Reaction,
Severity, Description and Group come from the form).

> **Start the rule content with `Rule {`.** Verified on ENS 10.7: the console inserts the
> form's Reaction only when the content begins with the `Rule` (or `Policy`) command. Any
> line before it — even a `#` comment — makes the compile fail with
> `Rule: Reaction was not set`. Put comments *inside* the `Rule { }` block (linter E122).

> **One broken Expert Rule disables all of them.** ENS compiles every Expert Rule on the
> endpoint into a single group; if any one fails to compile, *none* are enforced. Lint every
> rule, use the console's **Expert Rule Checker → Check** button before enforcing, and
> confirm the rule loaded (see [best-practices.md §9](best-practices.md)).

### How a rule is structured and evaluated

- **One `Rule` per Expert Rule.** Each Expert Rule entry (one ID in the console) holds
  exactly one `Rule { }`, of one engine type (the form's *Rule type*). Inside it you may
  have several `Process`, `Initiator` and `Target` sections.
- **No initiator = every process.** Omitting `Process`/`Initiator` is the same as `**`.
- **Several `Target` sections, or several `Match` blocks in one `Target`, are OR'd**
  (verified live on ENS 10.7: a rule with targets *A* and *B* fired when only *A* was
  created). A single event can never satisfy two targets at once, so you cannot AND two
  different operations this way — use `Next_Process_Behavior` for sequences.
- **An Exclude-only `Process` block means "every process except …"** (verified live).
- **AND / OR.** Within a `Process` or `Match` block, `Include` lines of the **same** match
  type are **OR**'d; **different** match types are **AND**'ed. `Exclude` lines work the
  same way, and an Exclude wins over an Include. `AggregateMatch -xtype "<name>"` creates
  its own group, so several `-xtype` groups are AND'ed together while the entries inside
  one group are OR'd:
  ```tcl
  Include OBJECT_NAME { -v "a.exe" }      ;# a.exe OR b.exe …
  Include OBJECT_NAME { -v "b.exe" }
  Include PROCESS_CMD_LINE { -v "**-enc**" } ;# … AND command line contains -enc
  ```
- **Engine types.** *Files*, *Registry* and *Processes* rules use the AAC syntax in this
  skill. *Buffer Overflow*, *Illegal API Use* and *Services* rules use the older Host IPS
  signature format (`Executable { Include … }`, `user_name`, `directives services:stop` …),
  which this skill does not cover; for service tampering prefer an AAC `VALUE`/`KEY` rule
  on `HKCCS\\Services\\<name>\\**` (see §4).

---

## 1. Pick the target by the behaviour

| The request says… | `Match` type | `-access` | Key fields |
|---|---|---|---|
| X **launches / spawns** a named child process, LOLBIN or shell (often with specific arguments) | `PROCESS` | `CREATE` | `OBJECT_NAME` of the child; `PROCESS_CMD_LINE` for arguments |
| X **executes files chosen by location** ("any exe in System32", "files in Temp", "LOLBins from Office") with no argument filter | `FILE` | `EXECUTE` | `OBJECT_NAME` path pattern (`**\\Windows\\System32\\*.exe`) |
| X **loads a DLL / driver / module**, DLL side-loading, BYOVD | `FILE` | `EXECUTE` | `OBJECT_NAME`, `SHA2_256`, `CERT_NAME*`, `VTP_TRUST` |
| X **drops / creates / writes** a file (payload, script, LNK, config) | `FILE` | `CREATE` (add `WRITE` for modify) | `OBJECT_NAME` path pattern |
| X **deletes / renames / encrypts** files (ransomware, log wiping) | `FILE` | `DELETE` / `RENAME` / `WRITE` | `TARGET_OBJECT_NAME` = rename destination |
| symlink / junction / reparse-point abuse | `FILE` | `SET_REPARSE` (or `CREATE_BINDLINK`) | |
| named-pipe creation / connection | `FILE` | `CREATE` / `CONNECT_NAMED_PIPE` | `OBJECT_NAME { -v "**pipe\\<name>" }` |
| X **sets / modifies a registry value** (Run key, IFEO, COM `InprocServer32`, SSP, Winlogon) | `VALUE` | `CREATE WRITE` | `OBJECT_NAME` = `HKLM\\…\\<value>`; `REGVAL_DATA -type …` for the data |
| X **creates / deletes a registry key**, or loads/replaces a hive | `KEY` | `CREATE` / `DELETE` / `LOAD_KEY` / `REPLACE_KEY` / `RESTORE_KEY` | |
| X **opens / reads memory of / injects into / terminates** another process (lsass dump, injection) | `PROCESS` | `-nt_access` mask (e.g. `"!0x10"` VM_READ, `"!0x20"` VM_WRITE) or `WRITE` / `TERMINATING` | `OBJECT_NAME` of the victim |
| RWX / executable memory section mapping | `SECTION` | `CREATE` / `EXECUTE` (`-access` only — `-nt_access` is rejected on `SECTION`) | `VTP_TRUST`, `IMAGE_PROPERTIES` |
| service creation / modification | `VALUE` / `KEY` under `HKCCS\\Services\\<name>\\**` (the legacy *Services* rule type is a different syntax) | `CREATE WRITE` (`DELETE` for removal) | `REGVAL_DATA` for `ImagePath` / `Start` |
| raw disk / MBR write | `DISK` | `WRITE` | |

Rules of thumb:

- **"Spawns process X (with arguments Y)" is a `PROCESS` + `CREATE` rule.** Put the child
  image in the target `OBJECT_NAME` and any argument filter in the **target**
  `PROCESS_CMD_LINE` (published rules put the command line in the target about 13× more
  often than in the initiator). This is the most common published launch pattern. (The
  official reference also documents `Match SECTION { Include -access "CREATE" }` for
  process creation; both compile — prefer the `PROCESS` form, which published rules use.)
- **"Prevents execution of files from a location / of a class of binaries"** (no arguments)
  is published as `FILE` + `EXECUTE` on the path pattern.
- **"Loads a DLL/driver" is `FILE` + `EXECUTE`**, not `SECTION`. Reserve `SECTION` for
  memory-mapping/RWX scenarios.
- **Registry "value" vs "key":** writing data under a key (Run, IFEO `Debugger`, CLSID
  `InprocServer32`, Winlogon `Shell`/`Userinit`, LSA `Security Packages`) is `VALUE`. Use
  `KEY` only when the key itself is created, deleted, or (re)loaded.
- Several behaviours in one request → several `Match` blocks (or several `Target`
  sections) inside the one `Rule`, or separate Expert Rules (one `Rule` each). Do not merge
  unrelated object types into one `Match`.

## 2. Decide the initiator

Published rules use three initiator shapes:

1. **A named actor** when the request names one ("Office apps spawning…", "OneDrive
   loading…", "w3wp.exe writing…"). List each image, bare name is the published
   convention:
   ```tcl
   Process {
       Include OBJECT_NAME { -v "winword.exe" }
       Include OBJECT_NAME { -v "excel.exe" }
   }
   ```
   `**\\name.exe` also works and is tighter against path planting; either is acceptable.
2. **No `Process` block at all** when the request is about *what* happens to a target,
   regardless of who does it ("detects modification of the Winlogon Shell value",
   "detects creation of files under …"). This is the published form for target-centric
   rules — prefer it over `Process { Include OBJECT_NAME { -v "**" } }`.
3. **`SYSTEM`** as the actor for kernel-side operations such as driver loads:
   ```tcl
   Process { Include OBJECT_NAME { -v "SYSTEM" } }
   ```

4. **Everyone except…** when the request says "unauthorised", "untrusted", "unsigned",
   "non-admin" or "other than X". Both published forms are valid:
   ```tcl
   Process { Exclude VTP_PRIVILEGES -type BITMASK { -v 0x8 } }      ;# Exclude-only block

   Process {
       Include OBJECT_NAME { -v "**" }                              ;# all processes…
       Exclude VTP_TRUST true                                       ;# …except trusted ones
       Exclude OBJECT_NAME { -v "**\\msiexec.exe" }                 ;# …and the installer
   }
   ```
   A bare `Include OBJECT_NAME { -v "**" }` is fine **when paired with an `Exclude`**; on
   its own it adds nothing — omit the block instead.

Do **not** invent an initiator list the request doesn't imply.

**Who actually performs the operation?** The initiator is the process that does the I/O,
which is often not the attacker's process:

| Request | The write is done by | Scope the rule on |
|---|---|---|
| create / modify a **service** | `services.exe` (via the SCM) | `PROCESS` + `CREATE` of `sc.exe` / `powershell.exe` with a `PROCESS_CMD_LINE` filter, or the `HKCCS\\Services\\…` value with no initiator |
| create a **scheduled task** | the Task Scheduler service (`svchost.exe`) | `PROCESS` + `CREATE` of `schtasks.exe` with `PROCESS_CMD_LINE`, or the `Tasks` folder / `TaskCache` keys with no initiator |
| **COM / DCOM** automation (e.g. a script driving Word) | the COM server, started by the DCOM launcher (`svchost.exe`), not the script | the COM server process as actor, or the script loading the COM DLL (`DLL_LOADED` / `FILE` `EXECUTE`) |
| **WMI** process creation | `WmiPrvSE.exe` | `WmiPrvSE.exe` as the initiator |
| files served over **SMB** | `System:Remote` | `System:Remote` (or `System*`) |

Scoping such a rule to the attacker's process (e.g. `powershell.exe` writing a service
key) silently never matches.

## 3. Field syntax that published rules use

**Command line** (target or initiator; wildcards as for paths):
```tcl
Include PROCESS_CMD_LINE { -v "**-enc**" }
Exclude PROCESS_CMD_LINE { -v "**\\Windows\\System32\\**" }
```

**Signed / trusted / unsigned** — `VTP_TRUST` takes a bare boolean (no `-type`, no `-v`):
```tcl
Exclude VTP_TRUST true      ;# skip binaries trusted by ENS (signed by trusted vendors)
Include VTP_TRUST false     ;# only untrusted / unsigned
```
Signer by certificate subject (chained = any cert in the chain):
```tcl
Exclude CERT_NAME_CHAINED { -v "*O=Microsoft Corporation*" }
Exclude CERT_NAME { -v "*Vendor Name Inc*" }
```

**File description** (from the PE version resource — matches renamed binaries):
```tcl
Include DESCRIPTION { -v "Microsoft OneDrive" }
```

**Hash lists** (one `SHA2_256` with many `-v`; also `MD5`, `SHA1`):
```tcl
Include SHA2_256 {
    -v "<64-hex-digit hash>"
    -v "<64-hex-digit hash>"
}
```

**Trellix-trusted actor** (`VTP_PRIVILEGES`, 15.5+). This is the *trust privilege VTP
grants the signed binary* — **not** Windows admin rights. `ISG` (`0x8`) = signed with a
trusted Trellix/McAfee certificate only; `IOCTL` (`0x1`) = in the Trellix trust store,
which also includes Microsoft-signed binaries. Published rules use it to exempt Trellix's
own processes ("unauthorised access to X" = anyone except Trellix code):
```tcl
Exclude VTP_PRIVILEGES -type BITMASK { -v ISG }     ;# same as { -v 0x8 }
```
For Windows users/groups use `USER_NAME` / `GROUP_NAME` (see §8); there is no
"is administrator" match type.

**Process loaded a given DLL** (`DLL_LOADED` is NAME_VALUE_BITMASK; module name without
`.dll`). Combine several conditions with `AggregateMatch`, each with a unique `-xtype`:
```tcl
Process {
    Include OBJECT_NAME { -v "powershell.exe" }
    Include AggregateMatch -xtype "inc1" { Include DLL_LOADED -name "mshtml" { -v 0x1 } }
    Include AggregateMatch -xtype "inc2" { Include DLL_LOADED -name "winhttp" { -v 0x1 } }
}
```

**AND across several command-line fragments** — one `AggregateMatch` per fragment
(fragments in a plain `Include` are OR'd):
```tcl
Include AggregateMatch -xtype "a1" { Include PROCESS_CMD_LINE { -v "**create**" } }
Include AggregateMatch -xtype "a2" { Include PROCESS_CMD_LINE { -v "**binPath=**" } }
```

**DAC-contained actor** (Dynamic Application Containment):
```tcl
Include PROCESS_STATE_BITS -name DAC_CONTAIN_PID_BITS { -v 0x1 }
```

**Registry value data** (always typed; `STRING`, `EXPANDABLE_STRING`, `MULTI_STRING`,
`INT32`, `INT64`):
```tcl
Match VALUE {
    Include OBJECT_NAME { -v "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" }
    Include REGVAL_DATA -type STRING { -v "**.dll" }
    Include -access "CREATE WRITE"
}
```

**Rename destination** (`TARGET_OBJECT_NAME`, 15.5+):
```tcl
Match VALUE {
    Include OBJECT_NAME { -v "HKLM\\Software\\Example\\**" }
    Include TARGET_OBJECT_NAME { -v "HKLM\\Software\\Example\\Protected\\**" }
    Include -access "RENAME"
}
```

## 4. Paths

- **Registry:** write `HKLM\\…` and `HKCU\\…` (`HKEY_LOCAL_MACHINE\\…` also works). Use
  `*` for one key level (e.g. a CLSID or user SID) and `**` for any depth. AAC root
  aliases save duplicate entries:

  | Root | Matches |
  |---|---|
  | `HKCU` | **every** user's hive (and `.default`), not just the current user |
  | `HKCR` | machine classes and every user's classes |
  | `HKLMS` / `HKCUS` | `…\\Software` **and** `…\\Software\\Wow6432Node` |
  | `HKCCS` | `HKLM\\SYSTEM\\CurrentControlSet` **and** every `ControlSet00X` |
  | `HKULM` / `HKULMS` | `HKLM`+`HKCU` / `HKLMS`+`HKCUS` |
  | `HKALL` | `HKLM` and all user hives |

  Never put a wildcard *inside* the root (`H*L*\\…`, `HK*\\…`): the name is then not
  normalised and silently never matches. A leading `**\\…` is fine (linter W208).
- **Files:** `**\\name.ext` for "anywhere"; `C:\\Users\\*\\AppData\\…` or `**\\Users\\*\\…`
  for per-user locations; environment variables such as `%windir%` are accepted.
- **Named pipes:** `"**pipe\\<pipename>"`.
- **`$` and `[` are TCL metacharacters inside double quotes** (`$name` substitutes a
  variable, `[cmd]` runs a command). Escape them: `"**\\\$Recycle.Bin\\**"`,
  `"C:\\\$WinREAgent\\**"`, `"*\[System.Reflection.Assembly\]::Load*"`. Or put the value
  in braces, which disables substitution: `-v {C:\$Recycle.Bin\**}` (single backslashes
  inside braces).
- **UNC / network:** `"\\\\*\\**"` (each `\` doubled).

## 5. Multi-stage behaviour (`Next_Process_Behavior`)

When the request describes a *sequence* ("creates a junction, then launches X, which then
connects to pipe Y"), chain stages. Each stage is a `Target` inside `Next_Process_Behavior`,
and every `Next_Process_Behavior` needs a `Target`. The official reference states the link
is defined alongside a `Match PROCESS` in the enclosing `Target` (the process whose later
behaviour is followed); published rules also chain from `FILE` matches as below:
```tcl
Rule {
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\Users\\*\\AppData\\Local\\Example\\Dir" }
            Include -access "SET_REPARSE"
        }
        Next_Process_Behavior {
            Target {
                Match FILE {
                    Include OBJECT_NAME { -v "example.exe" }
                    Include -access "EXECUTE"
                }
            }
        }
    }
}
```

## 6. TCL helpers for environment-dependent rules

Rules are TCL, so `set`, `if`, and these built-in helpers are available at rule level:

These are the only helpers the ENS rule compiler registers (`hostips` `ApState.cpp`):

| Helper | Subcommands / returns |
|---|---|
| `iSystem` | `version` (`major.minor.build`), `major`, `minor`, `build`, `csd` (e.g. `"Service Pack 1"`), `platform` (e.g. `"Windows 7"`), `type` (`Workstation` / `Server` / `Unknown`), `install_dir`, `sys32_dir`, `cpu_arch` (`320` / `640` / `641`), `os_arch` (`320` 32-bit, `640` 64-bit), `users_folders ?-no_defaults? Temp\|Profile\|Downloads\|<User Shell Folders name> …` (list of every user's folders, for `-l`) |
| `iUser` | `exist <name>` (`1`/`0`), `list` (all users), `groups <name>` (list) |
| `iReg ?-64\|-32?` | `open <key>`, `exists <key>`, `keys <key>` (subkey list), `value <key> <valueName>` (string/int, or a Tcl list for MULTI_SZ), `v_exists <key> <valueName>`; key roots `HKLM` `HKCR` `HKCC` `HKCU` `HKUS` |
| `iEnv NAME` | environment variable value (`""` if unset), e.g. `[iEnv COMMONPROGRAMFILES]` |
| `iList ?-d? list` | sorts and de-duplicates a list (`-d` treats entries as paths) |
| `iUtil cvt2args <cmdline>` | splits a command line into `{arg} {arg}` |
| `iTerminate "message"` | abandon compiling this rule (wrong host, product absent, …) |
| `iDump ?prefix? ?text?` | debug only: dumps matching globals to the rule-compiler log when logging is on |

Use `lappend list "item"` to build a list and `-l $list` (or `-l [iSystem users_folders …]`)
to match every entry. `-pfx` / `-sfx` set a prefix / suffix for the following entries and
take **exactly one value on their own line** (verified: `-sfx "x" -l $l` on one line fails
with `-sfx: Invalid number of arguments`):
```tcl
Rule {
    set tempdirs [iSystem users_folders Temp]
    Target {
        Match FILE {
            Include OBJECT_NAME {
                -sfx "\\payload.exe"
                -l $tempdirs
            }
            Include -access "CREATE"
        }
    }
}
```

```tcl
Rule {
    set os_arch [iSystem os_arch]
    Process { Include OBJECT_NAME { -v "example.exe" } }
    Target {
        Match PROCESS {
            Exclude OBJECT_NAME { -v "%windir%\\System32\\werfault.exe" }
            if { $os_arch == 640 } {
                Exclude OBJECT_NAME { -v "%windir%\\SysWOW64\\werfault.exe" }
            }
            Include -access "CREATE"
        }
    }
}
```

## 7. Memory-scan reaction

The console form offers block/report. When a request asks to **scan the actor or target
process memory**, put the SCAN reaction in the rule text:
```tcl
Reaction SCAN ACTOR_PROCESS SCANACTION REPORT
```

## 8. Field value reference (from the ENS rule compiler)

Taken from the compiler's own tables (`hostips` `ApRc/AacHelpers.cpp`, syscore
`aacapi.h`). Match-type names are **case-sensitive** (upper case); the linter rejects
unknown names (E154) and unknown symbolic bitmask values (E155).

**Symbolic bitmask fields.** Write the names (or numbers) in a `-v` body, or use the
shortcut option form. Several names are OR'd; prefix `!` to require a bit, `!*` to require all:

| Field (shortcut option) | Names |
|---|---|
| `FILE_ATTRIBUTES` (`-file_attributes`) | `READONLY` `HIDDEN` `SYSTEM` `DIRECTORY` `ARCHIVE` `DEVICE` `NORMAL` `TEMPORARY` `SPARSE_FILE` `REPARSE_POINT` `COMPRESSED` `OFFLINE` `NOT_CONTENT_INDEXED` `ENCRYPTED` `VIRTUAL` |
| `DRIVE_TYPE` (alias, compiled to `FILE_PROPERTIES`) | `DT_FIXED` `DT_REMOVABLE` `DT_NETWORK` `DT_CD_DVD` `DT_FLOPPY` |
| `FILE_PROPERTIES` (`-file_properties`) | `FILE_NETWORK` `FILE_REMOVABLE` `FILE_FLOPPY` `FILE_CD` `FILE_DFS` `FILE_REDIRECTOR` |
| `DISK_REGION` (`-disk_region`) | `MBR` (incl. GPT tables) `VBR` (system partition sector 0) `PARTITION` `NOT_PARTITIONED` `MULTI_PARTITION` |
| `IMAGE_PROPERTIES` (`-image_properties`, SECTION) | `64_BIT` `SYSTEM_MODE` `MAPPED_TO_ALL_PROCESSES` `MANAGED` `DLL` |
| `VTP_PRIVILEGES` (`-vtp_privileges`) | `ISG` (Trellix-signed) `IOCTL` (Trellix trust store, incl. Microsoft) `NONE` |
| `VTP_TRUST` (`-vtp_trust`) | `true` / `false` (bare: `Exclude VTP_TRUST true`) |
| `PROCESSOR_MODE` (`-processor_mode`) | `USER` / `KERNEL` |

```tcl
Include DRIVE_TYPE { -v "DT_REMOVABLE" }        ;# file on removable media
Include -file_attributes "HIDDEN"               ;# hidden file
Include -disk_region "MBR VBR"                  ;# boot sectors (DISK target)
```

**Integers** (`OBJECT_SIZE`/`FILE_SIZE`, `LBA`, `SESSION_ID`, `PROCESS_ID`,
`REGVAL_DATA -type INT32|INT64`, …) are **decimal**. One `-v` line is an exact value; a
**second `-v` line** makes an inclusive range `low … high` (the compiler takes the first
entry as the low bound and the second as the high bound). Put each `-v` on its own line —
`{ -v 60 -v 64 }` on one line is a single malformed entry (linter E141), not a range:
```tcl
Include OBJECT_SIZE {
    -v 0
    -v 1048576
}                                     ;# files of 0 .. 1 MiB
Include REGVAL_DATA -type INT32 {
    -v 60
    -v 64
}                                     ;# DWORD 60 .. 64
```
Note the difference: for **integer** types two `-v` lines are a *range*; for **string**
types (names, paths, command lines, MULTI_STRING data) they are alternatives (*OR*).

**Hashes** are plain hex, no `0x`, even length: `MD5`/`PE_MD5`/`CERT_HASH` 32 hex digits,
`SHA1` 40, `SHA2_256` 64, `SHA2_384` 96, `SHA2_512` 128. `PE_*` hashes cover the PE image
(process/section), plain hashes the whole file.

**Booleans** (`IS_DIRECTORY`, `PE`, `WOW64`, `IS_TRANSACTED`): `{ -v 1 }` / `{ -v 0 }`.

**Multi-string registry data** (`REGVAL_DATA -type MULTI_STRING`), verified live: give
**one `-v` line per string**; the rule matches when **any** string in the value equals any
`-v` entry, in any position. Two other spellings compile but are broken:
`-v "a" -v "b"` on one line never matches (linter E141), and `"a\0b\0\0"` only compares
the text before the first NUL, i.e. `"a"` (W209):
```tcl
Include REGVAL_DATA -type MULTI_STRING {
    -v "alpha"
    -v "beta"
}
```

**Users and groups.** `USER_NAME` / `GROUP_NAME` take account names and are converted to
SIDs when the rule is **enforced** — the console's *Check* button does **not** validate
them (it passes even a non-existent user), and an unknown name then breaks compilation of
*all* Expert Rules. Both the bare name (`AdamCarrivick`) and `HOST\\name` matched in a live
test. Prefer `USER_SID` / `GROUP_SID` with SID strings when in doubt:
```tcl
Include USER_NAME { -v "NT AUTHORITY\\SYSTEM" }
Include USER_SID { -v "S-1-5-18" }
```

**Remote (SMB) actors.** For writes that arrive over the network, the initiator name is
`System:Remote`; `REMOTE_MACHINE_ADDRESS` then matches the client address (target must be
a local file; the field is mainly intended for event reporting). An initiator of `System`
does **not** match SMB-served I/O — use `System*` to cover both kernel-side `System` and
`System:Remote`:
```tcl
Process { Include OBJECT_NAME { -v "System:Remote" } }
```

**Version resource** fields use `-name`: `Include VERSION_RESOURCE -name "CompanyName" { -v "*Vendor*" }`.
`DESCRIPTION`, `VERSION` and `PRODUCT_NAME` are shortcuts for common version-resource strings.

**Other limits and options** (official reference):
- `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`) cannot be blocked — an `-nt_access` rule
  on it only reports.
- `-type PATH` on an `Include`/`Exclude` treats entries as paths and strips trailing `\`,
  which avoids double separators when combined with `-sfx`.
- `CERT_HASH` matches the signing certificate's hash without checking the chain, and never
  matches unsigned objects; `CERT_NAME_CHAINED` checks the whole chain.
- `Reaction SCAN` requires ENS 10.7 Update 4 or later. Scan actions: `REPORT`,
  `CLEAN_PROCESS`, `DELETE_PROCESS`, `CLEAN_DELETE_PROCESS`, `REPORT_CLEAN_PROCESS`,
  `REPORT_DELETE_PROCESS`, `REPORT_CLEAN_DELETE_PROCESS`.
