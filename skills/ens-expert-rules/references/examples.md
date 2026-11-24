# ENS Expert Rules — Worked Examples

One worked example per target type. Each shows the **intent**, a complete **rule**, and how
it **triggers**. Every rule here is grammar-valid and lints clean, so these double as the
canonical inputs in `tests/good/`.

Adapt them to your environment — replace initiator processes and target paths/keys with the
specifics you need, then lint before deploying:

```
python scripts/lint_expert_rule.py rule.tcl
```

> These examples are patterned after publicly documented Trellix Expert Rule structures.
> See the repository `NOTICE` for attribution.

> **These are self-contained rules.** They include `Reaction` / `Severity` / `Group` /
> `Description` lines; when the rule is pasted into the ePO / ENS console form, drop those
> lines and enter the values in the form instead. To choose the `Match` type and initiator
> shape for a new request, use [rule-patterns.md](rule-patterns.md) — e.g. a request to stop
> an app *loading* a DLL is `Match FILE` + `EXECUTE`, not the `SECTION` example below.

---

## FILE — protect a directory from script hosts

**Intent.** Prevent common script interpreters from creating or modifying executables in a
startup folder (a classic persistence location).

```tcl
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Block script hosts writing executables to the Startup folder"

    Process {
        Include OBJECT_NAME { -v "**\\powershell.exe" }
        Include OBJECT_NAME { -v "**\\wscript.exe" }
        Include OBJECT_NAME { -v "**\\cscript.exe" }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\Start Menu\\Programs\\Startup\\**.exe" }
            Include -access "CREATE WRITE"
        }
    }
}
```

**Triggers when** `powershell.exe`, `wscript.exe`, or `cscript.exe` creates or writes an
`.exe` anywhere under a Startup folder.

---

## PROCESS — block remote-thread injection into a sensitive process

**Intent.** Stop arbitrary processes from opening `lsass.exe` with memory-write / thread
rights (credential dumping and injection).

```tcl
Rule {
    Reaction    BLOCK
    Severity    CRITICAL
    Group       "Custom Expert Rules"
    Description "Block VM_WRITE/CREATE_THREAD access to lsass.exe"

    Process {
        Include OBJECT_NAME { -v "**" }
        Exclude OBJECT_NAME { -v "**\\MsMpEng.exe" }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "**\\lsass.exe" }
            Include -nt_access "!0x0020 !0x0002"
        }
    }
}
```

**Triggers when** any process (except the excluded AV engine) opens `lsass.exe` requesting
`PROCESS_VM_WRITE` (`0x0020`) or `PROCESS_CREATE_THREAD` (`0x0002`). The initiator is left
broad here on purpose — the target is a single, highly specific process, so the rule still
discriminates.

---

## VALUE — guard a Run key value from modification

**Intent.** Detect changes to the `HKLM\...\Run` autostart values by anything other than
trusted installers.

```tcl
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Block writes to HKLM Run key autostart values"

    Process {
        Include OBJECT_NAME { -v "**" }
        Exclude OBJECT_NAME { -v "**\\msiexec.exe" }
        Exclude OBJECT_NAME { -v "**\\TiWorker.exe" }
    }
    Target {
        Match VALUE {
            Include OBJECT_NAME { -v "**\\CurrentVersion\\Run\\**" }
            Include -access "WRITE"
        }
    }
}
```

**Triggers when** a non-trusted process writes a value under a `CurrentVersion\Run` key.
Registry **value** targets use `-access` only — there is no `-nt_access` map for `VALUE`.

---

## KEY — prevent deletion of a service registry key

**Intent.** Stop tampering that deletes or reconfigures a security service's registry key.

```tcl
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Block deletion/modification of a protected service key"

    # No Process block: the rule is about the target, whoever the actor is.
    Target {
        Match KEY {
            Include OBJECT_NAME { -v "**\\Services\\MyProtectedSvc" }
            Include -access "DELETE WRITE"
        }
    }
}
```

**Triggers when** any process deletes or writes the protected service key. Tighten by adding
an initiator `Exclude` for your legitimate service-management tooling.

---

## SECTION — block mapping/execution of a section for an image

**Intent.** Detect executable mapping of a module from an untrusted location (reflective /
image-load abuse).

```tcl
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Block executable section mapping from the temp directory"

    Process {
        Include OBJECT_NAME { -v "**\\rundll32.exe" }
    }
    Target {
        Match SECTION {
            Include OBJECT_NAME { -v "**\\Temp\\**.dll" }
            Include -access "EXECUTE"
        }
    }
}
```

**Triggers when** `rundll32.exe` maps a `.dll` from a `Temp` path with execute intent.

---

## DISK — block raw writes to a physical disk

**Intent.** Prevent non-system tools from writing raw sectors (bootkit / MBR-wiper
behavior).

```tcl
Rule {
    Reaction    BLOCK
    Severity    CRITICAL
    Group       "Custom Expert Rules"
    Description "Block raw disk writes by non-system processes"

    Process {
        Include OBJECT_NAME { -v "**" }
        Exclude OBJECT_NAME { -v "**\\System32\\**" }
    }
    Target {
        Match DISK {
            Include OBJECT_NAME { -v "**\\PhysicalDrive*" }
            Include -access "WRITE"
        }
    }
}
```

**Triggers when** a process outside `System32` writes directly to a physical drive device.

---

## Notes on adapting these

- Swap `**` initiators for the specific actor(s) whenever you can — see
  [best-practices.md](best-practices.md) §1.
- Keep access flags minimal and valid for the `Match` type
  ([syntax.md §3](syntax.md)).
- Roll out in a monitor/report posture first, then promote to `BLOCK`.
