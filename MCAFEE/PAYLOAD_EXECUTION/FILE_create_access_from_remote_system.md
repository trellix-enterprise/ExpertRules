# FILE MODIFICATION FROM A REMOTE SYSTEM PROTECTION RULE

## Description
This rule prevents modifying local files from a remote system.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v SYSTEM:REMOTE
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v ** }
            Include -access "CREATE WRITE DELETE READ EXECUTE"
        }
    }
}
```

## Trigger
TBC

## Notes