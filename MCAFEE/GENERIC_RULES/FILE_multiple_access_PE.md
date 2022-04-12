# FILE PE MODIFICATION PROTECTION RULE

## Description
Rule that detects the modification of a PE file by any process.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v "**"
        }
    }
    Target {
        Match FILE {
            Include PE { -v 1}
            Include -access "WRITE DELETE SET_REPARSE RENAME"
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows Explorer.
3. Navigate to the folder **C:\\Windows\\**.
4. Change the name of the file **notepad.exe**.

## Notes