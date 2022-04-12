# DLL INJECTION THROUGH AppInit_DLLs REGISTRY VALUE PROTECTION RULE 

## Description
This rule detects malware (non-trusted process) that attempts to write into registry’s *AppInit_DLLs* entry to inject custom DLL into target processes . A DLL added into this registry entry will force user32.dll to load the DLL module at process startup.

## Rule TCL
```tcl
Rule {
    Initiator {
        Match PROCESS {
            Include OBJECT_NAME {-v "**"}
        }
    }
    Target {
        Match VALUE {
            Include OBJECT_NAME {
                -v "HKLMS\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINDOWS\\AppInit_DLLs"
            }
            Include ACCESS_MASK {
                -v "CREATE WRITE DELETE REPLACE_KEY RESTORE_KEY"
            }
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows Registry Editor.
3. Navigate to the key *HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows*.
4. Try to modify the *AppInit_DLLs* value.

## Notes
The most known malware using this technique is [T9000](https://unit42.paloaltonetworks.com/t9000-advanced-modular-backdoor-uses-complex-anti-analysis-techniques/).