# DLL INJECTION USING ALLOCATE VIRTUAL MEMORY PROTECTION RULE 

## Description
This rule detects when a non-VTP trusted process attempts to allocate virtual memory in the address space of a remote process. This is step is part of different code injection techniques used by memory resident malware.

## Rule TCL
```tcl
Rule {
    Process {
        Include VTP_TRUST false
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME {
                -v **
            }

            Include -nt_access "!0x20"
        }
    }
}
```

## Trigger
TBC.

## Notes
The most known malwares using this technique are Reflective DLL injection on Meterpreter, PoisonIvy and Mimikatz [T1055](https://attack.mitre.org/wiki/Technique/T1055).