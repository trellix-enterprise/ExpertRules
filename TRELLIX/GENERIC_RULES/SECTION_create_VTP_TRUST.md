# SECTION CREATION VTP TRAUSTED PROTECTION RULE

## Description
This rule detects when a process (notepad.exe in this example) attempts to load PE modules that are not fully trusted by VTP.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v notepad.exe
        }
    }
    Target {
        Match SECTION {
            Include VTP_TRUST true
            Include -access "CREATE" ; # Prevents section creation
        }
    }
}
```

## Trigger
1. Open Windows Notepad.

## Notes
As you will realize, the rule will be triggered every time. The reason why is because notepad only loads modules signed by Microsoft. And a module to be fully VTP trusted has to be also McAfee signed.