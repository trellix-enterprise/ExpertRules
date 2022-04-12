# Behavior Abuse of REGASM.EXE

## Author
McAfee

## Description
This rule detects the behavior abuse of REGASM.EXE when loading msvcrt.dll. This is generally observed with certain variants of Fareit malware.

## Rule Class 
Processes

## Rule TCL
```tcl
The original rule: 
Rule {
    Process {
        Include OBJECT_NAME { -v "**\\regasm.exe"  }
        Exclude PROCESS_CMD_LINE { -v "?*" }
    }
    Target {
        Match SECTION {
            Include OBJECT_NAME {  -v "**\\msvcrt.dll" }
        }
    }
}
```

## Trigger
Tested with the Fareit Sample: 01246b0e014407bef17bc5882bf0757de66aebf9258ff591671e40651fcc1b8f

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.