# T1003 – Copy SAM file using Volume Shadow Copy Service tools

## Author
McAfee

## Description
This rule trigger indicates an attempt to copy the SAM file using volume shadow copy service tools. 

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "esentutl.exe" }
        Include DLL_LOADED -name "vssapi" { -v 0x1 }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\windows\\system32\\config\\sam" }
            Include -access "READ"
        }
    }
}
```

## Trigger
TBC.

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
This rule is for monitoring/telemetry. Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.