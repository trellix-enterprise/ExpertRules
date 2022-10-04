# T1175 – COM - WMI using PowerShell/WMIC/MSHTA/VBScript

## Author
McAfee

## Description
This rule trigger indicates an attempt to abuse the COM object using WMI via PowerShell, WMIC, MSHTA, or VBScript. 

## Rule Class 
Processes

## Rule TCL
```tcl
Rule {
Process {
Include OBJECT_NAME {
        -v "powershell.exe"
                    -v "powershell_ise.exe"
        -v "mshta.exe"
        -v "wscript.exe"
        -v "cscript.exe"
    }
    Exclude PROCESS_CMD_LINE { -v "*McAfee\\MAR\\scripts\\*" }
}
Target {
    Match SECTION {
        Include OBJECT_NAME { -v "wmiutils.dll" }
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