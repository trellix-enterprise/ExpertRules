# T1047 - Execute a program using WMIC

## Author
McAfee

## Description
This rule trigger indicates an attempt to abuse the Windows Management Instrumentation feature for persistence. 

## Rule Class 
Processes

## Rule TCL
```tcl
Rule {
    Target {
        Match PROCESS {
            Include DESCRIPTION { -v "WMI Commandline Utility" }
            Include PROCESS_CMD_LINE { -v "* process */FORMAT:*" }
            Include PROCESS_CMD_LINE { -v "* process *call *create *" }
            Include -access "CREATE"
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