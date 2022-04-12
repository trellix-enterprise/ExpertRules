# T1053: Schedule task creation using powershell

## Author
McAfee Enterprise

## Description
This rule monitors attempt to execute malicious code from powershell using task scheduler.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "powershell.exe" }
        Include OBJECT_NAME { -v "powershell_ise.exe" }
        Include OBJECT_NAME { -v "pwsh.exe" }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "ScheduledTasks.psd1" }
            Include -access "READ"
        }
    }
}
```

## Trigger
NA

## Tested Platforms
OS: Windows 10 20H2 x64
ENS: 10.7.0

## Notes
This rule is for monitoring/telemetry. Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.
