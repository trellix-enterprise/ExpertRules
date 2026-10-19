# Block reflective assembly loading and SpoofFileLoad method invocation

## Author
Trellix

## Description
This rule detects in-memory .NET assembly loading and AMSI evasion techniques executed through PowerShell spawned by common parent processes.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "explorer.exe" }
        Include OBJECT_NAME { -v "cmd.exe" }
        Include OBJECT_NAME { -v "services.exe" }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "powershell.exe" }
            Include OBJECT_NAME { -v "pwsh.exe" }
            Include PROCESS_CMD_LINE { -v "*\[System.Reflection.Assembly\]::Load*" }
            Include PROCESS_CMD_LINE { -v "*Assembly]::LoadFrom*" }
            Include PROCESS_CMD_LINE { -v "*SpoofFileLoad*" }
            Include PROCESS_CMD_LINE { -v "*TrollAmsiDOTNET*" }
            Include PROCESS_CMD_LINE { -v "*TrollamsiDOTNET*" }
            Include PROCESS_CMD_LINE { -v "*.EntryPoint.Invoke*" }
            Include PROCESS_CMD_LINE { -v "*0x4D, 0x5A*" }
            Include PROCESS_CMD_LINE { -v "*MZHeader*" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
OS:  Win 10 ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.