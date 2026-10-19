# Detect Rubeus command arguments passed via PowerShell

## Author
Trellix

## Description
This rule detects Kerberos-based credential attacks using the Rubeus offensive tool executed through PowerShell from common Windows parent processes.

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
            Include PROCESS_CMD_LINE { -v "*Rubeus*" }
            Include PROCESS_CMD_LINE { -v "*rubeus*" }
            Include PROCESS_CMD_LINE { -v "*kerberoast*" }
            Include PROCESS_CMD_LINE { -v "*asktgt*" }
            Include PROCESS_CMD_LINE { -v "*asktgs*" }
            Include PROCESS_CMD_LINE { -v "*harvest*" }
            Include PROCESS_CMD_LINE { -v "*monitor*" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
OS: Win 10 ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.