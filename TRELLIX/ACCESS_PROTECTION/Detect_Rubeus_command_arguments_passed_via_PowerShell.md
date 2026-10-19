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
        Include OBJECT_NAME {
            -v "explorer.exe"
            -v "cmd.exe"
            -v "services.exe"
        }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME {
                -v "powershell.exe"
                -v "pwsh.exe"
            }
            Include PROCESS_CMD_LINE {
                -v "*Rubeus*"                       
                -v "*rubeus*"                       
                -v "*kerberoast*"                   
                -v "*asktgt*"                       
                -v "*asktgs*"                       
                -v "*harvest*"
                -v "*monitor*"
            }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
OS: Win 10 ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.