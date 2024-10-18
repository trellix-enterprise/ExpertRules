# T1007 System Service Discovery

## Author
Trellix

## Description
This Expert rule detects when user Gather windows running services information using system commands and windows API based payloads

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "cmd.exe" }
            Include OBJECT_NAME { -v "pwsh.exe" }
            Include OBJECT_NAME { -v "powershell.exe" }
            Include PROCESS_CMD_LINE { -v "**sc* query**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
Win 11x64 and Win server 2022

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
