# T1482: Powershell Enumerate AD Infrastructure (Domain Trust Discovery)

## Author
Trellix

## Description
This Expert rule detects Enumeration of Active Directory Infrastructure.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "pwsh.exe" }
            Include OBJECT_NAME { -v "powershell.exe" }
            Include PROCESS_CMD_LINE { -v "**Get-NetDomainTrust**" }
            Include PROCESS_CMD_LINE { -v "**Get-NetForestTrust**" }
            Include PROCESS_CMD_LINE { -v "**Get-ADDomain**" }
            Include PROCESS_CMD_LINE { -v "**Get-ADGroupMember**" }
            Include PROCESS_CMD_LINE { -v "**Get-DomainTrust**" }
            Include PROCESS_CMD_LINE { -v "**Get-ForestTrust**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
Win 11x64 and Win server 2022

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
