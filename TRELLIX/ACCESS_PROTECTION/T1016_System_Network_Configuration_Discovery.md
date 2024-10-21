# T1016 System Network Configuration Discovery

## Author
Trellix

## Description
This Expert rule detects user trying to check Windows system utilities and commands used to look for network configurations.

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
            Include PROCESS_CMD_LINE { -v "**nbtstat* -**" }
            Include PROCESS_CMD_LINE { -v "**ipconfig**" }
            Include PROCESS_CMD_LINE { -v "**nslookup**" }
            Include PROCESS_CMD_LINE { -v "**net* view**" }
            Include PROCESS_CMD_LINE { -v "**arp* -**" }
            Include PROCESS_CMD_LINE { -v "**net* config**" }
            Include PROCESS_CMD_LINE { -v "**tracert**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
NA

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
