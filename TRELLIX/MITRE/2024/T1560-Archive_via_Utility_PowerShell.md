# T1560 - Archive via Utility(Powershell)

## Author
Trellix

## Description
The expert rule detects attempt to archive Files using Powershell Compress-Archive command

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "pwsh.exe" }
            Include OBJECT_NAME { -v "powershell.exe" }
            Include PROCESS_CMD_LINE { -v "** Compress-Archive**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
NA


## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.