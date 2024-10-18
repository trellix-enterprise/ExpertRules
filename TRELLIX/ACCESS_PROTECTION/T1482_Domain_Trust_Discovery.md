# T1482 Domain Trust Discovery


## Author
Trellix

## Description
This Expert rule detects Domain Trust Discovery using nltest commands.

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
            Include PROCESS_CMD_LINE { -v "**nltest* /dclist:**" }
            Include PROCESS_CMD_LINE { -v "**nltest* /domain_trusts* /all_trusts**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
NA

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
