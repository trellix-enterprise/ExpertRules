# T1087 Account Discovery


## Author
Trellix

## Description
This Expert rule detects Account Discovery using net user commands.

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
            Include PROCESS_CMD_LINE { -v "**net* user**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
NA

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
