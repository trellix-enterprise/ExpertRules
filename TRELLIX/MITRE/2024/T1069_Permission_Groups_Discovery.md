# T1069 Permission Groups Discovery

## Author
Trellix

## Description
This Expert rule detects Adversaries may attempt to discover group and permission settings.

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
            Include PROCESS_CMD_LINE { -v "**net* localgroup**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
NA

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
