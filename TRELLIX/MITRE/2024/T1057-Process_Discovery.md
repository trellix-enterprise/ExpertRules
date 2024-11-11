#  T1057 - Process Discovery

## Author
Trellix

## Description
The expert rule detects Process Discovery using tasklist command.

## Rule Class 
Processes

## Rule TCL
```tcl
Rule {
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "cmd.exe" }
            Include OBJECT_NAME { -v "pwsh.exe" }
            Include OBJECT_NAME { -v "powershell.exe" }
            Include PROCESS_CMD_LINE { -v "**tasklist**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
NA


## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.