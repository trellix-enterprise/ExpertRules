# T1082 System Information Discovery


## Author
Trellix

## Description
This Expert rule detects System Information Discovery using systeminfo and net commands.

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
            Include PROCESS_CMD_LINE { -v "**systeminfo**" }
            Include PROCESS_CMD_LINE { -v "**net* /config**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
NA

## Notes
NA
