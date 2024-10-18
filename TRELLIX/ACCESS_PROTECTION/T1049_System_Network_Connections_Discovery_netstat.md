# T1049 System Network Connections Discovery usig netstat.

## Author
Trellix

## Description
This Expert rule detects Network Connections Discovery using netstat.

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
            Include PROCESS_CMD_LINE { -v "**netstat**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
NA

## Notes
NA
