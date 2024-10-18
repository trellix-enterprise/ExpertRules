# T1089 Service Stop


## Author
Trellix

## Description
This Expert rule detects service stop using sc and taskkill commands.

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
            Include PROCESS_CMD_LINE { -v "**sc* stop**" }
            Include PROCESS_CMD_LINE { -v "**sc* config* start*=*disabled**" }
            Include PROCESS_CMD_LINE { -v "**taskkill**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
NA

## Notes
NA
