# T1069 System Network Configuration Discovery

## Author
Trellix

## Description
This Expert rule detects when user try to check Windows system utilities and commands used to look for network configurations

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
NA