# T1105 Ingress Tool Transfer

## Author
Trellix

## Description
This Expert rule detects possible tool and/or file transfer using powershell or CMD.

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
            Include PROCESS_CMD_LINE { -v "**Invoke-WebRequest** -OutFile**" }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
NA

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
