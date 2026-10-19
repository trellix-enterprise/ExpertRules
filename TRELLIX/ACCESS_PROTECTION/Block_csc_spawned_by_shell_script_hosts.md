# Block csc spawned by shell script hosts

## Author
Trellix

## Description
This rule detects on-the-fly C# code compilation using the Microsoft C# compiler (csc.exe) launched from scripting engines — a common living-off-the-land technique.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v "powershell.exe"
            -v "pwsh.exe"
            -v "cmd.exe"
            -v "wscript.exe"
            -v "cscript.exe"
            -v "mshta.exe"
        }
    }

    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "csc.exe" }
            Include PROCESS_CMD_LINE {
                -v "*target:library*"       
                -v "*target:exe*"
             }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
OS: Win 10 ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.