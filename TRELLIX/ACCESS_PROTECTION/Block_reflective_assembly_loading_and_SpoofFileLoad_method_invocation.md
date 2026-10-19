# Block reflective assembly loading and SpoofFileLoad method invocation

## Author
Trellix

## Description
This rule detects in-memory .NET assembly loading and AMSI evasion techniques executed through PowerShell spawned by common parent processes.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v "explorer.exe"
            -v "cmd.exe"
            -v "services.exe"
        }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME {
                -v "powershell.exe"
                -v "pwsh.exe"
            }
            Include PROCESS_CMD_LINE {
                -v "*\[System.Reflection.Assembly\]::Load*"
                -v "*Assembly]::LoadFrom*"             
                -v "*SpoofFileLoad*"                   
                -v "*TrollAmsiDOTNET*"                 
                -v "*TrollamsiDOTNET*"                 
                -v "*.EntryPoint.Invoke*"              
                -v "*0x4D, 0x5A*"                      
                -v "*MZHeader*"                        
            }
            Include -access "CREATE"
        }
    }
}
```

## Tested Platforms
OS:  Win 10 ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.