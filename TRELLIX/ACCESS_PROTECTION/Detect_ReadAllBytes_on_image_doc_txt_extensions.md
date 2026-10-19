# Detect ReadAllBytes on image doc txt extensions

## Author
Trellix

## Description
This rule detects steganography / polyglot file attacks where malicious .NET assemblies are hidden inside seemingly innocent files and loaded via PowerShell.

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
                -v "*ReadAllBytes*.png*Assembly*"   
                -v "*ReadAllBytes*.jpg*Assembly*"
                -v "*ReadAllBytes*.txt*Assembly*"   
                -v "*ReadAllBytes*.pdf*Assembly*"
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