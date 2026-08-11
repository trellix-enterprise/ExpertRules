# Rule2.0_140726_Miasma_Payload_Artifact_Creation_Block

## Author
Trellix

## Description
This Rule designed to block/report node.exe from dropping the payload sync.js into the %LOCALAPPDATA%\NodeJS directory and creating .miasma lock directory.

## Rule Class 
File

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "node.exe" }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\Users\\*\\AppData\\Local\\NodeJS\\sync.js" }
            Include OBJECT_NAME { -v "**\\Users\\*\\.config\\.miasma*" }
            Include -access "CREATE"
        }
    }
}

```
## Tested Platforms
OS: Windows 10 20H1 x86 and Windows 10 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.