# Rule1.0_140726_Miasma_Persistence_Block

## Author
Trellix

## Description
This Rule is designed to block/report the creation or modification of registry values matching *miasma* under the Windows registry key (HKCU\Software\Microsoft\Windows\CurrentVersion\Run). This prevents the Miasma worm from establishing persistence during its post-exploitation phase on Windows endpoints. 

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    Target {
        Match VALUE {
            	Include OBJECT_NAME { -v "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*miasma*" }		
            	Include -access "CREATE WRITE"
        }
    }
}

```
## Tested Platforms
OS: Windows 10 20H1 x86 and Windows 10 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.