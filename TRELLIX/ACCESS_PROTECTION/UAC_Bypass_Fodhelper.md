# UAC Bypass - Fodhelper

## Author
Trellix

## Description
This rule trigger indicates when user trying to create Registry string values under HKCU path . 

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    
    Target {
        Match VALUE {
            Include OBJECT_NAME {              
            -v "HKCU\\SOFTWARE\\Classes\\ms-settings\\shell\\open\\command\\*"
            	
            }
            Include REGVAL_DATA -type STRING {
               -v "**"
            }
            
            Include -access "CREATE WRITE"
        }
    }
}
```

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 

## Notes
This rule applicable on 10.7.0 version.Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.

