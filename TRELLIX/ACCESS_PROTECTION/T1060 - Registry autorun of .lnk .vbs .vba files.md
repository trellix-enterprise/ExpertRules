# T1060 - Registry autorun of .lnk/.vbs/.vba files

## Author
McAfee

## Description
This rule trigger indicates an attempt to execute programs at user logon. 

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    Target {
        Match VALUE {
            Include OBJECT_NAME {              
                -v "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\**"
                -v "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\**"
                -v "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\**"
                -v "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\**"
                -v "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\**"
                -v "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\**"    
                -v "HKLM\\SOFTWARE\\WOW6432node\\Microsoft\\Windows\\CurrentVersion\\Run\\**"
                -v "HKLM\\Software\\WOW6432node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\**"
                -v "HKLM\\Software\\WOW6432node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\**"
                -v "HKCU\\SOFTWARE\\WOW6432node\\Microsoft\\Windows\\CurrentVersion\\Run\\**"
                -v "HKCU\\Software\\WOW6432node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\**"
                -v "HKCU\\Software\\WOW6432node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\**"
            }
            Include REGVAL_DATA -type STRING {
                -v "**.lnk"
                -v "**.vba"
                -v "**.vbs"
            }
            Include REGVAL_DATA -type EXPANDABLE_STRING {
                -v "**.lnk"
                -v "**.vba"
                -v "**.vbs"
            }
            Include REGVAL_DATA -type MULTI_STRING {
                -v "**.lnk"
                -v "**.vba"
                -v "**.vbs"
            }
            Include -access "CREATE WRITE"
        }
    }
}
```

## Trigger
TBC.

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
This rule is for monitoring/telemetry. Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.
