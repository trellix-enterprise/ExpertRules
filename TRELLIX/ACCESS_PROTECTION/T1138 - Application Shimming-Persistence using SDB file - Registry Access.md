# T1138 - Application Shimming-Persistence using SDB file - Registry Access

## Author
McAfee

## Description
This rule trigger indicates an attempt to abuse application shimming through registry access. 

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {  -v "sdbinst.exe"  }
    }
    Target {
        Match KEY {
            Include OBJECT_NAME {              
                -v "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom"
            }
            Include OBJECT_NAME {    
                -v "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB"
            }
            Include -access "WRITE CREATE"
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