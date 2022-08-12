# T1060 - Startup Folder - Files in startup folders

## Author
McAfee

## Description
This rule trigger indicates an attempt to create files in the startup folder.  

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
    Process {
        Exclude VTP_PRIVILEGES -type BITMASK { -v 0x8 }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "%systemdrive%\\Users\\*\\appdata\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\**.exe" }
            Include OBJECT_NAME { -v "%systemdrive%\\Users\\*\\Start Menu\\Programs\\Startup\\**.exe" }
            Include -access "CREATE"
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