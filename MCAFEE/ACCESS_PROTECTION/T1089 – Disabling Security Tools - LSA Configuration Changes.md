# T1089 – Disabling Security Tools - LSA Configuration Changes

## Author
McAfee

## Description
This rule trigger indicates an attempt to modify the Link State Advertisement (LSA) configuration, which is a pre-cursor to credential dumping. 

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    Process {
        Exclude VTP_PRIVILEGES -type BITMASK { -v 0x8 }         
    }
    Target {
        Match KEY  {
            Include OBJECT_NAME  {  -v "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Notification Packages"  }
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
This rule is for monitoring/telemetry. Customers are advised to fine-tune the rule to the authentication applications used in their environment or disable the signature if there are too many false positives. 