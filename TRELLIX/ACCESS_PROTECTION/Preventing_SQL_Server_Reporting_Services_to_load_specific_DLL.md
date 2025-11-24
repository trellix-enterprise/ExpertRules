# Detects injection of ATPAmsiGuard.dll 

## Author
Trellix

## Description
This rule blocks when a process ReportingServicesService.exe attempts to load ATPAMSIGuard.dll file.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Process {
            Include OBJECT_NAME { -v "**\ReportingServicesService.exe" }
    }
    Target {
        Match FILE {
            Include -access "CREATE EXECUTE"
            Include OBJECT_NAME { -v "**\ATPAMSIGuard.dll" }
        }
    }
}
```

## Tested Platforms
OS: Windows 11 x64 
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives. 
