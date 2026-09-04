#Suspicious Driver Service Registration — msidiskserver

## Author
Trellix

## Description
This expert rule detects the creation of a Windows service registry key named msidiskserver, a service name not associated with any known Microsoft or third-party vendor product. This identifier has been observed as the service used by a FishMonger/SprySOCKS driver-loading component to register and load a kernel-mode driver that conceals files and network activity from the operating system.


## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "**" }
    }
    Target {
        Match KEY {
            Include OBJECT_NAME { -v "HKLM\\SYSTEM\\CurrentControlSet\\Services\\msidiskserver" }
			Include -access "CREATE WRITE"
        }
    }
}
```

## Tested Platforms
OS: Windows 10 20H1 x86, Windows 10 x64 and Win server 2022
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.