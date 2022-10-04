# T1561 - MBR protection through DISK_REGION matching criteria

## Author
McAfee Enterprise

## Description
This expert rule detects suspicious write access of MBR partition through DISK_REGION matching criteria

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Process {
           Include OBJECT_NAME { -v "**" }
    }
    Target {
        Match DISK {
           # Match write ops on mbr vbr and un-partitioned regions
           Include OBJECT_NAME { -v "**" }
           Include DISK_REGION { -v 0xB }            
           Include ACCESS_MASK { -v 0x2 }                        
        }
    }
}

```

## Tested Platforms
OS: Windows 10 20H1 x64, Windows Server 2019
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
