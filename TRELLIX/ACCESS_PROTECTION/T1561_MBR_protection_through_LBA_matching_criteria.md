# T1561 - MBR protection through LBA matching criteria

## Author
Trellix Enterprise

## Description
This expert rule detects suspicious write access of MBR partition through LBA mactching criteria. 

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
           Include OBJECT_NAME { -v "**" }
           Include LBA { -v 0 -v 512 }           
           Include -access "WRITE"
        }
    }
}

```

## Trigger
Tested with the POCs:
http://www.chrysocome.net/downloads/dd-0.5.zip

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
