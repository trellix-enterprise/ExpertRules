# T1082 - Discovery: System Information Discovery

## Author
Trellix Enterprise

## Description
This expert rule blocks the attempt to read information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    set os_arch [iSystem os_arch]
    Process {        
        Include OBJECT_NAME { -v "rundll32.exe" }
    }
    Target {
        Match KEY {
            Include OBJECT_NAME {
                -v "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\**"
            }
            if { $os_arch == 640 } {
                Include OBJECT_NAME {
                    -v "HKLM\\Software\\WOW6432node\\Microsoft\\Windows NT\\CurrentVersion\\**"
                }
            }
		Include -access "READ"
        }
    }
}

```

## Trigger
rundll32 javascript:"\..\mshtml,RunHTMLApplication ";var%20WshShell=new%20ActiveXObject('WScript.Shell');var%20value=WshShell.RegRead("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\");

## Tested Platforms
OS: Windows 10 20H2 x64
ENS: 10.7.0

## Notes
This signature could be a performance intenstive one and customers are advised to fine-tune the rule based on the files / registry paths that need protection.
