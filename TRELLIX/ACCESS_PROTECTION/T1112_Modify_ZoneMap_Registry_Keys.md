# T1112 Modify Registry Keys

## Author
Trellix

## Description
This Expert rule detects creation or modification of ZoneMap registry keys.

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    
    Target {
        Match VALUE {
            Include OBJECT_NAME {              
            -v "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\ProxyByPass"
            -v "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\IntranetName"
            -v "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\UNCAsIntranet"
            -v "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\ProxyByPass"
            -v "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\IntranetName"
            -v "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\UNCAsIntranet"		
            }
            
            Include -access "CREATE WRITE"
        }
    }
}
```

## Tested Platforms
NA 

## Notes
NA
