# T1222.001 - Windows File and Directory Permissions Modification 

## Author
Trellix

## Description
This rule blocks the attempt to drop files with a hardcoded folder name for achieving higher level of permissions for Windows File and Directory.

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
	Process {
		Include AggregateMatch -xtype "ex1" {
			Exclude VTP_PRIVILEGES -type BITMASK { -v 0x8 }

		}				
	}
	Target {
		Match FILE {
			Include OBJECT_NAME { -v "%systemdrive%\\Users\\*\\appdata\\local\\temp\\**\\splwow64.exe" }	
			Include OBJECT_NAME { -v "%systemdrive%\\Users\\*\\appdata\\local\\temp\\**\\**.png" }	
			Include OBJECT_NAME { -v "%systemdrive%\\Users\\*\\appdata\\local\\temp\\**\\microsoft plz\\**.exe" }
			Include OBJECT_NAME { -v "**\\Microsoft\\Edge\\Application\\**\\**.exe" }			
			Include -access "CREATE WRITE RENAME EXECUTE"
		}
	}
}
```

## Tested Platforms
OS: Windows 10 20H2 x64
ENS: 10.7.0

## Notes
NA
