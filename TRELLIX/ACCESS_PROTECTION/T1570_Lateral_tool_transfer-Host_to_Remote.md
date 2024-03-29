# T1570: Lateral tool transfer-Host to Remote

## Author
Trellix

## Description
This expert rule detects the transfer of tools or files from a systems to a file network in a compromised environment.

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
      Process {
         Include OBJECT_NAME {-v "**"}
         Exclude OBJECT_NAME { -v "**\\DLP\\Agent\\FCAGTE.EXE" }
         Exclude OBJECT_NAME { -v "**\\DLP\\Agent\\fcag.exe" }
     }
Target {
 Match FILE {
 Include AggregateMatch -xtype "x1" {
     Include -file_properties "FILE_NETWORK"
 }
 Include AggregateMatch -xtype "x2" {    
	Include OBJECT_NAME { -v "**.exe" }
	Include OBJECT_NAME { -v "**.dll" }
	Include OBJECT_NAME { -v "**.dat" }
	Include OBJECT_NAME { -v "**.zip" }
	Include OBJECT_NAME { -v "**.7z" }
	Include OBJECT_NAME { -v "**.rar" }
	Include OBJECT_NAME { -v "**.tar" }
	Include OBJECT_NAME { -v "**.tgz" }
 }
	Include -access "CREATE WRITE DELETE EXECUTE"
		}
	}
}
```

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
