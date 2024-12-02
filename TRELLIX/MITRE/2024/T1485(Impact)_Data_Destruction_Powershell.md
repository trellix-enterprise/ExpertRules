# T1485(Impact)Data Destruction - Powershell 

## Author
Trellix

## Description
This Expert rule detects PowerShell creating or writing files into Recycle.Bin folder or its sub-folders.

## Rule Class 
Process

## Rule TCL
```tcl
	Rule {

		Process {
				Include OBJECT_NAME { -v "powershell.exe" }
		}
		
		Target {
			Match FILE {
				Include OBJECT_NAME { -v "**\\\$Recycle.Bin\\**" }
				Include -access "CREATE WRITE"
			}
		}
	}
```

## Tested Platforms
NA

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.