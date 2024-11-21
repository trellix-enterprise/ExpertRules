# T1082(Discovery) - System Information Discovery - vssadmin

## Author
Trellix

## Description
This Expert rule detects PowerShell launching vssadmin process for System Information Discovery.

## Rule Class 
Process

## Rule TCL
```tcl
	Rule {
		Process {
			Include OBJECT_NAME {
					-v "powershell.exe"
				}
			}
	Target {
		Match PROCESS {
			Include OBJECT_NAME { -v "vssadmin.exe" }
			Include -access "CREATE"
			}
		}
	}
```

## Tested Platforms
NA

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.

