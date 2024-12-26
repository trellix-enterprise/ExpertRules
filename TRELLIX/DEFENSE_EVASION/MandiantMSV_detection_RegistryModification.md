# Mandiant MSV detection - Registry Modification

## Author
Trellix

## Description
This rule detects the activity of Registry Modification by Mandiant MSV

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
	
	Target {
		Match KEY {
			Include OBJECT_NAME {
				-v "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Rortal"
			}
			Include OBJECT_NAME {
				-v "HKLM\\SYSTEM\\CurrentControlSet\\Services\\wind0ws"
			}
			Include OBJECT_NAME {
				-v "HKLM\\SYSTEM\\CurrentControlSet\\Services\\6to4"
			}
			Include -access "CREATE WRITE"
		}
	}
}
```

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.