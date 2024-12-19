# Abusing Fodhelper functionality to execute code

## Author
Trellix

## Description
This rule blocks the event of reg.exe creating a batch script in registry location to abuse Fodhelper functionality

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
	Process {
                Include OBJECT_NAME { -v "reg.exe" }      
		}
	Target {
		Match VALUE {
                   Include OBJECT_NAME { -v "HKCU\\Software\\Classes\\*\\Shell\\Open\\Command\\*" } 
                   Include REGVAL_DATA -type STRING { -v "**.bat" }
                   	
                   Include -access "CREATE WRITE"
		}
	}
}
```

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
