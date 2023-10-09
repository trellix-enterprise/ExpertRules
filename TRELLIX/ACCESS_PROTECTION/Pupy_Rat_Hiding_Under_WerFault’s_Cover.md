# Pupy Rat Hiding Under WerFault’s Cover

## Author
Trellix

## Description
The expert rule detectes a dll sideloading scenario for werfault binary.

## Rule Class 
FILE

## Rule TCL
```tcl
Rule {
	Process {
		
			Include OBJECT_NAME { -v "werfault.exe" }
		
	}
	Target {
		Match FILE {
			Include OBJECT_NAME { -v "faultrep.dll" }
                        Exclude OBJECT_NAME { -v "**\\windows\\system32\\faultrep.dll" }
                        Include -access "CREATE READ"

		}
	}
}
```


## Notes

