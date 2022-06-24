# RedCanary - GootKit - Attempt to access script files using scripting engine

## Author
McAfee Enterprise

## Description
This rule detects the behavior abuse of WSCRIPT.EXE & CSCRIPT.EXE while executing specific script files like .js, .jse, vbs and .vbe.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
		Process { 
		        Include OBJECT_NAME { -v "cscript.exe" }
			Include OBJECT_NAME { -v "wscript.exe" }
		}
		Target { 
			Match FILE { 
				Include OBJECT_NAME { -v "**Users\\*\\AppData\\*.js" }
				Include OBJECT_NAME { -v "**Users\\*\\AppData\\*.jse" }
				Include OBJECT_NAME { -v "**Users\\*\\AppData\\*.vbs" }
				Include OBJECT_NAME { -v "**Users\\*\\AppData\\*.vbe" }
				Include -access "CREATE READ WRITE EXECUTE"
			}

		}

 }
```

## Trigger

## Tested Platforms
OS: Windows 10 21H1 x64 and x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.