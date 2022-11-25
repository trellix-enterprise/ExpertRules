# PrintSpooler - Malicious DLL loaded into Fxssvc process

## Author
Trellix Enterprise

## Description
This rule blocks the attempt to load malicious DLL into Fxssvc and spoolsv process memory. 

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
	Process {
		Include OBJECT_NAME { -v "spoolsv.exe" }
		Include OBJECT_NAME { -v "Fxssvc.exe"}
        }
	Target {
		Match FILE {
			Include OBJECT_NAME { -v "%systemroot%\\System32\\ualapi.dll" }			
			Include -access "READ EXECUTE"
        }
    }
}
```

## Tested Platforms
OS: Windows 10 20H2 x64
ENS: 10.7.0

## Notes
NA
