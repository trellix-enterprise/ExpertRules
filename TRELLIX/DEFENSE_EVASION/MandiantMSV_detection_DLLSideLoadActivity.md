# MandiantMSV detection DLLSideLoadActivity

## Author
Trellix

## Description
This rule detects the activity of DLL side load of fxsst.dll by explorer process.

## Rule Class 
File

## Rule TCL
```tcl
Rule {
	Process {
		Include OBJECT_NAME { -v "explorer.exe" }
	}
	Target {
		Match FILE {
			Include OBJECT_NAME { -v "fxsst.dll" }
			Exclude OBJECT_NAME { -v "**\\Windows\\System32\\fxsst.dll" }
			Include -access "EXECUTE"
		}
	}
}
```

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.