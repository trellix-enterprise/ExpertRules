# Link file creation by a script file

## Author
Trellix

## Description
This Expert rule detects creation of link file in start up folder.

## Rule Class 
File

## Rule TCL
```tcl
Rule {
	Process {
				
			Include OBJECT_NAME { -v "wt.exe" }
			Include OBJECT_NAME { -v "cmd.exe" }
			Include OBJECT_NAME { -v "pwsh.exe" }
			Include OBJECT_NAME { -v "powershell.exe" }
	    }
			Target {
				Match FILE {
					Include OBJECT_NAME { -v "**\\Start Menu\\Programs\\Startup\\*.lnk" }
					Include -access "CREATE"
		}
	}
}
```

## Tested Platforms
Win 11x64

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
