# AppInstaller Abuse to execute suspicious payload

## Author
Trellix

## Description
This rule detects AppInstaller Abuse to execute / load winhttp.dll module

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
		Process {
				Include OBJECT_NAME { -v "AppInstaller.exe" }
				Include PROCESS_CMD_LINE { -v "**\-ServerName:App.*.mca**" }
			}
		Target {
			Match SECTION {
				Include OBJECT_NAME { -v "winhttp.dll" }
		    }
        }
 }
```

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives. 

