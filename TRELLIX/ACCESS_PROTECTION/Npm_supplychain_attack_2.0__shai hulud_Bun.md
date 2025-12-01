# Npm aupplychain attack 2.0 shai hulud Bun.exe


## Author
Trellix

## Description
This expert rule detects where bun.exe that attempt to create new processes using the command line containing bun_environment.js.

## Rule Class 
Process

## Rule TCL
```tcl

Rule {
	Process {
			Include OBJECT_NAME { -v "**" }
	  }
	  Target {
			Match PROCESS {
			       Include OBJECT_NAME { -v "bun.exe" }
				   Include PROCESS_CMD_LINE { -v "**bun_environment.js**"}
				   Include -access "CREATE"
			}
		}
}

```

## Tested Platforms
OS: Windows 10 20H2 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.
