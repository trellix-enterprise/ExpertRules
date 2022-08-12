# Detect Deletion Of Shadow Copies Using WMIC.EXE

## Author
McAfee

## Description
This rule detects access or deletion of volume shadow copies using Wmic.exe process. This behavior is observed with a few ransomware actors.

## Rule Class 
Processes

## Rule TCL
```tcl
The original rule: 

Rule {
	Target {
		Match PROCESS {
			Include OBJECT_NAME { -v "wmic.exe" }
			Include PROCESS_CMD_LINE { -v "* shadowcopy delete *" }
			Include PROCESS_CMD_LINE { -v "* shadowcopy delete" }
			Include PROCESS_CMD_LINE { -v "* shadowcopy /nointeractive *" }
			Include PROCESS_CMD_LINE { -v "* shadowcopy /nointeractive" }
			Include -access "CREATE"
		}
	}
}
```

## Trigger
NA

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.