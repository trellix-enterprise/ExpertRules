# Detect Deletion Of Backup Catalog Using WBADMIN.EXE

## Author
McAfee

## Description
This rule detects deletion of backup catalog that is stored on the local computer by wbadmin.exe process. This behavior is observed with a few ransomware actors.

## Rule Class 
Processes

## Rule TCL
```tcl
The original rule: 

Rule {
	Target {
		Match PROCESS {
			Include OBJECT_NAME { -v "wbadmin.exe" }
			Include PROCESS_CMD_LINE { -v "* delete catalog *" }
			Include PROCESS_CMD_LINE { -v "* delete catalog" }
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