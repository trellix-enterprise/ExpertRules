# Detect Suspicious Usage of BCDEDIT.EXE

## Author
McAfee

## Description
This rule detects suspicious usage of bcdedit.exe to disable recovery or to set specific boot status policies. This behavior is observed with a few ransomware actors.

## Rule Class 
Processes

## Rule TCL
```tcl
The original rule: 

Rule {
	Target {
		Match PROCESS {
			Include OBJECT_NAME { -v "bcdedit.exe" }
			Include PROCESS_CMD_LINE { -v "* recoveryenabled no *" }
			Include PROCESS_CMD_LINE { -v "* recoveryenabled no" }
			Include PROCESS_CMD_LINE { -v "* bootstatuspolicy ignoreallfailures *" }
			Include PROCESS_CMD_LINE { -v "* bootstatuspolicy ignoreallfailures" }
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