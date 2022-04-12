# Detect Execution Of RCLONE.EXE Using Config

## Author
McAfee

## Description
This rule detects the behavior abuse of RCLONE.EXE where RCLONE.EXE is executed by calling the config file. This behavior is observed with a few ransomware actors.

## Rule Class 
Files

## Rule TCL
```tcl
The original rule: 
Rule {
	Target {
		Match FILE {
			Include OBJECT_NAME { -v "C:\\Users\\**\\.config\\rclone*" }
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