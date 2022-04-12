# Detect 7zip anomalous usage

## Author
McAfee

## Description
This rule trigger indicates potential abuse of IMFEO Registry by potentially malicious applications. This is a monitoring type of rule and recommended be enabled at Report only mode.

## Rule Class 
Registry

## Rule TCL
```tcl
The original rule: 
Rule {
	Process {
		Exclude VTP_PRIVILEGES -type BITMASK { -v 0x8 }
	}
	Target {
		Match VALUE {
			Include OBJECT_NAME { -v "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\**" }
			Include OBJECT_NAME { -v "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\**" }
			Include -access "CREATE RENAME REPLACE_KEY RESTORE_KEY" 
		}
		Match VALUE {
			Include TARGET_OBJECT_NAME { -v "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\**" }
			Include TARGET_OBJECT_NAME { -v "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\**" }
			Include -access "RENAME" 
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
This is a monitoring type of rule and recommended to be enabled at Report only mode. Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives. 