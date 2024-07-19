# Detect execution of Trellix processes from unauthorized users

## Author
Trellix

## Description
This Expert rule detects execution of Trellix Processes and unsigned processes from unauthorized users.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
	Process {
	Include OBJECT_NAME { -v "**" }
		Exclude AggregateMatch {
		Include OBJECT_NAME { -v "%windir%\\EXPLORER.EXE" }
		Include OBJECT_NAME { -v "%windir%\\SYSWOW64\\EXPLORER.EXE" }
		Include OBJECT_NAME { -v "%windir%\\SYSWOW64\\RUNONCE.EXE" }
		Include OBJECT_NAME { -v "%windir%\\SYSTEM32\\RUNONCE.EXE" }
		Include OBJECT_NAME { -v "%windir%\\SYSTEM32\\CMD.EXE" }
		Include OBJECT_NAME { -v "%windir%\\SYSWOW64\\CMD.EXE" }
		}
	Exclude AggregateMatch {
		Include GROUP_SID { -v "S-1-16-12288" }
		Include GROUP_SID { -v "S-1-16-16384" }
        }
	Exclude AggregateMatch {
		Include VTP_PRIVILEGES { 8 }
		Include VTP_PRIVILEGES { 0x10000000 }
		}
	}
	Target {
		Match PROCESS {
		Include VTP_PRIVILEGES -type BITMASK { -v 0x8 }
		Exclude VTP_PRIVILEGES { 0x10000000 }
		Include -access "CREATE"
		}
	}
}

```
## Tested Platforms
OS: Windows 10 20H1 x86, Windows 10 20H2 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.