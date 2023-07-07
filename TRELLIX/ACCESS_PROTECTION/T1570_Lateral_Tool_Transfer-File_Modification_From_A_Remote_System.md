# T1570 - Lateral Tool Transfer: File Modification From A Remote System

## Author
Trellix

## Description
This expert rule detects the transfer of tools or files from a remote systems in a compromised environment.

## Rule Class 
Files

## Rule TCL
```tcl
The original rule: 
Rule {
	Process {
		Include OBJECT_NAME {
			-v SYSTEM:REMOTE
		}
	}
	Target {
		Match FILE {
			Include OBJECT_NAME { -v "**.exe" }
			Include OBJECT_NAME { -v "**.dll" }
			Include OBJECT_NAME { -v "**.dat" }
			Include OBJECT_NAME { -v "**.zip" }
			Include OBJECT_NAME { -v "**.7z" }
			Include OBJECT_NAME { -v "**.rar" }
			Include OBJECT_NAME { -v "**.tar" }
			Include OBJECT_NAME { -v "**.tgz" }
			Include -access "CREATE WRITE DELETE EXECUTE"
		}
	}
}

```

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
