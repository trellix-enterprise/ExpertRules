# SignDrop DLL Sideloading

## Author
Trellix

## Description
SignDrop is a local privilege escalation from a standard user to NT AUTHORITY\SYSTEM targeting Microsoft's own CLFS authentication mitigation. This stops the DLL sideloading step used by SignDrop to run attacker code in an elevated process.



## Rule Class 
File

## Rule TCL
```tcl
Rule {
	Process {
		Include DESCRIPTION { -v "Consent UI for administrative applications" }
	}
	Target {
		Match FILE {
			Include OBJECT_NAME { -v "hid.dll" }
			Exclude OBJECT_NAME { -v "**\\Windows\\WinSxS\\**\\hid.dll" }
			Exclude OBJECT_NAME {
				-v "**\\Windows\\System32\\hid.dll"
				if { [iSystem os_arch] == 640 } {
					-v "**\\Windows\\SysWOW64\\hid.dll"
				}
			}
			Include -access "EXECUTE"
		}
	}
}
```

## Tested Platforms
OS: Windows 10 20H1 x86 and Windows 11 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.