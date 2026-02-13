# Bindlink EDR Redirect

## Author
Trellix

## Description
The expert rule detects and blocks the unauthorized redirection of Endpoint Detection and Response (EDR) 's working folder to a folder of the attacker's choice utilizing bindlink functionality

## Rule Class 
File

## Rule TCL
```tcl
Rule {
		Process {
					Exclude VTP_TRUST true
		}
		Target {
				Match FILE {
						Include OBJECT_NAME { -v "bindflt.dll" }
						Include OBJECT_NAME { -v "bindlink.dll" }
						Include OBJECT_NAME { -v "bindfltapi.dll" }
						Include -access "EXECUTE"
				}
		}
}
```

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.