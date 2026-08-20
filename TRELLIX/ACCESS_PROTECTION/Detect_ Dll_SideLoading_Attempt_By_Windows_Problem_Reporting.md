# Dll SideLoading Attempt By Windows Problem Reporting

## Author
Trellix

## Description
This rule detects DLL Hijacking via Windows Problem Reporting — specifically targeting a known technique where attackers abuse WerFault.exe / wermgr.exe to load a malicious phoneinfo.dll.

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
				Process {
					Include DESCRIPTION { -v "Windows Problem Reporting" }
				}
				Target {
					Match FILE {
						Include OBJECT_NAME { -v "phoneinfo.dll" }
						Exclude VTP_PRIVILEGES -type BITMASK { -v 0x1 }
						Include -access	 "EXECUTE"
					}		
				}
		}
```

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.