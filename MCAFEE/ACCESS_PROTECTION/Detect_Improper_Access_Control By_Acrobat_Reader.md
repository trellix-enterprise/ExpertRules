# Detect Improper Access Control By Acrobat Reader (CVE-2021-21045)

## Author
McAfee

## Description
This rule trigger indicates an attempt to exploit an access control vulnerability that exists in some Adobe Acrobat Reader DC versions where an unauthenticated attacker could elevate privileges in the context of the current user.

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
	Process {
		Include OBJECT_NAME { -v "**\\RdrServicesUpdater2.exe"  
			-v "**\\RdrServicesUpdater.exe"}
	}
	Target {
		Match FILE {
			Include OBJECT_NAME {  -v "C:\\ProgramData\\Adobe\\**\\*.dll" }
			Exclude CERT_NAME { -v "*Adobe Inc*" 
					-v "*Microsoft Corporation*" }
		}
	}
}


```

## Trigger
NA

## Tested Platforms
OS: Windows 10 20H1 x86
ENS: 10.7.0 November'20 update
OS: Windows 10 19H1 x64
ENS: 10.6.1

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.