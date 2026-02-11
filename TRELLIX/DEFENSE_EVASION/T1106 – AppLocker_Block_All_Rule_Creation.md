# MPT-21011: Malicious use of AppLocker (block creation of all AppLocker EXE and DLL rules)

## Author
Trellix

## Description
AppLocker is a Microsoft whitelisting / blocklisting technology that can be used maliciously 
by attackers with administrative rights to deny execution of legitimate processes. This rule
blocks creation of all AppLocker rules that target EXEs or DLLs.

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
	Process {
                Include OBJECT_NAME { -v "**" }      
		}
	Target {
		Match VALUE {
                   Include OBJECT_NAME { -v "HKLMS\\Policies\\Microsoft\\Windows\\SrpV2\\Exe\\**" } 
                   Include OBJECT_NAME { -v "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy Objects\\**\\SrpV2\\Exe\\**" } 

                   Include OBJECT_NAME { -v "HKLMS\\Policies\\Microsoft\\Windows\\SrpV2\\Dll\\**" } 
                   Include OBJECT_NAME { -v "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy Objects\\**\\SrpV2\\Dll\\**" } 
                   	
                   Include -access "CREATE WRITE"
		}
	}
}
```

## Trigger
Creation of an EXE or DLL AppLocker rule

## Tested Platforms
OS: Windows 11 25H2 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.
