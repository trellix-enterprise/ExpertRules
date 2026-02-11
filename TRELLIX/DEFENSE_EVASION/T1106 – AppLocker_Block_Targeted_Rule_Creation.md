# MPT-21011: Malicious use of AppLocker (block creation of targeted AppLocker rules)

## Author
Trellix

## Description
AppLocker is a Microsoft whitelisting / blocklisting technology that can be used maliciously 
by attackers with administrative rights to deny execution of legitimate processes. This rule
blocks creation of AppLocker rules that target an EXE by name. It's important to note that
there are gaps in this defense. AppLocker rules can match by hash, publisher, and wild carded 
name. This rule only mitigates by literal name.

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

                   Include REGVAL_DATA -type STRING { -v "**MyTestApp.exe**" }
                   	
                   Include -access "CREATE WRITE"
		}
	}
}
```

## Trigger
Creation of an AppLocker EXE rule that denies execution of "MyTestApp.exe"

## Tested Platforms
OS: Windows 11 25H2 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives. If AppLocker is not in use, a better mitigation may be to block the creation of any AppLocker rule, or disable it entirely.
