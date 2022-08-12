# Detect Improper Limitation Of A Pathname To A Restricted Directory By Acrobat Reader (CVE-2021-21037)

## Author
McAfee

## Description
This rule trigger indicates an attempt to exploit a path traversal vulnerability that exists in Adobe Acrobat Reader where the victim opens a malicious file

## Rule Class 
Files

## Rule TCL
```tcl
The original rule: 
Rule {
	Process {
		Include OBJECT_NAME { -v "**\\AcroRd32.exe"  }
	}
	Target {
		Match FILE {
			Include OBJECT_NAME {  -v "C:\\Users\\*\\AppData\\Local\\A9R*\\**" }
			Exclude CERT_NAME { -v "*Adobe Inc*" 
					-v "*Microsoft Corporation*" }
			Include -access "EXECUTE"
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
Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-21037