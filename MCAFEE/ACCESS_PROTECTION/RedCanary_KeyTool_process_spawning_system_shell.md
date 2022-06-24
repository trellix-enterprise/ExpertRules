# RedCanary - ZOHO - KeyTool.exe process spawning system shell or PowerShell

## Author
McAfee Enterprise

## Description
This rule detects the behavior where Java utility KeyTool.exe process spawns system shell like cmd.exe, powershell.exe, pwsh.exe, WT.exe etc. This rule is created for vulnerability in ADSelfService Plus (CVE-2021-40539).

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    
	Process {
		Include OBJECT_NAME { -v "keytool.exe" } 
	}
	Target {
		Match PROCESS {
            Include OBJECT_NAME { -v "wt.exe" } 
		    Include OBJECT_NAME { -v "cmd.exe" } 
			Include OBJECT_NAME { -v "conhost.exe" } 
		    Include OBJECT_NAME { -v "pwsh.exe" }
		    Include OBJECT_NAME { -v "powershell.exe" }
		    Include -access "CREATE"
		}
	}
}
```

## Trigger

## Tested Platforms
OS: Windows 10 21H1 x64 and x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.