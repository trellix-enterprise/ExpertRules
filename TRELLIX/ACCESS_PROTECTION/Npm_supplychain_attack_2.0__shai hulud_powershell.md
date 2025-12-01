# Npm aupplychain attack 2.0 shai hulud Powershell.exe


## Author
Trellix

## Description
The rule is to detect the creation of new processes initiated by PowerShell during the execution of the Bun installation script.

## Rule Class 
Process

## Rule TCL
```tcl

Rule {
	Process {
			Include OBJECT_NAME { -v "**" }
	  }
	  Target {
			Match PROCESS {
			       	   Include OBJECT_NAME { -v "powershell.exe" }
				   Include PROCESS_CMD_LINE { -v "**bun.sh/install.ps1**" }
				   Include -access "CREATE"
			}
		}
}

```

## Tested Platforms
OS: Windows 10 20H2 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.
