# Npm Supplychain attack - Credentials

## Author
Trellix

## Description
The expert rule detects when trufflehog.exe executing filesystem commandlines.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
				Target {
						Match PROCESS {
							Include OBJECT_NAME { -v "trufflehog.exe" }
							Include PROCESS_CMD_LINE { -v "**filesystem * --json**" }
							Include -access "CREATE"
						}
				}
			}
```

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
