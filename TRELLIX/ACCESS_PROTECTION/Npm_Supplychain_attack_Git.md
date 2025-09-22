# Npm Supplychain attack - Git

## Author
Trellix

## Description
The expert rule detects creating yml files into github directories.

## Rule Class 
File

## Rule TCL
```tcl
Rule {
				Target {
						Match FILE {
							Include OBJECT_NAME { -v "**\\.github\\workflows\\shai-hulud-workflow.yml" }
							Include -access "CREATE WRITE"
						}
				}
			}
```

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
