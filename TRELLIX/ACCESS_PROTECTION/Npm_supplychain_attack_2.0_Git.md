# Npm Supplychain attack 2.0 - Git

## Author
Trellix

## Description
The expert rule detects creating yaml and yml files into github directories.

## Rule Class 
File

## Rule TCL
```tcl
Rule {
	Process {
			Include OBJECT_NAME { -v "**" }
	  }
	  Target {
			Match FILE {
			       Include OBJECT_NAME { -v "**\\.github\\workflows\\discussion.yaml" }
			       Include OBJECT_NAME { -v "**\\.github\\workflows\\formatter_*.yml" }
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