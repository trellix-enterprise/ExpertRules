# Rule2.0_250626_Miasma_Credential_Harvesting_Access_Block

## Author
Trellix

## Description
This Rule is designed to block/report node.exe and bun.exe runtimes from reading sensitive developer authentication stores, including AWS credentials, GitHub CLI OAuth tokens, .npmrc tokens, and SSH private keys. The rule blocks the Miasma worm from harvesting developer credentials and access tokens from local user profiles. 

## Rule Class 
File

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "node.exe" }
		Include OBJECT_NAME { -v "bun.exe" }
    }
    Target {
        Match FILE {
            	Include OBJECT_NAME { -v "**\\Users\\*\\.aws\\credentials" }
				Include OBJECT_NAME { -v "**\Users\\*\\AppData\\Roaming\\GitHub CLI\\hosts.yml" }
				Include OBJECT_NAME { -v "**\\Users\\*\\.npmrc" }
				Include OBJECT_NAME { -v "**\\Users\\*\\.ssh\\id_*" }
            	Include -access "READ"
        }
    }
}

```
## Tested Platforms
OS: Windows 10 20H1 x86 and Windows 10 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.