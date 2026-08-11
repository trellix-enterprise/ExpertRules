# Rule1.0_250626_Miasma_VSCode_AI_Hook_Execution_Block

## Author
Trellix

## Description
This Rule is designed to blocks/report Visual Studio Code (code.exe) from spawning node.exe to execute setup.mjs housed within .claude or .vscode configuration directories. This prevents the Miasma worm from leveraging auto-run hooks.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "code.exe" }
    }
    Target {
        Match PROCESS {
            	Include OBJECT_NAME { -v "node.exe" }
            	Include PROCESS_CMD_LINE { -v "**\\.claude\\setup.mjs*" }
		Include PROCESS_CMD_LINE { -v "**\\.vscode\\setup.mjs*" }
            	Include -access "CREATE"
        }
    }
}

```
## Tested Platforms
OS: Windows 10 20H1 x86 and Windows 10 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.