# Rule3.0_250626_Miasma_Python_Updater_Execution_Block

## Author
Trellix

## Description
This Rule is designed to block/report node.exe and bun.exe runtimes from spawning Python processes (python.exe / python3.exe) to execute setup.py scripts. This neutralizes the Miasma worm from launching secondary Python script for memory scraping, credential harvesting, and cross-runtime payload updates.  

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Process {
	    Include OBJECT_NAME { -v "node.exe" }
        Include OBJECT_NAME {  -v "bun.exe"  }    }
    Target {
        Match PROCESS {
            	Include OBJECT_NAME { -v "python.exe" }
		        Include OBJECT_NAME { -v "python3.exe" }
            	Include PROCESS_CMD_LINE { -v "*setup.py*" }
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