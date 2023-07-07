# T1070 - Indicator Removal on Host: Clear Windows Event Logs using powershell

## Author
Trellix

## Description
This expert rule detects suspicious attempt to clear Windows event logs through powershell

## Rule Class 
Process


## Rule TCL:
```tcl
Rule {
	Process {
			Include OBJECT_NAME {
				-v cmd.exe
				-v "**powershell**"
			}					
		}      
	Target {
			  Match PROCESS {            
					Include PROCESS_CMD_LINE { -v "**Clear-EventLog**" }
				}
		}
	}
```

## Trigger
NA

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.