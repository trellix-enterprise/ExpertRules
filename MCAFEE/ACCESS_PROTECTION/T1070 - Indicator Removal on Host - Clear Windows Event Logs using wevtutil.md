# T1070 - Indicator Removal on Host: Clear Windows Event Logs using wevtutil

## Author
McAfee Enterprise

## Description
This expert rule detects suspicious attempt to clear Windows event logs through wevtutil

## Rule Class 
Process

## Rule TCL:
```tcl
Rule {	
Process {
	Include AggregateMatch -xtype "ex1" {
			Exclude VTP_PRIVILEGES -type BITMASK { -v 0x8 }

		}
	Include AggregateMatch -xtype "ex2" {
			Exclude GROUP_SID { -v "S-1-16-16384" }			
		}
		Include AggregateMatch -xtype "ex3" {
			Exclude OBJECT_NAME { -v "**\\conhost.exe" }
			Exclude OBJECT_NAME { -v "**\\csrss.exe" }
			Exclude OBJECT_NAME { -v "**\\integrator.exe" }
	}
	}
	Target {
        Match PROCESS {		
		Include OBJECT_NAME {
			-v wevtutil.exe			
		}	
		Include DESCRIPTION {-v "Eventing Command Line Utility"}				
        Include PROCESS_CMD_LINE {-v "**cl**"}
		Include PROCESS_CMD_LINE {-v "**cl Application**"}
		Include PROCESS_CMD_LINE {-v "**cl System**"}
		Include PROCESS_CMD_LINE {-v "**cl Security**"}            
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