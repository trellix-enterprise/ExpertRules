# T1053 - Scheduled Task: create/modify/delete using COM Objects

## Author
McAfee Enterprise

## Description
This expert rule prevents the abuse of  task scheduling functionality to facilitate initial or recurring execution of malicious code.

## Rule Class 
Process

## Rule TCL
```tcl
The original rule: 
Rule {
	Process {
		Include AggregateMatch -xtype "combase_dll" {			
			Include DLL_LOADED -name "combase" { -v 0x1 } 
			}
		Include AggregateMatch -xtype "not_trusted" {
			Include VTP_TRUST false
		}
		Include AggregateMatch -xtype "excluded_proc" {			
			Exclude OBJECT_NAME { -v "**\\GoogleUpdate.exe" }
	  }
   }
	Target {
		Match FILE {
			Include OBJECT_NAME { -v "taskschd.dll" }
		}
	}
}

```

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
