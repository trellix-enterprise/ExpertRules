# T1055 - Process Injection: Suspicious Process Allocated Virtual Memory

## Author
McAfee Enterprise

## Description
This expert rule monitors virtual memory allocation by a DAC contained process.

## Rule Class 
Process

## Rule TCL
```tcl

Rule {
	Process {
		Include AggregateMatch -xtype "in2" {
			Include PROCESS_STATE_BITS -name DAC_CONTAIN_PID_BITS { -v 0x1 }
		}
	}
	Target {
		Match PROCESS {
			Include OBJECT_NAME {
				-v **
			}
			Include -nt_access "!0x20"
		}
	}
}

```

## Trigger
NA

## Tested Platforms
OS: Windows 10 20H2 x64
ENS: 10.7.0

## Notes
This rule is for monitoring/telemetry. Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.
