# T1490 - Inhibit System Recovery

## Author
Trellix

## Description
This Expert rule detects creation of delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
	Target {
		Match PROCESS {
			Include OBJECT_NAME { -v "vssadmin.exe" }
			Include PROCESS_CMD_LINE { -v "* delete shadows * /all * /quiet *" }
                        Include PROCESS_CMD_LINE { -v "* delete shadows * /all /quiet" }
                        Include PROCESS_CMD_LINE { -v "* delete shadows /all /quiet**" }
                        Include PROCESS_CMD_LINE { -v "* delete shadows * /quiet /all" }
                        Include PROCESS_CMD_LINE { -v "* delete shadows * /quiet * /all *" }
                        Include PROCESS_CMD_LINE { -v "* delete shadows /quiet /all**" }
			Include -access "CREATE"
		}
	}
}
```

## Tested Platforms
Win 11x64 and Win server 2022

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
