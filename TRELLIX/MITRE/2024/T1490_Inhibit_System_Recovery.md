# T1490 - Inhibit System Recovery

## Author
Trellix

## Description
This Expert rule detects attempt to inhibit system recovery using VSSADMIN.

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
