# EDR Freeze WerFaultSecure.exe

## Author
Trellix

## Description
The expert rule detects werFaultSecure.exe execute commandlines side by side.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
				Process {
						
						Exclude OBJECT_NAME { -v "**\\Windows\\System32\\wermgr.exe" }
						Exclude OBJECT_NAME { -v "**\\WINDOWS\\System32\\svchost.exe" }
						Exclude OBJECT_NAME { -v "**\\Windows\\SysWOW64\\wermgr.exe" }
						Exclude OBJECT_NAME { -v "**\\Windows\\SysWOW64\\svchost.exe" }
						Exclude OBJECT_NAME { -v "**\\\$WINDOWS.~BT\\Sources\\mighost.exe" }
						
				}
				Target {
						Match PROCESS {
							Include DESCRIPTION { -v "Windows Fault Reporting" }
							Include AggregateMatch -xtype "Inc1" {
									Include PROCESS_CMD_LINE { -v "**/encfile**" }
							}
							Include AggregateMatch -xtype "Inc2" {
									Include PROCESS_CMD_LINE { -v "**/cancel**" }
							}
							Include AggregateMatch -xtype "Inc3" {
									Include PROCESS_CMD_LINE { -v "**/type**" }
							}
							Include -access "CREATE"
						}
				}
			}
```

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
