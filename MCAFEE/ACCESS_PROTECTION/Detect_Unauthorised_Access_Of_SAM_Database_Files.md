# Detect Unauthorised Access Of SAM Database Files

## Author
McAfee

## Description
This expert rule detects suspicious access of SAM database files exploiting the vulnerability CVE-2021-36934, an elevation of privilege vulnerability exists because of overly permissive Access Control Lists (ACLs) on multiple system files, including the Security Accounts Manager (SAM) database. This vulnerability is also tagged as HiveNightmare and SeriousSAM.

## Rule Class 
Files

## Rule TCL
```tcl
The original rule: 
Rule {
	Process {
		Include AggregateMatch -xtype "ex1" {
			Exclude VTP_PRIVILEGES -type BITMASK { -v 0x8 }

		}
		Include AggregateMatch -xtype "ex2" {
			Exclude GROUP_SID { -v "S-1-16-16384" }
			Exclude GROUP_SID { -v "S-1-16-12288" }
		}
		Include AggregateMatch -xtype "ex3" {
			Exclude OBJECT_NAME { -v "vssadmin.exe" }
		}
	}
	Target {
		Match FILE {
			Include OBJECT_NAME { -v "**\\windows\\system32\\config\\SAM" }
			Include OBJECT_NAME { -v "**\\windows\\system32\\config\\SYSTEM" }
			Include OBJECT_NAME { -v "**\\windows\\system32\\config\\SOFTWARE" }
			Include OBJECT_NAME { -v "**\\windows\\system32\\config\\SECURITY" }
			Include -access "READ"
		}
	}
}

```

## Trigger
Tested with the POCs:
https://github.com/FireFart/hivenightmare
https://github.com/WiredPulse/Invoke-HiveNightmare
https://github.com/GossiTheDog/HiveNightmare

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.