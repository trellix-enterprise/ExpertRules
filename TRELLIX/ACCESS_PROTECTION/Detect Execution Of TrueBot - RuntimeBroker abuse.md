# Detect Execution Of TrueBot - RuntimeBroker abuse.

## Author
Trellix

## Description
This rule detects execution of unsigned RuntimeBroker process instance.

## Rule Class 
Files

## Rule TCL
```tcl
 
Rule {
	Process {
			Include OBJECT_NAME { -v "**" }             
	}
	Target {
		Match FILE {
	          Include OBJECT_NAME { -v "RuntimeBroker.exe" }
	          Exclude CERT_NAME_CHAINED { -v "*O=Microsoft Corporation*" }

                   Include -access "CREATE EXECUTE"
		}
	}
}
```

## Trigger
NA

## Tested Platforms
OS: Windows 10 19H1 x64 and x86
ENS: 10.7.0 and 10.6.1

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.