# Detect Execution Of TrueBot - RuntimeBroker abuse.

## Author
Trellix

## Description
This rule detects the behavior of the execution of RuntimeBroker having certificate other than Microsoft.

## Rule Class 
Files

## Rule TCL
```tcl
The original rule: 
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