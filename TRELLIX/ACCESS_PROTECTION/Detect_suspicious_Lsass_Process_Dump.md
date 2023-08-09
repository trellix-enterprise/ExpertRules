# Detect Suspecious Lsass Process Dump

## Author
Trellix

## Description
This rule trigger indicates Lsass process dump being created by a possibly malicious process.

## Rule Class 
Process

## Rule TCL
```tcl
Rule { 
    Process {
        Include PROCESS_STATE_BITS -name DAC_CONTAIN_PID_BITS { -v 0x1 }    
	}
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "lsass.exe" }
            Include  NT_ACCESS_MASK { -v "!0x10" }
            Include  NT_ACCESS_MASK { -v "!0x80" }
		}
	}
}
```

## Trigger
NA

## Tested Platforms
OS: Windows Server 2019
ENS: 10.7.0 

## Notes
This is a monitoring type of rule and recommended to be enabled at Report only mode. Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives. 