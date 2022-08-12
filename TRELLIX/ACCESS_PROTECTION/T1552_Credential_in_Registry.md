# T1552-Credential in Registry

## Author
McAfee Enterprise

## Description
This expert rule monitors access to the registry keys that hold the credentials for Putty sessions.

## Rule Class 
Registry

## Rule TCL
```tcl

Rule {
set os_arch [iSystem os_arch]
      Process {        
        Include PROCESS_STATE_BITS -name DAC_CONTAIN_PID_BITS { -v 0x1 }        
    }
    Target {
          Match KEY {
			Include OBJECT_NAME {              
				-v "HKLM\\Software\\SimonTatham\\Putty64\\Sessions\\**" 
				-v "HKCU\\Software\\SimonTatham\\Putty64\\Sessions\\**"	
				-v "HKLM\\Software\\SimonTatham\\Putty\\Sessions\\**" 	
				-v "HKCU\\Software\\SimonTatham\\Putty\\Sessions\\**" 
			}			
			if { $os_arch == 640 } {			
				Include OBJECT_NAME {	
					-v "HKLM\\Software\\WOW6432node\\SimonTatham\\Putty\\Sessions\\**"
					-v "HKCU\\Software\\WOW6432node\\SimonTatham\\Putty\\Sessions\\**"
				}
			}
			Include -access "READ"            
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
This rule is for monitoring/telemetry and is performance intensive. Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.
