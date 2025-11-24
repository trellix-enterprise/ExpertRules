# Interlock Remote Access Trojon

## Author
Trellix

## Description
The expert rule detect and blocks the execution of the Interlock RAT using command line. The command reflects PowerShell spawning PHP with suspicious arguments, particularly the loading of the config file from a non-standard location.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {				
				Target {
					Match PROCESS { 
						Include OBJECT_NAME { -v "php.exe" }
						Include PROCESS_CMD_LINE { -v "*-d extension=zip -d extension_dir=ext *" }	
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