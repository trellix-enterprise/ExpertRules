# Coverage  for InterlockRAT

## Author
Trellix

## Description
The expert rule detects when PowerShell spawning PHP with suspicious arguments in the commandline.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {				
				Target {
					Match PROCESS { 
						Include OBJECT_NAME { -v "php.exe" }
						Include PROCESS_CMD_LINE {
                                                        -v "* -d extension=zip *"
							-v "* -d extension_dir=ext *"
							-v "* *.cfg *"
							
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
