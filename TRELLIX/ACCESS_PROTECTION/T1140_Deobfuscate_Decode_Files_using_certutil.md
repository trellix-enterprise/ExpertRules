# T1140 - Certutil.exe - Deobfuscate/Decode Files or Information

## Author
Trellix

## Description
This rule blocks the attempt to decode the remote access tool portable executable file that has been hidden inside certificate using certutil.exe utility.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
		Target { 
			Match PROCESS { 
                Include OBJECT_NAME { -v "certutil.exe" }
				Include PROCESS_CMD_LINE { -v "* -decode *" }
				Include PROCESS_CMD_LINE { -v "* -decode" }
				Include PROCESS_CMD_LINE { -v "* -urlcache *" }
				Include PROCESS_CMD_LINE { -v "* -urlcache" }

                Include -access "CREATE EXECUTE"
							
			}
			  
		}

}
```

## Tested Platforms
OS: Windows 10 20H2 x64, Windows Server 2019, Windows 11
ENS: 10.7.0, 10.6.0

## Notes
certutil is a command-line utility that can be used to obtain certificate authority information and configure Certificate Services.
