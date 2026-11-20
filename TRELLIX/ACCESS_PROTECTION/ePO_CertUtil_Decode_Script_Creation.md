# ePO CertUtil Decode Script Creation

## Author
Trellix

## Description
This expert rule detects and blocks CertUtil.exe from being launched with the "decode" or "decodehex" option to produce script files (.ps1, .vbs, .js or .bat). Attackers abuse this built-in Windows utility to turn encoded payloads into executable scripts while evading detection.


## Rule Class 
File

## Rule TCL
```tcl
Rule {
        Target {
          	Match PROCESS {
            			Include DESCRIPTION { -v "CertUtil.exe" }
            			Include PROCESS_CMD_LINE { 
						-v "*decode *.ps1*"
                        			-v "*decode *.vbs*"
						-v "*decode *.js*"
						-v "*decode *.bat*"
						-v "*decodehex *.ps1*"
						-v "*decodehex *.vbs*"
						-v "*decodehex *.js*"
						-v "*decodehex *.bat*"

            			}
            			Include -access "CREATE"
          	}
	}
}
```

## Tested Platforms
OS: Windows 10 20H1 x86 and Windows 10 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.