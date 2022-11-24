# CrackMapExec - Post-Exploitation tool

## Author
Trellix Enterprise

## Description
This rule blocks the abuse of built-in features/protocols like SMB to achieve its functionality. CrackMapExec (a.k.a CME) is a post-exploitation tool follows the concept of "Living off the Land" and abuses in-built features to evade most endpoint protection/IDS/IPS solutions

## Rule Class 
Process

## Rule TCL
```tcl
Rule { 
           Process {
		           Include OBJECT_NAME { -v "services.exe" } 
				   Include OBJECT_NAME { -v "wmiprvse.exe" }
				   Include OBJECT_NAME { -v "mmc.exe" }
		   }
           Target {
                  Match PROCESS {
					Include OBJECT_NAME { -v "cmd.exe" }
					Include PROCESS_CMD_LINE { -v "*\\127.0.0.1\*$\*" }
					Include -access "CREATE"      
           }
       }
}
```

## Tested Platforms
OS: Windows 10 19H1 x64, Windows Server 2019, Windows 11
ENS: 10.7.0, 10.6.1

## Notes
NA
