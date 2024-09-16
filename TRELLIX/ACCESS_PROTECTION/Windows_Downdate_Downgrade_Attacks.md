# Detect Windows Downdate - Downgrade Attacks

## Author
Trellix

## Description
This rule blocks the creation of pending.xml file within winsxs folder and blocks creation of Registry value named as PoqexecCmdline.

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {

   Target {

			  Match VALUE {

				 Include OBJECT_NAME { -v "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide\\Configuration\\PoqexecCmdline" }

				 Include REGVAL_DATA -type MULTI_STRING { -v "*.xml*" }

				 Exclude REGVAL_DATA -type MULTI_STRING { -v "*\\winsxs\\pending.xml*" }

				 Include -access "CREATE WRITE"

			  }

		  Match FILE {

				 Include OBJECT_NAME { -v "**\\winsxs\\pending.xml" }

				 Exclude OBJECT_NAME {

						-v "C:\\\$WinREAgent\\Scratch\\Mount\\Windows\\WinSxS\\pending.xml"

						-v "c:\\windows\\winsxs\\pending.xml"

				 }

				 Include -access "CREATE"

		  }

   }

}
```

## Tested Platforms
OS: Windows 10 19H2 x64 and Windows 2016
ENS: 10.7.0

## Notes
NA
