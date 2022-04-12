# CVE 2021-21908 MSI Logic Issue EoP

## Author
McAfee Enterprise

## Description
This expert rule detects and prevents Escalation of Privilege (EoP) due to abuse of Logiccal issue found in MSI installer

## Expert Rule 1

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
  Process {
        Include OBJECT_NAME { -v "dotnet.exe" }
		  }
  Target {
		Match FILE {					
				Include OBJECT_NAME { -v "MSI_EoP.dll" }	
				Exclude VTP_PRIVILEGES -type BITMASK { -v 0x1 }
				Include -access	 "EXECUTE" 			
		}	
		
	}
}
```

## Expert Rule 2

## Rule Class 
Registry

## Rule TCL
```tcl
Rule { 
	Target {
	    Match VALUE {		
			Include OBJECT_NAME {              
				-v "HKCU\\Software\\Classes\\CLSID\\{13371337-1337-1337-1337-133713371338}\\InprocServer32\\*"                
			}

			Include REGVAL_DATA -type EXPANDABLE_STRING {
                -v "**MSI_EoP.dll"                
            }
			Include	-access "CREATE ADD WRITE"		
		}
	}
}
```

## Tested Platforms
OS: Windows 10 19H1 x64 and Win Server 2019
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
