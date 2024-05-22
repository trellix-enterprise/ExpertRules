# Msohtmed.exe Abuse.

## Author
Trellix

## Description
This rule trigger indicates that MSOHTMED.exe is making an attempt to download files from a remote location.

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
      Target {
            Match PROCESS {
               Include OBJECT_NAME { -v "**\\MSOHTMED.EXE" }
			    Exclude PROCESS_CMD_LINE { -v "*http://*.html" }
                Exclude PROCESS_CMD_LINE { -v "*http://*.htm" }
                Exclude PROCESS_CMD_LINE { -v "*https://*.html" }
                Exclude PROCESS_CMD_LINE { -v "*https://*.htm" }
					
                Include -access "CREATE"
                        
            }
                             
      }
   
}
```

## Tested Platforms
OS: Windows 2019 , Win 2016
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.