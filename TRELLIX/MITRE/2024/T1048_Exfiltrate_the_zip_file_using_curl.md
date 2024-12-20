# T1048 Exfiltrate the zip file using curl

## Author
Trellix

## Description
This Expert rule detects execution of curl commands.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
	  Target {
			   Match PROCESS {
						Include DESCRIPTION {-v "The curl executable" }
						Include PROCESS_CMD_LINE { -v "** -F *=@**" }
						Include PROCESS_CMD_LINE { -v "** --form *=@**" }
						Include PROCESS_CMD_LINE { -v "** -T**" }
						Include PROCESS_CMD_LINE { -v "** --upload-file**" }
						Include PROCESS_CMD_LINE { -v "** -d**" }
						Include PROCESS_CMD_LINE { -v "** --data**" }
						Include PROCESS_CMD_LINE { -v "** --data-binary**" }
						Include -access "CREATE"
				
		}
		
	}

}
```

## Tested Platforms
OS: Win 11, Win 20H1x86 

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
