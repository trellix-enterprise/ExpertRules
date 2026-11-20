# ePO SSH Reverse Tunnel Protocol Tunneling

## Author
Trellix

## Description
This expert rule detects and blocks ssh.exe from being launched to create a reverse SSH tunnel ("-R"), such as one forwarding RDP port 3389, or one whose command line references "ProgramData\ssh\tmp*" or "temp*" paths or "UserKnownHostsFile". Attackers use these tunnels to expose internal systems to external hosts and bypass firewalls for remote access.


## Rule Class 
File

## Rule TCL
```tcl
Rule {
	Target {
        	Match PROCESS {
            			Include OBJECT_NAME { -v "ssh.exe" }
				Include PROCESS_CMD_LINE { -v "*-R *:*:3389*" }
            			Include PROCESS_CMD_LINE { -v "**\\ProgramData\\ssh\\tmp*\\* -R *:*:*" }
				Include PROCESS_CMD_LINE { -v "**\\ProgramData\\ssh\\temp*\\* -R *:*:*" }
				Include PROCESS_CMD_LINE { -v "*-R *:*:* **\\ProgramData\\ssh\\tmp*\\*" }
				Include PROCESS_CMD_LINE { -v "*-R *:*:* **\\ProgramData\\ssh\\temp*\\*" }
				Include PROCESS_CMD_LINE { -v "*-R *:*:* UserKnownHostsFile*" }
				Include PROCESS_CMD_LINE { -v "*UserKnownHostsFile* -R *:*:*" }
				Include -access "CREATE"
          	}
	}
}
```

## Tested Platforms
OS: Windows 10 20H1 x86 and Windows 11 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.