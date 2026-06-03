# T1036 Masquerading Non Standard Wermgr Execution

## Author
Trellix

## Description
This rule detects and blocks unauthorized instances of wermgr.exe executing outside of standard system directories when spawned with SYSTEM-level privileges by the Windows Task Scheduler (svchost.exe), mitigating Local Privilege Escalation (LPE) techniques such as the MiniPlasma exploit.

## Rule Class
Process

## Rule TCL
```tcl
Rule {
	  Process {
	       Include OBJECT_NAME { -v "svchost.exe" }
		   Include PROCESS_CMD_LINE { -v "**schedule**" }
	  }
	  Target {
			Match PROCESS {
				Include OBJECT_NAME { -v "wermgr.exe" }
				Include GROUP_SID { -v "S-1-16-16384" }
				Exclude OBJECT_NAME { 
						-v "%systemdrive%\\Windows\\System32\\wermgr.exe"
						if { [iSystem os_arch] == 640 } {
								-v "%systemdrive%\\Windows\\Syswow64\\wermgr.exe"
						}
                }
				Include -access "CREATE"
			}
	  }
}

```

## Tested Platforms
OS: Windows 11 x64 and Windows Server 2022 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.