# Behavior Abuse of WSCRIPT.EXE

## Author
McAfee

## Description
This rule detects the behavior abuse of WSCRIPT.EXE while executing specific script files using CMD.EXE. This is generally observed with certain variants of QBOT and Trickbot malware.

## Rule Class 
Processes

## Rule TCL
```tcl
The original rule: 
Rule {
       Process {
                 Include OBJECT_NAME { -v "wscript.exe"  }
				 Include PROCESS_CMD_LINE { -v "**\\programdata\\*.vbs*" }

                }
Target {
          Match PROCESS {
                
                Include OBJECT_NAME { -v "cmd.exe"  }
				Include PROCESS_CMD_LINE { -v "**c:\\*\\*.cmd*" }		

				Include -access "CREATE"
                }
       }
}
```

## Trigger
Samples tested: 
81fef56212815515d22b62d3824ef5af
ad9afa1dc5b4e486d3155ed62ee5ed84

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.