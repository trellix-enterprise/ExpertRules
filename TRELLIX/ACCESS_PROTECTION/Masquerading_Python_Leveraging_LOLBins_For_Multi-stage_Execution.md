# Masquerading Python Leveraging LOLBins For Multi-stage Execution

## Author
Trellix

## Description
This rule blocks any python process spawning system tools with suspicious command-line arguments, indicating masqueraded use of trusted binaries for multi-stage execution.

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
            Process {
                 Include OBJECT_NAME { -v "python.exe" }
				 Include OBJECT_NAME { -v "pythonw.exe" }
            }
            Target {
				Match PROCESS {
						Include OBJECT_NAME {
							-v "whoami.exe"
							-v "wget.exe"
							-v "curl.exe"
							-v "rundll32.exe"
							-v "nltest.exe"
							-v "systeminfo.exe"
							-v "msiexec.exe"
							-v "regsvr32.exe"
							-v "netstat.exe"
							-v "net.exe"
							-v "net1.exe"
							-v "dpapimig.exe"
						}
						Include -access "CREATE"
				}
				
				Match PROCESS { 
						Include OBJECT_NAME { 
							-v "powershell.exe"
							-v "pwsh.exe" 
							-v "cmd.exe" 
						}
						Include PROCESS_CMD_LINE { 
							-v "**Expand-Archive *-Path**" 							
							-v "**Register-ScheduledTask**" 
							-v "**CreateShortcut**" 
							-v "**Win32_ComputerSystemProduct**" 
							-v "**-RunLevel Highest**"
							-v "**-WindowStyle Hidden**"
							-v "**CopyFromScreen**"
							-v "**\\*.lnk**"
							-v "**ExecutionPolicy Bypass**"
						}
						Include -access "CREATE"
                }
          
            }
      
}

```
## Trigger
NA

## Tested Platforms
OS: Windows 10 19H2 x64 and Windows 10 x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.