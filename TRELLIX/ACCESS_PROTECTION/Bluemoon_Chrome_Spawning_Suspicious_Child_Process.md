# Bluemoon Chrome Spawning Suspicious Child Process


## Author
Trellix

## Description
Rule Detects when Google Chrome (chrome.exe) creates (spawns) any of a set of known Living-off-the-Land (LOLBin) or script-execution processes. 

## Rule Class 
Process

## Rule TCL
```tcl
 Rule {
							Process {
									Include OBJECT_NAME { -v "chrome.exe" }
							}
							Target {
								Match PROCESS {
									Include OBJECT_NAME { -v "hh.exe" }
									Include OBJECT_NAME { -v "cmd.exe" }
									Include OBJECT_NAME { -v "powershell.exe" }
									Include OBJECT_NAME { -v "rundll32.exe" }
									Include OBJECT_NAME { -v "regsvr32.exe" }
									Include OBJECT_NAME { -v "wscript.exe" }
									Include OBJECT_NAME { -v "cscript.exe" }
									Include OBJECT_NAME { -v "pwsh.exe" }
									Include OBJECT_NAME { -v "tasklist.exe" }
									Include OBJECT_NAME { -v "taskkill.exe" }
									Include OBJECT_NAME { -v "tskill.exe" }
									Include OBJECT_NAME { -v "sc.exe" }
									Include OBJECT_NAME { -v "reg.exe" }
									Include OBJECT_NAME { -v "netsh.exe" }
									Include OBJECT_NAME { -v "net.exe" }
									Include OBJECT_NAME { -v "net1.exe" }
									Include OBJECT_NAME { -v "csc.exe" }
									Include OBJECT_NAME { -v "curl.exe" }
									Include OBJECT_NAME { -v "mshta.exe" }
									Include OBJECT_NAME { -v "certutil.exe" }
									Include OBJECT_NAME { -v "msiexec.exe" }
									Include -access "CREATE"
								}
							}
					}

```


## Tested Platforms
OS: Windows 10 20H2 x64 and Win 20 H1x86
ENS: 10.7.0 

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.