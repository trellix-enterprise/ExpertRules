# BitMove COM HIJACKING

## Author
Trellix

## Description
This rule detects when baaupdate.exe process tries to execute another application or process.This is an enveloping type of rule for restricting the access of a process.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "baaupdate.exe" }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "hh.exe" }
			Include OBJECT_NAME { -v "cmd.exe" }
			Include OBJECT_NAME { -v "powershell.exe" }
			Include OBJECT_NAME { -v "powershell_ise.exe" }
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
			Include OBJECT_NAME { -v "csc.exe" }
			Include OBJECT_NAME { -v "mshta.exe" }
			Include OBJECT_NAME { -v "schtasks.exe" }
			Include OBJECT_NAME { -v "certutil.exe" }
			Include OBJECT_NAME { -v "wmic.exe" }
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